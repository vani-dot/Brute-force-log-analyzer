# watcher.py
# ONE JOB: follow a log file as it is written and detect attacks as they happen.
#
# Everything else in this project is retrospective — you hand it a file and it
# tells you what already occurred. This is the part that makes it a monitor:
# it holds a rolling window of recent events in memory, re-runs the detector as
# lines arrive, and emits each finding ONCE, the moment it first crosses the
# threshold.
#
# Three problems this has to solve that batch analysis does not:
#
#   Rotation    logrotate replaces auth.log at midnight. Following a file
#               handle means silently monitoring a deleted inode forever, so
#               the file is re-opened when its identity or size says it changed.
#   Partial     a write can land mid-line. A line without a newline is held
#     lines     back until the rest arrives.
#   Repetition  a burst stays over the threshold for as long as it is in the
#               window. Without suppression an ongoing attack emits the same
#               finding every poll, forever.

import os
import queue
import threading
import time

from detector import BruteForceDetector, AnalysisResult
from log_parser import LogParser


class WatchState:
    STOPPED = "stopped"
    WAITING = "waiting"      # configured, but the file is not there yet
    RUNNING = "running"
    ERROR = "error"


class FileFollower:
    """tail -F semantics: survives rotation, truncation, and late creation."""

    def __init__(self, path):
        self.path = path
        self._handle = None
        self._inode = None
        self._buffer = ""

    @property
    def attached(self):
        return self._handle is not None

    def _identity(self):
        try:
            stat = os.stat(self.path)
            return stat.st_ino, stat.st_size
        except OSError:
            return None

    def open(self, from_end=True):
        """Attach to the file. Returns True if attached."""
        identity = self._identity()
        if identity is None:
            return False
        try:
            handle = open(self.path, "r", errors="replace")
        except OSError:
            return False

        self.close()
        self._handle = handle
        self._inode = identity[0]
        if from_end:
            self._handle.seek(0, os.SEEK_END)
        return True

    def _rotated(self):
        identity = self._identity()
        if identity is None:
            return True                       # file vanished
        inode, size = identity
        if inode != self._inode:
            return True                       # replaced by logrotate
        return size < self._handle.tell()     # truncated in place

    def read_lines(self):
        """Every complete line written since the last call."""
        if self._handle is None:
            if not self.open(from_end=True):
                return []
            return []

        if self._rotated():
            # Drain whatever remains of the old file, then follow the new one
            # from its beginning so nothing written during the swap is lost.
            tail = self._handle.read()
            self.close()
            if not self.open(from_end=False):
                return self._split(tail)
            return self._split(tail + self._handle.read())

        return self._split(self._handle.read())

    def _split(self, chunk):
        if not chunk:
            return []
        self._buffer += chunk
        # A trailing fragment with no newline is an incomplete write.
        if self._buffer.endswith("\n"):
            lines, self._buffer = self._buffer.splitlines(), ""
        else:
            parts = self._buffer.split("\n")
            lines, self._buffer = parts[:-1], parts[-1]
        return [line for line in lines if line.strip()]

    def close(self):
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
        self._handle = None


class LiveWatcher:
    """Follows a log, detects in real time, and pushes findings to listeners."""

    def __init__(self, path, detector=None, retention_seconds=7200,
                 poll_seconds=1.0, storage=None, dispatcher=None,
                 enricher=None, repeat_after=300, on_finding=None):
        self.path = path
        self.detector = detector or BruteForceDetector()
        self.retention = retention_seconds
        self.poll = poll_seconds
        self.storage = storage
        self.dispatcher = dispatcher
        self.enricher = enricher
        # How long before the SAME finding is allowed to fire again. Without
        # this an attack that stays over threshold re-emits on every poll.
        self.repeat_after = repeat_after
        self.on_finding = on_finding

        self._follower = FileFollower(path)
        self._events = []
        self._announced = {}              # (type, pivot, key) -> last emitted
        self._lock = threading.Lock()
        self._thread = None
        self._stop = threading.Event()
        self._subscribers = []

        self.state = WatchState.STOPPED
        self.error = ""
        self.started_at = None
        self.lines_read = 0
        self.lines_skipped = 0
        self.findings_emitted = 0
        self.last_poll_at = None

    # ---- subscriptions (the browser listens through these) ------------

    def subscribe(self):
        listener = queue.Queue(maxsize=256)
        with self._lock:
            self._subscribers.append(listener)
        return listener

    def unsubscribe(self, listener):
        with self._lock:
            if listener in self._subscribers:
                self._subscribers.remove(listener)

    def _publish(self, kind, payload):
        message = {"type": kind, "at": time.time(), "data": payload}
        with self._lock:
            listeners = list(self._subscribers)
        for listener in listeners:
            try:
                listener.put_nowait(message)
            except queue.Full:
                # A browser tab that stopped reading must not stall the
                # detector. Drop its backlog rather than block.
                pass

    # ---- lifecycle -----------------------------------------------------

    def start(self, from_end=True):
        if self._thread and self._thread.is_alive():
            return False
        self._stop.clear()
        self.started_at = time.time()
        self.error = ""
        self._follower.open(from_end=from_end)
        self.state = (WatchState.RUNNING if self._follower.attached
                      else WatchState.WAITING)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="bfla-watcher")
        self._thread.start()
        return True

    def stop(self, timeout=3.0):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        self._follower.close()
        self.state = WatchState.STOPPED
        self._publish("state", self.status())

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                self.state = WatchState.ERROR
                self.error = f"{type(exc).__name__}: {exc}"
                self._publish("state", self.status())
            self._stop.wait(self.poll)

    # ---- the actual work -------------------------------------------------

    def poll_once(self):
        """Read whatever is new and detect over the rolling window.

        Separated from the loop so tests can drive it deterministically
        instead of sleeping and hoping.
        """
        self.last_poll_at = time.time()
        lines = self._follower.read_lines()

        if not self._follower.attached:
            if self.state != WatchState.WAITING:
                self.state = WatchState.WAITING
                self._publish("state", self.status())
            return []
        if self.state == WatchState.WAITING:
            self.state = WatchState.RUNNING
            self._publish("state", self.status())

        if not lines:
            return []

        parser = LogParser()
        new_events, skipped = parser.parse_lines(lines)
        self.lines_read += len(lines)
        self.lines_skipped += skipped

        with self._lock:
            self._events.extend(new_events)
            self._events.sort(key=lambda e: e.timestamp)
            self._trim()
            window_events = list(self._events)

        findings = self.detector.analyze(window_events)
        fresh = self._only_new(findings)

        self._publish("activity", {
            "lines": len(lines),
            "events": len(new_events),
            "skipped": skipped,
            "buffered": len(window_events),
            "stats": self._stats(window_events),
        })

        for finding in fresh:
            self._handle_finding(finding, window_events)

        return fresh

    def _trim(self):
        """Drop events that have fallen out of the retention window.

        Uses the newest log timestamp rather than wall-clock, so replaying a
        historical file behaves the same as following a live one.
        """
        if not self._events or self.retention <= 0:
            return
        newest = self._events[-1].timestamp
        cutoff = newest - self.retention
        self._events = [e for e in self._events if e.timestamp >= cutoff]

    def _only_new(self, findings):
        now = time.time()
        fresh = []
        for finding in findings:
            signature = (finding.type, finding.pivot, finding.key)
            last = self._announced.get(signature)
            if last is not None and (now - last) < self.repeat_after:
                continue
            self._announced[signature] = now
            fresh.append(finding)
        return fresh

    @staticmethod
    def _stats(events):
        failures = sum(1 for e in events if e.is_failure)
        return {
            "events": len(events),
            "failures": failures,
            "successes": sum(1 for e in events if e.is_success),
            "unique_ips": len({e.ip for e in events}),
        }

    def _handle_finding(self, finding, window_events):
        self.findings_emitted += 1

        context = {"source": self.path, "mode": "live"}
        enrichment = {}
        if self.enricher is not None and finding.pivot == "ip":
            enrichment = self.enricher.lookup(finding.key)
            context["location"] = self.enricher.describe(enrichment)

        if self.storage is not None:
            history = self.storage.history_for(finding.key)
            if history:
                context["times_seen"] = history["times_seen"]
            result = AnalysisResult(self.path, window_events, self.lines_skipped,
                                    [finding], self.detector.threshold,
                                    self.detector.window)
            self.storage.record_run(result, mode="live",
                                    enrichment={finding.key: enrichment})

        alerts = []
        if self.dispatcher is not None:
            alerts = [r.to_dict()
                      for r in self.dispatcher.dispatch(finding, context)]

        payload = {"finding": finding.to_dict(), "enrichment": enrichment,
                   "context": context, "alerts": alerts}
        self._publish("finding", payload)

        if self.on_finding:
            self.on_finding(finding, payload)

    # ---- introspection ---------------------------------------------------

    def status(self):
        with self._lock:
            buffered = len(self._events)
            listeners = len(self._subscribers)
        return {
            "path": self.path,
            "state": self.state,
            "running": self.running,
            "error": self.error,
            "started_at": self.started_at,
            "uptime_seconds": (time.time() - self.started_at
                               if self.started_at else 0),
            "last_poll_at": self.last_poll_at,
            "poll_seconds": self.poll,
            "retention_seconds": self.retention,
            "threshold": self.detector.threshold,
            "window": self.detector.window,
            "lines_read": self.lines_read,
            "lines_skipped": self.lines_skipped,
            "events_buffered": buffered,
            "findings_emitted": self.findings_emitted,
            "listeners": listeners,
        }

    def snapshot(self):
        """Current rolling window as an AnalysisResult, for a page load."""
        with self._lock:
            events = list(self._events)
        return AnalysisResult(self.path, events, self.lines_skipped,
                              self.detector.analyze(events),
                              self.detector.threshold, self.detector.window)
