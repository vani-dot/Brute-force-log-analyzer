# test_watcher.py
# Tests for live monitoring.
#
# Every test drives poll_once() by hand instead of sleeping and hoping, so the
# suite is deterministic and finishes in milliseconds.

import os
import tempfile
import unittest

from alerts import AlertDispatcher, WebhookChannel
from detector import BruteForceDetector
from storage import Storage
from watcher import FileFollower, LiveWatcher, WatchState


def failure(second, user="root", ip="203.0.113.77"):
    return (f"Aug 24 10:00:{second:02d} host sshd[1]: Failed password for "
            f"invalid user {user} from {ip} port 40000 ssh2")


class TempLog:
    """A log file on disk that tests can append to and rotate."""

    def __enter__(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "auth.log")
        open(self.path, "w").close()
        return self

    def __exit__(self, *exc):
        self.dir.cleanup()

    def append(self, lines):
        with open(self.path, "a") as f:
            f.write("\n".join(lines) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def write_partial(self, text):
        with open(self.path, "a") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())

    def rotate(self):
        os.rename(self.path, self.path + ".1")
        open(self.path, "w").close()

    def truncate(self):
        open(self.path, "w").close()


class TestFileFollower(unittest.TestCase):

    def test_reads_lines_appended_after_attaching(self):
        with TempLog() as log:
            follower = FileFollower(log.path)
            follower.open(from_end=True)
            log.append(["one", "two"])
            self.assertEqual(follower.read_lines(), ["one", "two"])

    def test_ignores_what_was_there_before_when_starting_at_the_end(self):
        with TempLog() as log:
            log.append(["old"])
            follower = FileFollower(log.path)
            follower.open(from_end=True)
            self.assertEqual(follower.read_lines(), [])

    def test_reads_existing_content_when_starting_from_the_beginning(self):
        with TempLog() as log:
            log.append(["old"])
            follower = FileFollower(log.path)
            follower.open(from_end=False)
            self.assertEqual(follower.read_lines(), ["old"])

    def test_a_partial_line_is_held_until_the_newline_arrives(self):
        with TempLog() as log:
            follower = FileFollower(log.path)
            follower.open(from_end=True)
            log.write_partial("half a li")
            self.assertEqual(follower.read_lines(), [])
            log.write_partial("ne\n")
            self.assertEqual(follower.read_lines(), ["half a line"])

    def test_survives_rotation(self):
        with TempLog() as log:
            follower = FileFollower(log.path)
            follower.open(from_end=True)
            log.append(["before"])
            follower.read_lines()
            log.rotate()
            log.append(["after"])
            self.assertIn("after", follower.read_lines())

    def test_survives_truncation_in_place(self):
        with TempLog() as log:
            log.append(["a" * 100])
            follower = FileFollower(log.path)
            follower.open(from_end=True)
            log.truncate()
            log.append(["fresh"])
            self.assertIn("fresh", follower.read_lines())

    def test_a_file_that_does_not_exist_yet_is_not_an_error(self):
        follower = FileFollower("/nonexistent/path/auth.log")
        self.assertFalse(follower.open())
        self.assertEqual(follower.read_lines(), [])


class TestLiveDetection(unittest.TestCase):

    def watcher(self, log, **kwargs):
        kwargs.setdefault("detector", BruteForceDetector(threshold=4, window=600))
        watcher = LiveWatcher(log.path, poll_seconds=0.01, **kwargs)
        watcher._follower.open(from_end=False)
        watcher.state = WatchState.RUNNING
        return watcher

    def test_nothing_fires_below_the_threshold(self):
        with TempLog() as log:
            watcher = self.watcher(log)
            log.append([failure(i) for i in range(3)])
            self.assertEqual(watcher.poll_once(), [])

    def test_fires_exactly_when_the_threshold_is_crossed(self):
        with TempLog() as log:
            watcher = self.watcher(log)
            log.append([failure(i) for i in range(3)])
            watcher.poll_once()
            log.append([failure(3)])
            fresh = watcher.poll_once()
            self.assertTrue(fresh)
            self.assertIn("203.0.113.77", {f.key for f in fresh})

    def test_an_ongoing_attack_is_not_re_announced(self):
        with TempLog() as log:
            watcher = self.watcher(log, repeat_after=3600)
            log.append([failure(i) for i in range(6)])
            first = watcher.poll_once()
            log.append([failure(i) for i in range(6, 12)])
            second = watcher.poll_once()
            self.assertTrue(first)
            self.assertEqual(second, [])

    def test_it_re_announces_once_the_repeat_window_has_passed(self):
        with TempLog() as log:
            watcher = self.watcher(log, repeat_after=0)
            log.append([failure(i) for i in range(6)])
            self.assertTrue(watcher.poll_once())
            log.append([failure(i) for i in range(6, 12)])
            self.assertTrue(watcher.poll_once())

    def test_non_login_lines_are_counted_as_skipped(self):
        with TempLog() as log:
            watcher = self.watcher(log)
            log.append(["Aug 24 10:00:00 host sshd[1]: Received disconnect "
                        "from 1.2.3.4 port 22:11: Bye"])
            watcher.poll_once()
            self.assertEqual(watcher.lines_skipped, 1)

    def test_events_outside_the_retention_window_are_dropped(self):
        with TempLog() as log:
            watcher = self.watcher(log, retention_seconds=60)
            log.append([failure(0)])
            watcher.poll_once()
            log.append(["Aug 24 12:00:00 host sshd[1]: Failed password for "
                        "invalid user root from 203.0.113.77 port 1 ssh2"])
            watcher.poll_once()
            # The 10:00 event is two hours older than the newest one.
            self.assertEqual(watcher.status()["events_buffered"], 1)

    def test_detection_survives_rotation(self):
        with TempLog() as log:
            watcher = self.watcher(log, repeat_after=0)
            log.append([failure(i) for i in range(5)])
            watcher.poll_once()
            log.rotate()
            log.append([failure(i, ip="198.51.100.9") for i in range(20, 25)])
            fresh = watcher.poll_once()
            self.assertIn("198.51.100.9", {f.key for f in fresh})


class TestSubscribersAndStatus(unittest.TestCase):

    def test_subscribers_receive_findings(self):
        with TempLog() as log:
            watcher = LiveWatcher(log.path,
                                  detector=BruteForceDetector(threshold=4,
                                                              window=600))
            watcher._follower.open(from_end=False)
            watcher.state = WatchState.RUNNING
            listener = watcher.subscribe()
            log.append([failure(i) for i in range(5)])
            watcher.poll_once()

            kinds = []
            while not listener.empty():
                kinds.append(listener.get_nowait()["type"])
            self.assertIn("finding", kinds)
            self.assertIn("activity", kinds)

    def test_unsubscribing_stops_delivery(self):
        with TempLog() as log:
            watcher = LiveWatcher(log.path)
            listener = watcher.subscribe()
            watcher.unsubscribe(listener)
            self.assertEqual(watcher.status()["listeners"], 0)

    def test_a_full_subscriber_queue_does_not_block_detection(self):
        # A browser tab that stopped reading must not stall the detector.
        with TempLog() as log:
            watcher = LiveWatcher(log.path,
                                  detector=BruteForceDetector(threshold=4,
                                                              window=600))
            watcher._follower.open(from_end=False)
            watcher.state = WatchState.RUNNING
            listener = watcher.subscribe()
            while not listener.full():
                listener.put_nowait({"filler": True})
            log.append([failure(i) for i in range(5)])
            self.assertTrue(watcher.poll_once())    # completed anyway

    def test_status_reports_a_missing_file_as_waiting(self):
        watcher = LiveWatcher("/nonexistent/auth.log")
        watcher.poll_once()
        self.assertEqual(watcher.status()["state"], WatchState.WAITING)

    def test_snapshot_returns_the_current_window(self):
        with TempLog() as log:
            watcher = LiveWatcher(log.path,
                                  detector=BruteForceDetector(threshold=4,
                                                              window=600))
            watcher._follower.open(from_end=False)
            watcher.state = WatchState.RUNNING
            log.append([failure(i) for i in range(5)])
            watcher.poll_once()
            snapshot = watcher.snapshot()
            self.assertEqual(len(snapshot.events), 5)
            self.assertTrue(snapshot.findings)


class TestLiveIntegration(unittest.TestCase):
    """Live detection wired to storage and alerting, as the app runs it."""

    def test_findings_are_persisted_and_alerted(self):
        from test_alerts import Receiver

        with TempLog() as log, Receiver() as receiver:
            store = Storage(":memory:")
            watcher = LiveWatcher(
                log.path,
                detector=BruteForceDetector(threshold=4, window=600),
                storage=store,
                dispatcher=AlertDispatcher(
                    channels=[WebhookChannel(url=receiver.url())],
                    storage=store, min_severity="MEDIUM", cooldown_seconds=0))
            watcher._follower.open(from_end=False)
            watcher.state = WatchState.RUNNING

            log.append([failure(i) for i in range(5)])
            fresh = watcher.poll_once()

            self.assertTrue(fresh)
            self.assertEqual(store.summary()["runs"], len(fresh))
            self.assertEqual(len(receiver.received), len(fresh))
            self.assertEqual(store.recent_runs()[0]["mode"], "live")
            store.close()

    def test_lifecycle_start_and_stop(self):
        with TempLog() as log:
            watcher = LiveWatcher(log.path, poll_seconds=0.01)
            self.assertTrue(watcher.start())
            self.assertTrue(watcher.running)
            self.assertFalse(watcher.start())     # already running
            watcher.stop()
            self.assertFalse(watcher.running)
            self.assertEqual(watcher.status()["state"], WatchState.STOPPED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
