# storage.py
# ONE JOB: remember what previous analyses found.
#
# Without this the tool answers "is this log bad?". With it, it answers the
# question an analyst actually asks: "have I seen this address before?"
#
# SQLite because it needs no server, ships with Python, and a single file is
# the right amount of infrastructure for this.

import json
import os
import sqlite3
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   REAL    NOT NULL,
    source       TEXT    NOT NULL,
    mode         TEXT    NOT NULL DEFAULT 'batch',
    threshold    INTEGER NOT NULL,
    window       INTEGER NOT NULL,
    events       INTEGER NOT NULL,
    skipped      INTEGER NOT NULL,
    failures     INTEGER NOT NULL,
    successes    INTEGER NOT NULL,
    unique_ips   INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    high_count   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seen_at    REAL    NOT NULL,
    type       TEXT    NOT NULL,
    pivot      TEXT    NOT NULL,
    key        TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    detail     TEXT    NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    span       INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT    NOT NULL DEFAULT '',
    last_seen  TEXT    NOT NULL DEFAULT '',
    total      INTEGER NOT NULL DEFAULT 0,
    enrichment TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_key      ON findings(key);
CREATE INDEX IF NOT EXISTS idx_findings_run      ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_seen     ON findings(seen_at);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- One row per offender, updated in place. Answers "how long has this been
-- going on" without scanning every finding ever recorded.
CREATE TABLE IF NOT EXISTS offenders (
    key         TEXT PRIMARY KEY,
    pivot       TEXT NOT NULL,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    times_seen  INTEGER NOT NULL DEFAULT 0,
    high_count  INTEGER NOT NULL DEFAULT 0,
    worst       TEXT NOT NULL DEFAULT 'MEDIUM',
    enrichment  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS alerts_sent (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at   REAL NOT NULL,
    key       TEXT NOT NULL,
    severity  TEXT NOT NULL,
    channel   TEXT NOT NULL,
    ok        INTEGER NOT NULL,
    detail    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_alerts_key ON alerts_sent(key, sent_at);
"""


class Storage:
    """SQLite-backed history. Safe to use from multiple threads."""

    def __init__(self, path=":memory:"):
        self.path = path
        if path != ":memory:":
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)
        # check_same_thread=False because Flask serves requests on threads and
        # the live watcher runs on its own. Writes are serialised by SQLite
        # itself; WAL keeps readers from blocking behind them.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @contextmanager
    def _write(self):
        with self._conn:
            yield self._conn

    def close(self):
        self._conn.close()

    # ---- recording ---------------------------------------------------

    def record_run(self, result, mode="batch", enrichment=None, now=None):
        """Persist one AnalysisResult. Returns the new run id."""
        now = now if now is not None else time.time()
        enrichment = enrichment or {}
        stats = result.to_dict()["stats"]

        with self._write() as conn:
            cursor = conn.execute(
                """INSERT INTO runs (started_at, source, mode, threshold,
                                     window, events, skipped, failures,
                                     successes, unique_ips, finding_count,
                                     high_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (now, result.source, mode, result.threshold, result.window,
                 stats["events"], stats["skipped"], stats["failures"],
                 stats["successes"], stats["unique_ips"], stats["findings"],
                 stats["high"]))
            run_id = cursor.lastrowid

            for finding in result.findings:
                extra = enrichment.get(finding.key, {})
                conn.execute(
                    """INSERT INTO findings (run_id, seen_at, type, pivot, key,
                                             severity, detail, count, span,
                                             first_seen, last_seen, total,
                                             enrichment)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (run_id, now, finding.type, finding.pivot, finding.key,
                     finding.severity, finding.detail, finding.count,
                     finding.span, finding.first_seen, finding.last_seen,
                     finding.total, json.dumps(extra)))
                self._touch_offender(conn, finding, now, extra)

        return run_id

    @staticmethod
    def _touch_offender(conn, finding, now, extra):
        row = conn.execute("SELECT times_seen, high_count, worst FROM offenders "
                           "WHERE key = ?", (finding.key,)).fetchone()
        is_high = 1 if finding.severity == "HIGH" else 0
        if row is None:
            conn.execute(
                """INSERT INTO offenders (key, pivot, first_seen, last_seen,
                                          times_seen, high_count, worst,
                                          enrichment)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (finding.key, finding.pivot, now, now, 1, is_high,
                 finding.severity, json.dumps(extra)))
        else:
            # HIGH always wins as the recorded worst severity.
            worst = "HIGH" if (is_high or row["worst"] == "HIGH") else "MEDIUM"
            conn.execute(
                """UPDATE offenders
                      SET last_seen = ?, times_seen = times_seen + 1,
                          high_count = high_count + ?, worst = ?,
                          enrichment = CASE WHEN ? != '{}' THEN ?
                                            ELSE enrichment END
                    WHERE key = ?""",
                (now, is_high, worst, json.dumps(extra), json.dumps(extra),
                 finding.key))

    def record_alert(self, key, severity, channel, ok, detail="", now=None):
        now = now if now is not None else time.time()
        with self._write() as conn:
            conn.execute(
                """INSERT INTO alerts_sent (sent_at, key, severity, channel,
                                            ok, detail)
                   VALUES (?,?,?,?,?,?)""",
                (now, key, severity, channel, 1 if ok else 0, detail))

    def reset(self):
        """Delete every recorded run, finding, offender and alert.

        Returns what was removed, so the caller can report it rather than
        claiming success blindly.
        """
        counts = {}
        for table in ("runs", "findings", "offenders", "alerts_sent"):
            counts[table] = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        with self._write() as conn:
            for table in ("findings", "runs", "offenders", "alerts_sent"):
                conn.execute(f"DELETE FROM {table}")
            conn.execute("DELETE FROM sqlite_sequence "
                         "WHERE name IN ('runs','findings','alerts_sent')")
        return counts

    # ---- querying ----------------------------------------------------

    def recent_runs(self, limit=20):
        rows = self._conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(r) for r in rows]

    def run_findings(self, run_id):
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY severity, key",
            (run_id,)).fetchall()
        return [self._finding_row(r) for r in rows]

    def repeat_offenders(self, limit=20, min_times=2):
        """Keys seen across more than one analysis. The trend question."""
        rows = self._conn.execute(
            """SELECT * FROM offenders
                WHERE times_seen >= ?
             ORDER BY high_count DESC, times_seen DESC, last_seen DESC
                LIMIT ?""", (min_times, limit)).fetchall()
        return [self._offender_row(r) for r in rows]

    def history_for(self, key):
        """Everything known about one address, username or subnet."""
        row = self._conn.execute("SELECT * FROM offenders WHERE key = ?",
                                 (key,)).fetchone()
        if row is None:
            return None
        sightings = self._conn.execute(
            """SELECT f.*, r.source, r.mode FROM findings f
                 JOIN runs r ON r.id = f.run_id
                WHERE f.key = ? ORDER BY f.seen_at DESC LIMIT 50""",
            (key,)).fetchall()
        record = self._offender_row(row)
        record["sightings"] = [self._finding_row(s) for s in sightings]
        return record

    def last_alert_time(self, key, channel=None):
        if channel:
            row = self._conn.execute(
                "SELECT MAX(sent_at) AS t FROM alerts_sent "
                "WHERE key = ? AND channel = ? AND ok = 1",
                (key, channel)).fetchone()
        else:
            row = self._conn.execute(
                "SELECT MAX(sent_at) AS t FROM alerts_sent "
                "WHERE key = ? AND ok = 1", (key,)).fetchone()
        return row["t"]

    def recent_alerts(self, limit=25):
        rows = self._conn.execute(
            "SELECT * FROM alerts_sent ORDER BY sent_at DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(r) for r in rows]

    def summary(self):
        """Headline numbers for the dashboard. All computed, none stored."""
        row = self._conn.execute(
            """SELECT COUNT(*) AS runs,
                      COALESCE(SUM(events), 0) AS events,
                      COALESCE(SUM(finding_count), 0) AS findings,
                      COALESCE(SUM(high_count), 0) AS high
                 FROM runs""").fetchone()
        offenders = self._conn.execute(
            "SELECT COUNT(*) AS n FROM offenders").fetchone()["n"]
        repeats = self._conn.execute(
            "SELECT COUNT(*) AS n FROM offenders WHERE times_seen > 1"
        ).fetchone()["n"]
        alerts = self._conn.execute(
            "SELECT COUNT(*) AS n FROM alerts_sent WHERE ok = 1").fetchone()["n"]
        return {"runs": row["runs"], "events_analysed": row["events"],
                "findings_total": row["findings"], "high_total": row["high"],
                "distinct_offenders": offenders, "repeat_offenders": repeats,
                "alerts_sent": alerts}

    # ---- row helpers -------------------------------------------------

    @staticmethod
    def _finding_row(row):
        record = dict(row)
        record["enrichment"] = json.loads(record.get("enrichment") or "{}")
        return record

    @staticmethod
    def _offender_row(row):
        record = dict(row)
        record["enrichment"] = json.loads(record.get("enrichment") or "{}")
        record["days_active"] = max(
            (record["last_seen"] - record["first_seen"]) / 86400.0, 0.0)
        return record
