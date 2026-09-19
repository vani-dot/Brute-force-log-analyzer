# test_storage.py
# Tests for the SQLite history layer. All in-memory — no file is touched.

import os
import tempfile
import unittest

from detector import BruteForceDetector, Finding, AnalysisResult, HIGH, MEDIUM
from log_parser import LogParser
from storage import Storage
from test_detector import sample


def result_with(findings, source="test.log", events=None):
    return AnalysisResult(source, events or [], 0, findings, 5, 120)


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self.store = Storage(":memory:")

    def tearDown(self):
        self.store.close()


class TestSchema(StorageTestCase):

    def test_starts_empty(self):
        summary = self.store.summary()
        self.assertEqual(summary["runs"], 0)
        self.assertEqual(summary["distinct_offenders"], 0)
        self.assertEqual(self.store.recent_runs(), [])

    def test_creates_a_real_file_when_given_a_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "nested", "bfla.db")
            store = Storage(path)
            store.record_run(result_with([]))
            store.close()
            self.assertTrue(os.path.exists(path))

    def test_reopening_a_file_keeps_the_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "bfla.db")
            first = Storage(path)
            first.record_run(result_with(
                [Finding("burst", "ip", "1.2.3.4", MEDIUM, "x")]))
            first.close()

            second = Storage(path)
            self.assertEqual(second.summary()["runs"], 1)
            self.assertIsNotNone(second.history_for("1.2.3.4"))
            second.close()


class TestRecording(StorageTestCase):

    def test_records_a_run_and_its_findings(self):
        detector = BruteForceDetector()
        result = detector.analyze_file(sample("auth_sample.log"))
        run_id = self.store.record_run(result)

        self.assertEqual(len(self.store.run_findings(run_id)), len(result.findings))
        summary = self.store.summary()
        self.assertEqual(summary["runs"], 1)
        self.assertEqual(summary["high_total"], 1)

    def test_stats_recorded_match_the_result(self):
        result = BruteForceDetector().analyze_file(sample("noisy_sample.log"))
        self.store.record_run(result)
        run = self.store.recent_runs()[0]
        self.assertEqual(run["events"], len(result.events))
        self.assertEqual(run["skipped"], result.skipped)
        self.assertEqual(run["failures"], result.failure_count)

    def test_mode_is_recorded(self):
        self.store.record_run(result_with([]), mode="live")
        self.assertEqual(self.store.recent_runs()[0]["mode"], "live")

    def test_enrichment_is_stored_alongside_the_finding(self):
        finding = Finding("burst", "ip", "8.8.8.8", MEDIUM, "x")
        run_id = self.store.record_run(
            result_with([finding]),
            enrichment={"8.8.8.8": {"country": "Testland", "asn": 42}})
        stored = self.store.run_findings(run_id)[0]
        self.assertEqual(stored["enrichment"]["country"], "Testland")

    def test_findings_are_deleted_with_their_run(self):
        finding = Finding("burst", "ip", "1.1.1.1", MEDIUM, "x")
        run_id = self.store.record_run(result_with([finding]))
        with self.store._write() as conn:
            conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        self.assertEqual(self.store.run_findings(run_id), [])


class TestOffenderTracking(StorageTestCase):
    """The question persistence exists to answer: have I seen this before?"""

    def record(self, key, severity=MEDIUM, times=1, now=None):
        for i in range(times):
            self.store.record_run(
                result_with([Finding("burst", "ip", key, severity, "x")]),
                now=now if now is None else now + i)

    def test_first_sighting_creates_an_offender(self):
        self.record("9.9.9.9")
        record = self.store.history_for("9.9.9.9")
        self.assertEqual(record["times_seen"], 1)
        self.assertEqual(record["worst"], MEDIUM)

    def test_repeat_sightings_accumulate(self):
        self.record("9.9.9.9", times=4)
        self.assertEqual(self.store.history_for("9.9.9.9")["times_seen"], 4)

    def test_high_severity_is_remembered_as_the_worst(self):
        self.record("9.9.9.9", severity=MEDIUM)
        self.record("9.9.9.9", severity=HIGH)
        self.record("9.9.9.9", severity=MEDIUM)
        record = self.store.history_for("9.9.9.9")
        self.assertEqual(record["worst"], HIGH)
        self.assertEqual(record["high_count"], 1)

    def test_repeat_offenders_excludes_one_off_sightings(self):
        self.record("seen.once")
        self.record("seen.twice", times=2)
        keys = {o["key"] for o in self.store.repeat_offenders()}
        self.assertIn("seen.twice", keys)
        self.assertNotIn("seen.once", keys)

    def test_repeat_offenders_ranks_high_severity_first(self):
        self.record("noisy", times=9)
        self.record("dangerous", severity=HIGH, times=2)
        self.assertEqual(self.store.repeat_offenders()[0]["key"], "dangerous")

    def test_days_active_spans_first_to_last_sighting(self):
        self.store.record_run(
            result_with([Finding("burst", "ip", "slow", MEDIUM, "x")]), now=0)
        self.store.record_run(
            result_with([Finding("burst", "ip", "slow", MEDIUM, "x")]),
            now=86400 * 3)
        self.assertAlmostEqual(self.store.history_for("slow")["days_active"],
                               3.0, places=3)

    def test_unknown_key_has_no_history(self):
        self.assertIsNone(self.store.history_for("never.seen"))

    def test_history_carries_the_individual_sightings(self):
        self.record("9.9.9.9", times=3)
        self.assertEqual(len(self.store.history_for("9.9.9.9")["sightings"]), 3)


class TestAlertRecords(StorageTestCase):

    def test_records_a_sent_alert(self):
        self.store.record_alert("1.2.3.4", HIGH, "slack", True, "delivered")
        recent = self.store.recent_alerts()
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["channel"], "slack")

    def test_last_alert_time_ignores_failures(self):
        self.store.record_alert("1.2.3.4", HIGH, "slack", False, "boom", now=100)
        self.assertIsNone(self.store.last_alert_time("1.2.3.4"))
        self.store.record_alert("1.2.3.4", HIGH, "slack", True, "ok", now=200)
        self.assertEqual(self.store.last_alert_time("1.2.3.4"), 200)

    def test_last_alert_time_can_be_scoped_to_one_channel(self):
        self.store.record_alert("1.2.3.4", HIGH, "slack", True, "", now=100)
        self.assertEqual(self.store.last_alert_time("1.2.3.4", "slack"), 100)
        self.assertIsNone(self.store.last_alert_time("1.2.3.4", "email"))

    def test_summary_counts_only_successful_alerts(self):
        self.store.record_alert("a", HIGH, "slack", True)
        self.store.record_alert("b", HIGH, "slack", False)
        self.assertEqual(self.store.summary()["alerts_sent"], 1)


class TestSummary(StorageTestCase):

    def test_totals_add_up_across_runs(self):
        detector = BruteForceDetector()
        for name in ("auth_sample.log", "noisy_sample.log", "clean_sample.log"):
            self.store.record_run(detector.analyze_file(sample(name)))
        summary = self.store.summary()
        self.assertEqual(summary["runs"], 3)
        self.assertGreater(summary["events_analysed"], 0)
        self.assertEqual(summary["high_total"], 1)   # only auth_sample has one

    def test_repeat_count_reflects_reanalysing_the_same_log(self):
        detector = BruteForceDetector()
        result = detector.analyze_file(sample("auth_sample.log"))
        self.store.record_run(result)
        self.assertEqual(self.store.summary()["repeat_offenders"], 0)
        self.store.record_run(result)
        self.assertGreater(self.store.summary()["repeat_offenders"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
