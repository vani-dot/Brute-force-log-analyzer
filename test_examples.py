# test_examples.py
# Guards the two try-me files in the project root.
#
# They are the first thing anyone runs, so they must keep doing exactly what
# their names promise. If a detector change breaks either, this fails loudly.

import os
import unittest

from detector import BruteForceDetector, HIGH

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WITH_ATTACKS = os.path.join(BASE_DIR, "EXAMPLE-1-attacks-present.log")
NO_ATTACKS = os.path.join(BASE_DIR, "EXAMPLE-2-no-attacks.log")

RECOMMENDED = {"threshold": 4, "window": 600}


class TestBothFilesExist(unittest.TestCase):

    def test_they_are_in_the_project_root(self):
        for path in (WITH_ATTACKS, NO_ATTACKS):
            self.assertTrue(os.path.exists(path), path)

    def test_they_are_substantial_enough_to_be_interesting(self):
        for path in (WITH_ATTACKS, NO_ATTACKS):
            self.assertGreater(sum(1 for _ in open(path)), 150, path)


class TestFileWithAttacks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.result = BruteForceDetector(**RECOMMENDED).analyze_file(WITH_ATTACKS)
        cls.keys = {f.key for f in cls.result.findings}

    def test_reports_a_confirmed_breach(self):
        highs = [f for f in self.result.findings if f.severity == HIGH]
        self.assertEqual(len(highs), 1)
        self.assertIn("SUCCESS", highs[0].detail)

    def test_catches_the_fast_burst(self):
        self.assertIn("203.0.113.88", self.keys)

    def test_catches_the_password_spray(self):
        self.assertIn("203.0.113.171", self.keys)

    def test_catches_the_rsyslog_folded_flood(self):
        self.assertIn("198.51.100.240", self.keys)

    def test_catches_the_botnet_only_via_the_subnet_pivot(self):
        # No single address of it crosses the threshold. That is the point.
        self.assertIn("192.0.2.0/24", self.keys)
        individual = [k for k in self.keys if k.startswith("192.0.2.")
                      and not k.endswith("/24")]
        self.assertEqual(individual, [])

    def test_the_folded_flood_is_counted_as_many_attempts(self):
        flood = next(f for f in self.result.findings
                     if f.key == "198.51.100.240")
        self.assertGreater(flood.count, 40)

    def test_contains_operational_noise_that_is_skipped(self):
        self.assertGreater(self.result.skipped, 20)


class TestFileWithoutAttacks(unittest.TestCase):

    def test_produces_nothing_at_the_recommended_setting(self):
        result = BruteForceDetector(**RECOMMENDED).analyze_file(NO_ATTACKS)
        self.assertEqual(result.findings, [], [f.detail for f in result.findings])

    def test_produces_nothing_at_the_common_default_either(self):
        result = BruteForceDetector(threshold=5,
                                    window=120).analyze_file(NO_ATTACKS)
        self.assertEqual(result.findings, [])

    def test_never_reports_a_breach_however_sensitive(self):
        # Mistyped passwords and a shared internal host must not become a
        # "confirmed compromise" even when the burst threshold is very low.
        for threshold in (3, 4, 5, 8):
            result = BruteForceDetector(threshold=threshold,
                                        window=600).analyze_file(NO_ATTACKS)
            highs = [f for f in result.findings if f.severity == HIGH]
            self.assertEqual(highs, [], f"HIGH at threshold {threshold}")

    def test_it_does_contain_failures_and_successes(self):
        # A file with no failed logins would prove nothing.
        result = BruteForceDetector(**RECOMMENDED).analyze_file(NO_ATTACKS)
        self.assertGreater(result.failure_count, 30)
        self.assertGreater(result.success_count, 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
