# test_generate.py
# Tests for the log generator.
#
# The generator's job is to produce a log the detector has not seen, with
# attacks it must find on its own. These tests check the log is realistic and
# that the ground truth it reports is actually true.

import unittest

from detector import BruteForceDetector
from generate_log import build, syslog_time
from log_parser import LogParser
from datetime import datetime


class TestGeneratedLog(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text, cls.attacks = build(hours=24, seed=42)
        cls.events, cls.skipped = LogParser().parse_text(cls.text)

    def test_produces_a_substantial_log(self):
        self.assertGreater(self.text.count("\n"), 500)

    def test_is_reproducible_from_a_seed(self):
        again, _ = build(hours=24, seed=42)
        self.assertEqual(self.text, again)

    def test_different_seeds_give_different_logs(self):
        other, _ = build(hours=24, seed=43)
        self.assertNotEqual(self.text, other)

    def test_lines_are_in_chronological_order(self):
        timestamps = [e.timestamp for e in self.events]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_contains_realistic_non_login_noise(self):
        # If everything parsed, the log is not realistic.
        self.assertGreater(self.skipped, 100)

    def test_contains_both_failures_and_successes(self):
        self.assertTrue(any(e.is_failure for e in self.events))
        self.assertTrue(any(e.is_success for e in self.events))

    def test_includes_an_rsyslog_collapsed_line(self):
        self.assertIn("message repeated", self.text)

    def test_uses_only_documentation_ip_ranges_for_attackers(self):
        # Never a real address, even by accident.
        for event in self.events:
            first = event.ip.split(".")[0]
            if first in ("10", "172", "192"):
                continue
            self.assertIn(".".join(event.ip.split(".")[:3]),
                          ("192.0.2", "198.51.100", "203.0.113"), event.ip)

    def test_syslog_pads_a_single_digit_day_with_a_space(self):
        stamp = syslog_time(datetime(2026, 8, 4, 9, 15, 1))
        self.assertEqual(stamp, "Aug  4 09:15:01")
        self.assertIsNotNone(LogParser().parse_line(
            f"{stamp} host sshd[1]: Failed password for invalid user root "
            f"from 203.0.113.1 port 22 ssh2"))

    def test_hours_controls_the_span(self):
        short, _ = build(hours=2, seed=42)
        self.assertLess(short.count("\n"), self.text.count("\n"))


class TestGroundTruth(unittest.TestCase):
    """The generator must not claim to have planted something it did not."""

    @classmethod
    def setUpClass(cls):
        cls.text, cls.attacks = build(hours=24, seed=42)

    def test_reports_every_attack_it_planted(self):
        self.assertEqual(len(self.attacks), 6)
        names = {a["name"] for a in self.attacks}
        for expected in ("fast burst", "rsyslog-collapsed", "low-and-slow",
                         "botnet", "spray", "COMPROMISE"):
            self.assertTrue(any(expected in n for n in names), expected)

    def test_every_planted_key_appears_in_the_log(self):
        # The botnet is deliberately keyed only on a subnet and a username:
        # no single address of it crosses the threshold, which is the point.
        # So a /24 key is checked by its prefix rather than as a literal.
        for attack in self.attacks:
            evidence = []
            for key in attack["keys"]:
                if key.endswith("/24"):
                    evidence.append(key.rsplit(".", 1)[0] + ".")
                elif "." in key:
                    evidence.append(key)
            self.assertTrue(evidence, f"{attack['name']} has no address key")
            self.assertTrue(any(token in self.text for token in evidence),
                            attack["name"])

    def test_the_botnet_spreads_across_many_addresses_in_one_subnet(self):
        botnet = next(a for a in self.attacks if "botnet" in a["name"])
        subnet = next(k for k in botnet["keys"] if k.endswith("/24"))
        prefix = subnet.rsplit(".", 1)[0] + "."
        events, _ = LogParser().parse_text(self.text)
        hosts = {e.ip for e in events if e.ip.startswith(prefix) and e.is_failure}
        self.assertGreater(len(hosts), 8, "botnet should span many addresses")

    def test_the_compromise_really_does_end_in_a_success(self):
        compromise = next(a for a in self.attacks if "COMPROMISE" in a["name"])
        ip = next(k for k in compromise["keys"] if "/" not in k)
        events, _ = LogParser().parse_text(self.text)
        from_ip = [e for e in events if e.ip == ip]
        self.assertTrue(any(e.is_success for e in from_ip))
        self.assertGreaterEqual(sum(1 for e in from_ip if e.is_failure), 3)


class TestDetectorAgainstGeneratedLogs(unittest.TestCase):
    """The point of the whole exercise: can it find what it was not told about?"""

    SEEDS = [42, 99, 7]

    def score(self, threshold, window):
        caught = total = false_alarms = 0
        for seed in self.SEEDS:
            text, attacks = build(hours=24, seed=seed)
            findings = BruteForceDetector(threshold=threshold,
                                          window=window).analyze_text(text).findings
            hits = {f.key for f in findings}
            legitimate = set()
            for attack in attacks:
                legitimate |= attack["keys"]
            for attack in attacks:
                total += 1
                if hits & attack["keys"]:
                    caught += 1
            false_alarms += sum(1 for f in findings if f.key not in legitimate)
        return caught, total, false_alarms

    def test_measured_setting_catches_everything_with_no_false_alarms(self):
        caught, total, false_alarms = self.score(threshold=4, window=600)
        self.assertEqual(caught, total)
        self.assertEqual(false_alarms, 0)

    def test_default_setting_misses_the_slow_attacks(self):
        # Documents why the default is not the whole answer.
        caught, total, _ = self.score(threshold=5, window=120)
        self.assertLess(caught, total)

    def test_threshold_three_drowns_in_background_scanning(self):
        # The finding that the small hand-written samples could not show:
        # a threshold of 3 is perfect on toy data and unusable on real volume.
        caught, total, false_alarms = self.score(threshold=3, window=1800)
        self.assertEqual(caught, total)
        self.assertGreater(false_alarms, 20)

    def test_the_compromise_is_always_found_regardless_of_threshold(self):
        # It does not depend on the burst threshold at all.
        for threshold in (3, 5, 12, 50):
            text, attacks = build(hours=24, seed=42)
            findings = BruteForceDetector(threshold=threshold,
                                          window=120).analyze_text(text).findings
            compromise = next(a for a in attacks if "COMPROMISE" in a["name"])
            self.assertTrue({f.key for f in findings} & compromise["keys"],
                            f"missed the compromise at threshold {threshold}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
