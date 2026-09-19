# test_detector.py
# Unit tests for detector.py.
#
#   python -m unittest discover -v      # run every test file
#   python test_detector.py             # run just this one

import os
import unittest

from detector import (BruteForceDetector, Finding, AnalysisResult,
                      analyze_log, subnet_of, group_events, find_bursts,
                      find_compromises, drop_redundant_subnets, read_events,
                      HIGH, MEDIUM)
from log_parser import parse_line


# Sample logs sit next to this test file. Resolving them here rather than
# inside detector.py keeps the library honest: analyze_log takes a real path
# and does not guess, while the CLI in main.py does the convenience lookup.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def sample(name):
    """Absolute path to a bundled sample log, so tests run from any cwd."""
    return os.path.join(BASE_DIR, name)


def events_from(lines):
    """Helper: turn a list of raw log lines into parsed events."""
    return [parse_line(line) for line in lines if parse_line(line)]


def keys_of(findings):
    """Helper: just the keys that fired, for easy assertions."""
    return {f.key for f in findings}


class TestSubnetOf(unittest.TestCase):

    def test_groups_an_ipv4_address_into_a_24(self):
        self.assertEqual(subnet_of("10.10.10.7"), "10.10.10.0/24")

    def test_addresses_in_the_same_range_share_a_subnet(self):
        self.assertEqual(subnet_of("10.10.10.1"), subnet_of("10.10.10.250"))

    def test_addresses_in_different_ranges_do_not(self):
        self.assertNotEqual(subnet_of("10.10.10.1"), subnet_of("10.10.11.1"))

    def test_ipv6_is_returned_unchanged(self):
        # Known limitation: IPv6 is not grouped. Documented in the README.
        self.assertEqual(subnet_of("2001:db8::1"), "2001:db8::1")


class TestSlidingWindow(unittest.TestCase):
    """The core algorithm, tested at its boundaries."""

    def build(self, seconds_apart, count):
        lines = []
        for i in range(count):
            total = i * seconds_apart
            hh = 9 + total // 3600
            mm = (total % 3600) // 60
            ss = total % 60
            lines.append(f"Jun 19 {hh:02d}:{mm:02d}:{ss:02d} server sshd[1]: "
                         f"Failed password for invalid user admin "
                         f"from 192.168.1.5 port 5000 ssh2")
        return events_from(lines)

    def test_exactly_at_the_threshold_and_window_fires(self):
        # 5 failures spanning exactly 120s must alert (boundary is inclusive)
        events = self.build(seconds_apart=30, count=5)   # span = 4*30 = 120
        groups = group_events(events, lambda e: e.ip)
        findings = find_bursts(groups, "ip", threshold=5, window=120)
        self.assertEqual(len(findings), 1)

    def test_one_second_too_slow_does_not_fire(self):
        events = self.build(seconds_apart=31, count=5)   # span = 124 > 120
        groups = group_events(events, lambda e: e.ip)
        findings = find_bursts(groups, "ip", threshold=5, window=120)
        self.assertEqual(findings, [])

    def test_one_failure_short_of_the_threshold_does_not_fire(self):
        events = self.build(seconds_apart=1, count=4)
        groups = group_events(events, lambda e: e.ip)
        findings = find_bursts(groups, "ip", threshold=5, window=120)
        self.assertEqual(findings, [])

    def test_only_one_alert_per_key_even_with_many_failures(self):
        events = self.build(seconds_apart=1, count=50)
        groups = group_events(events, lambda e: e.ip)
        findings = find_bursts(groups, "ip", threshold=5, window=120)
        self.assertEqual(len(findings), 1)


class TestCompromiseDetection(unittest.TestCase):
    """Failures followed by a success from the same IP.

    The hard part is not spotting the pattern, it is not firing on the
    thousands of legitimate users who mistype a password and then get in.
    """

    def lines(self, users, success_user, ip="203.0.113.5"):
        out = []
        for i, user in enumerate(users):
            out.append(f"Jun 19 09:02:{i:02d} server sshd[1]: Failed password "
                       f"for invalid user {user} from {ip} port 4122{i} ssh2")
        out.append(f"Jun 19 09:02:59 server sshd[1]: Accepted password for "
                   f"{success_user} from {ip} port 41299 ssh2")
        return out

    def test_many_failures_on_another_account_then_success_is_flagged_high(self):
        # Failures against root, then a login as admin. Not a typo.
        events = events_from(self.lines(["root"] * 3, "admin"))
        findings = find_compromises(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].key, "203.0.113.5")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_three_failures_on_your_own_account_is_not_flagged(self):
        # Same account throughout: the signature of a mistyped password.
        # A higher bar applies, tested fully in test_allowlist.py.
        events = events_from(self.lines(["admin"] * 3, "admin"))
        self.assertEqual(find_compromises(events), [])

    def test_enough_failures_on_your_own_account_eventually_is_flagged(self):
        from detector import SAME_USER_MIN_FAILURES
        events = events_from(
            self.lines(["admin"] * (SAME_USER_MIN_FAILURES + 1), "admin"))
        self.assertEqual(len(find_compromises(events)), 1)

    def test_enumeration_across_usernames_is_flagged_even_when_brief(self):
        # Two failures is below min_failures, but two DIFFERENT usernames is
        # account enumeration, not a typo. Nobody mistypes their own login.
        events = events_from(self.lines(["root", "oracle"], "admin"))
        findings = find_compromises(events)
        self.assertEqual(len(findings), 1)
        self.assertIn("across 2 usernames", findings[0].detail)

    def test_single_typo_then_success_is_not_flagged(self):
        # THE false positive that mattered: one failure on one account then a
        # success is a real user fumbling their own password. The old detector
        # called this a HIGH severity breach on every host it ran on.
        events = events_from(self.lines(["jaswanth"], "jaswanth", ip="10.0.0.9"))
        self.assertEqual(find_compromises(events), [])

    def test_two_typos_on_one_account_then_success_is_not_flagged(self):
        events = events_from(self.lines(["jaswanth"] * 2, "jaswanth",
                                        ip="10.0.0.9"))
        self.assertEqual(find_compromises(events), [])

    def test_success_with_no_prior_failure_is_not_flagged(self):
        lines = ["Jun 19 09:08:47 server sshd[1]: Accepted password for "
                 "deploy from 192.168.1.20 port 60341 ssh2"]
        self.assertEqual(find_compromises(events_from(lines)), [])

    def test_failure_and_success_from_different_ips_is_not_flagged(self):
        lines = self.lines(["root", "oracle", "admin"], "admin")
        lines[-1] = ("Jun 19 09:02:59 server sshd[1]: Accepted password for "
                     "admin from 10.0.0.9 port 41299 ssh2")
        self.assertEqual(find_compromises(events_from(lines)), [])

    def test_success_long_after_the_failures_is_not_flagged(self):
        lines = self.lines(["root", "oracle", "admin"], "admin")
        lines[-1] = ("Jun 19 23:00:00 server sshd[1]: Accepted password for "
                     "admin from 203.0.113.5 port 41299 ssh2")
        self.assertEqual(find_compromises(events_from(lines)), [])


class TestBurstReporting(unittest.TestCase):
    """The alert must describe what happened, not restate the threshold."""

    def test_detail_reports_the_true_burst_size_not_the_threshold(self):
        lines = [f"Jun 19 09:00:{i:02d} server sshd[1]: Failed password for "
                 f"invalid user admin from 192.168.1.5 port 5000 ssh2"
                 for i in range(20)]
        groups = group_events(events_from(lines), lambda e: e.ip)
        findings = find_bursts(groups, "ip", threshold=5, window=120)
        # 20 failures inside the window, not the 5 that tripped the threshold
        self.assertIn("20 failures", findings[0].detail)

    def test_detail_reports_the_true_span(self):
        lines = [f"Jun 19 09:00:{i:02d} server sshd[1]: Failed password for "
                 f"invalid user admin from 192.168.1.5 port 5000 ssh2"
                 for i in range(0, 20, 2)]
        groups = group_events(events_from(lines), lambda e: e.ip)
        findings = find_bursts(groups, "ip", threshold=5, window=120)
        self.assertIn("in 18s", findings[0].detail)


class TestRepeatExpansion(unittest.TestCase):
    """read_events must turn one collapsed line into N events."""

    def test_collapsed_line_becomes_nine_events(self):
        events, skipped = read_events(sample("noisy_sample.log"))
        failures = [e for e in events if e.is_failure]
        self.assertEqual(len(failures), 9)

    def test_non_login_lines_are_skipped_not_parsed(self):
        events, skipped = read_events(sample("noisy_sample.log"))
        self.assertEqual(skipped, 5)
        self.assertNotIn("disconnect", {e.user for e in events})


class TestAlertDeduplication(unittest.TestCase):

    def test_subnet_alert_is_dropped_when_its_ip_already_fired(self):
        findings = [
            Finding("burst", "ip", "192.168.1.5", MEDIUM, ""),
            Finding("burst", "subnet", "192.168.1.0/24", MEDIUM, ""),
        ]
        kept = drop_redundant_subnets(findings)
        self.assertEqual(keys_of(kept), {"192.168.1.5"})

    def test_subnet_alert_is_kept_when_no_single_ip_fired(self):
        # This is the botnet case: the subnet is the only thing that caught it
        findings = [
            Finding("burst", "subnet", "10.10.10.0/24", MEDIUM, ""),
        ]
        kept = drop_redundant_subnets(findings)
        self.assertEqual(keys_of(kept), {"10.10.10.0/24"})


class TestAgainstSampleLogs(unittest.TestCase):
    """End-to-end tests over the committed sample logs."""

    def test_clean_log_produces_no_findings(self):
        findings = analyze_log(sample("clean_sample.log"), verbose=False)
        self.assertEqual(findings, [])

    def test_attack_log_finds_both_the_burst_and_the_compromise(self):
        findings = analyze_log(sample("auth_sample.log"), verbose=False)
        keys = keys_of(findings)
        self.assertIn("192.168.1.5", keys)     # the burst
        self.assertIn("203.0.113.5", keys)     # the successful compromise

    def test_compromise_is_ranked_above_the_burst(self):
        findings = analyze_log(sample("auth_sample.log"), verbose=False)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_default_settings_catch_the_botnet(self):
        findings = analyze_log(sample("evasion_sample.log"), verbose=False)
        self.assertIn("10.10.10.0/24", keys_of(findings))

    def test_default_settings_miss_the_slow_attack(self):
        # Documents the limitation the evaluation harness exists to measure.
        findings = analyze_log(sample("evasion_sample.log"), verbose=False)
        self.assertNotIn("203.0.113.50", keys_of(findings))

    def test_tuned_settings_catch_all_three_evasions(self):
        findings = analyze_log(sample("evasion_sample.log"), threshold=3, window=1800,
                               verbose=False)
        keys = keys_of(findings)
        self.assertIn("203.0.113.50", keys)      # low-and-slow
        self.assertIn("10.10.10.0/24", keys)     # botnet
        self.assertIn("198.51.100.77", keys)     # password spray

    def test_missing_file_raises_a_clear_error(self):
        with self.assertRaises(FileNotFoundError):
            analyze_log(sample("no_such_file.log"), verbose=False)


class TestDetectorObject(unittest.TestCase):
    """The detector carries its tuning, so one object can be reused."""

    def test_tuning_is_held_on_the_instance_not_passed_around(self):
        strict = BruteForceDetector(threshold=10, window=60)
        loose = BruteForceDetector(threshold=3, window=1800)
        events, _ = read_events(sample("evasion_sample.log"))
        self.assertEqual(strict.analyze(events), [])
        self.assertTrue(loose.analyze(events))

    def test_same_detector_reused_across_files_gives_stable_results(self):
        detector = BruteForceDetector(threshold=3, window=1800)
        first = detector.analyze_file(sample("evasion_sample.log")).findings
        detector.analyze_file(sample("clean_sample.log"))
        second = detector.analyze_file(sample("evasion_sample.log")).findings
        self.assertEqual(keys_of(first), keys_of(second))

    def test_compromise_detection_can_be_switched_off(self):
        detector = BruteForceDetector(detect_compromise=False)
        findings = detector.analyze_file(sample("auth_sample.log")).findings
        self.assertNotIn(HIGH, {f.severity for f in findings})

    def test_analyze_text_matches_analyze_file(self):
        detector = BruteForceDetector(threshold=3, window=1800)
        path = sample("evasion_sample.log")
        with open(path) as f:
            from_text = detector.analyze_text(f.read()).findings
        from_file = detector.analyze_file(path).findings
        self.assertEqual(keys_of(from_text), keys_of(from_file))


class TestAnalysisResult(unittest.TestCase):
    """The result object is what the web app serialises."""

    def result(self, name="auth_sample.log", **kw):
        return BruteForceDetector(**kw).analyze_file(sample(name))

    def test_counts_failures_and_successes_separately(self):
        result = self.result()
        self.assertEqual(result.failure_count, 10)
        self.assertEqual(result.success_count, 3)

    def test_high_findings_are_a_subset_of_all_findings(self):
        result = self.result()
        self.assertEqual(len(result.high_findings), 1)
        self.assertLessEqual(len(result.high_findings), len(result.findings))

    def test_top_offenders_are_ranked_worst_first(self):
        offenders = self.result().top_offenders()
        counts = [o["failures"] for o in offenders]
        self.assertEqual(counts, sorted(counts, reverse=True))
        self.assertEqual(offenders[0]["ip"], "192.168.1.5")

    def test_top_offenders_respects_its_limit(self):
        self.assertLessEqual(len(self.result().top_offenders(limit=2)), 2)

    def test_timeline_totals_match_the_failure_count(self):
        result = self.result()
        total = sum(bucket["failures"] for bucket in result.timeline())
        self.assertEqual(total, result.failure_count)

    def test_timeline_of_a_log_with_no_failures_is_empty(self):
        result = self.result("clean_sample.log")
        empty = AnalysisResult("x", [e for e in result.events
                                     if not e.is_failure], 0, [], 5, 120)
        self.assertEqual(empty.timeline(), [])

    def test_to_dict_is_json_serialisable(self):
        import json
        payload = json.dumps(self.result().to_dict())
        self.assertIn("findings", json.loads(payload))

    def test_stats_report_the_skipped_lines(self):
        self.assertEqual(self.result("noisy_sample.log").to_dict()["stats"]["skipped"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
