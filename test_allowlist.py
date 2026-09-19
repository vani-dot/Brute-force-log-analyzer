# test_allowlist.py
# Tests for allowlisting and the refined compromise rule.
#
# Both exist for the same reason: the detector was right and still wrong.
# The subnet pivot cannot know which network is yours, and "failure then
# success" is the signature of a breach AND of a typo.

import unittest

from detector import (Allowlist, BruteForceDetector, HIGH,
                      SAME_USER_MIN_FAILURES)
from test_detector import sample


class TestAllowlistMatching(unittest.TestCase):

    def setUp(self):
        self.allow = Allowlist(["10.0.0.0/8", "192.168.1.20",
                                "203.0.113.0/24", "backup"])

    def test_an_address_inside_an_allowed_network(self):
        self.assertTrue(self.allow.covers("10.4.5.6"))

    def test_a_subnet_inside_an_allowed_network(self):
        self.assertTrue(self.allow.covers("10.0.4.0/24"))

    def test_a_single_allowed_address(self):
        self.assertTrue(self.allow.covers("192.168.1.20"))
        self.assertFalse(self.allow.covers("192.168.1.21"))

    def test_an_allowed_username(self):
        self.assertTrue(self.allow.covers("backup"))
        self.assertFalse(self.allow.covers("root"))

    def test_an_unrelated_address(self):
        self.assertFalse(self.allow.covers("198.51.100.4"))

    def test_a_wider_subnet_is_not_covered_by_a_narrower_entry(self):
        # 203.0.0.0/16 contains the allowed /24, not the other way round.
        self.assertFalse(self.allow.covers("203.0.0.0/16"))

    def test_an_empty_allowlist_is_falsy_and_matches_nothing(self):
        empty = Allowlist([])
        self.assertFalse(empty)
        self.assertFalse(empty.covers("10.0.0.1"))

    def test_blank_entries_are_ignored(self):
        self.assertEqual(len(Allowlist(["", "  ", "10.0.0.0/8"])), 1)

    def test_garbage_is_treated_as_a_username_not_a_crash(self):
        allow = Allowlist(["not-a-network"])
        self.assertTrue(allow.covers("not-a-network"))
        self.assertFalse(allow.covers("10.0.0.1"))

    def test_ipv6_entries_do_not_match_ipv4(self):
        allow = Allowlist(["2001:db8::/32"])
        self.assertTrue(allow.covers("2001:db8::5"))
        self.assertFalse(allow.covers("10.0.0.1"))


class TestAllowlistInDetection(unittest.TestCase):

    def analyse(self, name, allowlist=None):
        return BruteForceDetector(threshold=4, window=600,
                                  allowlist=allowlist).analyze_file(sample(name))

    def test_suppresses_the_internal_subnet_finding(self):
        bare = self.analyse("logs/tricky/busy-office.log")
        allowed = self.analyse("logs/tricky/busy-office.log", ["10.0.0.0/8"])
        self.assertGreater(len(bare.findings), len(allowed.findings))
        self.assertTrue(allowed.suppressed)

    def test_suppressed_findings_are_reported_not_discarded(self):
        result = self.analyse("logs/tricky/busy-office.log", ["10.0.0.0/8"])
        for finding in result.suppressed:
            self.assertTrue(Allowlist(["10.0.0.0/8"]).covers(finding.key))
        self.assertEqual(result.to_dict()["stats"]["suppressed"],
                         len(result.suppressed))

    def test_an_unrelated_allowlist_changes_nothing(self):
        bare = self.analyse("auth_sample.log")
        other = self.analyse("auth_sample.log", ["172.16.0.0/12"])
        self.assertEqual(len(bare.findings), len(other.findings))
        self.assertEqual(other.suppressed, [])

    def test_a_real_attacker_is_not_hidden_by_an_internal_allowlist(self):
        result = self.analyse("logs/attacks/02-successful-breach.log",
                              ["10.0.0.0/8", "192.168.0.0/16"])
        self.assertTrue([f for f in result.findings if f.severity == HIGH])

    def test_allowlisting_the_attacker_does_silence_it(self):
        result = self.analyse("logs/attacks/02-successful-breach.log",
                              ["203.0.113.0/24"])
        self.assertEqual(result.findings, [])
        self.assertTrue(result.suppressed)

    def test_the_allowlist_is_reported_in_the_payload(self):
        payload = self.analyse("auth_sample.log", ["10.0.0.0/8"]).to_dict()
        self.assertEqual(payload["allowlist"]["entries"], ["10.0.0.0/8"])


class TestSameUserCompromiseRule(unittest.TestCase):
    """A person mistyping their own password is not a breach."""

    def log(self, failures, fail_user, success_user, ip="10.0.4.11"):
        lines = [f"Jun 19 09:0{i // 60}:{i % 60:02d} h sshd[1]: Failed password "
                 f"for {fail_user} from {ip} port 400{i} ssh2"
                 for i in range(failures)]
        lines.append(f"Jun 19 09:{failures // 60}:{failures % 60 + 1:02d} h "
                     f"sshd[1]: Accepted password for {success_user} "
                     f"from {ip} port 4999 ssh2")
        return "\n".join(lines)

    def highs(self, text, **kwargs):
        result = BruteForceDetector(threshold=99, **kwargs).analyze_text(text)
        return [f for f in result.findings if f.severity == HIGH]

    def test_four_typos_on_your_own_account_is_not_a_breach(self):
        self.assertEqual(self.highs(self.log(4, "jaswanth", "jaswanth")), [])

    def test_five_typos_on_your_own_account_is_still_not_a_breach(self):
        self.assertEqual(self.highs(self.log(5, "jaswanth", "jaswanth")), [])

    def test_beyond_the_bar_it_does_become_reportable(self):
        highs = self.highs(self.log(SAME_USER_MIN_FAILURES + 1,
                                    "jaswanth", "jaswanth"))
        self.assertEqual(len(highs), 1)
        self.assertIn("their own account", highs[0].detail)

    def test_enumeration_fires_at_two_usernames_however_few_attempts(self):
        text = ("Jun 19 09:00:01 h sshd[1]: Failed password for root "
                "from 203.0.113.9 port 1 ssh2\n"
                "Jun 19 09:00:04 h sshd[1]: Failed password for oracle "
                "from 203.0.113.9 port 2 ssh2\n"
                "Jun 19 09:00:07 h sshd[1]: Accepted password for admin "
                "from 203.0.113.9 port 3 ssh2")
        highs = self.highs(text)
        self.assertEqual(len(highs), 1)
        self.assertIn("across 2 usernames", highs[0].detail)

    def test_failures_on_a_different_account_use_the_lower_bar(self):
        text = "\n".join([
            "Jun 19 09:00:01 h sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2",
            "Jun 19 09:00:03 h sshd[1]: Failed password for root from 203.0.113.9 port 2 ssh2",
            "Jun 19 09:00:05 h sshd[1]: Failed password for root from 203.0.113.9 port 3 ssh2",
            "Jun 19 09:00:09 h sshd[1]: Accepted password for deploy from 203.0.113.9 port 4 ssh2",
        ])
        self.assertEqual(len(self.highs(text)), 1)

    def test_two_colleagues_fumbling_on_a_shared_host_is_not_enumeration(self):
        # The exact shape that broke EXAMPLE-2: user A mistypes, user B
        # mistypes, user B then logs in. Two distinct usernames failed, but
        # only ONE of them is an account the session did not end up using.
        # A jump box or NAT gateway looks like this all day.
        text = "\n".join([
            "Jun 19 09:00:01 h sshd[1]: Failed password for alice from 10.0.4.11 port 1 ssh2",
            "Jun 19 09:00:30 h sshd[1]: Failed password for deploy from 10.0.4.11 port 2 ssh2",
            "Jun 19 09:00:50 h sshd[1]: Accepted password for deploy from 10.0.4.11 port 3 ssh2",
        ])
        self.assertEqual(self.highs(text), [])

    def test_probing_two_other_accounts_then_getting_in_is_enumeration(self):
        # Attacker probes root and oracle, gets neither, then logs in as a
        # third account. Two accounts stayed shut. That is the signal.
        text = "\n".join([
            "Jun 19 09:00:01 h sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2",
            "Jun 19 09:00:04 h sshd[1]: Failed password for oracle from 203.0.113.9 port 2 ssh2",
            "Jun 19 09:00:07 h sshd[1]: Accepted password for deploy from 203.0.113.9 port 3 ssh2",
        ])
        self.assertEqual(len(self.highs(text)), 1)

    def test_failing_and_then_succeeding_on_the_same_account_uses_the_typo_bar(self):
        # root fails twice, alice fails once, root gets in. Only alice is a
        # door that stayed shut, so this is not enumeration.
        text = "\n".join([
            "Jun 19 09:00:01 h sshd[1]: Failed password for root from 10.0.4.11 port 1 ssh2",
            "Jun 19 09:00:04 h sshd[1]: Failed password for root from 10.0.4.11 port 2 ssh2",
            "Jun 19 09:00:07 h sshd[1]: Failed password for alice from 10.0.4.11 port 3 ssh2",
            "Jun 19 09:00:10 h sshd[1]: Accepted password for root from 10.0.4.11 port 4 ssh2",
        ])
        self.assertEqual(self.highs(text), [])

    def test_the_bar_scales_when_min_failures_is_tuned(self):
        strict = BruteForceDetector(min_failures=5)
        self.assertGreaterEqual(strict.same_user_min_failures, 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
