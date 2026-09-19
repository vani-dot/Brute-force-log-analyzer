# test_parser.py
# Unit tests for log_parser.py, using unittest from the standard library
# (no pip install needed, matching the rest of the project).
#
#   python -m unittest discover -v      # run every test file
#   python test_parser.py               # run just this one

import unittest

from log_parser import (LogParser, LogEvent, parse_line,
                        time_to_seconds, timestamp_to_seconds,
                        expand_repeat)


class TestTimeToSeconds(unittest.TestCase):

    def test_converts_a_normal_time(self):
        # 9*3600 + 15*60 + 1
        self.assertEqual(time_to_seconds("09:15:01"), 33301)

    def test_midnight_is_zero(self):
        self.assertEqual(time_to_seconds("00:00:00"), 0)

    def test_last_second_of_the_day(self):
        self.assertEqual(time_to_seconds("23:59:59"), 86399)


class TestTimestampToSeconds(unittest.TestCase):

    def test_same_time_on_consecutive_days_is_a_day_apart(self):
        # This is the regression test for the original bug: the old code
        # compared only HH:MM:SS, so these two looked 0 seconds apart.
        day1 = timestamp_to_seconds("Jun", "19", "09:15:01")
        day2 = timestamp_to_seconds("Jun", "20", "09:15:01")
        self.assertEqual(day2 - day1, 86400)

    def test_midnight_rollover_moves_forward_not_backward(self):
        # The old code produced a NEGATIVE gap here and missed the attack.
        before = timestamp_to_seconds("Jun", "19", "23:59:58")
        after = timestamp_to_seconds("Jun", "20", "00:00:03")
        self.assertEqual(after - before, 5)

    def test_unknown_month_returns_none(self):
        self.assertIsNone(timestamp_to_seconds("Xyz", "19", "09:15:01"))

    def test_malformed_time_returns_none(self):
        self.assertIsNone(timestamp_to_seconds("Jun", "19", "not-a-time"))


class TestParseLine(unittest.TestCase):

    FAILED = ("Jun 19 09:15:01 server sshd[1004]: Failed password for "
              "invalid user admin from 192.168.1.5 port 51234 ssh2")
    ACCEPTED = ("Jun 19 09:02:14 server sshd[1001]: Accepted password for "
                "admin from 203.0.113.5 port 41224 ssh2")
    EXISTING_USER = ("Jun 19 09:05:33 server sshd[1002]: Failed password for "
                     "root from 198.51.100.9 port 55102 ssh2")

    def test_extracts_every_field_from_a_failed_line(self):
        event = parse_line(self.FAILED)
        self.assertEqual(event.time_str, "09:15:01")
        self.assertEqual(event.date_str, "Jun 19")
        self.assertEqual(event.ip, "192.168.1.5")
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.result, "failed")

    def test_accepted_line_is_a_success(self):
        event = parse_line(self.ACCEPTED)
        self.assertEqual(event.result, "success")
        self.assertEqual(event.ip, "203.0.113.5")
        self.assertEqual(event.user, "admin")

    def test_username_without_the_invalid_user_prefix(self):
        # "for root from IP" has a different word count than
        # "for invalid user admin from IP", so this checks the username is
        # found by position relative to "from" rather than a fixed index.
        event = parse_line(self.EXISTING_USER)
        self.assertEqual(event.user, "root")
        self.assertEqual(event.ip, "198.51.100.9")

    def test_trailing_newline_and_carriage_return_are_ignored(self):
        event = parse_line(self.FAILED + "\r\n")
        self.assertEqual(event.ip, "192.168.1.5")

    # --- lines that are NOT login attempts ------------------------------

    def test_line_without_from_returns_none(self):
        # The old code raised ValueError here and killed the whole program.
        line = ("Jun 19 09:02:11 server sshd[1001]: Connection closed by "
                "203.0.113.5 port 41223")
        self.assertIsNone(parse_line(line))

    def test_blank_line_returns_none(self):
        self.assertIsNone(parse_line("\n"))

    def test_short_line_returns_none(self):
        self.assertIsNone(parse_line("Jun 19 09:00:00 server restarted"))

    def test_non_syslog_line_returns_none(self):
        self.assertIsNone(parse_line("hello from somewhere else entirely"))

    def test_recon_line_is_other_not_success(self):
        # Regression test: the old code treated anything without "Failed" as a
        # success, so this reconnaissance attempt was recorded as a login.
        line = ("Jun 19 09:20:00 server sshd[1007]: Invalid user oracle "
                "from 203.0.113.99 port 1234")
        event = parse_line(line)
        self.assertEqual(event.result, "other")


class TestNonLoginLines(unittest.TestCase):
    """Lines that contain the word "from" but are NOT authentication attempts.

    Regression tests for the phantom-event bug: the old parser accepted any
    line with "from" in it and took the preceding word as the username, so an
    ordinary disconnect notice became an event for a user called "disconnect".
    Real auth.log files are mostly these lines.
    """

    def test_received_disconnect_is_not_an_event(self):
        line = ("Jun 22 03:00:00 server sshd[4001]: Received disconnect from "
                "203.0.113.200 port 40001:11: Bye Bye [preauth]")
        self.assertIsNone(parse_line(line))

    def test_disconnected_from_authenticating_user_is_not_an_event(self):
        line = ("Jun 22 03:00:01 server sshd[4002]: Disconnected from "
                "authenticating user root 203.0.113.200 port 40002 [preauth]")
        self.assertIsNone(parse_line(line))

    def test_connection_reset_is_not_an_event(self):
        line = ("Jun 22 03:00:02 server sshd[4003]: Connection reset by "
                "198.51.100.4 port 40003 [preauth]")
        self.assertIsNone(parse_line(line))

    def test_session_opened_is_not_an_event(self):
        line = ("Jun 22 03:01:30 server sshd[4006]: pam_unix(sshd:session): "
                "session opened for user deploy by (uid=0)")
        self.assertIsNone(parse_line(line))

    def test_sudo_line_is_not_an_event(self):
        line = ("Jun 22 03:02:00 server sudo:   deploy : TTY=pts/0 ; "
                "PWD=/home/deploy ; USER=root ; COMMAND=/bin/ls")
        self.assertIsNone(parse_line(line))


class TestRepeatedMessages(unittest.TestCase):
    """rsyslog folds a flood of identical lines into one summary line.

    A brute force is exactly the traffic that triggers that folding, so
    reading the summary as a single failure silently loses the attack.
    """

    COLLAPSED = ("Jun 22 03:01:00 server sshd[4005]: message repeated 9 "
                 "times: [ Failed password for root from 203.0.113.200 "
                 "port 40005 ssh2]")

    def test_expand_repeat_recovers_the_original_line_and_count(self):
        line, count = expand_repeat(self.COLLAPSED)
        self.assertEqual(count, 9)
        self.assertIn("Failed password for root", line)
        self.assertNotIn("message repeated", line)

    def test_expand_repeat_keeps_the_timestamp_prefix(self):
        line, _ = expand_repeat(self.COLLAPSED)
        self.assertTrue(line.startswith("Jun 22 03:01:00"))

    def test_collapsed_line_parses_with_its_real_count(self):
        event = parse_line(self.COLLAPSED)
        self.assertEqual(event.count, 9)
        self.assertEqual(event.result, "failed")
        self.assertEqual(event.user, "root")
        self.assertEqual(event.ip, "203.0.113.200")

    def test_ordinary_line_has_a_count_of_one(self):
        self.assertEqual(parse_line(TestParseLine.FAILED).count, 1)

    def test_malformed_repeat_count_is_left_alone(self):
        line = ("Jun 22 03:01:00 server sshd[1]: message repeated many "
                "times: [ Failed password for root from 1.2.3.4 port 1 ssh2]")
        _, count = expand_repeat(line)
        self.assertEqual(count, 1)


class TestKnownLimitations(unittest.TestCase):
    """These assert the CURRENT behaviour of known bugs, so that if anyone
    fixes them the test fails loudly and the README can be updated."""

    def test_leap_day_collides_with_first_of_march(self):
        # Day-of-year maths assumes a non-leap year.
        feb29 = timestamp_to_seconds("Feb", "29", "12:00:00")
        mar01 = timestamp_to_seconds("Mar", "1", "12:00:00")
        self.assertEqual(feb29, mar01)  # known limitation, documented in README

    def test_year_boundary_goes_backwards(self):
        # Syslog carries no year, so December is "later" than January.
        dec31 = timestamp_to_seconds("Dec", "31", "23:59:00")
        jan01 = timestamp_to_seconds("Jan", "1", "00:01:00")
        self.assertLess(jan01, dec31)  # known limitation, documented in README


class TestLogEvent(unittest.TestCase):
    """The event object itself: behaviour that belongs with the data."""

    def make(self, ip="10.1.2.3", result=LogEvent.FAILED):
        return LogEvent(0, "09:00:00", "Jun 19", ip, "admin", result)

    def test_ipv4_reports_its_24_subnet(self):
        self.assertEqual(self.make().subnet, "10.1.2.0/24")

    def test_ipv6_is_left_ungrouped(self):
        # Known limitation, documented in the README.
        self.assertEqual(self.make(ip="2001:db8::1").subnet, "2001:db8::1")

    def test_is_failure_and_is_success_are_mutually_exclusive(self):
        failure = self.make(result=LogEvent.FAILED)
        success = self.make(result=LogEvent.SUCCESS)
        self.assertTrue(failure.is_failure)
        self.assertFalse(failure.is_success)
        self.assertTrue(success.is_success)
        self.assertFalse(success.is_failure)

    def test_recon_event_is_neither_failure_nor_success(self):
        recon = self.make(result=LogEvent.OTHER)
        self.assertFalse(recon.is_failure)
        self.assertFalse(recon.is_success)

    def test_to_dict_is_json_friendly(self):
        import json
        json.dumps(self.make().to_dict())   # must not raise


class TestParserIsReusable(unittest.TestCase):
    """A LogParser instance holds no per-file state."""

    def test_same_instance_parses_many_lines_independently(self):
        parser = LogParser()
        a = parser.parse_line(TestParseLine.FAILED)
        b = parser.parse_line(TestParseLine.ACCEPTED)
        self.assertEqual(a.result, "failed")
        self.assertEqual(b.result, "success")

    def test_parse_text_handles_a_pasted_blob(self):
        parser = LogParser()
        text = TestParseLine.FAILED + "\n" + TestParseLine.ACCEPTED
        events, skipped = parser.parse_text(text)
        self.assertEqual(len(events), 2)
        self.assertEqual(skipped, 0)

    def test_parse_text_counts_unrecognised_lines(self):
        parser = LogParser()
        events, skipped = parser.parse_text("total nonsense\n\nmore nonsense")
        self.assertEqual(events, [])
        self.assertEqual(skipped, 2)      # the blank line does not count


if __name__ == "__main__":
    unittest.main(verbosity=2)
