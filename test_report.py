# test_report.py
# Tests for the HTML report.
#
# The properties that matter: it is self-contained, it says where its data
# came from, it escapes attacker-controlled text, and its numbers match the
# analysis it was built from.

import re
import unittest

from detector import BruteForceDetector, Allowlist
from report import ReportBuilder, build_report
from test_detector import sample


def report_for(name, **kwargs):
    result = BruteForceDetector(threshold=4, window=600,
                                **kwargs).analyze_file(sample(name))
    return build_report(result, source_kind="sample"), result


class TestSelfContained(unittest.TestCase):

    def setUp(self):
        self.html, _ = report_for("auth_sample.log")

    def test_is_a_complete_html_document(self):
        self.assertTrue(self.html.lstrip().startswith("<!doctype html>"))
        self.assertIn("</html>", self.html)

    def test_pulls_nothing_from_the_network(self):
        # No stylesheet, script, image or font from anywhere.
        for pattern in (r'<link[^>]+href="http', r'<script[^>]+src=',
                        r'<img[^>]+src="http', r'@import'):
            self.assertIsNone(re.search(pattern, self.html), pattern)

    def test_styles_are_inline(self):
        self.assertIn("<style>", self.html)

    def test_opens_without_javascript(self):
        self.assertNotIn("<script", self.html)


class TestProvenance(unittest.TestCase):
    """Anyone reading a security finding needs to know what they are seeing."""

    def test_a_sample_says_it_is_synthetic(self):
        html, _ = report_for("auth_sample.log")
        self.assertIn("synthetic", html.lower())
        self.assertIn("Not captured from a real host", html)

    def test_an_upload_says_it_came_from_the_operator(self):
        result = BruteForceDetector().analyze_file(sample("auth_sample.log"))
        html = build_report(result, source_kind="upload")
        self.assertIn("Supplied by the operator", html)

    def test_a_live_capture_says_so(self):
        result = BruteForceDetector().analyze_file(sample("auth_sample.log"))
        self.assertIn("followed in real time",
                      build_report(result, source_kind="live"))


class TestVerdict(unittest.TestCase):

    def verdict_of(self, name, **kwargs):
        result = BruteForceDetector(threshold=4, window=600,
                                    **kwargs).analyze_file(sample(name))
        return ReportBuilder(result).verdict()

    def test_a_breach_is_called_a_breach(self):
        kind, headline, detail = self.verdict_of("auth_sample.log")
        self.assertEqual(kind, "breach")
        self.assertIn("compromise", headline.lower())
        self.assertIn("203.0.113.5", detail)

    def test_attempts_without_a_success_are_not_called_a_breach(self):
        kind, headline, _ = self.verdict_of("noisy_sample.log")
        self.assertEqual(kind, "attempts")
        self.assertIn("no confirmed breach", headline.lower())

    def test_a_clean_log_is_reported_clean(self):
        kind, headline, _ = self.verdict_of("clean_sample.log")
        self.assertEqual(kind, "clear")
        self.assertIn("no threats", headline.lower())


class TestContentMatchesTheAnalysis(unittest.TestCase):

    def test_every_finding_key_appears_in_the_report(self):
        html, result = report_for("auth_sample.log")
        for finding in result.findings:
            self.assertIn(finding.key, html)

    def test_the_tuning_used_is_stated(self):
        html, result = report_for("auth_sample.log")
        self.assertIn(str(result.threshold), html)
        self.assertIn(f"{result.window}s", html)

    def test_event_counts_match(self):
        html, result = report_for("noisy_sample.log")
        self.assertIn(f'>{len(result.events)}</div>', html)
        self.assertIn(f'>{result.skipped}</div>', html)

    def test_suppressed_findings_are_disclosed_not_hidden(self):
        result = BruteForceDetector(
            threshold=4, window=600,
            allowlist=["192.168.0.0/16"]).analyze_file(sample("auth_sample.log"))
        html = build_report(result, source_kind="sample")
        if result.suppressed:
            self.assertIn("Suppressed by allowlist", html)
            for finding in result.suppressed:
                self.assertIn(finding.key, html)

    def test_limitations_are_stated(self):
        html, _ = report_for("auth_sample.log")
        self.assertIn("Limitations", html)
        self.assertIn("leap", html.lower())

    def test_says_when_geo_is_not_configured_rather_than_inventing_one(self):
        html, _ = report_for("auth_sample.log")
        self.assertIn("no location is invented", html.lower())


class TestEscaping(unittest.TestCase):
    """A username in a log is attacker-controlled and may contain markup."""

    HOSTILE = "<script>alert(1)</script>"

    def build(self):
        lines = "\n".join(
            f"Jun 19 09:15:{i:02d} h sshd[1]: Failed password for invalid "
            f"user {self.HOSTILE} from 9.9.9.9 port 500{i} ssh2"
            for i in range(6))
        result = BruteForceDetector(threshold=4, window=600).analyze_text(lines)
        return build_report(result, source_kind="upload")

    def test_markup_from_a_log_never_reaches_the_document_as_markup(self):
        html = self.build()
        self.assertNotIn(self.HOSTILE, html)
        self.assertIn("&lt;script&gt;", html)

    def test_the_report_still_contains_no_script_tag(self):
        self.assertNotIn("<script", self.build())


if __name__ == "__main__":
    unittest.main(verbosity=2)
