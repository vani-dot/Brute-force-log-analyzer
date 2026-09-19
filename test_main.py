# test_main.py
# Tests for the command line surface: argument handling and exit codes.
#
# These matter because the tool is meant to be usable from a script:
#   main.py /var/log/auth.log || send_alert
# which only works if the exit code is honest about what was found.

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from test_detector import sample
from main import main, resolve, positive_int, EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR


def run(argv):
    """Run the CLI, returning (exit_code, stdout)."""
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


class TestExitCodes(unittest.TestCase):

    def test_clean_log_exits_zero(self):
        code, _ = run([sample("clean_sample.log")])
        self.assertEqual(code, EXIT_CLEAN)

    def test_log_with_findings_exits_one(self):
        code, _ = run([sample("auth_sample.log")])
        self.assertEqual(code, EXIT_FINDINGS)

    def test_missing_file_exits_two(self):
        code, _ = run(["no_such_file.log"])
        self.assertEqual(code, EXIT_ERROR)

    def test_threshold_high_enough_to_silence_everything_exits_zero(self):
        code, _ = run([sample("evasion_sample.log"), "-t", "99"])
        self.assertEqual(code, EXIT_CLEAN)


class TestArgumentValidation(unittest.TestCase):

    def test_non_numeric_threshold_is_rejected_cleanly(self):
        # The old code raised a raw ValueError traceback here.
        with self.assertRaises(Exception):
            positive_int("abc")

    def test_zero_threshold_is_rejected(self):
        with self.assertRaises(Exception):
            positive_int("0")

    def test_valid_threshold_is_accepted(self):
        self.assertEqual(positive_int("7"), 7)


class TestPathResolution(unittest.TestCase):

    def test_bundled_sample_is_found_from_any_directory(self):
        # Regression test: defaults used to resolve against the current
        # working directory, so `python path/to/main.py` failed unless you
        # cd'd into the project first.
        here = os.getcwd()
        try:
            os.chdir(tempfile.gettempdir())
            path = resolve("auth_sample.log")
            self.assertTrue(os.path.exists(path), f"{path} not found")
        finally:
            os.chdir(here)

    def test_unknown_path_is_returned_unchanged_for_the_error_message(self):
        self.assertEqual(resolve("nope.log"), "nope.log")


class TestJsonOutput(unittest.TestCase):

    def test_json_mode_emits_parseable_output(self):
        code, out = run([sample("auth_sample.log"), "--json"])
        payload = json.loads(out)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("findings", payload)
        self.assertTrue(payload["findings"])

    def test_json_findings_carry_the_expected_fields(self):
        _, out = run([sample("auth_sample.log"), "--json"])
        finding = json.loads(out)["findings"][0]
        for field in ("type", "pivot", "key", "severity", "detail"):
            self.assertIn(field, finding)

    def test_json_mode_suppresses_the_human_report(self):
        _, out = run([sample("auth_sample.log"), "--json"])
        self.assertNotIn("No threats detected", out)
        self.assertNotIn("=" * 72, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
