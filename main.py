# main.py
# Entry point of the entire project.
# Owns no logic of its own, it just wires the other files together.
#
#   python main.py                            -> analyses auth_sample.log
#   python main.py clean_sample.log           -> analyses any file you name
#   python main.py evasion_sample.log -t 3 -w 1800
#   python main.py auth_sample.log --json     -> machine-readable output
#
# Exit codes, so this can be used from a script or a cron job:
#   0  no findings
#   1  at least one finding
#   2  could not run (missing file, bad arguments)

import argparse
import json
import os
import sys

from detector import (BruteForceDetector, print_report,
                      DEFAULT_THRESHOLD, DEFAULT_WINDOW)

# Sample logs live next to this script, not in whatever directory the user
# happens to be standing in. The old code resolved them against the current
# working directory, so `python path/to/main.py` failed unless you cd'd first.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def resolve(filename):
    # Prefer the file the user actually pointed at; fall back to the copy
    # shipped alongside the script.
    if os.path.exists(filename):
        return filename
    bundled = os.path.join(BASE_DIR, filename)
    if os.path.exists(bundled):
        return bundled
    return filename


def positive_int(text):
    # argparse calls this to validate -t and -w. Raising ArgumentTypeError
    # gets a clean usage message instead of the raw ValueError traceback the
    # old int(sys.argv[2]) produced on `main.py auth_sample.log abc`.
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number")
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {value}")
    return value


def build_parser():
    parser = argparse.ArgumentParser(
        description="Detect brute force attacks in an SSH authentication log.")
    parser.add_argument("logfile", nargs="?", default="auth_sample.log",
                        help="log file to analyse (default: auth_sample.log)")
    parser.add_argument("-t", "--threshold", type=positive_int,
                        default=DEFAULT_THRESHOLD,
                        help=f"failures needed to alert (default: {DEFAULT_THRESHOLD})")
    parser.add_argument("-w", "--window", type=positive_int,
                        default=DEFAULT_WINDOW,
                        help=f"window in seconds (default: {DEFAULT_WINDOW})")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON for another tool to consume")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    path = resolve(args.logfile)

    detector = BruteForceDetector(threshold=args.threshold,
                                  window=args.window)

    # A missing file should print a clear message, not a wall of red traceback
    try:
        result = detector.analyze_file(path)
    except FileNotFoundError:
        print(f"No such log file: {args.logfile}", file=sys.stderr)
        return EXIT_ERROR
    except PermissionError:
        print(f"Cannot read log file: {args.logfile}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_report(result)

    # Non-zero when something was found, so `main.py auth.log || alert` works
    return EXIT_FINDINGS if result.findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
