# evaluate.py
# Measures how good the detector actually IS, instead of assuming it works.
#
# Anyone can build a detector. The question that turns a tool into a result is:
# how many real attacks does it miss, and how many false alarms does it raise?
#
# Every attack in the sample logs is labelled below (the "ground truth").
# We then run the detector at many threshold/window settings and count:
#
#   TP (caught) - labelled attacks that produced at least one finding
#   FN (missed) - labelled attacks that produced none
#   FP (false)  - findings that match no labelled attack
#
# from which:
#   precision = TP / (TP + FP)   of everything we alerted on, how much was real
#   recall    = TP / (TP + FN)   of everything real, how much did we catch
#   F1        = harmonic mean, the single number that punishes ignoring either
#
#   python evaluate.py

import argparse
import os

from detector import BruteForceDetector

# Sample logs live next to this script, not in the current working directory.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# One attack can legitimately show up under several pivots (as an IP, as a
# subnet, or as a username), so each attack lists every key that counts as
# a correct detection of it.
GROUND_TRUTH = {
    "auth_sample.log": [
        {"name": "burst on 192.168.1.5",
         "keys": {"192.168.1.5", "192.168.1.0/24", "admin"}},
        {"name": "compromise of admin via 203.0.113.5",
         "keys": {"203.0.113.5", "203.0.113.0/24", "admin"}},
    ],
    # No attacks at all. Any finding here is a false alarm by definition.
    # Includes a legitimate user mistyping their password then logging in,
    # which the compromise check used to report as a HIGH severity breach.
    "clean_sample.log": [],
    "evasion_sample.log": [
        {"name": "low-and-slow on root",
         "keys": {"203.0.113.50", "203.0.113.0/24", "root"}},
        {"name": "distributed botnet on admin",
         "keys": {"10.10.10.0/24", "admin"}},
        {"name": "password spray from 198.51.100.77",
         "keys": {"198.51.100.77", "198.51.100.0/24"}},
    ],
    # Real-world line shapes: rsyslog-collapsed repeats, disconnect notices,
    # session and sudo lines. The attack here is only visible if the parser
    # expands "message repeated 9 times" into nine attempts.
    "noisy_sample.log": [
        {"name": "rsyslog-collapsed burst on root",
         "keys": {"203.0.113.200", "203.0.113.0/24", "root"}},
    ],
}

# The settings we want to compare against each other
THRESHOLDS = [3, 5, 10]
WINDOWS = [120, 600, 1800, 3600]

# A wider sweep for the realistic corpus, where the interesting boundary sits
# between 3 and 5 rather than between 5 and 10.
REALISTIC_THRESHOLDS = [3, 4, 5, 6, 8, 10, 12]
REALISTIC_WINDOWS = [60, 120, 300, 600, 1800, 3600]

# Seeds for the generated corpus. Fixed so the numbers are reproducible.
REALISTIC_SEEDS = [42, 99, 7, 13, 2024]


def score_corpus(corpus, threshold, window):
    """Score one corpus of (source, text_or_path, attacks) at these settings."""
    caught = 0
    missed = []
    false_alarms = 0

    for source, attacks in corpus:
        detector = BruteForceDetector(threshold=threshold, window=window)
        if isinstance(source, tuple):        # ("text", blob)
            findings = detector.analyze_text(source[1]).findings
        else:
            findings = detector.analyze_file(source).findings
        hit_keys = {f.key for f in findings}

        legitimate = set()
        for attack in attacks:
            legitimate |= attack["keys"]

        for attack in attacks:
            if hit_keys & attack["keys"]:
                caught += 1
            else:
                missed.append(attack["name"])

        for finding in findings:
            if finding.key not in legitimate:
                false_alarms += 1

    return caught, missed, false_alarms


def score(threshold, window):
    # Run the detector over every labelled log at these settings and count
    # how it did.
    caught = 0
    missed = []
    false_alarms = 0

    for filename, attacks in GROUND_TRUTH.items():
        detector = BruteForceDetector(threshold=threshold, window=window)
        findings = detector.analyze_file(os.path.join(BASE_DIR, filename)).findings
        hit_keys = {f.key for f in findings}

        # Every key that would be a legitimate detection anywhere in this file
        legitimate = set()
        for attack in attacks:
            legitimate |= attack["keys"]

        # Did any finding match this specific attack?
        for attack in attacks:
            if hit_keys & attack["keys"]:
                caught += 1
            else:
                missed.append(attack["name"])

        # Anything we flagged that belongs to no labelled attack is noise
        for finding in findings:
            if finding.key not in legitimate:
                false_alarms += 1

    return caught, missed, false_alarms


def rates(caught, missed, false_alarms):
    # Guard every division: a setting that fires nothing has no precision to
    # speak of, and reporting 0.0 there would be misleading rather than merely
    # undefined.
    alerted = caught + false_alarms
    actual = caught + len(missed)

    precision = caught / alerted if alerted else None
    recall = caught / actual if actual else None

    if precision and recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0
    return precision, recall, f1


def fmt(value):
    return "  -  " if value is None else f"{value:.3f}"


def sweep(corpus, thresholds, windows, total, title):
    """Run a parameter sweep over a corpus and report the best setting."""
    print(title + "\n")
    header = (f"{'threshold':>9} {'window':>7} {'caught':>8} {'missed':>7} "
              f"{'false':>6} {'precis':>7} {'recall':>7} {'F1':>7}")
    print(header)
    print("-" * len(header))

    best = None
    for threshold in thresholds:
        for window in windows:
            caught, missed, false_alarms = score_corpus(corpus, threshold, window)
            precision, recall, f1 = rates(caught, missed, false_alarms)

            print(f"{threshold:>9} {window:>7} {f'{caught}/{total}':>8} "
                  f"{len(missed):>7} {false_alarms:>6} "
                  f"{fmt(precision):>7} {fmt(recall):>7} {f1:>7.3f}")

            # Rank by F1. Ties broken towards the SMALLEST threshold and
            # window that achieves it: among settings that score identically,
            # the most sensitive one detects soonest and has the most headroom
            # against an attacker who slows down.
            rank = (round(f1, 6), -threshold, -window)
            if best is None or rank > best[0]:
                best = (rank, threshold, window, missed, caught, false_alarms)

    rank, threshold, window, missed, caught, false_alarms = best
    print(f"\nBest operating point by F1: threshold={threshold}, window={window}s")
    print(f"  caught {caught}/{total} attacks with {false_alarms} "
          f"false alarm(s), F1={rank[0]:.3f}")
    for name in dict.fromkeys(missed):
        print(f"  STILL MISSED: {name}")
    return threshold, window


def realistic_corpus(seeds):
    """Generate N days of realistic traffic with planted attacks."""
    from generate_log import build
    corpus = []
    for seed in seeds:
        text, attacks = build(hours=24, seed=seed)
        corpus.append((("text", text), attacks))
    return corpus


def main():
    parser = argparse.ArgumentParser(
        description="Score the detector against labelled attacks.")
    parser.add_argument("--realistic", action="store_true",
                        help="also sweep against generated full-day logs")
    parser.add_argument("--only-realistic", action="store_true",
                        help="skip the hand-written samples")
    args = parser.parse_args()

    if not args.only_realistic:
        main_samples()

    if args.realistic or args.only_realistic:
        print("\n" + "=" * 66 + "\n")
        corpus = realistic_corpus(REALISTIC_SEEDS)
        total = sum(len(attacks) for _, attacks in corpus)
        sweep(corpus, REALISTIC_THRESHOLDS, REALISTIC_WINDOWS, total,
              f"REALISTIC CORPUS — {len(corpus)} generated days, "
              f"{total} planted attacks\n"
              f"Full-day traffic: staff logins, operational noise, and\n"
              f"internet background scanning around the planted attacks.")
        print("""
The hand-written samples and the realistic corpus disagree, and the
disagreement is the point. threshold=3 scores perfectly on nine hand-written
lines and collapses on a real day's traffic, because ordinary background
scanning — one or two probes from each of hundreds of addresses — accumulates
past three. The small sample simply had no background traffic to trip over.

This is what the small-sample caveat was warning about, demonstrated rather
than asserted.""")


def main_samples():
    total = sum(len(attacks) for attacks in GROUND_TRUTH.values())
    print(f"Ground truth: {total} labelled attacks across "
          f"{len(GROUND_TRUTH)} log files\n")

    header = (f"{'threshold':>9} {'window':>7} {'caught':>8} {'missed':>7} "
              f"{'false':>6} {'precis':>7} {'recall':>7} {'F1':>7}")
    print(header)
    print("-" * len(header))

    best = None
    for threshold in THRESHOLDS:
        for window in WINDOWS:
            caught, missed, false_alarms = score(threshold, window)
            precision, recall, f1 = rates(caught, missed, false_alarms)

            print(f"{threshold:>9} {window:>7} {f'{caught}/{total}':>8} "
                  f"{len(missed):>7} {false_alarms:>6} "
                  f"{fmt(precision):>7} {fmt(recall):>7} {f1:>7.3f}")

            # Rank by F1: it balances catching attacks against crying wolf,
            # where "most caught" alone would happily pick a setting that
            # alerts on everything. Ties broken by fewer false alarms.
            rank = (f1, -false_alarms)
            if best is None or rank > best[0]:
                best = (rank, threshold, window, missed, caught, false_alarms)

    rank, threshold, window, missed, caught, false_alarms = best
    print(f"\nBest operating point by F1: threshold={threshold}, window={window}s")
    print(f"  caught {caught}/{total} attacks with {false_alarms} "
          f"false alarm(s), F1={rank[0]:.3f}")
    for name in missed:
        print(f"  STILL MISSED: {name}")


if __name__ == "__main__":
    main()
