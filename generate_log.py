# generate_log.py
# Builds a realistic SSH authentication log, and records exactly what it
# planted so the detector's output can be checked against the truth.
#
#   python generate_log.py                          -> live_auth.log, 24 hours
#   python generate_log.py --hours 6 --out my.log
#   python generate_log.py --seed 7                 -> reproducible
#   python generate_log.py --truth                  -> print planted attacks
#
# WHY THIS EXISTS: the bundled samples are small, hand-written, and fixed.
# They prove specific behaviours but they do not look like a real log. This
# produces a full day of plausible traffic — legitimate logins, operational
# noise, internet background scanning — with attacks buried inside it at
# realistic density, so the detector has to find them rather than be handed
# them.
#
# The output is synthetic. It is shaped from published descriptions of SSH
# attack traffic, not captured from a real host, and the README says so.

import argparse
import os
import random
from datetime import datetime, timedelta

HOST = "webserver"

# People who legitimately use this box.
STAFF = ["deploy", "jaswanth", "alice", "backup", "ansible", "postgres"]
INTERNAL = ["10.0.4.%d" % n for n in (11, 12, 15, 23, 40)]

# What password guessers actually try, in roughly the order they try it.
COMMON_TARGETS = ["root", "admin", "test", "user", "oracle", "ubuntu", "git",
                  "postgres", "ftp", "guest", "pi", "jenkins", "mysql", "www"]

# Non-authentication lines. A real auth.log is mostly this.
NOISE_TEMPLATES = [
    "Received disconnect from {ip} port {port}:11: Bye Bye [preauth]",
    "Disconnected from authenticating user {user} {ip} port {port} [preauth]",
    "Connection closed by {ip} port {port} [preauth]",
    "Connection reset by {ip} port {port} [preauth]",
    "pam_unix(sshd:session): session opened for user {user} by (uid=0)",
    "pam_unix(sshd:session): session closed for user {user}",
    "Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:x",
    "error: kex_exchange_identification: Connection closed by remote host",
]
SUDO_TEMPLATE = ("sudo:  {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                 "USER=root ; COMMAND={cmd}")
CRON_TEMPLATE = "CRON[{pid}]: pam_unix(cron:session): session opened for user {user} by (uid=0)"
COMMANDS = ["/usr/bin/systemctl restart nginx", "/bin/journalctl -u api",
            "/usr/bin/apt update", "/bin/ls /var/log"]


def syslog_time(when):
    # Syslog pads a single-digit day with a space: "Aug  4 09:15:01".
    # Included deliberately — a parser that splits on a fixed column breaks
    # on it, one that splits on whitespace does not.
    return "%s %2d %s" % (when.strftime("%b"), when.day,
                          when.strftime("%H:%M:%S"))


class LogBuilder:
    """Collects (datetime, message) pairs, then renders them in time order."""

    def __init__(self, rng):
        self.rng = rng
        self.lines = []
        self.attacks = []          # ground truth, for verification

    def add(self, when, message):
        self.lines.append((when, message))

    def sshd(self, when, message):
        self.add(when, "sshd[%d]: %s" % (self.rng.randint(1000, 9999), message))

    def failure(self, when, user, ip):
        self.sshd(when, "Failed password for %s%s from %s port %d ssh2"
                  % ("invalid user " if user not in STAFF else "",
                     user, ip, self.rng.randint(30000, 65000)))

    def success(self, when, user, ip):
        self.sshd(when, "Accepted password for %s from %s port %d ssh2"
                  % (user, ip, self.rng.randint(30000, 65000)))

    def collapsed(self, when, user, ip, times):
        # How rsyslog records a flood: one line standing for `times` attempts.
        inner = ("Failed password for %s%s from %s port %d ssh2"
                 % ("invalid user " if user not in STAFF else "",
                    user, ip, self.rng.randint(30000, 65000)))
        self.sshd(when, "message repeated %d times: [ %s]" % (times, inner))

    def noise(self, when):
        template = self.rng.choice(NOISE_TEMPLATES)
        self.sshd(when, template.format(
            ip=self.random_public_ip(), port=self.rng.randint(30000, 65000),
            user=self.rng.choice(STAFF + COMMON_TARGETS)))

    def random_public_ip(self):
        # Documentation ranges only (RFC 5737) — never a real address.
        block = self.rng.choice(["192.0.2", "198.51.100", "203.0.113"])
        return "%s.%d" % (block, self.rng.randint(1, 254))

    def plant(self, name, keys, description):
        self.attacks.append({"name": name, "keys": set(keys),
                             "description": description})

    def render(self):
        self.lines.sort(key=lambda pair: pair[0])
        return "\n".join("%s %s %s" % (syslog_time(when), HOST, message)
                         for when, message in self.lines) + "\n"


# ---- traffic generators -------------------------------------------------

def add_normal_traffic(builder, start, hours):
    """Staff logging in and out, plus the operational noise around it."""
    rng = builder.rng
    for _ in range(int(hours * 4)):
        when = start + timedelta(seconds=rng.randint(0, hours * 3600))
        user = rng.choice(STAFF)
        ip = rng.choice(INTERNAL)

        # Roughly one in six real logins involves a mistyped password first.
        # This is the case the compromise check must NOT fire on.
        if rng.random() < 0.17:
            builder.failure(when, user, ip)
            when += timedelta(seconds=rng.randint(4, 25))
        builder.success(when, user, ip)
        builder.sshd(when + timedelta(seconds=1),
                     "pam_unix(sshd:session): session opened for user %s by (uid=0)" % user)

        if rng.random() < 0.4:
            builder.add(when + timedelta(seconds=rng.randint(5, 300)),
                        SUDO_TEMPLATE.format(user=user, cmd=rng.choice(COMMANDS)))

    for _ in range(int(hours * 12)):
        builder.noise(start + timedelta(seconds=rng.randint(0, hours * 3600)))

    for _ in range(int(hours * 2)):
        when = start + timedelta(seconds=rng.randint(0, hours * 3600))
        builder.add(when, CRON_TEMPLATE.format(pid=rng.randint(1000, 9999),
                                               user=rng.choice(["root", "backup"])))


def add_background_scanning(builder, start, hours):
    """Internet background radiation: one or two probes from many addresses.

    None of this should alert. It is the false-positive pressure that makes
    the clean-log result meaningful.
    """
    rng = builder.rng
    for _ in range(int(hours * 6)):
        ip = builder.random_public_ip()
        when = start + timedelta(seconds=rng.randint(0, hours * 3600))
        for i in range(rng.randint(1, 2)):
            builder.failure(when + timedelta(seconds=i * rng.randint(2, 40)),
                            rng.choice(COMMON_TARGETS), ip)


def add_fast_burst(builder, start):
    """Classic single-source brute force. Any detector should catch this."""
    rng = builder.rng
    ip = "198.51.100.%d" % rng.randint(200, 250)
    when = start
    for _ in range(rng.randint(18, 30)):
        builder.failure(when, "root", ip)
        when += timedelta(seconds=rng.randint(1, 4))
    builder.plant("fast burst on root", [ip, "198.51.100.0/24", "root"],
                  "%s hammering root, seconds apart" % ip)
    return ip


def add_collapsed_burst(builder, start):
    """A flood that rsyslog folded into one line. Invisible without expansion."""
    rng = builder.rng
    ip = "192.0.2.%d" % rng.randint(100, 200)
    times = rng.randint(30, 80)
    builder.failure(start, "admin", ip)
    builder.collapsed(start + timedelta(seconds=2), "admin", ip, times)
    builder.plant("rsyslog-collapsed flood on admin",
                  [ip, "192.0.2.0/24", "admin"],
                  "%s: %d attempts folded into one log line" % (ip, times))
    return ip


def add_low_and_slow(builder, start, hours):
    """One guess every few minutes. Defeats a short window entirely."""
    rng = builder.rng
    ip = "203.0.113.%d" % rng.randint(30, 60)
    gap = rng.randint(240, 420)
    when = start
    for _ in range(int((hours * 3600) // gap)):
        builder.failure(when, "ubuntu", ip)
        when += timedelta(seconds=gap)
    builder.plant("low-and-slow on ubuntu", [ip, "203.0.113.0/24", "ubuntu"],
                  "%s: one guess every %d seconds" % (ip, gap))
    return ip


def add_botnet(builder, start):
    """Many addresses in one /24, each staying under the threshold."""
    rng = builder.rng
    third = rng.randint(10, 90)
    subnet = "192.0.2.%d" % third
    when = start
    for host in range(1, rng.randint(14, 22)):
        ip = "192.0.2.%d" % ((third + host) % 254 or 1)
        for _ in range(rng.randint(2, 3)):
            builder.failure(when, "test", ip)
            when += timedelta(seconds=rng.randint(1, 5))
    builder.plant("distributed botnet on test", ["192.0.2.0/24", "test"],
                  "many hosts in 192.0.2.0/24, each below the threshold")
    return subnet


def add_password_spray(builder, start):
    """One source, one guess each against many accounts."""
    rng = builder.rng
    ip = "203.0.113.%d" % rng.randint(150, 240)
    when = start
    for user in builder.rng.sample(COMMON_TARGETS, min(10, len(COMMON_TARGETS))):
        builder.failure(when, user, ip)
        when += timedelta(seconds=rng.randint(3, 12))
    builder.plant("password spray", [ip, "203.0.113.0/24"],
                  "%s: one attempt each across 10 accounts" % ip)
    return ip


def add_compromise(builder, start):
    """Enumeration that succeeds. The finding that actually matters."""
    rng = builder.rng
    ip = "198.51.100.%d" % rng.randint(10, 90)
    when = start
    tried = rng.sample(COMMON_TARGETS, 4)
    for user in tried:
        builder.failure(when, user, ip)
        when += timedelta(seconds=rng.randint(3, 15))
    victim = rng.choice(STAFF)
    builder.success(when, victim, ip)
    builder.sshd(when + timedelta(seconds=2),
                 "pam_unix(sshd:session): session opened for user %s by (uid=0)" % victim)
    builder.add(when + timedelta(seconds=rng.randint(20, 90)),
                SUDO_TEMPLATE.format(user=victim, cmd="/bin/bash"))
    builder.plant("COMPROMISE — enumeration then success",
                  [ip, "198.51.100.0/24"],
                  "%s tried %d usernames then logged in as %s"
                  % (ip, len(tried), victim))
    return ip


def build(hours=24, seed=None, day=None):
    """Return (log_text, planted_attacks)."""
    rng = random.Random(seed)
    builder = LogBuilder(rng)

    day = day or datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

    add_normal_traffic(builder, day, hours)
    add_background_scanning(builder, day, hours)

    # Attacks land at plausible hours, spread through the day.
    def at(hour):
        return day + timedelta(hours=hour % max(hours, 1),
                               minutes=rng.randint(0, 59))

    add_fast_burst(builder, at(2))
    add_collapsed_burst(builder, at(4))
    add_low_and_slow(builder, day + timedelta(hours=1), hours - 2)
    add_botnet(builder, at(11))
    add_password_spray(builder, at(15))
    add_compromise(builder, at(19))

    return builder.render(), builder.attacks


def verify(path, attacks, threshold=None, window=None):
    """Analyse the generated log and report which planted attacks were found.

    This is the honest test. The generator knows what it buried; the detector
    does not. Anything the detector reports that was not planted is a false
    alarm, and anything planted that it did not report is a miss.
    """
    from detector import BruteForceDetector, DEFAULT_THRESHOLD, DEFAULT_WINDOW

    threshold = threshold or DEFAULT_THRESHOLD
    window = window or DEFAULT_WINDOW

    detector = BruteForceDetector(threshold=threshold, window=window)
    result = detector.analyze_file(path)
    hit_keys = {f.key for f in result.findings}

    print(f"\n{'=' * 68}")
    print(f"Verification — detector at threshold={threshold}, window={window}s")
    print("=" * 68)
    print(f"{len(result.events)} events parsed, {result.skipped} lines skipped, "
          f"{len(result.findings)} finding(s) raised\n")

    caught, missed = [], []
    for attack in attacks:
        matched = hit_keys & attack["keys"]
        if matched:
            caught.append(attack)
            print(f"  [FOUND ] {attack['name']}")
            print(f"           matched on {', '.join(sorted(matched))}")
        else:
            missed.append(attack)
            print(f"  [MISSED] {attack['name']}")
            print(f"           expected one of {', '.join(sorted(attack['keys']))}")

    legitimate = set()
    for attack in attacks:
        legitimate |= attack["keys"]
    false_alarms = [f for f in result.findings if f.key not in legitimate]

    if false_alarms:
        print()
        for finding in false_alarms:
            print(f"  [FALSE ] {finding.pivot} {finding.key} — {finding.detail}")

    total = len(attacks)
    recall = len(caught) / total if total else 0.0
    precision = (len(caught) / (len(caught) + len(false_alarms))
                 if caught or false_alarms else 0.0)

    print(f"\n{'-' * 68}")
    print(f"  caught {len(caught)}/{total}   "
          f"missed {len(missed)}   false alarms {len(false_alarms)}")
    print(f"  recall {recall:.3f}   precision {precision:.3f}")

    if missed:
        print("\n  Try a wider window — the missed attacks are the slow ones:")
        print(f"    python generate_log.py --seed <same> --verify -t 3 -w 1800")

    return 0 if not missed and not false_alarms else 1


def main():
    parser = argparse.ArgumentParser(
        description="Generate a realistic SSH auth.log with planted attacks.")
    parser.add_argument("--out", default="live_auth.log", help="output file")
    parser.add_argument("--hours", type=int, default=24,
                        help="hours of traffic to generate (default: 24)")
    parser.add_argument("--seed", type=int, default=None,
                        help="seed for a reproducible log")
    parser.add_argument("--truth", action="store_true",
                        help="print the attacks that were planted")
    parser.add_argument("--verify", action="store_true",
                        help="analyse the generated log and score the detector "
                             "against what was planted")
    parser.add_argument("-t", "--threshold", type=int, default=None,
                        help="threshold to verify with (default: the tool's)")
    parser.add_argument("-w", "--window", type=int, default=None,
                        help="window to verify with (default: the tool's)")
    args = parser.parse_args()

    text, attacks = build(hours=args.hours, seed=args.seed)
    with open(args.out, "w") as f:
        f.write(text)

    lines = text.count("\n")
    size = os.path.getsize(args.out)
    print(f"Wrote {args.out}: {lines} lines, {size / 1024:.1f} KB, "
          f"{args.hours}h of traffic")
    print(f"Planted {len(attacks)} attacks:")
    for attack in attacks:
        print(f"  - {attack['name']}")
        print(f"      {attack['description']}")
    if args.truth:
        print("\nDetection keys that count as a hit:")
        for attack in attacks:
            print(f"  {attack['name']}: {sorted(attack['keys'])}")

    if args.verify:
        return verify(args.out, attacks, args.threshold, args.window)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
