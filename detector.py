# detector.py
# ONE JOB: take parsed events and decide what looks like an attack.
#
#   Finding             - one alert
#   AnalysisResult      - everything one run produced, ready to print or serve
#   BruteForceDetector  - holds the tuning, runs every strategy

import ipaddress

from log_parser import LogEvent, LogParser

# Defaults, kept as named constants instead of magic numbers buried in code.
DEFAULT_THRESHOLD = 5     # how many failures before we care
DEFAULT_WINDOW = 120      # ...within how many seconds

# A success this soon after failures from the same IP looks like the attacker
# finally guessed right, rather than a real user who mistyped days ago.
COMPROMISE_WINDOW = 600

# How many failures must precede a success before we call it a compromise.
#
# WHY NOT 1: one failure then a success from the same IP is what happens every
# time a legitimate user fat-fingers their own password. At min_failures=1 the
# HIGHEST severity alert in the tool fired on that, which would bury a real
# analyst in noise on any real host. Three is the point where "typo" stops
# being the simplest explanation.
MIN_FAILURES_FOR_COMPROMISE = 3

# The same threshold is not appropriate when every failure was against the
# SAME account that then logged in successfully. That is the exact shape of a
# person fumbling their own password, and on a busy host it happens daily.
# Enumeration across several accounts is damning at two attempts; repeated
# failures on one's own account are ordinary until they become excessive.
SAME_USER_MIN_FAILURES = 6

HIGH = "HIGH"
MEDIUM = "MEDIUM"


class Allowlist:
    """Sources that must never raise an alert.

    WHY THIS EXISTS: the subnet pivot is what catches a botnet, and it is also
    what fires on your own office. Every member of staff mistyping a password
    from 10.0.4.x aggregates into one /24 finding — a perfect detection of
    nothing. The pivot is not wrong; it simply has no way to know that range
    is yours. Telling it is the only fix.

    Accepts three kinds of entry:
        10.0.0.0/8        a network — matches any address inside it, and any
                          /24 finding that falls within it
        192.168.1.20      a single address
        backup            a username, matched exactly
    """

    def __init__(self, entries=()):
        self.networks = []
        self.names = set()
        self.raw = []

        for entry in entries:
            entry = str(entry).strip()
            if not entry:
                continue
            self.raw.append(entry)
            try:
                # strict=False so "10.0.4.7/24" is accepted as its network.
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self.names.add(entry)

    def __bool__(self):
        return bool(self.networks or self.names)

    def __len__(self):
        return len(self.raw)

    def covers(self, key):
        """Is this finding key allowlisted?"""
        if key in self.names:
            return True
        if not self.networks:
            return False
        try:
            # A subnet finding ("10.0.4.0/24") is allowlisted when the whole
            # range sits inside an allowlisted network, not merely overlaps it.
            candidate = ipaddress.ip_network(key, strict=False)
        except ValueError:
            return False
        return any(candidate.subnet_of(network)
                   for network in self.networks
                   if candidate.version == network.version)

    def filter(self, findings):
        if not self:
            return findings, []
        kept, suppressed = [], []
        for finding in findings:
            (suppressed if self.covers(finding.key) else kept).append(finding)
        return kept, suppressed

    def to_dict(self):
        return {"entries": list(self.raw), "count": len(self.raw)}


class Finding:
    """One alert. Carries enough evidence for a human to judge it."""

    __slots__ = ("type", "pivot", "key", "severity", "detail",
                 "count", "span", "first_seen", "last_seen", "total")

    def __init__(self, type, pivot, key, severity, detail, count=0, span=0,
                 first_seen="", last_seen="", total=0):
        self.type = type              # "burst" or "compromise"
        self.pivot = pivot            # what we grouped by: ip / user / subnet
        self.key = key                # the ip, username or subnet itself
        self.severity = severity
        self.detail = detail
        self.count = count            # attempts involved
        self.span = span              # seconds they spanned
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.total = total            # total failures for this key in the log

    @property
    def is_high(self):
        return self.severity == HIGH

    def to_dict(self):
        return {
            "type": self.type,
            "pivot": self.pivot,
            "key": self.key,
            "severity": self.severity,
            "detail": self.detail,
            "count": self.count,
            "span": self.span,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total": self.total,
        }

    def __repr__(self):
        return f"Finding({self.severity} {self.pivot} {self.key})"


class AnalysisResult:
    """Everything one analysis run produced."""

    def __init__(self, source, events, skipped, findings, threshold, window,
                 suppressed=None, allowlist=None):
        self.source = source
        self.events = events
        self.skipped = skipped
        self.findings = findings
        self.threshold = threshold
        self.window = window
        # Findings an allowlist removed. Kept and reported rather than
        # silently dropped: an operator needs to see what was hidden.
        self.suppressed = suppressed or []
        self.allowlist = allowlist

    @property
    def high_findings(self):
        return [f for f in self.findings if f.is_high]

    @property
    def failure_count(self):
        return sum(1 for e in self.events if e.is_failure)

    @property
    def success_count(self):
        return sum(1 for e in self.events if e.is_success)

    @property
    def unique_ips(self):
        return len({e.ip for e in self.events})

    def top_offenders(self, limit=10):
        """Failure count per IP, worst first. Drives the web app's chart."""
        counts = {}
        for event in self.events:
            if event.is_failure:
                counts[event.ip] = counts.get(event.ip, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: -kv[1])
        return [{"ip": ip, "failures": n} for ip, n in ranked[:limit]]

    def timeline(self, buckets=40):
        """Failures over time, bucketed, for the web app's activity chart."""
        failures = [e for e in self.events if e.is_failure]
        if not failures:
            return []

        first = failures[0].timestamp
        last = failures[-1].timestamp
        span = max(last - first, 1)
        width = max(span / buckets, 1)

        counts = [0] * buckets
        labels = [""] * buckets
        for event in failures:
            index = min(int((event.timestamp - first) / width), buckets - 1)
            counts[index] += 1
            if not labels[index]:
                labels[index] = event.time_str
        return [{"label": labels[i], "failures": counts[i]}
                for i in range(buckets)]

    def to_dict(self):
        return {
            "source": self.source,
            "threshold": self.threshold,
            "window": self.window,
            "stats": {
                "events": len(self.events),
                "skipped": self.skipped,
                "failures": self.failure_count,
                "successes": self.success_count,
                "unique_ips": self.unique_ips,
                "findings": len(self.findings),
                "high": len(self.high_findings),
                "suppressed": len(self.suppressed),
            },
            "findings": [f.to_dict() for f in self.findings],
            "suppressed": [f.to_dict() for f in self.suppressed],
            "allowlist": (self.allowlist.to_dict() if self.allowlist
                          else {"entries": [], "count": 0}),
            "top_offenders": self.top_offenders(),
            "timeline": self.timeline(),
        }


class BruteForceDetector:
    """Holds the tuning and runs every detection strategy over parsed events.

    Separating this from the parser is what lets the same detection logic
    serve the CLI, the evaluation harness and the web app without change.
    """

    def __init__(self, threshold=DEFAULT_THRESHOLD, window=DEFAULT_WINDOW,
                 compromise_window=COMPROMISE_WINDOW,
                 min_failures=MIN_FAILURES_FOR_COMPROMISE,
                 detect_compromise=True, allowlist=None,
                 same_user_min_failures=None):
        self.threshold = threshold
        self.window = window
        self.compromise_window = compromise_window
        self.min_failures = min_failures
        # Scales with min_failures when the caller tunes it, so lowering
        # sensitivity lowers both bars together.
        self.same_user_min_failures = (
            same_user_min_failures if same_user_min_failures is not None
            else max(SAME_USER_MIN_FAILURES,
                     min_failures * 2))
        self.detect_compromise = detect_compromise
        self.allowlist = (allowlist if isinstance(allowlist, Allowlist)
                          else Allowlist(allowlist or ()))

    # ---- grouping -----------------------------------------------------

    @staticmethod
    def group_events(events, key_func, result=LogEvent.FAILED):
        # The plain dictionary grouping, generalised.
        # Instead of hardcoding "group by IP", the caller passes a function
        # that says what to group by. Changing that one function is what lets
        # the SAME sliding window detect three different attack shapes.
        groups = {}
        for event in events:
            # result=None means "keep everything", used by compromise detection
            if result is not None and event.result != result:
                continue
            groups.setdefault(key_func(event), []).append(event)
        return groups

    # ---- strategy 1: the sliding window -------------------------------

    def find_bursts(self, groups, pivot):
        # Are there `threshold` failures inside `window` seconds?
        findings = []

        for key, group in groups.items():
            # Not enough failures overall, no point sliding a window
            if len(group) < self.threshold:
                continue

            # Slide a window of size `threshold` across the list.
            # i is the first entry of the window, j is the last.
            for i in range(len(group) - self.threshold + 1):
                j = i + self.threshold - 1
                if group[j].timestamp - group[i].timestamp > self.window:
                    continue

                # Over threshold. Now widen to the TRUE extent of the burst so
                # the alert reports what actually happened rather than
                # restating the threshold back at the analyst. The old code
                # always said "5 failures" even when 400 arrived in the window.
                last = j
                while (last + 1 < len(group)
                       and group[last + 1].timestamp - group[i].timestamp
                       <= self.window):
                    last += 1

                count = last - i + 1
                span = group[last].timestamp - group[i].timestamp
                findings.append(Finding(
                    type="burst", pivot=pivot, key=key, severity=MEDIUM,
                    detail=(f"{count} failures in {span}s "
                            f"({group[i].time_str} to {group[last].time_str}), "
                            f"{len(group)} total"),
                    count=count, span=span,
                    first_seen=group[i].time_str, last_seen=group[last].time_str,
                    total=len(group),
                ))
                break  # one alert per key is enough
        return findings

    # ---- strategy 2: failures that ended in a success -----------------

    def find_compromises(self, events):
        # THE MOST IMPORTANT DETECTION IN THIS FILE.
        #
        # Counting failures only ever measures ATTEMPTS. This measures the
        # thing that actually matters: an attempt that WORKED. A burst check
        # alone will happily alert on an attacker who tried five times and
        # never got in, while staying silent on one who tried three times and
        # succeeded.
        #
        # Two shapes count as a compromise:
        #   1. Failures against several accounts OTHER than the one that then
        #      succeeded. That is enumeration: probing accounts you cannot get
        #      into, then getting into a different one.
        #
        #      The "other than" matters. Counting every distinct failed
        #      username flagged any shared internal host — a jump box or a NAT
        #      gateway — the moment two colleagues each fumbled a password and
        #      one of them then logged in. Requiring the failures to be on
        #      accounts the attacker did NOT end up using separates the two:
        #      an attacker probes doors that stay shut, a workplace does not.
        #   2. Enough failures against a DIFFERENT account, then a success.
        #   3. A lot of failures against the SAME account that then logged in.
        #      This last bar is deliberately higher: it is also the signature
        #      of somebody fumbling their own password, which happens all day
        #      on any multi-user host.
        findings = []

        # Group every event by IP this time, not just the failures
        by_ip = self.group_events(events, lambda e: e.ip, result=None)

        for ip, group in by_ip.items():
            for i, event in enumerate(group):
                # We only care about the moment someone actually got in
                if not event.is_success:
                    continue

                # Look back at this same IP: how many earlier failures were
                # recent enough to be part of the same attack?
                failures = [e for e in group[:i]
                            if e.is_failure
                            and event.timestamp - e.timestamp
                            <= self.compromise_window]

                if not failures:
                    continue

                targeted = {e.user for e in failures}
                # Accounts that were tried and stayed shut — the ones the
                # session did NOT end up using.
                probed = targeted - {event.user}
                # Did the account that succeeded also fail on the way in?
                fumbled_own = event.user in targeted

                if len(probed) >= 2:
                    # Enumeration: two or more doors tried and refused, then a
                    # different one opened. A workplace does not look like this;
                    # an attacker working through a username list does.
                    reason = f"across {len(targeted)} usernames"

                elif fumbled_own:
                    # The successful account is also among the failures. That
                    # is the signature of somebody fumbling their own password,
                    # whether or not a colleague on the same host fumbled too.
                    # A much higher bar applies before it becomes reportable.
                    if len(failures) < self.same_user_min_failures:
                        continue
                    reason = (f"on their own account {event.user}, beyond the "
                              f"{self.same_user_min_failures}-attempt bar for "
                              f"a typo")

                else:
                    # Every failure was against some other account, but only
                    # one distinct account. Enough attempts still make it
                    # worth reporting.
                    if len(failures) < self.min_failures:
                        continue
                    reason = f"on {next(iter(targeted))}"

                span = event.timestamp - failures[0].timestamp
                findings.append(Finding(
                    type="compromise", pivot="ip", key=ip, severity=HIGH,
                    detail=(f"{len(failures)} failure(s) {reason} then SUCCESS "
                            f"as user {event.user} at {event.time_str}"),
                    count=len(failures), span=span,
                    first_seen=failures[0].time_str, last_seen=event.time_str,
                    total=len(failures),
                ))
                break  # one alert per IP is enough
        return findings

    # ---- noise control ------------------------------------------------

    @staticmethod
    def drop_redundant_subnets(findings):
        # If 192.168.1.5 already fired, then "192.168.1.0/24 also fired" tells
        # the analyst nothing new. Real SOC tools live or die on not drowning
        # people in duplicate alerts.
        flagged = {LogEvent(0, "", "", f.key, "", "").subnet
                   for f in findings if f.pivot == "ip"}
        return [f for f in findings
                if not (f.pivot == "subnet" and f.key in flagged)]

    # ---- the whole run --------------------------------------------------

    def analyze(self, events):
        """Parsed events -> ranked findings."""
        findings = []

        # Strategy 1: did anyone actually get in after failing?
        if self.detect_compromise:
            findings += self.find_compromises(events)

        # Strategy 2: the same sliding window, applied three different ways.
        #   by ip     -> the classic brute force burst from one machine
        #   by user   -> password spraying, and many machines on one account
        #   by subnet -> a botnet whose individual IPs stay under the limit
        pivots = [
            ("ip", lambda e: e.ip),
            ("user", lambda e: e.user),
            ("subnet", lambda e: e.subnet),
        ]
        for pivot, key_func in pivots:
            findings += self.find_bursts(self.group_events(events, key_func),
                                         pivot)

        # Clean up duplicate noise, drop anything the operator has told us to
        # ignore, then show the worst findings first.
        findings = self.drop_redundant_subnets(findings)
        findings, self.last_suppressed = self.allowlist.filter(findings)
        findings.sort(key=lambda f: 0 if f.is_high else 1)
        return findings

    def analyze_text(self, text, source="pasted input"):
        events, skipped = LogParser().parse_text(text)
        return self._result(source, events, skipped)

    def analyze_file(self, filename):
        events, skipped = LogParser().parse_file(filename)
        return self._result(filename, events, skipped)

    def _result(self, source, events, skipped):
        findings = self.analyze(events)
        return AnalysisResult(source, events, skipped, findings,
                              self.threshold, self.window,
                              suppressed=getattr(self, "last_suppressed", []),
                              allowlist=self.allowlist)


# ---- procedural wrappers, for the CLI and the evaluation harness --------

def subnet_of(ip):
    return LogEvent(0, "", "", ip, "", "").subnet


def read_events(filename):
    return LogParser().parse_file(filename)


def group_events(events, key_func, result=LogEvent.FAILED):
    return BruteForceDetector.group_events(events, key_func, result)


def find_bursts(groups, pivot, threshold, window):
    return BruteForceDetector(threshold=threshold, window=window).find_bursts(
        groups, pivot)


def find_compromises(events, window=COMPROMISE_WINDOW,
                     min_failures=MIN_FAILURES_FOR_COMPROMISE):
    return BruteForceDetector(compromise_window=window,
                              min_failures=min_failures).find_compromises(events)


def drop_redundant_subnets(findings):
    return BruteForceDetector.drop_redundant_subnets(findings)


def analyze_log(filename, threshold=DEFAULT_THRESHOLD, window=DEFAULT_WINDOW,
                detect_compromise=True, verbose=True, allowlist=None):
    """Analyse one file and optionally print the report. Returns findings."""
    detector = BruteForceDetector(threshold=threshold, window=window,
                                  detect_compromise=detect_compromise,
                                  allowlist=allowlist)
    result = detector.analyze_file(filename)
    if verbose:
        print_report(result)
    return result.findings


def print_report(result):
    print("=" * 72)
    print(f"Log:     {result.source}")
    print(f"Events:  {len(result.events)} parsed, "
          f"{result.skipped} unrecognised line(s) skipped")
    print("=" * 72)

    if not result.findings:
        print("No threats detected.")
        if result.suppressed:
            print(f"({len(result.suppressed)} finding(s) suppressed by "
                  f"allowlist: {', '.join(f.key for f in result.suppressed)})")
        return

    for f in result.findings:
        print(f"[{f.severity:<6}] {f.pivot:<7} {f.key:<18} {f.detail}")

    print("-" * 72)
    line = f"{len(result.findings)} finding(s)."
    if result.suppressed:
        line += (f" {len(result.suppressed)} suppressed by allowlist "
                 f"({', '.join(f.key for f in result.suppressed)}).")
    print(line)
