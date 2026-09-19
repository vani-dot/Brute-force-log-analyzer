# log_parser.py
# ONE JOB: turn raw log text into clean, structured events.
# No detection logic lives in this file.
#
# Named log_parser rather than parser because `parser` was a standard library
# module up to Python 3.9, and shadowing a stdlib name is a trap.
#
#   LogEvent   - one authentication attempt, as an object rather than a dict
#   LogParser  - knows syslog/sshd line syntax, produces LogEvents

# Maps the month name syslog writes into a number we can do maths with.
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Days that have already passed before the 1st of each month.
# Index 1 = Jan (0 days before it), index 2 = Feb (31 days before it), etc.
DAYS_BEFORE_MONTH = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]


class LogEvent:
    """One authentication attempt, parsed out of a single log line.

    An object rather than a dictionary so the fields are declared in one
    place, typos become AttributeErrors instead of silent KeyErrors, and
    behaviour that belongs to an event (is it a failure? what subnet?) lives
    with the data instead of being scattered through the detector.
    """

    __slots__ = ("timestamp", "time_str", "date_str", "ip", "user",
                 "result", "count", "raw")

    FAILED = "failed"
    SUCCESS = "success"
    OTHER = "other"

    def __init__(self, timestamp, time_str, date_str, ip, user, result,
                 count=1, raw=""):
        self.timestamp = timestamp    # absolute seconds, for time maths
        self.time_str = time_str      # "09:15:01", for printing
        self.date_str = date_str      # "Jun 19", for printing
        self.ip = ip
        self.user = user
        self.result = result          # failed / success / other
        self.count = count            # attempts this line stands for
        self.raw = raw                # the original line, for the web UI

    @property
    def is_failure(self):
        return self.result == self.FAILED

    @property
    def is_success(self):
        return self.result == self.SUCCESS

    @property
    def subnet(self):
        # "10.10.10.7" -> "10.10.10.0/24"
        # This is what lets us catch a botnet: many IPs that each stay under
        # the threshold, but all live in the same /24 address range.
        parts = self.ip.split(".")
        if len(parts) != 4:
            return self.ip          # IPv6 and anything odd stays ungrouped
        return ".".join(parts[:3]) + ".0/24"

    def to_dict(self):
        # For JSON responses and the web UI.
        return {
            "timestamp": self.timestamp,
            "time": self.time_str,
            "date": self.date_str,
            "ip": self.ip,
            "user": self.user,
            "result": self.result,
            "count": self.count,
        }

    def __repr__(self):
        return (f"LogEvent({self.date_str} {self.time_str} {self.result} "
                f"{self.user}@{self.ip} x{self.count})")


class LogParser:
    """Understands sshd/syslog line syntax. Knows nothing about attacks."""

    # The ONLY line shapes that are authentication attempts. Checked in order,
    # so "Failed password for invalid user x" matches "Failed password" and
    # never falls through to the "Invalid user" recon marker.
    #
    # WHY A WHITELIST: the old code accepted any line containing the word
    # "from" and took the word before it as the username. A perfectly ordinary
    # "Received disconnect from 203.0.113.5 port 41223:11: Bye" therefore
    # became an event for a user literally called "disconnect". Real auth.log
    # files are mostly these lines, so the event count filled with garbage.
    RESULT_MARKERS = (
        ("Failed password", LogEvent.FAILED),
        ("Failed publickey", LogEvent.FAILED),
        ("Accepted password", LogEvent.SUCCESS),
        ("Accepted publickey", LogEvent.SUCCESS),
        ("Invalid user", LogEvent.OTHER),      # reconnaissance, not a login
    )

    # rsyslog collapses a flood of identical lines into one summary line.
    REPEAT_MARKER = "message repeated "

    # ---- time helpers -------------------------------------------------

    @staticmethod
    def time_to_seconds(time_str):
        # Split "09:15:01" into ["09", "15", "01"], then into a number
        hours, minutes, seconds = (int(p) for p in time_str.split(":"))
        return hours * 3600 + minutes * 60 + seconds

    @classmethod
    def timestamp_to_seconds(cls, month_str, day_str, time_str):
        # "Jun", "19", "09:15:01"  ->  one absolute number for the whole year.
        #
        # WHY THIS EXISTS: counting seconds since midnight alone made
        # "Jun 19 09:15:01" and "Jun 20 09:15:01" look 1 SECOND apart instead
        # of a full day, causing false alerts on multi-day logs. It also broke
        # across midnight (23:59:58 -> 00:00:03 produced a NEGATIVE gap and
        # got missed). Folding the date in fixes both problems.
        if month_str not in MONTHS:
            return None

        # Guard against malformed dates/times instead of crashing
        try:
            day = int(day_str)
            seconds_today = cls.time_to_seconds(time_str)
        except (ValueError, IndexError):
            return None

        day_of_year = DAYS_BEFORE_MONTH[MONTHS[month_str]] + day
        return day_of_year * 86400 + seconds_today

    # ---- line handling ------------------------------------------------

    @classmethod
    def classify(cls, line):
        # Which kind of authentication event is this line, if any?
        # Returns a LogEvent result constant, or None if the line is not an
        # authentication attempt at all.
        for marker, result in cls.RESULT_MARKERS:
            if marker in line:
                return result
        return None

    @classmethod
    def expand_repeat(cls, line):
        # "Jun 22 03:01:00 h sshd[1]: message repeated 9 times: [ Failed
        #  password for root from 203.0.113.200 port 40005 ssh2]"
        #     -> ("Jun 22 03:01:00 h sshd[1]: Failed password for root
        #         from 203.0.113.200 port 40005 ssh2", 9)
        #
        # WHY: rsyslog folds repeated identical lines into a single summary.
        # A brute force is exactly the traffic that triggers that folding, so
        # reading the summary as ONE failure silently loses the attack.
        # Lines without the marker come back unchanged with a count of 1.
        marker = line.find(cls.REPEAT_MARKER)
        if marker == -1:
            return line, 1

        tail = line[marker + len(cls.REPEAT_MARKER):].split()
        if not tail:
            return line, 1
        try:
            count = int(tail[0])
        except ValueError:
            return line, 1

        # The original line is wrapped in square brackets after "times:"
        open_bracket = line.find("[", marker)
        close_bracket = line.rfind("]")
        if open_bracket == -1 or close_bracket <= open_bracket:
            return line, 1

        # Keep the real timestamp prefix, splice the wrapped line back in
        prefix = line[:marker]
        inner = line[open_bracket + 1:close_bracket].strip()
        return prefix + inner, max(count, 1)

    def parse_line(self, line):
        """Raw line -> LogEvent, or None if it is not a login attempt."""
        original = line.rstrip("\n")

        # Unwrap an rsyslog "message repeated N times" line before anything
        line, count = self.expand_repeat(original)

        # Only authentication attempts get past this point
        result = self.classify(line)
        if result is None:
            return None

        words = line.split()

        # A truncated line can still reach here. The old code called
        # words.index("from") straight away, which raised ValueError and
        # killed the whole program; returning None lets the caller skip it.
        if len(words) < 6 or "from" not in words:
            return None

        # "from" shifts position line to line, so find it rather than assume
        from_index = words.index("from")
        if from_index == 0 or from_index + 1 >= len(words):
            return None

        timestamp = self.timestamp_to_seconds(words[0], words[1], words[2])
        if timestamp is None:
            return None

        return LogEvent(
            timestamp=timestamp,
            time_str=words[2],
            date_str=words[0] + " " + words[1],
            # The IP always sits one word AFTER "from"
            ip=words[from_index + 1],
            # The username always sits one word BEFORE "from". Works for both
            # "for invalid user admin from IP" and "for root from IP".
            user=words[from_index - 1],
            result=result,
            count=count,
            raw=original,
        )

    def parse_lines(self, lines):
        """Iterable of raw lines -> (events, skipped_count).

        An rsyslog "message repeated N times" line becomes N events. All N
        share the one timestamp syslog recorded, which is the only honest
        reading: the log does not say when the others happened.
        """
        events = []
        skipped = 0

        for line in lines:
            event = self.parse_line(line)
            if event is None:
                if line.strip():      # do not count blank lines as skipped
                    skipped += 1
                continue
            events.extend([event] * event.count)

        # Sort by time. Log files are usually chronological already, but once
        # we group by subnet and username we are merging lines from many
        # sources, so we cannot assume the order is correct.
        events.sort(key=lambda e: e.timestamp)
        return events, skipped

    def parse_file(self, filename):
        # "with" closes the file automatically, even if something goes wrong.
        with open(filename, errors="replace") as f:
            return self.parse_lines(f)

    def parse_text(self, text):
        """Parse a pasted or uploaded blob of log text. Used by the web app."""
        return self.parse_lines(text.splitlines())


# A module-level parser and thin function wrappers, so the simple procedural
# API still works for callers that do not need an object.
_DEFAULT = LogParser()

parse_line = _DEFAULT.parse_line
parse_text = _DEFAULT.parse_text
parse_file = _DEFAULT.parse_file
time_to_seconds = LogParser.time_to_seconds
timestamp_to_seconds = LogParser.timestamp_to_seconds
expand_repeat = LogParser.expand_repeat
classify = LogParser.classify
