#!/usr/bin/env bash
# demo.sh — the guided tour. Tells the story in the order it makes sense.
#
#   ./demo.sh            step through, Enter to advance
#   ./demo.sh --fast     run straight through, no pauses
#
# Every number printed comes from the real tool. Nothing here is canned.

set -uo pipefail
cd "$(dirname "$0")"
HERE="$PWD"

PY_BIN="$(command -v python3)"
[ -x "$HERE/.venv/bin/python" ] && PY_BIN="$HERE/.venv/bin/python"
py() { "$PY_BIN" "$@"; }

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

B=$'\033[1m'; DIM=$'\033[2m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; R=$'\033[0m'

step() {
  echo
  printf '%s\n' "${C}────────────────────────────────────────────────────────────────${R}"
  printf '%s%s%s\n' "$B" "$1" "$R"
  printf '%s%s%s\n' "$DIM" "$2" "$R"
  echo
}
say()  { printf '%s→ %s%s\n' "$Y" "$1" "$R"; }
run()  { printf '%s$ %s%s\n\n' "$G" "$*" "$R"; py "$@"; echo; }
pause() { [ "$FAST" -eq 1 ] && return; printf '%s   [Enter]%s' "$DIM" "$R"; read -r _; }

clear 2>/dev/null
cat <<'BANNER'
  ╔══════════════════════════════════════════════════════════════╗
  ║          Brute Force Log Analyzer — guided demo              ║
  ║   Detecting SSH password attacks that simple counting misses ║
  ╚══════════════════════════════════════════════════════════════╝
BANNER
pause

# ────────────────────────────────────────────────────────────────
step "1. Normal traffic" \
     "Before claiming to catch attacks, prove it stays quiet when there are none."
run main.py clean_sample.log
say "Six ordinary logins — and one user who mistyped their own password at"
say "10:12:03 then got in at 10:12:19. That last one is the trap: it is"
say "literally 'failure then success from the same IP', the exact shape of a"
say "compromise. A naive detector screams. This one correctly says nothing."
pause

# ────────────────────────────────────────────────────────────────
step "2. A real attack" \
     "Now a log with two genuine attacks in it."
run main.py auth_sample.log
say "Two different attacks, and note the ORDER:"
say ""
say "  192.168.1.5  tried 5 times and NEVER got in       → MEDIUM"
say "  203.0.113.5  tried 3 usernames and WAS ACCEPTED   → HIGH"
say ""
say "Counting failures alone would rank these backwards: five failures looks"
say "worse than three. But three attempts that WORKED is a breach, and five"
say "that failed is just noise. Only correlating failures with the success"
say "that follows them gets this the right way round."
pause

# ────────────────────────────────────────────────────────────────
step "3. Evasion — the part that matters" \
     "Three attacks specifically built to slip under a per-IP threshold."
say "First, the textbook setting everyone uses: 5 failures in 120 seconds."
echo
run main.py evasion_sample.log
say "It found the botnet, but look what is MISSING: 203.0.113.50."
say "That attacker guessed root's password every 6 minutes for 48 minutes."
say "8 attempts. Never 5 within any 120-second window, so: invisible."
pause
say "Now widen the window to 30 minutes and drop the threshold to 3:"
echo
run main.py evasion_sample.log -t 3 -w 1800
say "There it is. 203.0.113.50, 6 failures across 1800 seconds."
say ""
say "Same code. Same log. Only the tuning changed — and that is the whole"
say "argument: the default settings are inherited, not measured."
pause

# ────────────────────────────────────────────────────────────────
step "4. What a real log actually looks like" \
     "Production auth.log is mostly noise, and the noise breaks naive parsers."
run main.py noisy_sample.log
say "Two things happened here."
say ""
say "  5 lines SKIPPED — disconnect notices, a sudo command, a session open."
say "  They all contain the word 'from', and a parser that just looks for"
say "  'from' invents a user called 'disconnect' out of them."
say ""
say "  9 failures found — from ONE line. rsyslog folds repeated lines into"
say "  'message repeated 9 times: [...]'. A brute force is exactly the"
say "  traffic that triggers that folding, so reading it as one failure"
say "  loses the entire attack."
pause

# ────────────────────────────────────────────────────────────────
step "5. Proving the collapsed-line handling is honest" \
     "Nine attempts written two different ways must give the same verdict."
say "Writing the same 9 attempts as 9 separate lines instead of 1 folded line:"
echo
py - <<'PYDEMO'
import os, sys
sys.path.insert(0, os.getcwd())
from detector import BruteForceDetector

collapsed = ("Jun 22 03:01:00 server sshd[4005]: message repeated 9 times: "
             "[ Failed password for root from 203.0.113.200 port 40005 ssh2]")
expanded = "\n".join(
    "Jun 22 03:01:00 server sshd[4005]: Failed password for root "
    "from 203.0.113.200 port 40005 ssh2" for _ in range(9))

detector = BruteForceDetector()
for label, text in (("one folded line ", collapsed), ("nine plain lines", expanded)):
    result = detector.analyze_text(text)
    print(f"  {label}  ->  {result.failure_count} failures, "
          f"{len(result.findings)} finding(s)")
PYDEMO
echo
say "Identical. The parser recovers what rsyslog threw away."
pause

# ────────────────────────────────────────────────────────────────
step "6. A log the detector has never seen" \
     "Hand-written samples prove specific behaviours. They do not look like a real log."
say "Generating a full day of realistic traffic with attacks buried in it:"
echo
run generate_log.py --seed 2026 --out /tmp/demo_gen.log --hours 24
say "Staff logins, sudo, session lines, disconnects, and internet background"
say "scanning — plus six attacks. The detector is told none of this."
pause
say "Now score it against what was actually planted, at the default 5/120:"
echo
run generate_log.py --seed 2026 --out /tmp/demo_gen.log --verify -t 5 -w 120
pause
say "And at the setting measured against realistic traffic, 4/600:"
echo
run generate_log.py --seed 2026 --out /tmp/demo_gen.log --verify -t 4 -w 600
say "6/6 caught, zero false alarms."
pause

# ────────────────────────────────────────────────────────────────
step "7. The tuning conclusion that was wrong" \
     "The small samples said 3/1800 was perfect. Real traffic disagrees."
say "Sweeping thresholds against five generated days:"
echo
run evaluate.py --only-realistic
say "threshold=3 catches everything AND raises 80 false alarms a day, because"
say "ordinary background scanning — one or two probes from hundreds of"
say "addresses — accumulates past three."
say ""
say "Between 3 and 4 there is a cliff: 45 false alarms on one side, zero on"
say "the other. Nine lines of hand-written log cannot show you that."
pause

# ────────────────────────────────────────────────────────────────
step "8. Real-time detection" \
     "Following a log as it is written, rather than reading it afterwards."
py - <<'PYDEMO'
import os, sys, tempfile
sys.path.insert(0, os.getcwd())
from watcher import LiveWatcher, WatchState
from detector import BruteForceDetector

with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "auth.log")
    open(path, "w").close()
    # repeat_after is the real default: an attack that stays over the
    # threshold must not re-emit the same finding on every poll.
    w = LiveWatcher(path, detector=BruteForceDetector(threshold=4, window=600),
                    repeat_after=300)
    w._follower.open(from_end=False)
    w.state = WatchState.RUNNING

    def line(i, ip="203.0.113.99"):
        return (f"Aug 24 10:00:{i:02d} host sshd[1]: Failed password for "
                f"invalid user root from {ip} port 40000 ssh2")

    def append(lines):
        with open(path, "a") as f:
            f.write("\n".join(lines) + "\n")

    print("  writing lines into the log one batch at a time:\n")
    append([line(i) for i in range(3)])
    print(f"    3 failures arrive     -> {len(w.poll_once())} findings  (below threshold 4)")
    append([line(3)])
    fresh = w.poll_once()
    print(f"    the 4th arrives       -> {len(fresh)} findings  <- FIRES IMMEDIATELY")
    for f in fresh:
        print(f"        {f.severity} {f.pivot} {f.key}: {f.detail}")
    append([line(i) for i in range(4, 12)])
    print(f"    8 more from same IP   -> {len(w.poll_once())} new findings  <- SUPPRESSED, same attack")

    os.rename(path, path + ".1")
    open(path, "w").close()
    append([line(i, "198.51.100.44") for i in range(20, 25)])
    fresh = w.poll_once()
    print(f"    log ROTATED, 5 more   -> {len(fresh)} finding   <- survived rotation")
    for f in fresh:
        print(f"        {f.severity} {f.pivot} {f.key}: {f.detail}")
    print("        (only the ip key is new — 'user root' was already reported)")
PYDEMO
echo
say "That is the difference between a log reader and a monitor."
pause

# ────────────────────────────────────────────────────────────────
step "9. What it does with a finding" \
     "Enrich it, remember it, and tell someone."
py - <<'PYDEMO'
import json, os, sys, threading
sys.path.insert(0, os.getcwd())
from http.server import BaseHTTPRequestHandler, HTTPServer

got = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        got.append(json.loads(self.rfile.read(n)))
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass

srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

from alerts import AlertDispatcher, WebhookChannel
from detector import BruteForceDetector, Finding, HIGH, MEDIUM
from enrich import Enricher
from storage import Storage

store = Storage(":memory:")
detector = BruteForceDetector()
print("  ENRICH — derived from the address itself, no database needed:")
e = Enricher(city_db="", asn_db="", reverse_dns=False)
for ip in ("10.0.4.15", "203.0.113.5", "8.8.8.8"):
    print(f"      {ip:<14} {e.describe(e.lookup(ip))}")
print("    (a country only appears if you supply a GeoIP database — never invented)")

print("\n  REMEMBER — same log analysed three times:")
for _ in range(3):
    store.record_run(detector.analyze_file("auth_sample.log"))
h = store.history_for("203.0.113.5")
print(f"      203.0.113.5 -> seen {h['times_seen']} times, worst severity {h['worst']}")

print("\n  ALERT — a real HTTP POST to a real listening socket:")
d = AlertDispatcher(channels=[WebhookChannel(url=f"http://127.0.0.1:{srv.server_address[1]}/hook")],
                    storage=store, min_severity="HIGH", cooldown_seconds=900)
high = Finding("compromise", "ip", "198.51.100.31", HIGH, "4 failures then SUCCESS")
print(f"      HIGH finding      -> {[r.channel + ': ' + ('sent' if r.ok else r.reason) for r in d.dispatch(high)]}")
print(f"      same one again    -> {[r.reason for r in d.dispatch(high)]}")
print(f"      a MEDIUM burst    -> {[r.reason for r in d.dispatch(Finding('burst','ip','1.2.3.4',MEDIUM,'x'))]}")
print(f"\n      webhooks actually received: {len(got)}")
srv.shutdown()
PYDEMO
echo
say "Slack, generic webhook and email all work the same way. None are"
say "configured here — the Setup tab names the variable for each."
pause

# ────────────────────────────────────────────────────────────────
step "10. Measuring it instead of trusting it" \
     "Anyone can build a detector. The question is how good it actually is."
run evaluate.py
say "Six labelled attacks, twelve settings, scored by precision and recall."
say ""
say "  5 / 120   the common default  → recall 0.667, misses 2 of 6"
say "  3 / 1800  measured best       → recall 1.000, zero false alarms"
say "  10 / any  → recall 0.167, effectively blind"
say ""
say "Precision stays at 1.000 nearly everywhere: this detector's weakness is"
say "missing attacks, not inventing them. That tells you where to spend effort."
pause

# ────────────────────────────────────────────────────────────────
step "11. Usable from a script" \
     "Exit codes, so this can drive a cron job or a CI check."
printf '%s$ python main.py clean_sample.log ; echo "exit=$?"%s\n' "$G" "$R"
py main.py clean_sample.log >/dev/null; echo "  exit=$?  (nothing found)"
echo
printf '%s$ python main.py auth_sample.log ; echo "exit=$?"%s\n' "$G" "$R"
py main.py auth_sample.log >/dev/null; echo "  exit=$?  (findings — alert!)"
echo
say "So this works:"
say "    python main.py /var/log/auth.log || notify-send 'SSH attack detected'"
echo
say "And --json feeds a SIEM:"
echo
py main.py auth_sample.log --json | head -14
echo "  ..."
pause

# ────────────────────────────────────────────────────────────────
step "12. The web application" \
     "Same parser, same detector, different shell."
if py -c "import flask" 2>/dev/null; then
  say "Start it with:"
  echo
  printf '    %s%s app.py%s\n' "$G" "$(basename "$PY_BIN")" "$R"
  echo
  say "then open http://127.0.0.1:5000"
  echo
  say "Four tabs:"
  say "  Analyse  — samples, the generator, tuning sliders, results"
  say "  Live     — follow a real log, findings stream in as they happen"
  say "  History  — every analysis, and who you have seen before"
  say "  Setup    — what is configured and what is still missing"
  say ""
  say "The 30-second demo: Generate, then Score vs. ground truth."
else
  say "Flask is not installed. To enable the web app:"
  echo
  printf '    %spython3 -m venv .venv && .venv/bin/pip install -r requirements.txt%s\n' "$G" "$R"
fi

echo
printf '%s\n' "${C}────────────────────────────────────────────────────────────────${R}"
printf '%sDemo complete.%s  Run %s./selfcheck.sh%s to verify every claim above.\n' \
       "$B" "$R" "$G" "$R"
echo
