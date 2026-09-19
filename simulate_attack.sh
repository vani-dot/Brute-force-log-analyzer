#!/usr/bin/env bash
# simulate_attack.sh — writes SSH log lines to a file, slowly, so you can
# watch the Live tab detect an attack as it happens.
#
#   ./simulate_attack.sh                    -> writes to /tmp/demo_auth.log
#   ./simulate_attack.sh /tmp/my.log        -> writes wherever you say
#
# Point the Live tab at the same file, press Start, then run this.

set -u
LOG="${1:-/tmp/demo_auth.log}"
: > "$LOG"

HOST=demo-server
say() { printf '\033[36m%s\033[0m\n' "$1"; }
line() { printf '%s %s sshd[%d]: %s\n' "$(date '+%b %e %H:%M:%S')" "$HOST" "$RANDOM" "$1" >> "$LOG"; }

fail()    { line "Failed password for invalid user $1 from $2 port $((RANDOM % 30000 + 30000)) ssh2"; }
ok()      { line "Accepted password for $1 from $2 port $((RANDOM % 30000 + 30000)) ssh2"; }
noise()   { line "Received disconnect from $1 port $((RANDOM % 30000 + 30000)):11: Bye Bye [preauth]"; }

say "Writing to $LOG"
say "Point the Live tab at that path, press Start, then watch."
echo

say "[1/4] Normal traffic — nothing should fire"
for u in deploy alice backup; do ok "$u" "10.0.4.$((RANDOM % 40 + 10))"; sleep 1; done
noise "203.0.113.$((RANDOM % 200 + 20))"; sleep 2

say "[2/4] A slow trickle — still under the threshold"
for i in 1 2 3; do fail root 203.0.113.66; sleep 2; done

say "[3/4] Crossing the threshold — this should FIRE"
for i in 4 5 6 7; do fail root 203.0.113.66; sleep 1; done
sleep 3

say "[4/4] Enumeration ending in a success — this is the HIGH one"
for u in admin oracle postgres ubuntu; do fail "$u" 198.51.100.42; sleep 1; done
ok jaswanth 198.51.100.42
sleep 2

echo
say "Done. $(wc -l < "$LOG" | tr -d ' ') lines written to $LOG"
