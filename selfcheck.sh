#!/usr/bin/env bash
# selfcheck.sh — one command that answers "is this thing actually working?"
#
#   ./selfcheck.sh
#
# Checks each piece independently and prints PASS/FAIL per line, so a failure
# tells you WHICH part broke rather than just that something did.

set -uo pipefail
cd "$(dirname "$0")"
HERE="$PWD"

# Absolute, and always called through py() so a space in the path (this
# project lives under "BruteForce Project") cannot split it into two words.
PY_BIN="$(command -v python3)"
[ -x "$HERE/.venv/bin/python" ] && PY_BIN="$HERE/.venv/bin/python"
py() { "$PY_BIN" "$@"; }
export PY_BIN

pass=0; fail=0
report() {
  if [ "$1" -eq 0 ]; then
    printf '  \033[32m✓\033[0m %s\n' "$2"; pass=$((pass+1))
  else
    printf '  \033[31m✗\033[0m %s\n' "$2"; fail=$((fail+1))
    [ -n "${3:-}" ] && printf '%s\n' "$3" | tail -4 | sed 's/^/      /'
  fi
}

# Assert the tool's output contains a string.
#
# Output is captured before grepping rather than piped into it: main.py
# deliberately exits 1 when it finds something, and under `set -o pipefail` a
# pipeline inherits that failure even when grep matched — which would report
# every successful detection as a broken check.
expect() {
  local label="$1" needle="$2"; shift 2
  local out; out="$(py "$@" 2>&1)"
  printf '%s' "$out" | grep -qF -- "$needle"
  report "$?" "$label" "$out"
}

# Assert the tool's output does NOT contain a string.
expect_absent() {
  local label="$1" needle="$2"; shift 2
  local out; out="$(py "$@" 2>&1)"
  if printf '%s' "$out" | grep -qF -- "$needle"; then
    report 1 "$label" "$out"
  else
    report 0 "$label"
  fi
}

# Assert the tool exits with a specific code.
expect_exit() {
  local label="$1" want="$2"; shift 2
  local out; out="$(py "$@" 2>&1)"; local got=$?
  [ "$got" -eq "$want" ]
  report "$?" "$label (wanted $want, got $got)" "$out"
}

# Assert an inline Python snippet runs without raising.
expect_py() {
  local label="$1" code="$2"
  local out; out="$(py -c "$code" 2>&1)"
  report "$?" "$label" "$out"
}

echo
echo "Brute Force Log Analyzer — self check"
echo "  interpreter: $(py --version 2>&1)"
echo "  directory:   $HERE"
echo

echo "Detection core"
expect "clean log produces no findings" \
       "No threats detected" main.py clean_sample.log
expect "attack log flags the compromise as HIGH" \
       "[HIGH  ] ip      203.0.113.5" main.py auth_sample.log
expect "attack log flags the burst from 192.168.1.5" \
       "192.168.1.5" main.py auth_sample.log
expect "rsyslog-collapsed burst counted as 9 attempts" \
       "9 failures" main.py noisy_sample.log
expect "non-login lines skipped, not parsed" \
       "5 unrecognised" main.py noisy_sample.log
expect_absent "low-and-slow MISSED at the default 5/120" \
       "203.0.113.50" main.py evasion_sample.log
expect "low-and-slow CAUGHT when tuned to 3/1800" \
       "203.0.113.50" main.py evasion_sample.log -t 3 -w 1800

echo
echo "Command line contract"
expect_exit "exit 0 on a clean log"      0 main.py clean_sample.log
expect_exit "exit 1 when findings exist" 1 main.py auth_sample.log
expect_exit "exit 2 on a missing file"   2 main.py no_such_file.log
expect_exit "exit 2 on a bad threshold"  2 main.py auth_sample.log -t abc
expect_py   "--json emits valid JSON" \
  "import json,subprocess,os
out = subprocess.run([os.environ['PY_BIN'], 'main.py', 'auth_sample.log', '--json'],
                     capture_output=True, text=True).stdout
assert json.loads(out)['findings']"
expect_py   "runs from another directory" \
  "import subprocess, os
r = subprocess.run([os.environ['PY_BIN'], os.path.join(os.getcwd(), 'main.py')],
                   cwd='/', capture_output=True, text=True)
assert 'auth_sample.log' in r.stdout, r.stdout + r.stderr"

echo
echo "Log generator (builds a fresh log, detector must find the attacks)"
expect_py "generates a full day of realistic traffic" \
  "from generate_log import build
text, attacks = build(hours=24, seed=42)
assert text.count(chr(10)) > 500, text.count(chr(10))
assert len(attacks) == 6, len(attacks)"
expect_py "log is mostly operational noise, as a real one is" \
  "from generate_log import build
from log_parser import LogParser
text, _ = build(hours=24, seed=42)
events, skipped = LogParser().parse_text(text)
assert skipped > 100, skipped"
expect_py "detector finds 6/6 planted attacks at 4/600" \
  "from generate_log import build
from detector import BruteForceDetector
text, attacks = build(hours=24, seed=42)
hits = {f.key for f in BruteForceDetector(threshold=4, window=600).analyze_text(text).findings}
caught = sum(1 for a in attacks if hits & a['keys'])
assert caught == len(attacks), f'{caught}/{len(attacks)}'"
expect_py "no false alarms at 4/600 across 3 generated days" \
  "from generate_log import build
from detector import BruteForceDetector
bad = 0
for seed in (42, 99, 7):
    text, attacks = build(hours=24, seed=seed)
    legit = set()
    for a in attacks: legit |= a['keys']
    f = BruteForceDetector(threshold=4, window=600).analyze_text(text).findings
    bad += sum(1 for x in f if x.key not in legit)
assert bad == 0, bad"
expect_py "threshold 3 drowns in background scanning (the real finding)" \
  "from generate_log import build
from detector import BruteForceDetector
text, attacks = build(hours=24, seed=42)
legit = set()
for a in attacks: legit |= a['keys']
f = BruteForceDetector(threshold=3, window=1800).analyze_text(text).findings
bad = sum(1 for x in f if x.key not in legit)
assert bad > 10, bad"

echo
echo "Persistence (SQLite)"
expect_py "records a run and its findings" \
  "from storage import Storage
from detector import BruteForceDetector
s = Storage(':memory:')
r = BruteForceDetector().analyze_file('auth_sample.log')
rid = s.record_run(r)
assert len(s.run_findings(rid)) == len(r.findings)
assert s.summary()['runs'] == 1"
expect_py "tracks repeat offenders across analyses" \
  "from storage import Storage
from detector import BruteForceDetector
s = Storage(':memory:')
d = BruteForceDetector()
for _ in range(3): s.record_run(d.analyze_file('auth_sample.log'))
h = s.history_for('203.0.113.5')
assert h['times_seen'] == 3, h['times_seen']
assert h['worst'] == 'HIGH'"

echo
echo "Enrichment (honest about what it does not know)"
expect_py "classifies addresses from the address itself" \
  "from enrich import classify
assert classify('10.0.4.15')['kind'] == 'private'
assert classify('203.0.113.5')['kind'] == 'documentation'
assert classify('8.8.8.8')['kind'] == 'public'
assert classify('nonsense')['kind'] == 'invalid'"
expect_py "invents no country when no GeoIP database is set" \
  "from enrich import Enricher
e = Enricher(city_db='', asn_db='', reverse_dns=False)
r = e.lookup('8.8.8.8')
assert 'country' not in r and 'asn' not in r, r
assert e.status['geo'] is False"

echo
echo "Alert delivery (real HTTP, not mocked)"
expect_py "webhook actually POSTs a HIGH finding" \
  "from test_alerts import Receiver
from alerts import AlertDispatcher, WebhookChannel
from detector import Finding, HIGH
with Receiver() as rx:
    d = AlertDispatcher(channels=[WebhookChannel(url=rx.url())], cooldown_seconds=0)
    res = d.dispatch(Finding('compromise','ip','198.51.100.31',HIGH,'x'))
    assert res[0].ok, res[0].reason
    assert len(rx.received) == 1
    assert rx.received[0]['body']['finding']['key'] == '198.51.100.31'"
expect_py "cooldown stops a repeat, severity floor stops MEDIUM" \
  "from test_alerts import Receiver
from alerts import AlertDispatcher, WebhookChannel
from detector import Finding, HIGH, MEDIUM
with Receiver() as rx:
    d = AlertDispatcher(channels=[WebhookChannel(url=rx.url())], cooldown_seconds=600)
    assert d.dispatch(Finding('c','ip','1.1.1.1',HIGH,'x'), now=1000)[0].ok
    assert d.dispatch(Finding('c','ip','1.1.1.1',HIGH,'x'), now=1100)[0].skipped
    assert d.dispatch(Finding('b','ip','2.2.2.2',MEDIUM,'x'), now=9999)[0].skipped
    assert len(rx.received) == 1, len(rx.received)"
expect_py "an unreachable channel is reported, never raised" \
  "from alerts import WebhookChannel
from detector import Finding, HIGH
r = WebhookChannel(url='http://127.0.0.1:1/dead', timeout=0.5).send(
        Finding('c','ip','1.1.1.1',HIGH,'x'))
assert not r.ok and r.reason"

echo
echo "Live monitoring (real file, real appends, real rotation)"
expect_py "fires exactly when the threshold is crossed" \
  "import os, tempfile
from watcher import LiveWatcher, WatchState
from detector import BruteForceDetector
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, 'auth.log'); open(p,'w').close()
    w = LiveWatcher(p, detector=BruteForceDetector(threshold=4, window=600))
    w._follower.open(from_end=False); w.state = WatchState.RUNNING
    def line(i): return f'Aug 24 10:00:0{i} h sshd[1]: Failed password for invalid user root from 203.0.113.9 port 1 ssh2'
    with open(p,'a') as f: f.write(chr(10).join(line(i) for i in range(3)) + chr(10))
    assert w.poll_once() == [], 'fired below threshold'
    with open(p,'a') as f: f.write(line(3) + chr(10))
    assert w.poll_once(), 'did not fire at threshold'"
expect_py "survives log rotation" \
  "import os, tempfile
from watcher import LiveWatcher, WatchState
from detector import BruteForceDetector
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, 'auth.log'); open(p,'w').close()
    w = LiveWatcher(p, detector=BruteForceDetector(threshold=4, window=600), repeat_after=0)
    w._follower.open(from_end=False); w.state = WatchState.RUNNING
    def line(i, ip): return f'Aug 24 10:00:{i:02d} h sshd[1]: Failed password for invalid user root from {ip} port 1 ssh2'
    with open(p,'a') as f: f.write(chr(10).join(line(i,'203.0.113.9') for i in range(5)) + chr(10))
    w.poll_once()
    os.rename(p, p + '.1'); open(p,'w').close()
    with open(p,'a') as f: f.write(chr(10).join(line(i,'198.51.100.4') for i in range(20,25)) + chr(10))
    keys = {f.key for f in w.poll_once()}
    assert '198.51.100.4' in keys, keys"
expect_py "a half-written line is held until it completes" \
  "import os, tempfile
from watcher import FileFollower
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, 'a.log'); open(p,'w').close()
    fo = FileFollower(p); fo.open(from_end=True)
    with open(p,'a') as f: f.write('half a li')
    assert fo.read_lines() == []
    with open(p,'a') as f: f.write('ne' + chr(10))
    assert fo.read_lines() == ['half a line']"

echo
echo "Sample log folder (demo data, clearly labelled as synthetic)"
expect_py "clean logs produce nothing at the recommended 4/600" \
  "import glob
from detector import BruteForceDetector
for p in sorted(glob.glob('logs/clean/*.log')):
    n = len(BruteForceDetector(threshold=4, window=600).analyze_file(p).findings)
    assert n == 0, f'{p} produced {n}'"
expect_py "every attack log is caught at some setting" \
  "import glob
from detector import BruteForceDetector
for p in sorted(glob.glob('logs/attacks/*.log')):
    hit = any(BruteForceDetector(threshold=t, window=w).analyze_file(p).findings
              for t in (3,4,5) for w in (120,600,1800,3600))
    assert hit, p"
expect_py "the breach log yields a HIGH finding" \
  "from detector import BruteForceDetector
r = BruteForceDetector(threshold=4, window=600).analyze_file('logs/attacks/02-successful-breach.log')
assert r.high_findings, r.findings"
expect_py "provenance is stated, not implied" \
  "import app
assert 'synthetic' in app.DATA_PROVENANCE.lower()
assert 'not captured from any real host' in app.DATA_PROVENANCE.lower()
import os; assert os.path.exists('logs/README.md')"

echo
echo "Allowlist (the detector was right and still wrong)"
expect_py "internal subnet finding is suppressed, and disclosed" \
  "from detector import BruteForceDetector
bare = BruteForceDetector(threshold=4, window=600).analyze_file('logs/tricky/busy-office.log')
allow = BruteForceDetector(threshold=4, window=600, allowlist=['10.0.0.0/8']).analyze_file('logs/tricky/busy-office.log')
assert len(allow.findings) < len(bare.findings), (len(bare.findings), len(allow.findings))
assert allow.suppressed, 'suppressed findings must still be reported'"
expect_py "a real attacker is not hidden by an internal allowlist" \
  "from detector import BruteForceDetector
r = BruteForceDetector(threshold=4, window=600, allowlist=['10.0.0.0/8']).analyze_file('logs/attacks/02-successful-breach.log')
assert r.high_findings, 'the breach must still fire'"
expect_py "a user mistyping their own password 4x is not a breach" \
  "from detector import BruteForceDetector
lines = [f'Jun 19 09:0{i}:00 h sshd[1]: Failed password for jaswanth from 10.0.4.11 port 40{i} ssh2' for i in range(4)]
lines.append('Jun 19 09:05:00 h sshd[1]: Accepted password for jaswanth from 10.0.4.11 port 4099 ssh2')
r = BruteForceDetector(threshold=99).analyze_text(chr(10).join(lines))
assert not [f for f in r.findings if f.severity == 'HIGH'], r.findings"
expect_py "enumeration then success still fires at two usernames" \
  "from detector import BruteForceDetector
lines = ['Jun 19 09:00:01 h sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2',
         'Jun 19 09:00:04 h sshd[1]: Failed password for oracle from 203.0.113.9 port 2 ssh2',
         'Jun 19 09:00:07 h sshd[1]: Accepted password for admin from 203.0.113.9 port 3 ssh2']
r = BruteForceDetector(threshold=99).analyze_text(chr(10).join(lines))
assert [f for f in r.findings if f.severity == 'HIGH'], r.findings"

echo
echo "HTML report"
expect_py "builds a self-contained document" \
  "import re
from detector import BruteForceDetector
from report import build_report
h = build_report(BruteForceDetector(threshold=4, window=600).analyze_file('auth_sample.log'))
assert h.lstrip().startswith('<!doctype html>')
assert '<script' not in h, 'report must not need javascript'
for pat in (r'<link[^>]+href=\"http', r'<img[^>]+src=\"http', r'@import'):
    assert re.search(pat, h) is None, pat"
expect_py "states where the data came from" \
  "from detector import BruteForceDetector
from report import build_report
r = BruteForceDetector().analyze_file('auth_sample.log')
assert 'Not captured from a real host' in build_report(r, source_kind='sample')
assert 'Supplied by the operator' in build_report(r, source_kind='upload')"
expect_py "escapes markup that came out of a log" \
  "from detector import BruteForceDetector
from report import build_report
lines = [f'Jun 19 09:15:0{i} h sshd[1]: Failed password for invalid user <script>alert(1)</script> from 9.9.9.9 port 50{i} ssh2' for i in range(6)]
h = build_report(BruteForceDetector(threshold=4, window=600).analyze_text(chr(10).join(lines)))
assert '<script>alert(1)</script>' not in h
assert '&lt;script&gt;' in h"

echo
echo "IP lookup (2 offline sources, 2 network sources, all opt-in)"
expect_py "offline classification needs no network at all" \
  "from enrich import Enricher
e = Enricher(city_db='', asn_db='', reverse_dns=False)
r = e.investigate('203.0.113.5', ['builtin'])
assert r['classification']['kind'] == 'documentation', r
assert 'TEST-NET' in r['summary']"
expect_py "online lookup refuses to send a private address offsite" \
  "from enrich import Enricher
r = Enricher().investigate('10.0.4.15', ['builtin', 'online'])
assert r['methods']['online']['ok'] is False
assert 'not sent' in r['methods']['online']['error']
assert r['methods']['online']['data'] == {}"
expect_py "online is never consulted unless asked for by name" \
  "from enrich import Enricher
r = Enricher().investigate('8.8.8.8', ['builtin'])
assert 'online' not in r['methods'], r['methods'].keys()"
expect_py "every method declares whether it leaves the machine" \
  "from enrich import Enricher
ps = {p['name']: p for p in Enricher().providers()}
assert ps['builtin']['sends_data_offsite'] is False
assert ps['maxmind']['sends_data_offsite'] is False
assert ps['rdns']['sends_data_offsite'] is False
assert ps['online']['sends_data_offsite'] is True"

echo
echo "Evaluation harness"
expect "best operating point is 3 / 1800" "threshold=3, window=1800s" evaluate.py
expect "reaches F1 = 1.000 on the sample set" "F1=1.000" evaluate.py

echo
echo "Test suite"
out="$(py -m unittest discover 2>&1)"; code=$?
report "$code" "$(printf '%s' "$out" | grep -oE 'Ran [0-9]+ tests' || echo 'tests')" "$out"

echo
echo "Web application"
if py -c "import flask" 2>/dev/null; then
  expect_py "app imports cleanly" "import app"
  expect_py "index page renders" \
    "import app; app.app.config['TESTING']=True
r = app.app.test_client().get('/')
assert r.status_code == 200 and b'Brute Force Log Analyzer' in r.data"
  expect_py "analyze API agrees with the CLI" \
    "import app; app.app.config['TESTING']=True
d = app.app.test_client().post('/api/analyze', json={'sample':'auth_sample.log'}).get_json()
assert d['stats']['high'] == 1, d['stats']
assert '203.0.113.5' in [f['key'] for f in d['findings']]"
  expect_py "tuning changes the outcome" \
    "import app; app.app.config['TESTING']=True
c = app.app.test_client()
lo = c.post('/api/analyze', json={'sample':'evasion_sample.log','threshold':5,'window':120}).get_json()
hi = c.post('/api/analyze', json={'sample':'evasion_sample.log','threshold':3,'window':1800}).get_json()
assert len(hi['findings']) > len(lo['findings'])"
  expect_py "path traversal refused" \
    "import app; app.app.config['TESTING']=True
r = app.app.test_client().get('/api/samples/..%2f..%2fetc%2fpasswd')
assert r.status_code in (404, 308), r.status_code"
  expect_py "generate + score against ground truth over HTTP" \
    "import app; app.app.config['TESTING']=True
c = app.app.test_client()
g = c.post('/api/generate', json={'hours':24,'seed':42}).get_json()
assert g['lines'] > 500 and len(g['planted']) == 6
v = c.post('/api/verify', json={'seed':42,'threshold':4,'window':600}).get_json()
assert v['caught'] == v['planted'], v
assert v['false_alarms'] == []"
  expect_py "sample cards report live-computed stats" \
    "import app; app.app.config['TESTING']=True
from detector import BruteForceDetector
from config import config
c = app.app.test_client()
d = BruteForceDetector(allowlist=config.allowlist)
for card in c.get('/api/samples').get_json()['samples']:
    r = d.analyze_file(app.sample_path(card['name']))
    assert card['events'] == len(r.events), card['name']
    assert card['findings'] == len(r.findings), card['name']
    assert card['high'] == len(r.high_findings), card['name']"
  expect_py "history records runs and repeat offenders" \
    "import app; app.app.config['TESTING']=True
c = app.app.test_client()
for _ in range(2): c.post('/api/analyze', json={'sample':'auth_sample.log'})
h = c.get('/api/history').get_json()
assert h['enabled'], h
assert h['summary']['runs'] >= 2
assert any(o['key'] == '203.0.113.5' for o in h['repeat_offenders'])"
  expect_py "config reports gaps and leaks no secrets" \
    "import json, app; app.app.config['TESTING']=True
d = app.app.test_client().get('/api/config').get_json()
body = json.dumps(d).lower()
for s in ('smtp_password', 'webhook_url', 'password'):
    assert f'\"{s}\":' not in body, s
assert all(g['variable'].startswith('BFLA_') for g in d['config']['missing'])"
  expect_py "live start/stop over HTTP on a real file" \
    "import os, tempfile, app; app.app.config['TESTING']=True
c = app.app.test_client()
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d,'auth.log'); open(p,'w').close()
    s = c.post('/api/live/start', json={'path':p,'threshold':4,'window':600}).get_json()
    assert s['running'], s
    with open(p,'a') as f:
        for i in range(5):
            f.write(f'Aug 24 10:00:0{i} h sshd[1]: Failed password for invalid user root from 203.0.113.9 port 1 ssh2' + chr(10))
    app.watcher.poll_once()
    snap = c.get('/api/live/snapshot').get_json()
    assert snap['findings'], snap
    assert not c.post('/api/live/stop').get_json()['running']"
  expect_py "uploaded file is analysed, reported and remembered" \
    "import io, app; app.app.config['TESTING']=True
c = app.app.test_client()
app.storage.reset()
raw = open('logs/attacks/02-successful-breach.log','rb').read()
d = c.post('/api/analyze', content_type='multipart/form-data',
           data={'logfile': (io.BytesIO(raw), 'my-server.log'),
                 'threshold':'4','window':'600'}).get_json()
assert d['source'] == 'my-server.log' and d['source_kind'] == 'upload'
assert d['stats']['high'] == 1, d['stats']
rep = c.post('/api/report', json={'text': raw.decode(), 'source':'my-server.log',
                                  'threshold':4,'window':600})
assert rep.status_code == 200 and b'Supplied by the operator' in rep.data
h = c.get('/api/history').get_json()
assert h['summary']['runs'] >= 1 and h['runs'][0]['source'] == 'my-server.log'"
  expect_py "clearing history really clears it" \
    "import app; app.app.config['TESTING']=True
c = app.app.test_client()
c.post('/api/analyze', json={'sample':'auth_sample.log'})
assert c.get('/api/history').get_json()['summary']['runs'] > 0
c.post('/api/history/reset')
h = c.get('/api/history').get_json()
assert h['summary']['runs'] == 0 and h['repeat_offenders'] == [] and h['runs'] == []"
  expect_py "lookup endpoint honours the chosen methods" \
    "import app; app.app.config['TESTING']=True
c = app.app.test_client()
d = c.post('/api/lookup', json={'ip':'10.0.4.15','methods':['builtin','online']}).get_json()
assert d['methods']['online']['ok'] is False
assert 'not sent' in d['methods']['online']['error']"
  expect_py "sample list states its provenance" \
    "import app; app.app.config['TESTING']=True
p = app.app.test_client().get('/api/samples').get_json()
assert 'synthetic' in p['provenance'].lower()
names = {s['name'] for s in p['samples']}
assert any(n.startswith('logs/attacks/') for n in names), names"
  expect_py "oversized upload rejected with 413" \
    "import io, app; app.app.config['TESTING']=True
big = io.BytesIO(b'x' * (app.config.max_upload_bytes + 1024))
r = app.app.test_client().post('/api/analyze', content_type='multipart/form-data',
                               data={'logfile': (big, 'huge.log')})
assert r.status_code == 413, r.status_code"
else
  echo "  - Flask not installed, web checks skipped"
  echo "    run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
fi

echo
echo "Docker"
if command -v docker >/dev/null 2>&1; then
  report 0 "docker CLI present (build with: docker compose up --build)"
else
  echo "  - docker not installed, skipped"
fi

echo
printf '%s passed' "$pass"
[ "$fail" -gt 0 ] && printf ', \033[31m%s failed\033[0m' "$fail"
echo; echo
[ "$fail" -eq 0 ]
