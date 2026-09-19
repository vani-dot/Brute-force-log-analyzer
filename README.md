# Brute Force Log Analyzer

Detects SSH password-guessing attacks in authentication logs — including three
attack patterns that simple failure-counting misses entirely.

Runs three ways, all on the same detection core:

| | Command | What it does |
|---|---|---|
| **Web app** | `python app.py` | Upload or generate a log, tune the detector, watch a live log |
| **CLI** | `python main.py auth.log` | One-shot analysis, exit code, JSON output |
| **Live monitor** | Live tab, or `BFLA_WATCH_PATH` | Follows a log as it is written and alerts in real time |

---

## Start here

```bash
cd brute_force_log_analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

./selfcheck.sh        # 42 checks — proves every part works
python app.py         # http://127.0.0.1:5000
```

Or with Docker, no venv needed:

```bash
docker compose up --build
```

### See it work in 30 seconds

In the web app: **Generate** → **Score vs. ground truth**.

The generator writes a full day of realistic traffic — staff logins,
operational noise, internet background scanning — and buries six attacks in
it. The detector is told nothing about them. The score panel then shows
exactly which it found and which it missed.

---

## The three things this does that a failure counter does not

**1. It measures breaches, not attempts.** A burst check alerts loudly on an
attacker who tried five times and failed, while staying silent on one who
tried three times and got in. Correlating failures with the success that
follows them fixes that inversion.

**2. It pivots the grouping key.** Counting per-IP is trivially evaded. The
same sliding window, grouped by username or by /24 subnet instead, catches
password spraying and botnets that never cross a per-IP threshold.

**3. It measures its own accuracy.** `evaluate.py` scores the detector against
labelled attacks at twelve settings and reports precision, recall and F1 — so
the tuning is chosen from evidence rather than inherited from a tutorial.

---

## What is optional, and what it needs from you

Everything below is off until you supply a value. Nothing fakes it — the
**Setup** tab shows each feature as ready or not configured, and names the
variable that would switch it on.

| Feature | Set this | Where to get it |
|---|---|---|
| Live log monitoring | `BFLA_WATCH_PATH` | Path to your log, e.g. `/var/log/auth.log` |
| Slack alerts | `BFLA_SLACK_WEBHOOK_URL` | Slack app → Incoming Webhooks |
| Webhook alerts | `BFLA_WEBHOOK_URL` | Any endpoint that accepts JSON |
| Email alerts | `BFLA_SMTP_HOST`, `BFLA_MAIL_FROM`, `BFLA_MAIL_TO` | Your mail server |
| Country + network operator | `BFLA_GEOIP_CITY_DB`, `BFLA_GEOIP_ASN_DB` | Free GeoLite2 `.mmdb` files from maxmind.com |

Copy `.env.example` to `.env` and fill in what you want. Without a GeoIP
database, addresses are still classified — private, documentation, public —
from the address itself. No location is ever invented.

**Persistence works out of the box.** Every analysis is recorded to SQLite, so
the **History** tab can answer "have I seen this address before?"

---

## The problem

A server records every login attempt in `/var/log/auth.log`:

```
Jun 19 09:15:01 server sshd[1004]: Failed password for invalid user admin from 192.168.1.5 port 51234 ssh2
```

Many failures in a short time from one source means somebody is guessing passwords. Finding that by eye across thousands of lines is impractical — hence this tool.

## How it works

```
[ Log file  /  upload  /  pasted text ]
                  |
                  v
        LogParser.parse_lines()
                  |
                  v
     [ LogEvent: timestamp, ip, user, result ]
                  |
                  v
     BruteForceDetector.analyze()
       |                        |
       v                        v
[ group by ip / user / subnet ]  [ failures ending in SUCCESS? ]
       |                        |
       v                        |
[ slide a window:               |
  N failures within T seconds? ]|
       |                        |
       +----------+-------------+
                  v
          [ AnalysisResult ]
             /          \
    print_report()    to_dict() -> JSON -> browser
```

`LogParser` understands log syntax. `BruteForceDetector` understands attacks. `main.py` and `app.py` are thin shells that wire them to a terminal or a browser respectively — neither owns any detection logic.

## Detection strategies

The tool runs four checks over every log:

| Check | Catches |
|---|---|
| **Compromise** — enough failures, or failures across several usernames, followed by a success from the same IP | An attack that actually **worked** |
| **Burst by IP** | Classic brute force from a single machine |
| **Burst by username** | Password spraying, and many machines targeting one account |
| **Burst by /24 subnet** | Botnets whose individual IPs each stay under the threshold |

The compromise check matters most. Counting failures only ever measures *attempts*; a failure sequence ending in `Accepted` is a **breach**. In the sample log, `203.0.113.5` fails against `root`, `oracle` and `admin` in nine seconds and is then accepted as `admin` — three attempts, well under any sane burst threshold. A naive counter ignores it completely while alerting loudly on an attacker who tried five times and never got in.

The hard part is not spotting that shape, it is **not** firing on the far more common one: a legitimate user mistyping their own password and then logging in. That is also "failure then success from the same IP". Two rules separate them:

1. **At least three failures** before the success. One or two fumbles on a single account is a typo, not an incident.
2. **Or failures against two or more different usernames**, however few. Nobody mistypes their own login three different ways — that is account enumeration, and a success on the back of it is worse than a burst regardless of how few attempts it took.

`clean_sample.log` contains exactly that typo case (`jaswanth` fails once at 10:12:03, succeeds at 10:12:19) and must stay silent.

Grouping by username and subnet exists because per-IP counting is trivially evaded. A botnet spreading eight attempts across eight addresses, or a spray trying one password against many accounts, never crosses a per-IP threshold — but is obvious the moment you pivot the grouping key.

## Project structure

```
brute_force_log_analyzer/
│
│  detection core — no I/O, no framework
├── log_parser.py        # LogEvent, LogParser — log syntax only
├── detector.py          # Finding, AnalysisResult, BruteForceDetector
│
│  the shells around it
├── main.py              # CLI
├── app.py               # Flask web app + JSON API
├── templates/index.html # Single page UI, four tabs
├── static/app.js        # No dependencies, no build step
├── static/style.css     # No framework
│
│  the optional layers
├── config.py            # One place for every setting; blanks stay blank
├── storage.py           # SQLite history — runs, findings, repeat offenders
├── enrich.py            # Address classification, and GeoIP if you supply it
├── alerts.py            # Slack / webhook / email delivery
├── watcher.py           # Live tail: follow a log, detect as it is written
│
│  proving it works
├── generate_log.py      # Builds a realistic log with attacks planted in it
├── evaluate.py          # Scores the detector against labelled attacks
├── selfcheck.sh         # 42 checks across every layer
├── demo.sh              # Guided tour
├── test_*.py            # 248 tests
│
│  sample data
├── auth_sample.log      # A burst and a successful compromise
├── clean_sample.log     # Normal traffic and a typo — zero alerts expected
├── evasion_sample.log   # Low-and-slow, botnet, password spray
├── noisy_sample.log     # Real-world noise, rsyslog-collapsed burst
│
│  deployment
├── Dockerfile           # Non-root, gunicorn, healthcheck
├── docker-compose.yml
└── .env.example         # Every setting, documented, blank
```

It is `log_parser.py` rather than `parser.py` because `parser` was a standard library module up to Python 3.9, and shadowing a stdlib name is a trap worth avoiding.

### The object model

| Class | Responsibility |
|---|---|
| `LogEvent` | One authentication attempt. Knows `is_failure`, `is_success`, `subnet` |
| `LogParser` | Syslog/sshd line syntax → `LogEvent`s. Holds no per-file state |
| `Finding` | One alert, with the evidence behind it |
| `AnalysisResult` | Everything one run produced: events, stats, findings, chart data |
| `BruteForceDetector` | Holds the tuning, runs every strategy |

The detector takes its tuning in the constructor rather than as arguments to every call, so a configured detector can be handed around and reused. `AnalysisResult.to_dict()` is what the web app serialises — the browser gets exactly the numbers the terminal prints.

Thin module-level functions (`parse_line`, `analyze_log`, `find_bursts`, …) wrap the classes for callers that do not need an object.

---

## Checking it works

```bash
./selfcheck.sh     # 22 checks across every layer, exits 0 if all pass
./demo.sh          # guided 8-step tour of what the tool catches and why
./demo.sh --fast   # same, without the pauses
```

See [DEMO.md](DEMO.md) for a click-by-click walkthrough of the web app.

## Running the web app

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

- **Load a sample** with one click, or **paste** log lines, or **drag a log file** onto the box
- **Drag the sliders** for threshold, window and compromise sensitivity — results re-analyse instantly, so you can watch an attack appear and disappear as you tune
- **Findings** are ranked worst-first with severity badges and the pivot that caught them
- **Failures over time** and **top sources** are plain HTML/CSS bars — no charting library, no CDN, nothing to install

The `Use tuned preset` button jumps to `3 / 1800`, the operating point `evaluate.py` scores best.

### HTTP API

| Route | Purpose |
|---|---|
| `GET /` | The UI |
| `GET /api/samples` | Names and descriptions of the bundled logs |
| `GET /api/samples/<name>` | Raw text of one bundled log |
| `POST /api/analyze` | Analyse pasted text, a named sample, or an uploaded file |

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"sample": "auth_sample.log", "threshold": 5, "window": 120}'
```

The web layer owns HTTP concerns only. It parses nothing and detects nothing itself.

### What the web layer has to handle that the CLI does not

A CLI takes input from its operator. A web app takes it from strangers, so `app.py` adds:

- **Upload cap** of 5 MB, returning `413` rather than exhausting memory
- **Tuning clamped, not trusted** — a threshold of `0` alerts on everything and a window of a century is not a useful question, so both are forced into range instead of rejected
- **Sample lookup is a whitelist membership test**, not a path join on user input, so `../../etc/passwd` cannot escape the project directory
- **Output escaping in the browser** — a username in a log line is attacker-controlled and can contain `<script>`. Every interpolation of log data in `app.js` goes through `esc()`, and a test enforces it
- **Invalid UTF-8 decoded with `errors="replace"`** rather than crashing on a malformed byte

## Running the CLI

Requires Python 3.6+. No dependencies (Flask is only needed for the web app).

```bash
python main.py                                   # defaults to auth_sample.log
python main.py clean_sample.log                  # analyse any file
python main.py evasion_sample.log -t 3 -w 1800   # custom threshold and window
python main.py auth_sample.log --json            # machine-readable output
python main.py --help
python evaluate.py                               # run the evaluation harness
```

`-t/--threshold` and `-w/--window` default to `5` failures in `120` seconds. Bundled sample logs resolve relative to the script, so the tool works from any directory.

### Exit codes

The tool is meant to be usable from a script or a cron job, which only works if the exit code is honest about what it found:

| Code | Meaning |
|---|---|
| `0` | No findings |
| `1` | At least one finding |
| `2` | Could not run — missing file, bad arguments |

```bash
python main.py /var/log/auth.log || notify-send "SSH attack detected"
```

## Tests

248 tests using `unittest` from the standard library:

```bash
python -m unittest discover -v
```

```
Ran 248 tests in 5.9s

OK
```

The web tests skip themselves cleanly if Flask is not installed, so the suite
still runs on a bare Python.

`./selfcheck.sh` is the faster answer to "does it work?" — 42 checks across
the detector, the CLI contract, the generator, persistence, enrichment, alert
delivery, live monitoring, and every HTTP route. Each prints ✓ or ✗ so a
failure says *which* layer broke.

Coverage includes time arithmetic, field extraction from both log line shapes, every category of line that is *not* a login attempt, sliding-window boundaries (exactly at the threshold fires, one second beyond does not), compromise detection including its negative cases, alert deduplication, exit codes, argument validation, and the web layer's routing and abuse cases.

Two tests are worth calling out:

- **`test_every_id_app_js_looks_up_exists_in_the_page`** renders the template, extracts every element id `app.js` reaches for, and asserts the page defines it. This catches the classic front-end bug where a renamed id makes one control silently bind to `null` and do nothing.
- **`TestKnownLimitations`** asserts the *current* behaviour of the leap-year and year-boundary bugs, so that if anyone fixes them the suite fails loudly and the limitations section below can be updated.

Regression tests guard each of the original bugs — same-time-different-day comparison, midnight rollover, crashing on lines without `from`, misreading reconnaissance attempts as successful logins, phantom events from disconnect notices, rsyslog-collapsed bursts, and the typo-as-compromise false positive.

## Sample output

Attack log — the compromise is ranked above the burst:

```
========================================================================
Log:     auth_sample.log
Events:  13 parsed, 0 unrecognised line(s) skipped
========================================================================
[HIGH  ] ip      203.0.113.5        3 failure(s) across 3 usernames then SUCCESS as user admin at 09:02:14
[MEDIUM] ip      192.168.1.5        5 failures in 12s (09:15:01 to 09:15:13), 5 total
[MEDIUM] user    admin              5 failures in 12s (09:15:01 to 09:15:13), 6 total
------------------------------------------------------------------------
3 finding(s).
```

Clean log, including the mistyped password:

```
Log:     clean_sample.log
Events:  8 parsed, 0 unrecognised line(s) skipped
No threats detected.
```

Real-world noise — five lines correctly rejected as non-events, and one `message repeated 9 times` line correctly counted as nine attempts:

```
========================================================================
Log:     noisy_sample.log
Events:  10 parsed, 5 unrecognised line(s) skipped
========================================================================
[MEDIUM] ip      203.0.113.200      9 failures in 0s (03:01:00 to 03:01:00), 9 total
[MEDIUM] user    root               9 failures in 0s (03:01:00 to 03:01:00), 9 total
```

Evasion log, tuned to catch slower attacks:

```
$ python main.py evasion_sample.log -t 3 -w 1800

[MEDIUM] ip      203.0.113.50       6 failures in 1800s (09:00:00 to 09:30:00), 8 total
[MEDIUM] ip      198.51.100.77      4 failures in 12s (11:00:01 to 11:00:13), 4 total
[MEDIUM] user    root               6 failures in 1800s (09:00:00 to 09:30:00), 8 total
[MEDIUM] user    admin              8 failures in 21s (10:00:01 to 10:00:22), 8 total
[MEDIUM] subnet  10.10.10.0/24      8 failures in 21s (10:00:01 to 10:00:22), 8 total
```

Note the low-and-slow attack surfacing under both `ip` and `user`, while the spray surfaces only under `ip` — different attack shapes reveal themselves through different pivots. Each alert reports the *true* size of the burst it found, not the threshold that tripped it.

## Evaluation

Building a detector is easy. Knowing how good it is requires labelled data and measurement, which is what `evaluate.py` provides. Every attack across the four sample logs is labelled as ground truth, and the detector is run at twelve threshold/window combinations:

```
Ground truth: 6 labelled attacks across 4 log files

threshold  window   caught  missed  false  precis  recall      F1
-----------------------------------------------------------------
        3     120      5/6       1      0   1.000   0.833   0.909
        3     600      5/6       1      0   1.000   0.833   0.909
        3    1800      6/6       0      0   1.000   1.000   1.000
        3    3600      6/6       0      1   0.857   1.000   0.923
        5     120      4/6       2      0   1.000   0.667   0.800
        5     600      4/6       2      0   1.000   0.667   0.800
        5    1800      5/6       1      0   1.000   0.833   0.909
        5    3600      5/6       1      0   1.000   0.833   0.909
       10     120      1/6       5      0   1.000   0.167   0.286
       10     600      1/6       5      0   1.000   0.167   0.286
       10    1800      1/6       5      0   1.000   0.167   0.286
       10    3600      1/6       5      0   1.000   0.167   0.286

Best operating point by F1: threshold=3, window=1800s
  caught 6/6 attacks with 0 false alarm(s), F1=1.000
```

Precision is *of everything we alerted on, how much was real*; recall is *of everything real, how much did we catch*; F1 is the harmonic mean, which punishes ignoring either. Ranking by F1 rather than raw catches matters — "most caught" alone would happily pick a setting that alerts on everything.

Four things this table shows:

1. **The common default of 5-in-120s catches only 4 of 6 attacks.** The settings most tutorials use are not the best ones.
2. **Widening the window helps until it doesn't.** At 1800s everything is caught cleanly; at 3600s precision drops to 0.857 as legitimate scattered traffic starts to look like a pattern. That boundary is the tuning trade-off made visible.
3. **A high threshold is nearly blind.** At 10, the only surviving detection is the compromise check — because that check doesn't depend on the threshold at all.
4. **Precision stays at 1.000 almost everywhere.** The detector's problem is missing attacks, not inventing them. That is the right failure mode to have, and it tells you to spend effort on recall.

### The small sample was lying, and the generator proved it

`threshold=3, window=1800` scores a perfect F1 = 1.000 on the four
hand-written samples above. Run the same sweep against five generated days of
realistic traffic and it falls apart:

```bash
python evaluate.py --realistic
```

```
REALISTIC CORPUS — 5 generated days, 30 planted attacks

threshold  window   caught  missed  false  precis  recall      F1
        3     300     30/30       0     45   0.400   1.000   0.571
        3    1800     30/30       0     80   0.273   1.000   0.429
        4     600     30/30       0      0   1.000   1.000   1.000   ← best
        5    1800     30/30       0      0   1.000   1.000   1.000
       10     120     25/30       5      0   1.000   0.833   0.909

Best operating point by F1: threshold=4, window=600s
```

At threshold 3 the detector raises **80 false alarms a day**. Not because the
logic is wrong, but because ordinary internet background scanning — one or two
probes from each of hundreds of addresses — accumulates past three. The
hand-written samples simply had no background traffic to trip over.

**The honest answer is 4 failures in 600 seconds**, and it took generating
realistic traffic to find out. This is what the small-sample caveat was
warning about, demonstrated rather than asserted.

Between thresholds 3 and 4 sits a cliff: 45 false alarms on one side, zero on
the other. That cliff is invisible on nine lines of hand-written log.

**Caveat that remains:** generated traffic is shaped from published
descriptions of SSH attack patterns, not captured from a real host. It is a
much better test than the hand-written samples and still not real data.
Validating against a honeypot capture is the next step.

## Known limitations

Stated deliberately — knowing where a detector breaks matters as much as knowing what it catches.

- **Year boundary.** Syslog does not record the year, so a log spanning 31 Dec to 1 Jan produces a negative time gap and the attack is missed.
- **Leap years.** Day-of-year arithmetic assumes a non-leap year, so 29 Feb and 1 Mar collapse to the same day.
- **Memory.** The whole log is loaded into a list, and the web app reads uploads fully into memory before parsing. Fine for the 5 MB cap; unsuitable for a multi-gigabyte production log without switching to streaming.
- **Collapsed timestamps.** An rsyslog `message repeated N times` line becomes N events sharing one timestamp, because the log does not record when the others happened. The burst therefore looks tighter than it was.
- **IPv4 only.** `LogEvent.subnet` assumes four dot-separated octets and returns IPv6 addresses ungrouped.
- **Synthetic data.** The tool has not been validated against real-world attack traffic.
- **No allowlisting.** A legitimate service with credential problems will alert repeatedly, with no way to suppress it.
- **Single user, no persistence.** The web app analyses and forgets. Nothing is stored, and there are no accounts — it is a local analysis tool, not a multi-tenant service.
- **Development server.** `app.py` runs Flask's built-in server with `debug=True`. Real deployment needs a WSGI server and debug off.

## Concepts demonstrated

File I/O and line-by-line parsing · string splitting and indexing · dictionaries for grouping · the sliding window algorithm · time arithmetic and normalisation · higher-order functions for pluggable grouping · object-oriented design with single-responsibility classes · separation of core logic from its interfaces · command line arguments and exit codes · REST API design · request validation and input clamping · output escaping and path-traversal defence · unit testing and boundary-condition tests · regression tests · detection tuning and evaluation against ground truth · precision, recall and F1

## Possible extensions

- Stream large files instead of loading them fully
- Validate against real honeypot data from an internet-exposed host
- Persist findings so the web app can show history and trends
- Push alerts to a SIEM, Slack, or email as they are found
- Compare results against `fail2ban` on identical input
- Risk scoring instead of binary alerting
