# How to demo this

Three steps. Copy-paste each block.

---

## Step 0 — one-time setup

```bash
cd "/Users/jaswanth/Vanitha/BruteForce Project/brute_force_log_analyzer"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The quotes around the path matter — `BruteForce Project` has a space in it.

---

## Step 1 — prove it works (15 seconds)

```bash
./selfcheck.sh
```

42 checks across every layer. Each prints ✓ or ✗, so a failure tells you
*which* part broke. Exits `0` only if all pass.

```
Detection core
  ✓ clean log produces no findings
  ✓ attack log flags the compromise as HIGH
  ✓ low-and-slow MISSED at the default 5/120
  ✓ low-and-slow CAUGHT when tuned to 3/1800
Log generator
  ✓ detector finds 6/6 planted attacks at 4/600
  ✓ threshold 3 drowns in background scanning
Alert delivery (real HTTP, not mocked)
  ✓ webhook actually POSTs a HIGH finding
Live monitoring (real file, real appends, real rotation)
  ✓ fires exactly when the threshold is crossed
  ✓ survives log rotation
...
42 passed
```

---

## Step 2 — the web app

```bash
PORT=5055 python app.py
```

Then open **http://127.0.0.1:5055**

> **Why not port 5000?** On macOS, port 5000 is taken by AirPlay Receiver
> (Control Center). Either use `PORT=5055` as above, or turn AirPlay
> Receiver off in System Settings → General → AirDrop & Handoff.

On startup it prints exactly what is and isn't configured:

```
 * Persistence : .../bfla.db
 * Geo lookup  : no database configured
 * Alerting    : no channel configured
 * Live watch  : no BFLA_WATCH_PATH set
```

### The 30-second demo

On the **Analyse** tab:

1. Click **Generate** — builds ~1100 lines of a realistic day: staff logins,
   sudo, sessions, disconnects, internet background scanning, with 6 attacks
   buried inside. It lists what it planted.
2. Click **Score vs. ground truth** — the detector was told none of it.

```
caught 6/6    0 false alarms    precision 1.000    recall 1.000
  FOUND   fast burst on root
  FOUND   rsyslog-collapsed flood on admin
  FOUND   low-and-slow on ubuntu
  FOUND   distributed botnet on test
  FOUND   password spray
  FOUND   COMPROMISE — enumeration then success
```

3. Now drag **Failure threshold** to 5 and **Time window** to 120 — the
   textbook default — and score again. It drops to 5/6. The default misses
   the slow attacker.

That contrast is the whole project in one screen.

### Also worth clicking

- **Clean traffic** sample → zero findings. It contains a user who mistyped
  their password then logged in — the exact shape of a breach. Staying quiet
  on that matters more than catching things.
- **Real-world noise** sample → look at **Skipped: 5**. Those are disconnect
  and sudo lines that a naive parser turns into fake events. And the 9
  failures came from *one* line, because rsyslog collapses repeats.

---

## Step 3 — live monitoring

This is the part that makes it a monitor rather than a log reader.

**Terminal 1** — the app is already running from Step 2.

**Terminal 2:**

```bash
cd "/Users/jaswanth/Vanitha/BruteForce Project/brute_force_log_analyzer"
./simulate_attack.sh
```

It writes SSH log lines to `/tmp/demo_auth.log`, slowly, over about 30 seconds.

**In the browser**, before running it:

1. Go to the **Live monitor** tab
2. Put `/tmp/demo_auth.log` in the log path box
3. Set threshold **4**, window **600**
4. Press **Start**
5. Now run `./simulate_attack.sh` in Terminal 2 and watch

What you will see, in order:

| Simulator stage | What the page does |
|---|---|
| Normal logins | Activity feed ticks. No findings. |
| 3 slow failures | Still nothing — below the threshold. |
| 4th failure lands | **MEDIUM fires immediately** for the IP and the username. |
| 4 usernames tried, then a success | **HIGH fires** — an actual breach. |

Verified output from that simulation:

```
FIRED  MEDIUM ip    203.0.113.66     4 failures in 6s, 4 total
FIRED  MEDIUM user  root             4 failures in 6s, 4 total
FIRED  MEDIUM ip    198.51.100.42    4 failures in 3s, 4 total
FIRED  HIGH   ip    198.51.100.42    4 failure(s) across 4 usernames
                                     then SUCCESS as user jaswanth
```

### Watching your own machine instead

macOS has no plain-text sshd log, so export one first:

```bash
log show --predicate 'process == "sshd"' --last 6h > /tmp/mac_auth.log
```

On Linux, point it straight at `/var/log/auth.log`.

---

## Terminal-only tour

No browser needed:

```bash
./demo.sh          # 12 guided steps, Enter to advance
./demo.sh --fast   # straight through
```

Or the individual pieces:

```bash
python main.py auth_sample.log                    # analyse a file
python main.py evasion_sample.log -t 3 -w 1800    # retune it
python generate_log.py --seed 42 --verify         # generate + score
python evaluate.py --realistic                    # the tuning sweep
```

---

## If something goes wrong

| Symptom | Fix |
|---|---|
| `Address already in use` | Port 5000 is AirPlay. Use `PORT=5055 python app.py` |
| `command not found: python` | Use `python3`, or activate the venv first |
| Buttons do nothing | Hard-refresh: Cmd+Shift+R. `./selfcheck.sh` covers the template/JS wiring |
| "Could not reach the server" | `app.py` isn't running, or you're on the wrong port |
| Live tab: "No log path to follow" | Type a path in the box, or set `BFLA_WATCH_PATH` |
| Findings differ from the CLI | Check the sliders match your CLI flags — same code underneath |

---

## What is deliberately not configured

The **Setup** tab lists these live, and names the variable for each:

| Feature | Variable | Where to get it |
|---|---|---|
| Live monitoring default path | `BFLA_WATCH_PATH` | Your log file |
| Slack alerts | `BFLA_SLACK_WEBHOOK_URL` | Slack app → Incoming Webhooks |
| Webhook alerts | `BFLA_WEBHOOK_URL` | Any endpoint taking JSON |
| Email alerts | `BFLA_SMTP_HOST`, `BFLA_MAIL_FROM`, `BFLA_MAIL_TO` | Your mail server |
| Country + network operator | `BFLA_GEOIP_CITY_DB`, `BFLA_GEOIP_ASN_DB` | Free GeoLite2 files, maxmind.com |

Copy `.env.example` to `.env` and fill in what you want. Blank means the
feature is off and says so — nothing is faked. Without a GeoIP database,
addresses are still classified (private / documentation / public) from the
address itself; no location is ever invented.
