# Threshold-Based Detection of SSH Brute Force Attacks: Evasion Modes and Parameter Tuning

**Project Report**

---

## 1. Abstract

Secure Shell (SSH) services exposed to the internet are subjected to continuous automated password-guessing attacks. This project implements a log analysis tool in Python that reads SSH authentication logs, extracts structured events, and detects brute force activity using a sliding-window threshold over grouped failure events.

Beyond implementing the baseline detector, this work examines its weaknesses. Three attack patterns are shown to defeat conventional per-IP failure counting: low-and-slow guessing, distributed attacks from multiple addresses, and password spraying across many accounts. The detector is extended to counter these by pivoting the grouping key across IP address, username, and network subnet, and by correlating failure sequences that terminate in a successful login. A further class of defect is addressed at the parsing layer, where lines that are not authentication attempts were being admitted as events and rsyslog-collapsed repeat lines were being undercounted.

The detection core is exposed through two interfaces: a command-line tool and a web application, sharing the same parser and detector objects so that both report identical results. The system is evaluated against labelled data across twelve parameter configurations, scored by precision, recall, and F1. The commonly used setting of five failures within 120 seconds detected only four of six labelled attacks, while a threshold of three failures within 1800 seconds detected all six without false alarms (F1 = 1.000). The work concludes that detection parameters must be measured rather than assumed, and documents the residual limitations of the implementation.

**Keywords:** intrusion detection, brute force, SSH, log analysis, sliding window, password spraying, detection tuning

---

## 2. Introduction

### 2.1 Problem Statement

A server running SSH records every authentication attempt in a log file, typically `/var/log/auth.log`. A single line records the timestamp, the source IP address, the targeted username, and whether authentication succeeded:

```
Jun 19 09:15:01 server sshd[1004]: Failed password for invalid user admin from 192.168.1.5 port 51234 ssh2
```

An internet-facing host accumulates thousands of such entries daily, the majority of them hostile. Manual inspection is impractical. An automated tool is required to identify the specific pattern that indicates attack: repeated authentication failures, concentrated in time, originating from a common source.

### 2.2 Objectives

1. Parse unstructured SSH log lines into structured events comprising timestamp, source address, username, and outcome.
2. Detect brute force attacks using a sliding-window threshold over grouped failure events.
3. Identify attack patterns that evade the baseline approach, and extend the detector to counter them.
4. Measure detection accuracy against labelled ground truth and determine appropriate parameters empirically.
5. Document the residual limitations of the implementation.

### 2.3 Scope

The system analyses OpenSSH password-authentication log lines in standard syslog format, operating offline on stored log files supplied either as a command-line argument or through a web upload. Continuous real-time monitoring of a live log, automated response such as firewall blocking, key-based authentication events, and non-SSH services are outside the scope of this work.

---

## 3. Literature Survey

**`fail2ban`** is the established open-source tool in this domain. It monitors log files using regular expressions and inserts firewall rules to block offending addresses after a configurable number of failures within a time window. Its detection model is per-IP counting, which is the same baseline this project implements and then extends.

**Security Information and Event Management (SIEM)** platforms perform equivalent correlation at enterprise scale, aggregating logs from many hosts and applying rules across them. Their advantage over single-host tools is precisely the ability to correlate across sources, which is the capability the subnet and username pivots in this project imitate at small scale.

**The MITRE ATT&CK framework** catalogues brute force as technique T1110, with sub-techniques distinguishing password guessing (T1110.001), password spraying (T1110.003), and credential stuffing (T1110.004). This taxonomy directly informed the attack patterns used to test the detector in this work, as each sub-technique produces a measurably different signature in the log.

**Observed gap.** Published tutorial implementations of this class of tool consistently adopt threshold parameters without justification and are not evaluated against labelled data. Neither their false-negative rate against evasive attackers nor their false-positive rate against benign traffic is typically reported. This project addresses that gap.

---

## 4. System Analysis

### 4.1 Existing System

Manual log review, or a basic counter that groups failures by source IP and alerts above a fixed threshold. Limitations of this model:

- Counts only failures, therefore measuring attempts rather than outcomes; a successful compromise is not distinguished from a failed one.
- Grouping solely by IP address is defeated by any attacker distributing attempts across multiple addresses.
- A fixed time window is defeated by an attacker who simply waits between attempts.
- Threshold values are assumed rather than measured.
- Naive line handling admits non-authentication lines as events and reads an rsyslog-collapsed repeat line as a single attempt.
- Reporting is confined to a terminal, requiring the operator to be comfortable at a command line.

### 4.2 Proposed System

A modular analyser addressing each limitation:

| Limitation | Countermeasure |
|---|---|
| Failures counted, outcomes ignored | Correlate failure sequences ending in `Accepted` |
| Per-IP grouping evaded by distribution | Additionally group by username and by /24 subnet |
| Fixed window evaded by delay | Threshold and window configurable at runtime |
| Unjustified parameters | Evaluation harness scoring accuracy against labelled data |
| Spurious and undercounted events | Whitelist of authentication line forms; expansion of `message repeated N times` |
| False alarms on ordinary user error | Compromise correlation requires sufficient failures or evidence of username enumeration |
| Terminal-only reporting | Web application over the same detection core, with interactive parameter tuning |

### 4.3 System Requirements

**Software:** Python 3.6 or later. The command-line tool and evaluation harness use the standard library only (`argparse`, `json`, `os`, `sys`, `unittest`). The web application additionally requires Flask 3.0 or later; the test suite skips its web tests cleanly when Flask is absent.
**Hardware:** Any system capable of running Python. Memory proportional to log size, as events are held in a list. Web uploads are capped at 5 MB.
**Input:** OpenSSH authentication log in standard syslog format, supplied as a file path, an upload, or pasted text.

---

## 5. System Design

### 5.1 Architecture

```
   [ Log file ]   [ Upload ]   [ Pasted text ]
         \            |             /
          +-----------+------------+
                      v
        +--------------------------------+
        |  log_parser.LogParser          |  line -> LogEvent
        +--------------------------------+
                      v
        +--------------------------------+
        |  detector.BruteForceDetector   |  group -> slide window
        |                                |  -> Finding objects
        +--------------------------------+
                      v
        +--------------------------------+
        |  detector.AnalysisResult       |  events, stats, findings
        +--------------------------------+
             |          |            |
             v          v            v
      print_report  to_dict()   evaluate.py
        [main.py]   [app.py]     scoring
                       |
                       v
                 JSON -> browser
```

The two interfaces are shells. `main.py` renders an `AnalysisResult` to a terminal; `app.py` serialises the same object to JSON for a browser. Neither contains parsing or detection logic, which is why both necessarily agree.

### 5.2 Module Description

| Module | Responsibility |
|---|---|
| `log_parser.py` | `LogEvent` and `LogParser`. Converts a raw log line into a structured event; returns `None` for lines that are not authentication attempts |
| `detector.py` | `Finding`, `AnalysisResult`, `BruteForceDetector`. Groups events, applies the sliding window, correlates compromises, deduplicates and ranks findings |
| `main.py` | Command-line entry point; accepts log filename, threshold, window, and an optional JSON output mode; returns a meaningful exit code |
| `app.py` | Flask web application; HTTP routing, request validation, and JSON serialisation |
| `templates/`, `static/` | Single-page interface. No framework, no CDN, no build step |
| `evaluate.py` | Scores detection accuracy against labelled ground truth across parameter combinations |
| `test_parser.py`, `test_detector.py`, `test_main.py`, `test_app.py` | 117 unit tests |

The class model separates data from the code that acts on it:

| Class | Responsibility |
|---|---|
| `LogEvent` | One authentication attempt. Exposes `is_failure`, `is_success`, `subnet` |
| `LogParser` | Line syntax. Holds no per-file state, so one instance serves any number of inputs |
| `Finding` | One alert, carrying the evidence that produced it |
| `AnalysisResult` | The output of one run: events, statistics, findings, and chart data |
| `BruteForceDetector` | Holds the tuning; runs every detection strategy |

The detector receives its tuning through the constructor rather than as arguments to each call, so a configured detector can be passed between the CLI, the evaluation harness, and a web request handler unchanged.

### 5.3 Data Flow

Each line is classified against a whitelist of authentication line forms and, if recognised, parsed into a `LogEvent`. A line recording *N* collapsed repetitions expands into *N* events. Events failing authentication are grouped by a key function. A window of size *N* slides across each group; if *N* events span no more than *T* seconds, a finding is raised. Separately, every successful authentication is examined for preceding failures from the same address. Findings are deduplicated, ranked by severity, and reported.

### 5.4 Detection Strategies

| Strategy | Grouping key | Attack pattern detected |
|---|---|---|
| Compromise correlation | IP (all events) | An attack that succeeded |
| Burst detection | IP | Classic single-source brute force |
| Burst detection | Username | Password spraying; distributed attack on one account |
| Burst detection | /24 subnet | Botnet with per-address counts below threshold |

---

## 6. Implementation

The sliding window is the core algorithm. For a chronologically ordered group of failure events, a window of `threshold` entries advances one position at a time; if the elapsed time between the first and last entry of any window falls within `window` seconds, the group is reported.

```python
for i in range(len(group) - self.threshold + 1):
    j = i + self.threshold - 1
    if group[j].timestamp - group[i].timestamp > self.window:
        continue

    # widen to the true extent of the burst before reporting
    last = j
    while (last + 1 < len(group)
           and group[last + 1].timestamp - group[i].timestamp <= self.window):
        last += 1

    findings.append(Finding(...))
    break   # one alert per key is sufficient
```

The widening step exists because an alert should describe what occurred rather than restate its own trigger condition. Reporting "5 failures" when four hundred arrived inside the window discards the information an analyst most needs.

Complexity is O(n) for parsing and O(n × threshold) for windowing per group.

The grouping function is supplied by the caller rather than fixed, which allows one window implementation to serve all three pivots without duplication:

```python
pivots = [
    ("ip",     lambda e: e.ip),
    ("user",   lambda e: e.user),
    ("subnet", lambda e: e.subnet),
]
```

**Timestamp normalisation.** An initial implementation compared only the time-of-day portion of each entry. This caused entries on consecutive days at the same clock time to appear one second apart, and produced negative intervals across midnight. The corrected implementation folds the date into an absolute second count before comparison.

**Line classification.** An initial implementation accepted any line containing the token `from` and took the preceding word as the username. Applied to a real log, this admitted ordinary operational lines — `Received disconnect from 203.0.113.5 port 41223:11` — as authentication events attributed to a user named `disconnect`. Since such lines constitute the majority of a real `auth.log`, the event count was materially corrupted. The corrected implementation classifies against a whitelist of authentication line forms and rejects everything else.

**Collapsed repeat lines.** `rsyslog` folds consecutive identical lines into a single `message repeated N times: [ ... ]` summary. A brute force attack is precisely the traffic that triggers this folding, so reading such a line as one failure caused the attack it summarises to be missed entirely. The parser now recovers the wrapped line and the repetition count, and emits *N* events. All *N* carry the single timestamp the log recorded, since the log does not state when the intermediate attempts occurred; the burst therefore appears more compressed than it was, which is conservative with respect to detection.

**Compromise correlation.** For each successful authentication, preceding failures from the same address within a 600-second window are counted. A finding is raised where either at least three such failures are present, or the failures targeted two or more distinct usernames. This detection is independent of the burst threshold.

The threshold of three is not arbitrary. An initial implementation raised a HIGH severity finding on a single failure followed by a success, which is the exact signature of a legitimate user mistyping their own password — an event occurring many times daily on any multi-user host. The highest-severity alert in the system was therefore also its most frequent false positive. The alternative criterion, failures against multiple distinct usernames, admits genuinely brief attacks: a user may mistype a password repeatedly, but does not mistype their own username three different ways, so enumeration followed by success is reportable however few attempts it required.

**Alert deduplication.** Where a subnet finding covers an address that has already produced its own finding, the subnet finding is suppressed as redundant.

**Web application.** The web layer consists of four routes over the same detector objects:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Single-page interface |
| `/api/samples` | GET | Names and descriptions of bundled logs |
| `/api/samples/<name>` | GET | Raw text of one bundled log |
| `/api/analyze` | POST | Analyse pasted text, a named sample, or an uploaded file |

`AnalysisResult.to_dict()` produces the response body directly, so the browser receives precisely the figures the terminal prints. The interface supports file upload, drag-and-drop, and pasted text, and re-analyses on every change to a tuning control, allowing an attack to be watched appearing and disappearing as parameters move. Charts are rendered as proportionally sized HTML elements; no charting library, external stylesheet, or build step is used.

A web interface accepts input from unauthenticated strangers, which the command-line tool does not. Four consequences were addressed explicitly:

1. **Resource exhaustion.** Uploads are read into memory, so a 5 MB cap is enforced, returning HTTP 413 rather than failing.
2. **Parameter abuse.** Tuning values arriving from the browser are clamped into a permitted range rather than trusted or rejected; a threshold of zero would alert on every event, and an unbounded window is not a meaningful query.
3. **Path traversal.** Sample retrieval is a membership test against a fixed set of filenames, not a path join on user input, so a request for `../../etc/passwd` cannot escape the application directory.
4. **Cross-site scripting.** A username in a log line is attacker-controlled and may contain markup. The API returns it verbatim as JSON data, and every interpolation of log-derived text in the client script passes through an escaping function before reaching `innerHTML`. A test enforces this by inspecting the client source for unescaped interpolations of log-derived fields.

The last of these is the most easily overlooked. An attacker who can write to a monitored log can, in principle, choose the username that an analyst's browser will later render.

---

## 7. Testing

One hundred and seventeen unit tests were written using the `unittest` module. The twenty-nine tests covering the web layer use Flask's test client, requiring no running server or network access, and skip themselves when Flask is not installed so that the suite remains runnable on a bare Python installation.

| Category | Coverage |
|---|---|
| Field extraction | Both log line forms; timestamp, IP, username, result |
| Non-login lines | Blank, malformed, truncated, and non-authentication lines return `None` |
| Window boundaries | Exactly at threshold and window fires; one second beyond does not |
| Compromise correlation | Positive case and three negative cases |
| Deduplication | Subnet suppressed when its IP fired; retained when it did not |
| Non-authentication lines | Disconnect, connection-reset, session, and sudo lines rejected |
| Collapsed repeats | `message repeated N times` expanded to N events with the correct count |
| False positive control | A single mistyped password followed by a success raises nothing |
| Command-line interface | Argument validation, path resolution, JSON output, exit codes |
| Web routing | Every route, both upload paths, and the JSON contract |
| Web input validation | Oversized uploads, malformed tuning values, path traversal, invalid UTF-8 |
| Template wiring | Every element identifier `app.js` addresses is asserted present in the rendered page |
| Regression | One test per defect identified during development |
| Known limitations | Current behaviour of unfixed defects asserted deliberately |

```
Ran 117 tests in 0.024s

OK
```

Without Flask installed:

```
Ran 117 tests in 0.005s

OK (skipped=29)
```

The template wiring test merits specific mention. A single-page interface fails silently when a renamed element identifier causes a handler to bind to `null`; the control simply stops responding, and no error is raised. The test renders the template, extracts every identifier the client script addresses, and asserts the page defines each one. Its effectiveness was confirmed by deliberately renaming an identifier and observing the failure.

Four sample logs were constructed: an attack log containing a burst and a successful compromise, a clean log of benign traffic including a mistyped password, an evasion log containing a low-and-slow attack, a distributed botnet, and a password spray, and a noise log of realistic non-authentication line forms containing an attack visible only through correct handling of collapsed repeat lines.

---

## 8. Results and Discussion

### 8.1 Detection Output

Analysis of the attack log at default parameters:

```
[HIGH  ] ip   203.0.113.5   3 failure(s) across 3 usernames then SUCCESS as user admin at 09:02:14
[MEDIUM] ip   192.168.1.5   5 failures in 12s (09:15:01 to 09:15:13), 5 total
[MEDIUM] user admin         5 failures in 12s (09:15:01 to 09:15:13), 6 total
```

The HIGH severity finding is significant. Address `203.0.113.5` attempted three distinct usernames over nine seconds and was then accepted as `admin` — a compromise. A conventional failure-counting detector reports nothing here, as three failures fall below any usual threshold, while reporting the burst from `192.168.1.5`, an attacker who made five attempts and never gained access. **The baseline approach therefore alerts on the attack that failed and remains silent on the attack that succeeded.** Correlating failures with subsequent successes corrects this inversion.

Analysis of the noise log demonstrates the parsing corrections:

```
Events:  10 parsed, 5 unrecognised line(s) skipped
[MEDIUM] ip   203.0.113.200  9 failures in 0s (03:01:00 to 03:01:00), 9 total
[MEDIUM] user root           9 failures in 0s (03:01:00 to 03:01:00), 9 total
```

The prior implementation reported four events and no findings for this input: five operational lines were admitted or discarded incorrectly, and the nine-attempt burst, recorded by `rsyslog` as one collapsed line, was counted once and fell below the threshold. The attack was invisible.

Analysis of the clean log, which includes a user mistyping their password at 10:12:03 and authenticating successfully at 10:12:19, reports no findings. The prior implementation raised a HIGH severity compromise alert on this sequence.

### 8.2 Parameter Evaluation

The detector was scored against six labelled attacks across twelve configurations. Precision is the proportion of raised findings that correspond to a labelled attack; recall is the proportion of labelled attacks detected; F1 is their harmonic mean.

| Threshold | Window (s) | Caught | Missed | False alarms | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 | 120 | 5/6 | 1 | 0 | 1.000 | 0.833 | 0.909 |
| 3 | 600 | 5/6 | 1 | 0 | 1.000 | 0.833 | 0.909 |
| **3** | **1800** | **6/6** | **0** | **0** | **1.000** | **1.000** | **1.000** |
| 3 | 3600 | 6/6 | 0 | 1 | 0.857 | 1.000 | 0.923 |
| 5 | 120 | 4/6 | 2 | 0 | 1.000 | 0.667 | 0.800 |
| 5 | 600 | 4/6 | 2 | 0 | 1.000 | 0.667 | 0.800 |
| 5 | 1800 | 5/6 | 1 | 0 | 1.000 | 0.833 | 0.909 |
| 5 | 3600 | 5/6 | 1 | 0 | 1.000 | 0.833 | 0.909 |
| 10 | 120 | 1/6 | 5 | 0 | 1.000 | 0.167 | 0.286 |
| 10 | 600 | 1/6 | 5 | 0 | 1.000 | 0.167 | 0.286 |
| 10 | 1800 | 1/6 | 5 | 0 | 1.000 | 0.167 | 0.286 |
| 10 | 3600 | 1/6 | 5 | 0 | 1.000 | 0.167 | 0.286 |

The harness selects its operating point by F1 rather than by raw detections, since ranking by detections alone would favour any configuration sensitive enough to alert indiscriminately.

### 8.3 Discussion

**The conventional default is not optimal.** Five failures within 120 seconds, the setting most commonly cited, detected four of six attacks at a recall of 0.667 — missing both the low-and-slow attack and the password spray.

**Widening the window improves recall until precision degrades.** At 1800 seconds all six attacks were detected with no false alarms. At 3600 seconds recall remained at 1.000 but precision fell to 0.857, as unrelated benign failures in the clean log became close enough in time to resemble a pattern. This boundary is the precision–recall trade-off made concrete, and it is the reason F1 rather than recall is the appropriate selection criterion.

**A high threshold approaches blindness.** At a threshold of ten, recall collapsed to 0.167: the only surviving detection was the compromise correlation, which does not depend on the threshold. This illustrates why a detector should not rely on a single detection mechanism.

**Precision is uniformly high; recall is where the difficulty lies.** Precision remains at 1.000 in eleven of twelve configurations. The detector's characteristic failure is to miss attacks rather than to invent them, which is the preferable failure mode for a reporting tool and indicates that tuning effort is properly directed at recall.

**Limitation of the evaluation.** Six labelled attacks in synthetic logs is a small sample. The identified operating point is optimal for this dataset and should be understood as a demonstration of the tuning method rather than a universally applicable setting. Validation against real-world traffic would be required before deployment.

### 8.4 Comparison with fail2ban

`fail2ban` is the established tool addressing this problem, and an honest comparison must begin by acknowledging that it is more capable than this project in almost every operational dimension. It monitors logs continuously rather than analysing a stored file, and responds automatically by inserting firewall rules to block offending addresses — this project detects and reports but does not act. It handles arbitrary services through configurable regular-expression filters organised into jails, whereas this implementation understands only OpenSSH. It manages log rotation, maintains a persistent ban database, escalates ban durations for repeat offenders, and supports address whitelisting. It is packaged in every major distribution and has been deployed and hardened over two decades. Any suggestion that this project supersedes it would be unserious.

The comparison is nevertheless instructive, because the two tools pursue different objectives. `fail2ban` is a mitigation tool: its purpose is to make continued attack expensive by blocking sources that cross a threshold, and for that purpose per-IP counting is entirely sufficient — an attacker distributing attempts across many addresses is, from a blocking perspective, already being throttled per address. This project is an analysis tool, whose purpose is to characterise what occurred. That difference in objective produces two concrete divergences. First, `fail2ban` counts authentication failures and does not correlate a failure sequence with a subsequent success; it is therefore structurally unable to report that a particular attack *succeeded*, which is the highest-severity finding this project produces. Second, its default `sshd` jail aggregates strictly by source address, so password spraying across many accounts and distributed attempts from a subnet — attacks that the username and subnet pivots in this project detect — do not register as a single correlated event.

One further observation follows from the evaluation in Section 8.2. The default `fail2ban` configuration for the `sshd` jail is `maxretry = 5` within `findtime = 600` seconds. That configuration corresponds directly to a row of the evaluation table, which detected four of six labelled attacks at a recall of 0.667. This is not offered as a criticism of `fail2ban`, whose defaults are appropriately conservative for a tool that blocks network access automatically and where a false positive locks out a legitimate user. It does, however, support the central argument of this report: widely adopted threshold parameters are inherited rather than measured, and their detection characteristics are rarely stated. A tool that only reports, and cannot lock anyone out, is free to operate at a more sensitive setting than a tool that enforces.

---

## 9. Conclusion

A modular SSH log analyser was implemented, comprising parsing, detection, reporting, and evaluation components exposed through both a command-line tool and a web application, supported by one hundred and seventeen unit tests. Beyond the baseline sliding-window detector, the work identified three evasion techniques defeating per-IP failure counting and countered them by pivoting the grouping key, and identified that failure counting alone inverts alert priority by ignoring successful compromises.

Three defect classes were identified and corrected during the work, each of which had produced a materially wrong result on realistic input: non-authentication lines admitted as events, `rsyslog`-collapsed bursts undercounted by their repetition factor, and ordinary user password errors reported at the highest available severity. The last is the most instructive, since the affected check was simultaneously the most valuable detection in the system and, at its original sensitivity, its most frequent false positive. A detection is not useful in proportion to what it catches alone, but in proportion to what it catches relative to what it raises.

The principal finding is methodological. Detection parameters that appear reasonable performed poorly when measured: the conventional setting achieved a recall of 0.667, while an empirically selected configuration detected every labelled attack without false alarms. Threshold-based detection is only as good as its tuning, and tuning requires measurement against labelled data rather than assumption.

---

## 10. Future Enhancements

1. **Streaming input** to process logs exceeding available memory, in place of the current list-based approach and upload cap.
2. **Validation against real traffic** captured from an internet-exposed host or a public honeypot dataset.
3. **Persistence** so that the web application can retain findings and present trends across successive analyses.
4. **Alert delivery** to a SIEM platform, message channel, or mail transport as findings are raised.
5. **Comparative evaluation** against `fail2ban` on identical input.
6. **Risk scoring** replacing binary alerting, ranking findings by aggregate severity.
7. **Correction of documented defects**: year-boundary arithmetic, leap-year handling, and IPv6 subnet grouping.
8. **Production deployment** behind a WSGI server with debug mode disabled, the development server being unsuitable for exposure.

---

## 11. References

1. OpenSSH Project. *sshd(8) Manual Page.* https://man.openbsd.org/sshd
2. fail2ban Project. *fail2ban Documentation.* https://www.fail2ban.org
3. MITRE. *ATT&CK Technique T1110: Brute Force.* https://attack.mitre.org/techniques/T1110/
4. MITRE. *ATT&CK Sub-technique T1110.003: Password Spraying.* https://attack.mitre.org/techniques/T1110/003/
5. OWASP Foundation. *Blocking Brute Force Attacks.* https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
6. Python Software Foundation. *unittest — Unit testing framework.* https://docs.python.org/3/library/unittest.html
7. Gerhards, R. *The Syslog Protocol.* RFC 5424, IETF, 2009. https://www.rfc-editor.org/rfc/rfc5424

---

## Appendix A — Repository

Source code, sample logs, tests, and evaluation harness:
`https://github.com/<your-username>/brute-force-log-analyzer`
