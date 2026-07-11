# Brute-Force Login Detector

A Python tool that scans authentication logs and flags IP addresses showing brute-force login behavior — five or more failed attempts within a 120-second window — using dictionary-based grouping and a sliding-window algorithm.

## Features
- Parses standard auth-log formatted login attempts
- Groups failed attempts by source IP
- Flags IPs that cross 5 failures within 120 seconds
- Outputs a clear, readable alert report

## Sample output
```
[ALERT] 192.168.1.5 — 5+ failed logins between 09:15:01 and 09:15:13
```

## How it works
1. Reads the log file line by line
2. Extracts timestamp, IP address, and result from each line
3. Stores failed attempts per IP using a dictionary
4. Checks each IP with a sliding window for 5+ failures within 120 seconds
5. Prints an alert for any IP that crosses the threshold

## Tech stack
Python 3.x, standard library only, no external dependencies

## Usage
```bash
python main.py
```

## Project structure
- `parser.py` — parses raw log lines, converts timestamps to seconds
- `detector.py` — groups failures by IP, runs sliding window detection
- `main.py` — entry point, calls analyze_log()

## Author
BTech Cybersecurity Student
