# Simple TCP Port Scanner

A lightweight, multithreaded TCP port scanner written in Python. Scans a target
host across a given port range and reports which ports are open, along with
the commonly associated service (FTP, SSH, HTTP, etc.).

## Why this project
Port scanning is one of the first steps in a network security assessment —
it helps identify which services are exposed on a machine so they can be
reviewed for misconfiguration or unnecessary exposure.

## How it works
- Uses Python's `socket` module to attempt a TCP connection to each port.
- Runs scans in parallel using `threading` for speed.
- Maps well-known ports (21, 22, 80, 443, 3306, etc.) to their typical service
  name for readable output.

## Usage
```bash
python port_scanner.py 127.0.0.1 --start 1 --end 1024
```

## Sample output
```
Scanning 127.0.0.1 from port 1 to 1024...
Started at: 2026-09-22 10:15:03

Open ports found:
  Port    22  -  SSH
  Port    80  -  HTTP
```

## ⚠️ Responsible use
Only scan machines you own or have explicit permission to test (e.g. your own
laptop `127.0.0.1`, or a lab/VM environment). Scanning systems you don't own
without authorization is illegal in most jurisdictions.

## Possible extensions (good to mention in an interview)
- Add banner grabbing to identify service versions.
- Export results to CSV/JSON.
- Add UDP scanning support.
