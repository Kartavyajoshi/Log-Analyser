# Log-Analyser

A lightweight, production-ready log analyzer built in Python for scanning application, web, and system logs, extracting patterns, and surfacing suspicious activity.

## Features

- Parse common log formats, including:
  - standard application logs
  - Apache/Nginx access logs
  - error and warning lines
- Count log levels and suspicious events
- Detect common security indicators such as:
  - failed authentication
  - permission denied
  - invalid requests
  - exceptions and tracebacks
  - timeout and crash patterns
- Generate structured summaries for investigation and reporting
- Run as a CLI script or import as a Python library

## Project structure

```text
.
├── README.md
├── pyproject.toml
├── requirements.txt
├── src/
│   └── log_analyzer/
│       ├── __init__.py
│       ├── __main__.py
│       ├── analyzer.py
│       ├── cli.py
│       └── models.py
└── tests/
    └── test_analyzer.py
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m log_analyzer.cli ./sample.log --json
```

## Example usage

```bash
python -m log_analyzer.cli /var/log/nginx/access.log --top 10
python -m log_analyzer.cli ./logs/app.log --json --limit 25
```

## Example output

```text
Log analysis summary
====================
File: ./logs/app.log
Total entries: 124
INFO: 72
WARNING: 18
ERROR: 28
CRITICAL: 6
Unique IPs: 13
Suspicious events: 9

Top error messages:
  - Permission denied for user admin: 7
  - Failed login attempt: 5
  - Exception in worker pool: 3
```

## Why this project matters

Log analysis is vital for incident response, system health monitoring, and security investigations. This project gives you a practical foundation for scanning logs, identifying anomalies, and turning raw events into actionable intelligence.

## License

MIT
