# Log-Analyser

A lightweight Python log analysis tool with both a command-line interface and a desktop GUI. It parses application, web, and system logs and highlights suspicious activity.

## GUI mode

The GUI uses Python's built-in Tkinter library, so no extra GUI dependency is required.

```bash
python -m log_analyzer
```

The desktop application lets you:

- open `.log` and `.txt` files
- paste log data directly into the editor
- analyze levels, HTTP status codes, IP addresses, and suspicious events
- inspect a formatted JSON report
- export the report as a JSON file

On Linux, install Tkinter if it is not already available:

```bash
# Debian/Ubuntu
sudo apt install python3-tk
```

## CLI mode

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
python -m log_analyzer.cli ./sample.log --json
```

For a readable terminal report:

```bash
python -m log_analyzer.cli ./sample.log
```

## Project structure

```text
.
├── README.md
├── pyproject.toml
├── requirements.txt
├── src/log_analyzer/
│   ├── analyzer.py
│   ├── cli.py
│   ├── gui.py
│   ├── models.py
│   └── __main__.py
└── tests/
    └── test_analyzer.py
```

## Detection capabilities

The analyzer recognizes common application log levels, Apache/Nginx access logs, syslog-style entries, HTTP status codes, IP addresses, authentication failures, permission errors, exceptions, timeouts, and other suspicious indicators.

## License

MIT
