# Log-Analyser

A lightweight Python log analysis tool with both a command-line interface and a desktop GUI. It parses application, web, and system logs and highlights suspicious activity.

## GUI mode (advanced)

The application includes a modern desktop dashboard with:

- live log editing
- dashboard cards for totals and metrics
- suspicious event table
- searchable alert filtering
- bar-chart level distribution
- dark/light mode toggle
- JSON export support

Launch it with:

```bash
python -m log_analyzer
```

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
│   ├── __main__.py
│   └── __init__.py
└── tests/
    └── test_analyzer.py
```

## Detection capabilities

The analyzer recognizes common application log levels, Apache/Nginx access logs, syslog-style entries, HTTP status codes, IP addresses, authentication failures, permission errors, exceptions, timeouts, and other suspicious indicators.

## License

MIT
