import re
from collections import Counter
from pathlib import Path
from typing import Iterable

from .models import AnalysisReport, LogEntry

SUSPICIOUS_PATTERNS = [
    "failed login",
    "login failed",
    "unauthorized",
    "permission denied",
    "denied",
    "traceback",
    "exception",
    "critical error",
    "panic",
    "timeout",
    "segmentation fault",
    "authentication failed",
    "access denied",
    "invalid request",
    "internal server error",
    "fatal",
    "sql injection",
    "xss",
    "sandbox escape",
    "network unreachable",
    "resource exhausted",
    "tampering",
]

LOG_LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _normalize_level(raw_level: str | None) -> str:
    if raw_level is None:
        return "INFO"
    upper = raw_level.strip().upper()
    for level in LOG_LEVELS:
        if upper == level:
            return level
    if "CRITICAL" in upper:
        return "CRITICAL"
    if "ERROR" in upper:
        return "ERROR"
    if "WARNING" in upper:
        return "WARNING"
    if "DEBUG" in upper:
        return "DEBUG"
    if "TRACE" in upper:
        return "TRACE"
    return "INFO"


def _extract_apache_nginx_entry(line: str, line_number: int) -> LogEntry | None:
    match = re.search(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>[^\"]+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)',
        line,
    )
    if not match:
        return None

    message = f"{match.group('method')} {match.group('path')} -> {match.group('status')}"
    status_code = int(match.group('status'))
    level = "ERROR" if status_code >= 500 else "WARNING" if status_code >= 400 else "INFO"
    return LogEntry(
        line_number=line_number,
        raw=line,
        level=level,
        message=message,
        source="web",
        status_code=status_code,
        ip=match.group("ip"),
        timestamp=match.group("timestamp"),
    )


def _extract_standard_entry(line: str, line_number: int) -> LogEntry | None:
    match = re.search(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ][\d:.+-]+Z?)\s+(?P<level>[A-Z]+)\s+(?P<message>.*)',
        line,
    )
    if not match:
        return None

    level = _normalize_level(match.group("level"))
    message = match.group("message").strip()
    ip = None
    if match := IP_PATTERN.search(message):
        ip = match.group(0)

    return LogEntry(
        line_number=line_number,
        raw=line,
        level=level,
        message=message,
        source="generic",
        ip=ip,
        timestamp=match.group("timestamp"),
    )


def _extract_system_entry(line: str, line_number: int) -> LogEntry | None:
    match = re.search(
        r'(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>\S+)\s+(?P<level>[A-Z]+):\s+(?P<message>.*)',
        line,
    )
    if not match:
        return None

    level = _normalize_level(match.group("level"))
    message = match.group("message").strip()
    ip = None
    if match_ip := IP_PATTERN.search(message):
        ip = match_ip.group(0)

    return LogEntry(
        line_number=line_number,
        raw=line,
        level=level,
        message=message,
        source="system",
        ip=ip,
        timestamp=match.group("timestamp"),
    )


def parse_log_line(line: str, line_number: int) -> LogEntry | None:
    if not line or not line.strip():
        return None

    candidate = line.strip()
    parsers = [
        _extract_apache_nginx_entry,
        _extract_standard_entry,
        _extract_system_entry,
    ]
    for parser in parsers:
        entry = parser(candidate, line_number)
        if entry is not None:
            return entry

    # Fallback: detect a generic level keyword in the line.
    upper = candidate.upper()
    for level_name in LOG_LEVELS:
        if level_name in upper:
            return LogEntry(
                line_number=line_number,
                raw=candidate,
                level=_normalize_level(level_name),
                message=candidate,
                source="generic",
                ip=None,
                timestamp=None,
            )

    return LogEntry(
        line_number=line_number,
        raw=candidate,
        level="INFO",
        message=candidate,
        source="generic",
        ip=None,
        timestamp=None,
    )


def _build_suspicious_events(entries: Iterable[LogEntry]) -> list[dict[str, object]]:
    suspicious = []
    for entry in entries:
        line = entry.message.lower()
        if any(pattern in line for pattern in SUSPICIOUS_PATTERNS):
            suspicious.append(
                {
                    "line_number": entry.line_number,
                    "level": entry.level,
                    "message": entry.message,
                    "ip": entry.ip,
                }
            )
    return suspicious


def analyze_text(text: str) -> AnalysisReport:
    entries: list[LogEntry] = []
    total_lines = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        total_lines += 1
        entry = parse_log_line(raw_line, line_number)
        if entry is not None:
            entries.append(entry)

    levels = Counter(entry.level for entry in entries)
    status_codes = Counter(str(entry.status_code) for entry in entries if entry.status_code is not None)
    unique_ips = sorted({entry.ip for entry in entries if entry.ip})
    suspicious_events = _build_suspicious_events(entries)

    error_messages = Counter(
        entry.message.strip() for entry in entries if entry.level in {"ERROR", "CRITICAL", "WARNING"}
    )
    top_errors = error_messages.most_common(10)

    return AnalysisReport(
        total_lines=total_lines,
        parsed_entries=len(entries),
        levels=dict(levels),
        status_codes=dict(status_codes),
        unique_ips=unique_ips,
        suspicious_events=suspicious_events,
        top_errors=list(top_errors),
    )


def analyze_log_file(path: str | Path) -> AnalysisReport:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Log file does not exist: {path}")

    text = file_path.read_text(encoding="utf-8", errors="replace")
    return analyze_text(text)
