import argparse
import json
from pathlib import Path

from .analyzer import analyze_log_file


def _format_report(report) -> str:
    lines = [
        "Log analysis summary",
        "====================",
        f"Total lines: {report.total_lines}",
        f"Parsed entries: {report.parsed_entries}",
    ]

    if report.levels:
        lines.append("Levels:")
        for level, count in sorted(report.levels.items()):
            lines.append(f"  - {level}: {count}")

    if report.unique_ips:
        lines.append(f"Unique IPs: {len(report.unique_ips)}")
        lines.append(f"IP addresses: {', '.join(report.unique_ips[:10])}")

    if report.suspicious_events:
        lines.append(f"Suspicious events: {len(report.suspicious_events)}")
        for event in report.suspicious_events[:5]:
            lines.append(f"  - [{event['line_number']}] {event['message']}")

    if report.top_errors:
        lines.append("Top errors:")
        for message, count in report.top_errors[:5]:
            lines.append(f"  - {message}: {count}")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze log files for suspicious activity.")
    parser.add_argument("path", help="Path to the log file to inspect")
    parser.add_argument("--json", action="store_true", help="Emit the report in JSON format")
    parser.add_argument("--limit", type=int, default=5, help="Limit suspicious events and top errors in text output")
    args = parser.parse_args()

    report = analyze_log_file(Path(args.path))

    if args.json:
        print(report.to_json())
        return 0

    summary = {
        "total_lines": report.total_lines,
        "parsed_entries": report.parsed_entries,
        "levels": report.levels,
        "status_codes": report.status_codes,
        "unique_ips": report.unique_ips,
        "suspicious_events": report.suspicious_events[: args.limit],
        "top_errors": list(report.top_errors[: args.limit]),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
