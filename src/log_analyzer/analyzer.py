import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LogEntry:
    line_number: int
    raw: str
    level: str
    message: str
    source: str = "generic"
    status_code: int | None = None
    ip: str | None = None
    timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "level": self.level,
            "message": self.message,
            "source": self.source,
            "status_code": self.status_code,
            "ip": self.ip,
            "timestamp": self.timestamp,
        }


@dataclass
class AnalysisReport:
    total_lines: int = 0
    parsed_entries: int = 0
    levels: dict[str, int] = field(default_factory=dict)
    status_codes: dict[str, int] = field(default_factory=dict)
    unique_ips: list[str] = field(default_factory=list)
    suspicious_events: list[dict[str, Any]] = field(default_factory=list)
    top_errors: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "parsed_entries": self.parsed_entries,
            "levels": dict(sorted(self.levels.items())),
            "status_codes": dict(sorted(self.status_codes.items())),
            "unique_ips": self.unique_ips,
            "suspicious_events": self.suspicious_events,
            "top_errors": [{"message": msg, "count": count} for msg, count in self.top_errors],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
