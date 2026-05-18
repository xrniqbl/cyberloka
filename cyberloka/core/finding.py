"""Data model for a single security finding."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def order(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


@dataclass
class Finding:
    """A single vulnerability or informational finding."""

    module: str
    title: str
    severity: Severity
    description: str
    target: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str | None = None
    confidence: str = "firm"  # tentative | firm | confirmed
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # URLs / link bug terkait finding ini (endpoint vulnerable, PoC, screenshot, dll.)
    # Dipakai di PDF/HTML report sebagai daftar "Link Bug" yang clickable.
    urls: list[str] = field(default_factory=list)
    # ID bug-tracker eksternal opsional (mis. JIRA SEC-1234, GitHub issue URL).
    bug_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
