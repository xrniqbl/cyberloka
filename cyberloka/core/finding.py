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
    """A single vulnerability or informational finding.

    Field tambahan untuk laporan yang lebih mendalam:
    - impact          : dampak bila celah dieksploitasi (1-3 kalimat)
    - attack_scenario : cerita serangan langkah-demi-langkah (apa yang attacker lakukan)
    - fix_examples    : contoh kode/config perbaikan per stack (dict: stack -> snippet)
    - manual_steps    : langkah verifikasi manual yang harus dilakukan tester
    """

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
    extra: dict[str, Any] = field(default_factory=dict)
    impact: str = ""
    attack_scenario: str = ""
    fix_examples: dict[str, str] = field(default_factory=dict)
    manual_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
