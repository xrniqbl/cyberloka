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

    @property
    def base_score(self) -> int:
        return {"critical": 92, "high": 75, "medium": 50, "low": 25, "info": 5}[
            self.value
        ]

    @property
    def color(self) -> str:
        return {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#2563eb",
            "info": "#64748b",
        }[self.value]


CONFIDENCE_DELTA = {"confirmed": 5, "firm": 0, "tentative": -12}

# Simple CWE → OWASP Top 10 (2021) mapping. Used only for tagging in report.
CWE_TO_OWASP = {
    "CWE-22": "A01:2021 – Broken Access Control",
    "CWE-89": "A03:2021 – Injection",
    "CWE-79": "A03:2021 – Injection",
    "CWE-78": "A03:2021 – Injection",
    "CWE-94": "A03:2021 – Injection",
    "CWE-1336": "A03:2021 – Injection",
    "CWE-918": "A10:2021 – Server-Side Request Forgery",
    "CWE-611": "A05:2021 – Security Misconfiguration",
    "CWE-352": "A01:2021 – Broken Access Control",
    "CWE-287": "A07:2021 – Identification & Authentication Failures",
    "CWE-345": "A08:2021 – Software & Data Integrity Failures",
    "CWE-353": "A08:2021 – Software & Data Integrity Failures",
    "CWE-1021": "A04:2021 – Insecure Design",
    "CWE-693": "A05:2021 – Security Misconfiguration",
    "CWE-1004": "A05:2021 – Security Misconfiguration",
    "CWE-200": "A01:2021 – Broken Access Control",
    "CWE-209": "A04:2021 – Insecure Design",
    "CWE-319": "A02:2021 – Cryptographic Failures",
    "CWE-326": "A02:2021 – Cryptographic Failures",
    "CWE-327": "A02:2021 – Cryptographic Failures",
    "CWE-538": "A01:2021 – Broken Access Control",
    "CWE-548": "A05:2021 – Security Misconfiguration",
    "CWE-601": "A01:2021 – Broken Access Control",
    "CWE-829": "A08:2021 – Software & Data Integrity Failures",
    "CWE-937": "A06:2021 – Vulnerable & Outdated Components",
    "CWE-1035": "A06:2021 – Vulnerable & Outdated Components",
}


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
    # Dipakai oleh PDF/HTML report untuk menampilkan "Link Bug" yang clickable.
    urls: list[str] = field(default_factory=list)
    # ID bug-tracker eksternal opsional (mis. JIRA SEC-1234, GitHub issue URL).
    bug_id: str | None = None
    # Step-by-step bagaimana attacker mengeksploitasi celah ini (plain Indonesia).
    # Dipakai PDF/HTML untuk section "Langkah Eksploitasi (Skenario Hacker)".
    # Auto-diisi oleh scanner._enrich_findings() bila modul tidak meng-set sendiri.
    exploitation_steps: list[str] = field(default_factory=list)
    # Daftar signal yang sudah divalidasi otomatis oleh scanner (multi-signal),
    # sehingga finding ini bukan deteksi pasif yang bisa false-positive.
    # Dipakai PDF/HTML untuk section "Validasi Aktif".
    validation_proof: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_score(self) -> int:
        """Composite 1-100 risk score from severity + confidence."""
        score = self.severity.base_score + CONFIDENCE_DELTA.get(self.confidence, 0)
        return max(1, min(100, score))

    @property
    def owasp_category(self) -> str | None:
        if not self.cwe:
            return None
        return CWE_TO_OWASP.get(self.cwe.upper())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["risk_score"] = self.risk_score
        d["owasp_category"] = self.owasp_category
        return d
