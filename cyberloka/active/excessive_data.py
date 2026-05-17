"""Excessive data exposure detector.

Cek apakah API mengembalikan field sensitif yang seharusnya tidak ditujukan
ke client (mis. `password`, `passwordHash`, `ssn`, `creditCard`, `cvv`,
`internalNote`, `apiKey`, `secret`).

Strategi: scan response JSON dari endpoint /api/* untuk key/field yang
namanya mencurigakan. Tidak menyimpan datanya — hanya melaporkan keberadaan
field dengan key tersebut.
"""
from __future__ import annotations

import json

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Field name yang TIDAK boleh ada di response API publik
SENSITIVE_KEY_PATTERNS = [
    # Auth secrets
    ("password", "password / passwordHash", Severity.CRITICAL),
    ("passwd", "password", Severity.CRITICAL),
    ("password_hash", "password hash", Severity.CRITICAL),
    ("hashedpassword", "password hash", Severity.CRITICAL),
    ("salt", "password salt", Severity.HIGH),
    ("secret", "secret/token", Severity.HIGH),
    ("apikey", "API key", Severity.HIGH),
    ("api_key", "API key", Severity.HIGH),
    ("private_key", "private key", Severity.CRITICAL),
    ("privatekey", "private key", Severity.CRITICAL),
    ("access_token", "access token", Severity.HIGH),
    ("refresh_token", "refresh token", Severity.HIGH),
    # Financial
    ("creditcard", "credit card number", Severity.CRITICAL),
    ("credit_card", "credit card number", Severity.CRITICAL),
    ("cardnumber", "card number", Severity.CRITICAL),
    ("card_number", "card number", Severity.CRITICAL),
    ("cvv", "CVV", Severity.CRITICAL),
    ("cvc", "CVC", Severity.CRITICAL),
    ("pin", "PIN", Severity.HIGH),
    # PII Indonesian
    ("ssn", "SSN", Severity.CRITICAL),
    ("nik", "NIK (KTP Indonesia)", Severity.HIGH),
    ("ktp", "nomor KTP", Severity.HIGH),
    ("npwp", "NPWP", Severity.HIGH),
    # Internal
    ("internalnote", "internal note (untuk staff)", Severity.MEDIUM),
    ("internal_note", "internal note", Severity.MEDIUM),
    ("admin_note", "admin note", Severity.MEDIUM),
    ("admin_only", "admin-only field", Severity.MEDIUM),
    ("debug_info", "debug info", Severity.MEDIUM),
    ("stack_trace", "stack trace", Severity.HIGH),
    ("stacktrace", "stack trace", Severity.HIGH),
    ("__v", "Mongoose internal version key", Severity.LOW),
    ("_id", "MongoDB ObjectId raw (bisa ekspos info DB)", Severity.LOW),
]


def _walk_json(obj, path="", out: dict[str, str] | None = None) -> dict[str, str]:
    """Return dict {full_path: value_redacted} of all keys."""
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{path}.{k}" if path else k
            if not isinstance(v, (dict, list)):
                # store the key path
                out[new_path] = "<value>" if v is None else (str(v)[:8] + "..." if isinstance(v, str) and len(str(v)) > 8 else "<value>")
            _walk_json(v, new_path, out)
    elif isinstance(obj, list):
        if obj:
            _walk_json(obj[0], path + "[0]", out)
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return findings

    api_endpoints: list[str] = []
    for ep in getattr(discovered, "endpoints", []):
        if ep.method.upper() != "GET":
            continue
        if "/api/" in ep.url.lower() or ep.url.lower().endswith(".json"):
            api_endpoints.append(ep.url)
    api_endpoints = list(dict.fromkeys(api_endpoints))[:15]

    if not api_endpoints:
        return findings

    client = HttpClient(config)
    try:
        for url in api_endpoints:
            resp = client.get(url)
            if resp is None:
                continue
            ctype = resp.headers.get("Content-Type", "")
            if "json" not in ctype.lower():
                continue
            try:
                data = json.loads(resp.text or "{}")
            except (ValueError, json.JSONDecodeError):
                continue

            paths = _walk_json(data)
            hits: dict[str, list[str]] = {}  # severity bucket -> list paths
            seen_keys: set[str] = set()
            for path in paths:
                # ambil key terakhir
                last = path.split(".")[-1].split("[")[0].lower()
                for key, label, sev in SENSITIVE_KEY_PATTERNS:
                    if key == last and key not in seen_keys:
                        seen_keys.add(key)
                        hits.setdefault(f"{sev.value}|{label}", []).append(path)
                        break

            for k, found_paths in hits.items():
                sev_str, label = k.split("|", 1)
                sev = next(s for s in (
                    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFO,
                ) if s.value == sev_str)
                findings.append(
                    Finding(
                        module="excessive_data",
                        title=f"Field sensitif `{label}` ter-ekspos di response API",
                        severity=sev,
                        description=(
                            "API mengembalikan field yang seharusnya hanya dipakai "
                            "internal / di-strip sebelum response. Frontend tidak "
                            "membutuhkannya tapi terlanjur dikirim — pelanggaran "
                            "prinsip data minimization."
                        ),
                        target=url,
                        evidence=f"path: {', '.join(found_paths[:5])}",
                        cwe="CWE-213",
                        remediation=(
                            "Pakai DTO / serializer yang eksplisit menentukan field "
                            "yang di-expose:\n"
                            "  - Express: pakai library seperti class-transformer @Expose\n"
                            "  - Django REST: Serializer dengan fields=['id','name','email']\n"
                            "  - JANGAN pakai 'fields=__all__' atau spread req.body\n"
                            "  - Untuk sensitive field (password): set select=false di schema "
                            "(Mongoose) atau exclude di base query."
                        ),
                        references=[
                            "https://owasp.org/www-project-api-security/2023/en/0xa3-broken-object-property-level-authorization.html",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
