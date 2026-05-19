"""Inspect JWT-shaped tokens found in cookies / response bodies."""
from __future__ import annotations

import base64
import json
import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,})\b")


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _inspect(token: str) -> dict | None:
    try:
        h, p, _ = token.split(".", 2)
        header = json.loads(_b64url_decode(h))
        payload = json.loads(_b64url_decode(p))
    except Exception:  # noqa: BLE001
        return None
    return {"header": header, "payload": payload}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        haystack = resp.text or ""
        for c in resp.cookies:
            haystack += f"\n{c.name}={c.value}"
        seen: set[str] = set()
        for m in JWT_RE.finditer(haystack):
            tok = m.group(1)
            if tok in seen:
                continue
            seen.add(tok)
            info = _inspect(tok)
            if not info:
                continue
            alg = (info["header"].get("alg") or "").lower()
            issues: list[str] = []
            sev = Severity.LOW
            if alg == "none":
                issues.append("alg=none (signature dimatikan)")
                sev = Severity.CRITICAL
            elif alg.startswith("hs"):
                issues.append("HMAC-based (rentan brute-force jika secret lemah)")
                sev = max(sev, Severity.MEDIUM, key=lambda s: s.order * -1)
            if "exp" not in info["payload"]:
                issues.append("klaim `exp` tidak ada (token tidak kedaluwarsa)")
                sev = Severity.HIGH if sev.order > Severity.HIGH.order else sev
            findings.append(
                Finding(
                    module="jwt",
                    title="JWT terdeteksi dengan potensi masalah",
                    severity=sev,
                    description=(
                        "Token JWT ditemukan pada respons aplikasi. Periksa konfigurasi "
                        "algoritma dan klaim keamanannya."
                    ),
                    target=target.base_url,
                    evidence=json.dumps(info, indent=2)[:600],
                    cwe="CWE-345",
                    remediation=(
                        "Gunakan algoritma asimetris (RS256/EdDSA), set `exp`/`nbf`, validasi "
                        "`iss`/`aud`, putar kunci secara berkala, dan jangan terima `alg=none`."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
                    ],
                    extra={"issues": issues, "alg": alg},
                )
            )
    finally:
        client.close()
    return findings
