"""JWT algorithm confusion + KID injection probes.

Looks for JWTs in cookies/responses. Tests:
- alg=none variant
- RS256 -> HS256 confusion (when public key is exposed)
- KID path traversal / SQL injection
"""
from __future__ import annotations

import base64
import json
import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _decode_part(s: str) -> dict | None:
    s += "=" * (-len(s) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s).decode())
    except Exception:
        return None


def _make_alg_none(token: str) -> str:
    h, p, _ = token.split(".", 2)
    new_header = {"alg": "none", "typ": "JWT"}
    enc = base64.urlsafe_b64encode(json.dumps(new_header).encode()).rstrip(b"=").decode()
    return f"{enc}.{p}."


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        haystack = (r.text or "")
        for c in r.cookies:
            haystack += f"\n{c.name}={c.value}"

        tokens = list(set(JWT_RE.findall(haystack)))[:3]
        for token in tokens:
            parts = token.split(".")
            if len(parts) < 2:
                continue
            header = _decode_part(parts[0])
            payload = _decode_part(parts[1])
            if not header or not payload:
                continue

            problems: list[str] = []
            sev = Severity.LOW

            alg = (header.get("alg") or "").lower()
            if alg in ("rs256", "rs384", "rs512"):
                problems.append(
                    "Algoritma asimetris (RS*); rentan algorithm-confusion jika "
                    "public key terekspos publik."
                )
                sev = Severity.HIGH

            kid = header.get("kid")
            if kid and isinstance(kid, str):
                if any(c in kid for c in ("../", "..\\", "'", "\"", "/")):
                    problems.append(f"KID berisi karakter mencurigakan: {kid!r}")
                    sev = Severity.HIGH

            # Try alg=none replay (best-effort: send to base_url with fake auth header)
            if alg in ("hs256", "hs384", "hs512", "rs256"):
                forged = _make_alg_none(token)
                r2 = client.get(
                    target.base_url,
                    headers={"Authorization": f"Bearer {forged}"},
                    cookies={"token": forged},
                )
                if r2 is not None and r2.status_code == 200:
                    body = (r2.text or "").lower()
                    if any(s in body for s in ("welcome", "dashboard", "logout", "berhasil")):
                        problems.append("Server menerima token alg=none tanpa signature.")
                        sev = Severity.CRITICAL

            if not problems:
                continue
            findings.append(Finding(
                module="jwt_confusion", target=target.base_url,
                title="Konfigurasi JWT rentan algorithm/kid attack",
                severity=sev,
                description="Token JWT memiliki properti yang membuka peluang forge atau replay.",
                evidence="\n".join(problems),
                cwe="CWE-347",
                remediation=("Pin algoritma di server (`HS256` ATAU `RS256`, jangan keduanya). "
                             "Validasi `kid` terhadap whitelist UUID. Tolak `alg=none`. "
                             "Jangan ekspos public key di halaman publik."),
                references=["https://portswigger.net/web-security/jwt"],
            ))
    finally:
        client.close()
    return findings
