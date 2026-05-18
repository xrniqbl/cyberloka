"""JWT token audit (alg=none, weak secret hints, expiry)."""
from __future__ import annotations

import base64
import json
import re
import time

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

JWT_REGEX = re.compile(r"eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{4,}\.[a-zA-Z0-9_-]*")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:  # noqa: BLE001
        return None
    return header, payload, parts[2]


def _scan_text(text: str) -> list[str]:
    return list(set(JWT_REGEX.findall(text)))


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings

        sources: list[tuple[str, str]] = []
        # cookies
        for c in resp.cookies:
            sources.append((f"cookie:{c.name}", c.value or ""))
        # headers
        for hk in ("Authorization", "X-Auth-Token", "X-Access-Token"):
            v = resp.headers.get(hk)
            if v:
                sources.append((f"header:{hk}", v))
        # Set-Cookie raw
        sc = resp.headers.get("Set-Cookie")
        if sc:
            sources.append(("Set-Cookie", sc))
        # body
        if resp.text:
            sources.append(("body", resp.text))

        seen_tokens: set[str] = set()
        for origin, blob in sources:
            for tok in _scan_text(blob):
                if tok in seen_tokens:
                    continue
                seen_tokens.add(tok)
                decoded = _decode_jwt(tok)
                if not decoded:
                    continue
                header, payload, sig = decoded
                alg = (header.get("alg") or "").lower()
                kid = header.get("kid")
                exp = payload.get("exp")
                short_tok = tok[:20] + "..." + tok[-6:]

                if alg in ("none", ""):
                    findings.append(
                        Finding(
                            module="jwt",
                            title=f"JWT memakai alg=none ({short_tok})",
                            severity=Severity.CRITICAL,
                            description=(
                                "Token JWT mengiklankan algoritma `none` — siapapun bisa "
                                "memalsukan klaim tanpa signature."
                            ),
                            target=target.base_url,
                            evidence=f"source={origin}\nheader={header}",
                            cwe="CWE-347",
                            remediation=(
                                "Tolak `alg=none` di server. Hardcode algoritma yang "
                                "diharapkan (mis. RS256 atau HS256) saat verifikasi token."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                            ],
                        )
                    )
                    continue

                if exp and isinstance(exp, (int, float)) and exp < time.time():
                    findings.append(
                        Finding(
                            module="jwt",
                            title=f"JWT sudah kedaluwarsa namun masih dipakai ({short_tok})",
                            severity=Severity.MEDIUM,
                            description="Token kedaluwarsa terdeteksi di response.",
                            target=target.base_url,
                            evidence=f"source={origin}\nexp={exp}",
                            remediation="Pastikan server menolak token expired.",
                        )
                    )

                if alg.startswith("hs") and len(sig) < 32:
                    findings.append(
                        Finding(
                            module="jwt",
                            title=f"JWT HMAC dengan signature pendek ({short_tok})",
                            severity=Severity.MEDIUM,
                            description="Signature HMAC sangat pendek, kemungkinan secret lemah.",
                            target=target.base_url,
                            evidence=f"source={origin}\nalg={alg}\nsig_len={len(sig)}",
                            remediation=(
                                "Gunakan secret minimal 256-bit (32 byte) acak, atau "
                                "beralih ke RS256/ES256."
                            ),
                        )
                    )

                # Always emit info-level summary so security team aware
                findings.append(
                    Finding(
                        module="jwt",
                        title=f"JWT terdeteksi di response ({short_tok})",
                        severity=Severity.INFO,
                        description=(
                            "Token JWT terlihat di respons. Pastikan token tidak masuk ke "
                            "log/URL/referrer dan disimpan di HttpOnly cookie atau memory."
                        ),
                        target=target.base_url,
                        evidence=(
                            f"source={origin}\nalg={alg}\nkid={kid}\nclaims={list(payload.keys())}"
                        ),
                        remediation=(
                            "Simpan JWT di HttpOnly+Secure+SameSite cookie. Hindari "
                            "menaruh JWT di URL atau localStorage untuk aplikasi sensitif."
                        ),
                        extra={"alg": alg, "claims": list(payload.keys())},
                    )
                )
    finally:
        client.close()
    return findings
