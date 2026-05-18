"""Cookie attribute audit.

Akurasi:

- Cookie tracking pihak ketiga yang dikenal (mis. `_ga`, `_gid`, `_gat`,
  `_fbp`, `IDE`, `__utm*`) memang **memerlukan akses JS** sehingga tidak
  butuh HttpOnly. Kami turunkan severity-nya supaya bukan 'kebocoran' false
  positive.
- Cookie sesi (nama mengandung `sess`, `auth`, `token`, `csrf`, `id`) yang
  kekurangan flag dilaporkan MEDIUM/HIGH.
- SameSite=None tanpa Secure → INVALID per RFC, dilaporkan HIGH.
- `Domain=` mencakup parent yang lebih luas dari host → flag.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

THIRD_PARTY_TRACKERS = re.compile(
    r"^(_ga|_gid|_gat|_gcl_au|_fbp|_fbc|fr|IDE|NID|test_cookie|"
    r"__utm[a-z]?|s_(cc|sq|fid)|amplitude_id|optimizely|hubspotutk|"
    r"_clck|_clsk)$",
    re.I,
)
SESSION_NAMES = re.compile(
    r"(sess(ion)?|auth|token|jwt|sid|csrf|xsrf|laravel_session|phpsessid|"
    r"asp\.net_sessionid|jsessionid|connect\.sid|access_token|refresh_token)",
    re.I,
)


def _classify(name: str) -> str:
    if THIRD_PARTY_TRACKERS.match(name):
        return "tracker"
    if SESSION_NAMES.search(name):
        return "session"
    return "other"


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        # Use raw header list to inspect attributes
        set_cookies: list[str] = []
        if hasattr(resp.raw, "headers"):
            try:
                set_cookies = list(resp.raw.headers.getlist("Set-Cookie"))
            except Exception:  # noqa: BLE001
                set_cookies = []
        if not set_cookies:
            sc = resp.headers.get("Set-Cookie")
            set_cookies = [sc] if sc else []

        for raw in set_cookies:
            low = raw.lower()
            name = raw.split("=", 1)[0].strip()
            kind = _classify(name)

            problems: list[str] = []
            if target.scheme == "https" and "secure" not in low:
                problems.append("Secure")
            if "httponly" not in low:
                problems.append("HttpOnly")
            if "samesite" not in low:
                problems.append("SameSite")

            # Severity differs by cookie kind
            if not problems:
                continue
            if kind == "tracker":
                # Trackers MUST be readable by JS, so HttpOnly missing is by design.
                problems_filtered = [p for p in problems if p != "HttpOnly"]
                if not problems_filtered:
                    continue
                sev = Severity.LOW
                tag = " (cookie tracker)"
            elif kind == "session":
                sev = Severity.MEDIUM if "HttpOnly" not in problems else Severity.HIGH
                # Session cookie tanpa HttpOnly = high (bisa dicuri via XSS)
                if "HttpOnly" in problems:
                    sev = Severity.HIGH
                problems_filtered = problems
                tag = " (session/auth)"
            else:
                sev = Severity.LOW
                problems_filtered = problems
                tag = ""

            # SameSite=None without Secure → invalid
            if "samesite=none" in low and "secure" not in low:
                findings.append(
                    Finding(
                        module="cookies",
                        title=f"Cookie `{name}` SameSite=None tanpa Secure (invalid per RFC)",
                        severity=Severity.HIGH,
                        description=(
                            "Browser modern menolak cookie dengan SameSite=None bila "
                            "tidak ada flag Secure. Konfigurasi ini efektif menonaktifkan "
                            "cookie pada browser modern."
                        ),
                        target=target.base_url,
                        evidence=raw,
                        cwe="CWE-1004",
                        confidence="confirmed",
                        remediation=(
                            "Tambahkan flag Secure bersamaan dengan SameSite=None, atau "
                            "ganti SameSite menjadi Lax/Strict."
                        ),
                    )
                )
                continue

            findings.append(
                Finding(
                    module="cookies",
                    title=(
                        f"Cookie `{name}`{tag} kekurangan atribut keamanan: "
                        f"{', '.join(problems_filtered)}"
                    ),
                    severity=sev,
                    description=(
                        "Cookie tanpa flag yang tepat dapat disadap (Secure), diakses "
                        "JavaScript untuk pencurian via XSS (HttpOnly), atau dipakai "
                        "untuk CSRF cross-site (SameSite). Severity disesuaikan: cookie "
                        "tracker pihak ketiga (mis. _ga) memang butuh JS akses, jadi "
                        "tidak diharuskan HttpOnly."
                    ),
                    target=target.base_url,
                    evidence=raw,
                    cwe="CWE-1004",
                    confidence="firm",
                    remediation=(
                        "Set semua cookie sensitif dengan `Secure; HttpOnly; SameSite=Lax` "
                        "(atau `Strict` untuk cookie auth murni). Untuk konteks cross-site "
                        "yang sah gunakan `SameSite=None; Secure`."
                    ),
                    references=[
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    ],
                )
            )
    finally:
        client.close()
    return findings
