"""Outdated JS library detector.

Detect known-vulnerable versions of common frontend libraries dari
URL script tag atau body content. Min-secure-version berdasarkan advisory
publik (per ~2024-2025).
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Pattern: nama library, regex untuk extract versi, min secure version
# Min secure ditetapkan konservatif (versi yang sudah patch CVE major).
_LIBS: list[tuple[str, re.Pattern[str], tuple[int, ...], Severity, str]] = [
    ("jQuery", re.compile(r"jquery[/-](\d+\.\d+(?:\.\d+)?)", re.I), (3, 5, 0), Severity.MEDIUM,
     "jQuery <3.5.0 punya CVE-2020-11023 (XSS lewat innerHTML)"),
    ("jQuery (banner)", re.compile(r"jQuery v?(\d+\.\d+(?:\.\d+)?)", re.I), (3, 5, 0), Severity.MEDIUM, ""),
    ("Bootstrap", re.compile(r"bootstrap[/-](\d+\.\d+(?:\.\d+)?)", re.I), (4, 6, 1), Severity.MEDIUM,
     "Bootstrap <4.6.1 / <5.0.1 punya CVE-2024-6485/6531 (XSS)"),
    ("AngularJS (legacy)", re.compile(r"angular[/-]?(\d+\.\d+(?:\.\d+)?)/angular\.", re.I), (1, 8, 3), Severity.HIGH,
     "AngularJS sudah end-of-life. Migrasi ke Angular modern."),
    ("Lodash", re.compile(r"lodash[/-](\d+\.\d+(?:\.\d+)?)", re.I), (4, 17, 21), Severity.HIGH,
     "Lodash <4.17.21 punya prototype pollution CVE-2020-8203"),
    ("Moment.js", re.compile(r"moment[/-](\d+\.\d+(?:\.\d+)?)", re.I), (2, 29, 4), Severity.MEDIUM,
     "Moment <2.29.4 punya path traversal CVE-2022-31129. Moment juga sudah deprecated."),
    ("React", re.compile(r"react[/-](\d+\.\d+(?:\.\d+)?)\.min\.js", re.I), (16, 14, 0), Severity.LOW,
     "React tua kadang punya isu di server-side rendering"),
    ("Vue.js", re.compile(r"vue[/-](\d+\.\d+(?:\.\d+)?)", re.I), (2, 7, 16), Severity.LOW,
     "Vue 2 sudah end-of-life Dec 2023; migrasi ke Vue 3"),
    ("Tinymce", re.compile(r"tinymce[/-](\d+\.\d+(?:\.\d+)?)", re.I), (6, 7, 3), Severity.MEDIUM,
     "TinyMCE <6.7.3 punya XSS"),
    ("CKEditor", re.compile(r"ckeditor[/-](\d+\.\d+(?:\.\d+)?)", re.I), (4, 22, 0), Severity.MEDIUM,
     "CKEditor 4 mendekati EOL"),
    ("Handlebars", re.compile(r"handlebars[/-](\d+\.\d+(?:\.\d+)?)", re.I), (4, 7, 7), Severity.HIGH,
     "Handlebars <4.7.7 punya prototype pollution CVE-2021-23369"),
    ("DOMPurify", re.compile(r"dompurify[/-]?(\d+\.\d+(?:\.\d+)?)", re.I), (3, 0, 9), Severity.MEDIUM,
     "DOMPurify <3.0.9 punya bypass XSS"),
    ("Axios", re.compile(r"axios[/-](\d+\.\d+(?:\.\d+)?)", re.I), (1, 7, 4), Severity.HIGH,
     "Axios <1.7.4 punya SSRF/credential leak (CVE-2024-39338)"),
]


def _ver(s: str) -> tuple[int, ...]:
    parts: list[int] = []
    for p in s.split("."):
        m = re.match(r"(\d+)", p)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None or not resp.text:
            return findings
        body = resp.text

        seen: set[tuple[str, str]] = set()
        for lib, rgx, minimum, sev, note in _LIBS:
            for ver in rgx.findall(body):
                if (lib, ver) in seen:
                    continue
                seen.add((lib, ver))
                cur = _ver(ver)
                if cur and cur < minimum:
                    min_str = ".".join(str(x) for x in minimum)
                    findings.append(
                        Finding(
                            module="outdated_js",
                            title=f"{lib} versi usang {ver} (min aman: {min_str})",
                            severity=sev,
                            description=(
                                f"Library frontend {lib} {ver} terdeteksi. "
                                f"Versi minimum yang direkomendasikan: {min_str}. "
                                f"{note}"
                            ),
                            target=target.base_url,
                            evidence=f"{lib} {ver}",
                            cwe="CWE-1395",
                            remediation=(
                                f"Update {lib} ke versi terbaru lewat package manager "
                                "(npm/yarn). Setup Dependabot/Renovate untuk auto-PR "
                                "saat advisory baru muncul. Gunakan `npm audit` di CI."
                            ),
                            references=[
                                "https://github.com/advisories",
                            ],
                        )
                    )

        # Selain library, coba detect lewat URL CDN yang ter-pin ke versi lama
        cdn_re = re.compile(
            r"https?://(?:cdn\.[\w.-]+|[\w.-]*\.cloudflare\.com|[\w.-]*\.jsdelivr\.net|"
            r"unpkg\.com|cdnjs\.cloudflare\.com)/(?:ajax/libs/)?([\w.-]+)/(\d+\.\d+\.\d+)/",
            re.I,
        )
        cdn_seen: set[tuple[str, str]] = set()
        for m in cdn_re.finditer(body):
            name, ver = m.group(1).lower(), m.group(2)
            if (name, ver) in cdn_seen:
                continue
            cdn_seen.add((name, ver))
            # cek di _LIBS minimum-nya
            for lib, _rgx, minimum, sev, note in _LIBS:
                if lib.lower().split()[0] in name:
                    cur = _ver(ver)
                    if cur and cur < minimum:
                        min_str = ".".join(str(x) for x in minimum)
                        if not any(f.title.startswith(f"{lib} versi usang {ver}") for f in findings):
                            findings.append(
                                Finding(
                                    module="outdated_js",
                                    title=f"CDN-pinned {lib} {ver} usang (min aman: {min_str})",
                                    severity=sev,
                                    description=(
                                        f"Halaman load {lib} {ver} dari CDN. "
                                        f"Versi ini di bawah minimum aman {min_str}. {note}"
                                    ),
                                    target=target.base_url,
                                    evidence=m.group(0),
                                    cwe="CWE-1395",
                                    remediation=(
                                        "Update version pin di CDN URL ke versi terbaru. "
                                        "Pertimbangkan host sendiri agar bisa proper integrity."
                                    ),
                                )
                            )
    finally:
        client.close()
    return findings
