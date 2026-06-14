"""Static + dynamic prototype-pollution heuristic."""
from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

VULN_JS_PATTERNS = [
    re.compile(r"Object\.assign\s*\(\s*\w+\s*,\s*JSON\.parse"),
    re.compile(r"_\.merge\s*\("),
    re.compile(r"\$\.extend\s*\(\s*true"),
    re.compile(r"deepMerge\s*\("),
    re.compile(r"setIn\s*\("),
]
PAYLOADS = (
    "__proto__[polluted]=cyberloka",
    "constructor[prototype][polluted]=cyberloka",
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is not None:
            body = r.text or ""
            for pat in VULN_JS_PATTERNS:
                m = pat.search(body)
                if m:
                    findings.append(Finding(
                        module="proto_pollution",
                        title="Pola merge yang rentan prototype pollution di JS bundle",
                        severity=Severity.LOW,
                        description=("Pola fungsi merge mendalam yang sering jadi sumber "
                                     "prototype pollution ditemukan di kode klien. "
                                     "Verifikasi tidak menerima input user mentah."),
                        target=target.base_url,
                        evidence=m.group(0),
                        cwe="CWE-1321", confidence="tentative",
                        remediation=("Pakai `Object.create(null)`, freeze prototype, atau "
                                     "library yang aman seperti `lodash@>=4.17.21`. "
                                     "Sanitasi key sebelum merge: tolak `__proto__`, "
                                     "`constructor`, `prototype`."),
                    ))
                    break

        state = get_state(config)
        urls = state.param_urls if state else []
        for url in urls[:5]:
            token = "clk" + secrets.token_hex(3)
            parsed = urlparse(url)
            base_params = list(parse_qsl(parsed.query, keep_blank_values=True))
            for tmpl in (f"__proto__[{token}]=clkval", f"constructor[prototype][{token}]=clkval"):
                k, v = tmpl.split("=", 1)
                mutated = urlunparse(parsed._replace(query=urlencode(base_params + [(k, v)])))
                r2 = client.get(mutated)
                if r2 is None:
                    continue
                ctype = (r2.headers.get("Content-Type") or "").lower()
                body = r2.text or ""
                # Refleksi HTML biasa BUKAN bukti pollution. Hanya berarti bila key
                # unik kita muncul di respons JSON (struktur objek menyerap key proto),
                # DAN tidak muncul pada request kontrol tanpa payload.
                if token in body and "json" in ctype:
                    ctrl = client.get(url)
                    if ctrl is not None and token in (ctrl.text or ""):
                        continue
                    findings.append(Finding(
                        module="proto_pollution",
                        title="Parameter prototype-pollution diterima & muncul di respons JSON",
                        severity=Severity.MEDIUM,
                        confidence="tentative",
                        description=("Server menerima key `__proto__`/`constructor[prototype]` dan key "
                                     "unik yang disuntik muncul di respons JSON (absen di kontrol). "
                                     "Indikasi kuat prototype pollution — konfirmasi dampak (DoS/RCE) "
                                     "secara manual via property gadget."),
                        target=mutated,
                        evidence=f"key unik `{token}` muncul di JSON, absen di kontrol",
                        cwe="CWE-1321",
                        remediation=("Tolak key berbahaya di parser body/query. Update body-parser/qs "
                                     "(qs >=6.10, lodash >=4.17.21)."),
                        references=["https://snyk.io/learn/prototype-pollution-attacks/"],
                    ))
                    return findings
    finally:
        client.close()
    return findings
