"""SSRF probe on URL-shaped query params — verification-first (differential).

Versi lama: status 200 + ("127.0.0.1"/"localhost"/`<title>` di body) → "SSRF".
Heuristik `<title>` membuat halaman HTML apa pun lolos (false positive masif).

Pendekatan baru — diferensial:
  - Kontrol: isi param dengan host eksternal yang TAK MUNGKIN ada (`*.invalid`).
    Kalau aplikasi sebenarnya tidak mem-fetch URL, respons untuk kontrol & untuk
    probe internal akan mirip (sekadar refleksi) → BUKAN SSRF, di-skip.
  - Probe internal: arahkan ke endpoint metadata cloud. Hanya dilaporkan bila
    respons internal BERBEDA nyata dari kontrol DAN memuat penanda metadata yang
    mustahil muncul kecuali server benar-benar mem-fetch-nya.
Untuk SSRF buta (tanpa output), modul `oob_probe` (callback OAST) yang menangani.
"""
from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core import probe as probelib
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

URL_PARAM_HINTS = ("url", "uri", "redirect", "next", "image", "fetch", "dest", "callback", "src", "proxy", "load")
# Endpoint metadata + penanda isinya (mustahil muncul tanpa fetch sungguhan).
INTERNAL_PROBES = [
    ("http://169.254.169.254/latest/meta-data/", ("ami-id", "instance-id", "instance-type", "ami-launch-index", "hostname")),
    ("http://metadata.google.internal/computeMetadata/v1/", ("metadata-flavor", "service-accounts", "oauth2/token")),
]


def _set_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, value if k == key else v) for k, v in params]
    return urlunparse(parsed._replace(query=urlencode(new)))


def _candidates(base_url: str, urls: list[str]) -> list[str]:
    pool = list(dict.fromkeys([base_url] + urls))
    out: list[str] = []
    for u in pool:
        if any(any(h in k.lower() for h in URL_PARAM_HINTS)
               for k, _ in parse_qsl(urlparse(u).query, keep_blank_values=True)):
            out.append(u)
    return out[:15]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    state = get_state(config)
    urls = state.param_urls if state else []
    candidates = _candidates(target.base_url, urls)
    if not candidates:
        return []
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in candidates:
            for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
                if not any(h in k.lower() for h in URL_PARAM_HINTS):
                    continue
                # Kontrol: host eksternal yang tak mungkin ter-resolve.
                ctrl_url = _set_param(url, k, f"http://cyberloka-{secrets.token_hex(4)}.invalid/")
                ctrl = client.get(ctrl_url)
                ctrl_text = (ctrl.text or "") if ctrl is not None else ""
                for probe_url, markers in INTERNAL_PROBES:
                    r = client.get(_set_param(url, k, probe_url))
                    if r is None:
                        continue
                    body = (r.text or "")
                    low = body.lower()
                    hit = next((m for m in markers if m in low), None)
                    # SSRF nyata: penanda metadata muncul DAN respons berbeda dari
                    # kontrol (kalau hanya refleksi, keduanya mirip → tak dihitung).
                    if hit and probelib.similarity(body, ctrl_text) < 0.9:
                        findings.append(Finding(
                            module="ssrf",
                            title=f"SSRF ke metadata cloud TERVERIFIKASI pada `{k}`",
                            severity=Severity.CRITICAL,
                            confidence="confirmed",
                            description=("Server mem-fetch URL yang dikontrol klien dan mengembalikan isi "
                                         "endpoint metadata internal (penanda muncul, respons berbeda dari "
                                         "kontrol host-invalid). Attacker dapat mencuri kredensial IAM."),
                            target=_set_param(url, k, probe_url),
                            evidence=f"marker '{hit}' di respons; berbeda dari kontrol host-invalid",
                            cwe="CWE-918",
                            remediation=("Allowlist host tujuan, blokir IP private/link-local "
                                         "(169.254.0.0/16, 127.0.0.0/8), tolak skema selain http(s), "
                                         "dan untuk AWS pakai IMDSv2 (hop-limit=1)."),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                            ],
                        ))
                        return findings
    finally:
        client.close()
    return findings
