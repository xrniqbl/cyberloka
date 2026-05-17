"""NoSQL injection detection (MongoDB-style operators).

Strategi non-destruktif:
- Bandingkan response asli dengan response saat parameter diganti payload
  yang menyuntikkan operator Mongo (`[$ne]=null`, `[$gt]=`, `[$regex]=.*`).
- Bila signifikan berbeda dalam ukuran/status_code, ada indikasi bahwa
  query Mongo dibentuk dari input user tanpa sanitasi.
- Juga uji JSON body bila Content-Type endpoint memungkinkan POST JSON
  (best-effort).
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.active._helpers import collect_target_urls, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Set query string menjadi {param}[$ne]=null (URL form yang umum diparsing
# Express/Mongoose menjadi object Mongo).
def _craft_op(url: str, param: str, op: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    new_pairs = []
    replaced = False
    for k, v in pairs:
        if k == param and not replaced:
            new_pairs.append((f"{k}[{op}]", value))
            replaced = True
        else:
            new_pairs.append((k, v))
    if not replaced:
        new_pairs.append((f"{param}[{op}]", value))
    return urlunparse(p._replace(query=urlencode(new_pairs, doseq=True)))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    seen_param: set[str] = set()
    client = HttpClient(config)
    try:
        for url in collect_target_urls(target, default_param="id"):
            # Get baseline
            base_resp = client.get(url)
            if base_resp is None:
                continue
            base_len = len(base_resp.text or "")
            base_status = base_resp.status_code

            # Untuk tiap parameter di URL coba operator [$ne]=invalidvalue
            for param, _ in iter_param_urls(url, "1"):
                key = f"{url.split('?')[0]}|{param}"
                if key in seen_param:
                    continue
                seen_param.add(key)

                # Probe 1: [$ne]=cyberloka — harus return *banyak* record bila param dipakai sebagai filter Mongo
                ne_url = _craft_op(url, param, "$ne", "cyberloka_ne_marker")
                ne_resp = client.get(ne_url)

                # Probe 2: [$regex]=^.{0,9999}$ — match-all
                rx_url = _craft_op(url, param, "$regex", "^.{0,9999}$")
                rx_resp = client.get(rx_url)

                if ne_resp is None or rx_resp is None:
                    continue

                ne_len = len(ne_resp.text or "")
                rx_len = len(rx_resp.text or "")

                # Heuristik: kedua probe menghasilkan response signifikan lebih besar dari baseline,
                # atau status berubah dari 4xx ke 2xx.
                ratio_ne = ne_len / max(1, base_len)
                ratio_rx = rx_len / max(1, base_len)
                status_flip = (
                    base_status >= 400 and ne_resp.status_code < 400 and rx_resp.status_code < 400
                )
                size_jump = ratio_ne >= 1.4 and ratio_rx >= 1.4 and abs(ne_len - rx_len) < max(ne_len, rx_len) * 0.2

                if status_flip or size_jump:
                    findings.append(
                        Finding(
                            module="nosqli",
                            title=f"Kemungkinan NoSQL Injection (MongoDB) pada `{param}`",
                            severity=Severity.HIGH,
                            description=(
                                "Saat parameter diisi operator Mongo (`$ne`, `$regex`), response "
                                "berubah signifikan vs nilai biasa. Ini indikasi parameter "
                                "dipakai langsung sebagai filter query."
                            ),
                            target=url,
                            evidence=(
                                f"baseline_status={base_status} len={base_len}\n"
                                f"$ne_status={ne_resp.status_code} len={ne_len} ratio={ratio_ne:.2f}\n"
                                f"$regex_status={rx_resp.status_code} len={rx_len} ratio={ratio_rx:.2f}"
                            ),
                            cwe="CWE-943",
                            confidence="tentative",
                            remediation=(
                                "Validasi tipe input: terima hanya tipe yang diharapkan (mis. "
                                "string ObjectId, int). Untuk Express+Mongoose, gunakan "
                                "`express-mongo-sanitize` atau validasi via Joi/Zod. JANGAN "
                                "passing `req.query` langsung sebagai filter."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                            ],
                        )
                    )

            # Probe JSON body untuk endpoint POST yang dideteksi crawler
            discovered = getattr(target, "discovered", None)
            if discovered is None:
                continue
            for ep in getattr(discovered, "endpoints", []):
                if ep.method.upper() != "POST" or not ep.params:
                    continue
                if not ep.params:
                    continue
                # Hanya satu probe per endpoint untuk hemat request
                payload: dict = {}
                for f in ep.params:
                    payload[f] = {"$ne": "cyberloka_marker"}
                resp_json = client.post(
                    ep.url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp_norm = client.post(
                    ep.url,
                    json={f: "x" for f in ep.params},
                    headers={"Content-Type": "application/json"},
                )
                if resp_json is None or resp_norm is None:
                    continue
                if resp_json.status_code < 400 and resp_norm.status_code >= 400:
                    findings.append(
                        Finding(
                            module="nosqli",
                            title=f"Kemungkinan NoSQL Injection JSON pada {ep.url}",
                            severity=Severity.HIGH,
                            description=(
                                "Body JSON yang memuat operator `$ne` diterima (2xx) sementara "
                                "body normal ditolak — server kemungkinan men-passthrough JSON "
                                "ke query Mongo."
                            ),
                            target=ep.url,
                            evidence=(
                                f"json_op_status={resp_json.status_code} normal_status={resp_norm.status_code}"
                            ),
                            cwe="CWE-943",
                            confidence="tentative",
                            remediation=(
                                "Validasi schema body. Tolak object yang field-nya bernilai "
                                "object (bila harusnya string/number)."
                            ),
                        )
                    )
    finally:
        client.close()
    return findings
