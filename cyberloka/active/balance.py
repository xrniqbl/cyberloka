"""Balance / wallet manipulation tests for e-commerce.

Saldo (e-wallet, points, cashback) endpoints are favorite targets for
business-logic abuse: negative withdraw, integer overflow, decimal rounding,
parameter tampering. This module probes endpoints whose URLs hint at
balance / wallet / withdraw / topup operations.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

BALANCE_HINTS = re.compile(
    r"(saldo|wallet|balance|withdraw|tarik(?:[-_]?dana)?|topup|top[-_]?up|"
    r"cashback|reward|points?|poin|deposit|transfer(?:[-_]?dana)?|"
    r"refund|payout|disbursement)",
    re.I,
)
AMOUNT_PARAMS = re.compile(
    r"^(amount|jumlah|nominal|total|saldo|qty|points?|poin|value|nilai|harga)$",
    re.I,
)
SUCCESS_MARKERS = (
    "berhasil", "sukses", "success", "ok",
    "transferred", "withdrawn", "approved",
    "saldo bertambah", "topup berhasil",
)
ERROR_MARKERS = (
    "amount must be positive", "negative amount", "amount cannot be negative",
    "invalid amount", "harga tidak valid", "minimum withdraw",
    "tidak mencukupi", "saldo tidak cukup", "insufficient",
)


def _balance_endpoints(config: ScanConfig) -> list[tuple[str, str]]:
    """Return list of (url, method) candidates."""
    state = get_state(config)
    if not state:
        return []
    out: set[tuple[str, str]] = set()
    for u in state.urls + state.param_urls:
        if BALANCE_HINTS.search(u):
            out.add((u, "GET"))
    for form in state.forms:
        action_low = (form.get("action") or "").lower()
        names = " ".join(i.get("name", "") for i in form["inputs"]).lower()
        if BALANCE_HINTS.search(action_low) or BALANCE_HINTS.search(names):
            out.add((form["action"], (form.get("method") or "post").upper()))
    return list(out)[:8]


def _mutate_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = list(parse_qsl(parsed.query, keep_blank_values=True))
    new = []
    replaced = False
    for k, v in params:
        if k == key:
            new.append((k, value)); replaced = True
        else:
            new.append((k, v))
    if not replaced:
        new.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(new)))


def _try_payload(client: HttpClient, url: str, method: str, key: str,
                 payload: str) -> tuple[int, str] | None:
    if method == "POST":
        r = client.post(url, data={key: payload})
    else:
        r = client.get(_mutate_query(url, key, payload))
    if r is None:
        return None
    return r.status_code, (r.text or "")


def _amount_keys_from_url(url: str) -> list[str]:
    keys = []
    for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if AMOUNT_PARAMS.match(k):
            keys.append(k)
    return keys


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    endpoints = _balance_endpoints(config)
    if not endpoints:
        return findings
    client = HttpClient(config)
    try:
        seen: set[str] = set()
        for url, method in endpoints:
            keys = _amount_keys_from_url(url) or ["amount", "jumlah", "nominal"]
            for key in keys[:2]:
                # Test cases
                for label, payload, sev in [
                    ("negatif", "-1000", Severity.HIGH),
                    ("negatif kecil", "-0.01", Severity.HIGH),
                    ("nol", "0", Severity.MEDIUM),
                    ("integer overflow", "99999999999999", Severity.MEDIUM),
                    ("desimal sangat kecil", "0.0001", Severity.MEDIUM),
                ]:
                    res = _try_payload(client, url, method, key, payload)
                    if res is None:
                        continue
                    status, body = res
                    body_low = body.lower()
                    rejected = any(m in body_low for m in ERROR_MARKERS)
                    accepted = (
                        status in (200, 201) and
                        any(m in body_low for m in SUCCESS_MARKERS) and
                        not rejected
                    )
                    if accepted and url not in seen:
                        seen.add(url)
                        findings.append(Finding(
                            module="balance",
                            title=f"Endpoint saldo menerima nilai abnormal ({label}={payload}) pada `{key}`",
                            severity=sev,
                            description=(
                                "Endpoint terkait saldo/wallet/withdraw merespons sukses "
                                "saat dikirim nilai yang seharusnya ditolak. Validasi server "
                                "tampak lemah — verifikasi manual apakah saldo benar-benar "
                                "berubah."
                            ),
                            target=url,
                            evidence=f"method={method}, {key}={payload}, status={status}, "
                                     f"len={len(body)}",
                            cwe="CWE-840",
                            confidence="tentative",
                            remediation=(
                                "Validasi saldo di server dengan ketat: nilai harus > 0, "
                                "<= saldo tersedia, integer atau presisi 2 desimal sesuai "
                                "currency. Pakai database transaction + row-lock saat "
                                "mengubah saldo. Tambahkan idempotency key per request "
                                "untuk mencegah double-spend."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
                            ],
                        ))
                        break
                if url in seen:
                    break
    finally:
        client.close()
    return findings
