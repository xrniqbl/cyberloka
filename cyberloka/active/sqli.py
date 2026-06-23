"""Detect (likely) SQL injection — strict-validation v0.10.1.

Two paths:
  * Error-based: signature DB-error + control fetch tanpa payload tidak
    memuat signature yang sama (anti generic-error-page false-positive).
  * Boolean-based: stable baseline (panjang konsisten antar fetch),
    payload TRUE & FALSE menghasilkan panjang yang konsisten beda,
    diulang 2x untuk konfirmasi.
"""
from __future__ import annotations

import re

from cyberloka.active._helpers import append_param, candidate_urls, iter_param_urls
from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    stable_baseline,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.reporting.awam import get_awam

ERROR_SIGNATURES = [
    r"sql syntax.*mysql",
    r"warning.*mysql",
    r"valid mysql result",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"odbc.*sql server",
    r"microsoft sql native client",
    r"pg::syntaxerror",
    r"postgresql.*error",
    r"sqlite\.",
    r"sqlite3::sqlexception",
    r"oracle.*ora-\d{4,}",
    r"you have an error in your sql syntax",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.I)

QUOTE_PAYLOAD = "'\""
TRUE_PAYLOAD = " AND 1=1-- -"
FALSE_PAYLOAD = " AND 1=2-- -"


def _scan_url(client: HttpClient, url: str) -> list[tuple[str, str, str, ValidationProof]]:
    """Return list of (param, signature, evidence, proof)."""
    hits: list[tuple[str, str, str, ValidationProof]] = []
    if "?" not in url:
        url = append_param(url, "id", "1")

    # Error-based — with control fetch
    for param, mutated in iter_param_urls(url, "1" + QUOTE_PAYLOAD):
        resp = client.get(mutated)
        if resp is None:
            continue
        m = ERROR_RE.search(resp.text or "")
        if not m:
            continue
        # Control: same param with benign value should NOT trigger DB error.
        ctrl_url = next((u for _, u in iter_param_urls(url, "1")), None)
        ctrl = client.get(ctrl_url) if ctrl_url else None
        if ctrl is not None and ERROR_RE.search(ctrl.text or ""):
            # Generic page already has SQL-error-shaped text → false positive.
            continue
        sig = truncate(m.group(0), 120)
        proof = ValidationProof(
            method="error-based+control",
            confirmed=True,
            steps=[
                f"Inject quote payload pada `{param}` → response memuat signature DB error: `{sig}`.",
                f"Kontrol fetch dengan nilai benign — TIDAK memuat signature.",
                "Konsistensi: error muncul hanya ketika payload disisipkan.",
            ],
            samples=[sig],
        )
        hits.append((param, "error-based", sig, proof))

    # Boolean-based — strict: stable baseline + double-confirm
    for param, mutated_true in iter_param_urls(url, "1" + TRUE_PAYLOAD):
        false_url = mutated_true.replace(
            "1+AND+1%3D1--+-", "1+AND+1%3D2--+-"
        ).replace(TRUE_PAYLOAD, FALSE_PAYLOAD)
        if false_url == mutated_true:
            continue
        # Stable baseline (param=1, no SQL): make sure response is consistent.
        baseline_url = next((u for _, u in iter_param_urls(url, "1")), None)
        if baseline_url is None:
            continue
        stable, lo, hi = stable_baseline(client, baseline_url)
        if not stable:
            # Baseline length flapping by itself — skip to avoid false positive.
            continue

        def _probe() -> tuple[int, int] | None:
            r1 = client.get(mutated_true)
            r2 = client.get(false_url)
            if r1 is None or r2 is None:
                return None
            if r1.status_code != r2.status_code:
                return None
            return len(r1.text or ""), len(r2.text or "")

        first = _probe()
        if first is None:
            continue
        diff1 = abs(first[0] - first[1])
        if diff1 <= 200:
            continue
        # Confirm by repeating the probe.
        second = _probe()
        if second is None:
            continue
        diff2 = abs(second[0] - second[1])
        if diff2 <= 200:
            continue
        # Direction (true longer/shorter than false) must match across both runs.
        if (first[0] > first[1]) != (second[0] > second[1]):
            continue
        proof = ValidationProof(
            method="boolean-based+double-confirm",
            confirmed=True,
            steps=[
                f"Baseline pada `{param}`=1 stabil: {lo}-{hi} bytes.",
                f"Run 1: TRUE-len={first[0]} vs FALSE-len={first[1]} (selisih {diff1}).",
                f"Run 2: TRUE-len={second[0]} vs FALSE-len={second[1]} (selisih {diff2}).",
                "Arah selisih konsisten antar dua run.",
            ],
            samples=[
                f"true_len={first[0]}, false_len={first[1]}",
                f"true_len={second[0]}, false_len={second[1]}",
            ],
        )
        hits.append((
            param,
            "boolean-based",
            f"baseline={lo}-{hi}, t1={first[0]} f1={first[1]} | t2={second[0]} f2={second[1]}",
            proof,
        ))
    return hits


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("sqli")
    seen_points: set[tuple[str, str]] = set()
    try:
        # Smart targeting: uji base_url + SEMUA endpoint berparameter hasil crawl.
        for url in candidate_urls(target, config, fallback_param="id", fallback_value="1"):
            hits = _scan_url(client, url)
            for param, sig, ev, proof in hits:
                # Dedup lintas-URL berdasarkan (path-shape, param).
                from urllib.parse import urlparse
                dedup = (urlparse(url).path, param)
                if dedup in seen_points:
                    continue
                seen_points.add(dedup)
                findings.append(
                    Finding(
                        module="sqli",
                        title=f"Kemungkinan SQL Injection ({sig}) pada parameter `{param}`",
                        severity=Severity.CRITICAL,
                        description=(
                            "Respons aplikasi berubah / memuat error SQL setelah disuntik payload, "
                            "sudah divalidasi dengan kontrol fetch (error-based) atau "
                            "double-run (boolean-based)."
                        ),
                        target=url,
                        evidence=ev,
                        cwe="CWE-89",
                        confidence="confirmed",
                        urls=[url],
                        remediation=(
                            "Gunakan parameterized query / prepared statements. JANGAN concatenate "
                            "input ke query. Untuk ORM, hindari raw SQL dengan input user. Tambahkan "
                            "validasi tipe + WAF sebagai lapis pertahanan tambahan."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        ],
                        extra=build_extra(
                            proof=proof,
                            awam_steps=awam_steps,
                            awam_summary=awam_summary,
                        ),
                    )
                )
    finally:
        client.close()
    return findings
