"""Open redirect detection — strict-validation v0.10.3.

Masalah lama: scanner laporkan open-redirect saat Location header memuat
suatu URL tujuan, padahal banyak skenario AMAN:
  * Server redirect ke login/SSO terlebih dahulu (Location berisi URL
    internal), bukan ke domain attacker.
  * Server redirect dengan whitelist — host evil.example.com tetap di-
    rewrite jadi domain origin.
  * Header Location memuat path internal yang dimulai dengan //.

Solusi: 4 lapis validasi.

Lapisan:
  1. Param hint match (next/url/redirect/dst.) - mempersempit param
     kandidat.
  2. Status redirect harus 301/302/303/307/308.
  3. Hostname Location harus EQUAL evil.example.com (bukan endswith
     yang bisa di-bypass kalau ada subdomain wildcard).
  4. Double-token: kirim payload ke domain BERBEDA kedua. Kalau Location
     juga memuat host kedua kita, redirect benar-benar arbitrary, BUKAN
     whitelist yang kebetulan match.
  5. Negative-baseline: param=URL_internal, Location TIDAK boleh memuat
     domain kita. Kalau iya, server selalu echo input -> bukan redirect
     fungsional.
"""
from __future__ import annotations

import secrets
from urllib.parse import urlparse

from cyberloka.active._helpers import candidate_urls, iter_param_urls
from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

REDIRECT_PARAM_HINTS = ("next", "url", "redirect", "redir", "return", "returnto",
                         "rurl", "dest", "destination", "continue", "to", "goto",
                         "callback")
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _evil_url(host: str) -> str:
    return f"https://{host}/cyberloka-{secrets.token_hex(3)}"


def _scan_url(client, url, target, awam_summary, awam_steps):
    findings: list[Finding] = []
    if True:
        candidate_params = [
            p for p, _u in iter_param_urls(url, "PLACEHOLDER")
            if any(h in p.lower() for h in REDIRECT_PARAM_HINTS)
        ]
        if not candidate_params:
            return findings

        for param in candidate_params:
            host_a = "evil-cyberloka-a.example.com"
            host_b = "evil-cyberloka-b.example.com"
            evil_a = _evil_url(host_a)
            evil_b = _evil_url(host_b)

            mutated_a = next(
                (u for p, u in iter_param_urls(url, evil_a) if p == param),
                None,
            )
            if not mutated_a:
                continue
            resp_a = client.get(mutated_a, allow_redirects=False)
            if resp_a is None or resp_a.status_code not in REDIRECT_STATUSES:
                continue
            loc_a = resp_a.headers.get("Location", "")
            host_a_back = urlparse(loc_a).hostname or ""
            if host_a_back != host_a:
                continue

            mutated_b = next(
                (u for p, u in iter_param_urls(url, evil_b) if p == param),
                None,
            )
            if not mutated_b:
                continue
            resp_b = client.get(mutated_b, allow_redirects=False)
            if resp_b is None or resp_b.status_code not in REDIRECT_STATUSES:
                continue
            loc_b = resp_b.headers.get("Location", "")
            host_b_back = urlparse(loc_b).hostname or ""
            if host_b_back != host_b:
                continue

            # Negative-baseline (URL internal yang valid)
            internal_url = target.base_url.rstrip("/") + "/cyberloka-baseline"
            mutated_neg = next(
                (u for p, u in iter_param_urls(url, internal_url) if p == param),
                None,
            )
            if mutated_neg:
                resp_neg = client.get(mutated_neg, allow_redirects=False)
                if resp_neg is not None and resp_neg.status_code in REDIRECT_STATUSES:
                    loc_neg = resp_neg.headers.get("Location", "")
                    h_neg = urlparse(loc_neg).hostname or ""
                    if h_neg in (host_a, host_b):
                        continue  # echo sembarang -> tidak reliable

            proof = ValidationProof(
                method="dual-host+status-redirect+negative-baseline",
                confirmed=True,
                steps=[
                    f"GET {mutated_a} -> {resp_a.status_code} Location: {loc_a}",
                    f"Host Location: `{host_a_back}` == payload host `{host_a}`",
                    f"GET {mutated_b} -> {resp_b.status_code} Location: {loc_b}",
                    f"Host Location: `{host_b_back}` == payload host kedua `{host_b}`",
                    "Negative-baseline (URL internal) -> Location BUKAN domain kita.",
                    "Kesimpulan: server menerima URL arbitrary tanpa validasi.",
                ],
                samples=[f"loc_a={loc_a}", f"loc_b={loc_b}"],
            )
            findings.append(
                Finding(
                    module="redirect",
                    title=f"Open Redirect terkonfirmasi pada parameter `{param}`",
                    severity=Severity.MEDIUM,
                    description=(
                        "Server mengembalikan redirect HTTP ke domain eksternal arbitrer "
                        "(dikonfirmasi 2 host berbeda). Bisa dipakai untuk phishing yang "
                        "tampak resmi karena URL awal masih domain Anda."
                    ),
                    target=mutated_a,
                    evidence=f"Location-A: {loc_a}\nLocation-B: {loc_b}",
                    cwe="CWE-601",
                    confidence="confirmed",
                    urls=[mutated_a],
                    remediation=(
                        "Whitelist destinasi redirect. Bila perlu open redirect, "
                        "gunakan id internal yang dipetakan ke URL, atau verifikasi "
                        "host target ada di daftar yang diizinkan."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                    ],
                    extra=build_extra(
                        proof=proof,
                        awam_steps=awam_steps,
                        awam_summary=awam_summary,
                    ),
                )
            )
            break
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("redirect")
    seen_points: set[tuple] = set()
    try:
        from urllib.parse import urlparse
        # fallback_param=None: open-redirect hanya relevan pada parameter nyata.
        for url in candidate_urls(target, config, fallback_param=None):
            path = urlparse(url).path
            for f in _scan_url(client, url, target, awam_summary, awam_steps):
                key = (path, f.title)
                if key in seen_points:
                    continue
                seen_points.add(key)
                findings.append(f)
    finally:
        client.close()
    return findings
