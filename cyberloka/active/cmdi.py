"""Command injection probes - marker random + baseline latency + reproduction.

Akurasi:
1. Marker UNIK per scan (random nonce) supaya tidak bertabrakan dengan dev
   page yang menampilkan kata 'cyberloka'.
2. Baseline latency dipakai untuk konfirmasi time-based: hanya bila latency
   payload >= sleep-0.7s DAN baseline < sleep-1.5s.
3. Reproduksi 1x untuk meredam jitter.
"""
from __future__ import annotations

import secrets
import time

from cyberloka.active._helpers import (
    append_param,
    baseline,
    candidate_params,
    iter_param_urls,
    stable_latency,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

SLEEP_S = 5
PARAM_HINTS = ("cmd", "exec", "host", "ip", "ping", "query", "name")


def _marker_payloads(marker: str) -> list[str]:
    return [
        f";echo {marker}",
        f"|echo {marker}",
        f"&& echo {marker}",
        f"`echo {marker}`",
        f"$(echo {marker})",
        f";printf {marker}",
        f"& echo {marker}",
        f"| echo {marker}",
    ]


def _sleep_payloads(s: int) -> list[str]:
    return [
        f";sleep {s}",
        f"|sleep {s}",
        f"&& sleep {s}",
        f"`sleep {s}`",
        f"$(sleep {s})",
        f"& ping -n {s + 1} 127.0.0.1",
        f"| ping -n {s + 1} 127.0.0.1",
    ]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        if "?" not in url:
            for cand in candidate_params(url, PARAM_HINTS):
                url = append_param(url, cand, "x")
                break

        base = baseline(client, url, samples=2)
        base_lat = base["latency"] if base else stable_latency(client, url)
        seen: set[str] = set()

        # Marker-based
        marker = "CYB" + secrets.token_hex(4) + "MK"
        for payload in _marker_payloads(marker):
            for param, mutated in iter_param_urls(url, "x" + payload):
                if param in seen:
                    continue
                resp = client.get(mutated)
                if resp is None:
                    continue
                if marker in (resp.text or ""):
                    resp2 = client.get(mutated)
                    confidence = (
                        "confirmed"
                        if resp2 is not None and marker in (resp2.text or "")
                        else "firm"
                    )
                    findings.append(
                        Finding(
                            module="cmdi",
                            title=f"Command Injection (marker) terverifikasi pada `{param}`",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Marker unik `{marker}` muncul pada respons setelah menyuntikkan "
                                "command separator. Berarti shell mengeksekusi input attacker → "
                                "potensi RCE penuh."
                            ),
                            target=mutated,
                            evidence=(
                                f"payload={payload!r}\n"
                                f"marker={marker}\n"
                                f"snippet:\n{truncate(resp.text or '', 240)}"
                            ),
                            cwe="CWE-78",
                            confidence=confidence,
                            urls=[mutated],
                            remediation=(
                                "JANGAN passing input user ke shell (`os.system`, `exec`, "
                                "`subprocess(shell=True)`, `eval`). Pakai API yang menerima "
                                "list of args, validasi whitelist parameter, atau hindari "
                                "shell sama sekali."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                            ],
                        )
                    )
                    seen.add(param)
                    break

        # Time-based
        for payload in _sleep_payloads(SLEEP_S):
            for param, mutated in iter_param_urls(url, "x" + payload):
                if param in seen:
                    continue
                t0 = time.monotonic()
                resp = client.get(mutated)
                dt = time.monotonic() - t0
                if resp is None:
                    continue
                if dt >= SLEEP_S - 0.7 and base_lat < SLEEP_S - 1.5:
                    t0b = time.monotonic()
                    resp2 = client.get(mutated)
                    dt2 = time.monotonic() - t0b
                    confidence = "confirmed" if resp2 and dt2 >= SLEEP_S - 0.7 else "firm"
                    findings.append(
                        Finding(
                            module="cmdi",
                            title=f"Command Injection (time-based) terverifikasi pada `{param}`",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Respons tertunda ~{dt:.1f}s saat payload memerintahkan sleep "
                                f"{SLEEP_S}s, sementara baseline ~{base_lat:.2f}s. "
                                "Indikasi kuat shell mengeksekusi input."
                            ),
                            target=mutated,
                            evidence=(
                                f"payload={payload!r}\n"
                                f"baseline_latency={base_lat:.2f}s\n"
                                f"first_attempt={dt:.2f}s\n"
                                f"reproduced={dt2:.2f}s"
                            ),
                            cwe="CWE-78",
                            confidence=confidence,
                            urls=[mutated],
                            remediation=(
                                "Sama dengan marker-based: hindari shell pass-through. "
                                "Gunakan subprocess dengan list args dan whitelist input."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                            ],
                        )
                    )
                    seen.add(param)
                    break
    finally:
        client.close()
    return findings
