"""Command injection probes — strict-validation v0.10.1.

False-positive guards:
  * Marker-based: kirim DUA marker berbeda secara berurutan; HARUS
    keduanya muncul di response masing-masing dan tidak muncul di
    request kontrol tanpa payload.
  * Time-based: ulangi 2x. Hanya laporkan kalau elapsed melewati batas
    pada KEDUA percobaan, dan request kontrol (tanpa sleep) cepat.
"""
from __future__ import annotations

import secrets
import time

from cyberloka.active._helpers import append_param, iter_param_urls
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

SLEEP_S = 4


def _make_marker_payloads(marker: str) -> list[str]:
    return [
        f";echo {marker}",
        f"|echo {marker}",
        f"&& echo {marker}",
        f"`echo {marker}`",
        f"$(echo {marker})",
    ]


SLEEP_PAYLOADS = [
    f";sleep {SLEEP_S}",
    f"|sleep {SLEEP_S}",
    f"&& sleep {SLEEP_S}",
    f"`sleep {SLEEP_S}`",
    f"$(sleep {SLEEP_S})",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("cmdi")
    try:
        url = target.base_url
        if "?" not in url:
            url = append_param(url, "cmd", "ping")

        # ---------------- Marker test (double-marker cross-check) ----------------
        marker_a = f"cyberlokaA{secrets.token_hex(3)}"
        marker_b = f"cyberlokaB{secrets.token_hex(3)}"
        for payload_a, payload_b in zip(
            _make_marker_payloads(marker_a), _make_marker_payloads(marker_b)
        ):
            for param, mutated_a in iter_param_urls(url, "x" + payload_a):
                resp_a = client.get(mutated_a)
                if resp_a is None or marker_a not in (resp_a.text or ""):
                    continue
                # Cross-check with second marker
                mutated_b = next(
                    (u for _, u in iter_param_urls(url, "x" + payload_b)
                     if f"={list(iter_param_urls(url, 'x'))[0][0]}=" or True),
                    None,
                )
                # Simpler: re-mutate same param with marker_b
                mutated_b = mutated_a.replace(marker_a, marker_b)
                resp_b = client.get(mutated_b)
                if resp_b is None or marker_b not in (resp_b.text or ""):
                    continue
                # Control: param tanpa command separator should NOT echo marker
                ctrl_url = mutated_a.replace(payload_a, "ctrlbenign")
                ctrl = client.get(ctrl_url)
                ctrl_body = (ctrl.text or "") if ctrl is not None else ""
                if marker_a in ctrl_body:
                    # server echoes whatever — false positive
                    continue

                proof = ValidationProof(
                    method="double-marker",
                    confirmed=True,
                    steps=[
                        f"Kirim payload marker `{marker_a}` pada param `{param}`.",
                        f"Response memuat `{marker_a}` (echo).",
                        f"Kirim payload marker kedua `{marker_b}` pada param yang sama.",
                        f"Response kedua memuat `{marker_b}` (echo).",
                        "Kontrol: kirim nilai biasa (tanpa separator) — marker TIDAK muncul.",
                    ],
                    samples=[
                        f"hit_a: param={param} marker={marker_a}",
                        f"hit_b: param={param} marker={marker_b}",
                    ],
                )
                findings.append(
                    Finding(
                        module="cmdi",
                        title=f"Command Injection (double-marker) pada `{param}`",
                        severity=Severity.CRITICAL,
                        description=(
                            "Dua marker berbeda yang disuntik lewat command-separator "
                            "muncul kembali di response — shell di server menjalankan "
                            "perintah `echo <marker>`."
                        ),
                        target=mutated_a,
                        evidence=f"payload_a={payload_a} payload_b={payload_b}",
                        cwe="CWE-78",
                        confidence="confirmed",
                        urls=[mutated_a, mutated_b],
                        remediation=(
                            "JANGAN passing input user ke shell (`os.system`, `exec`, "
                            "`subprocess(shell=True)`). Pakai API yang menerima list of args, "
                            "validasi whitelist parameter, atau hindari shell sama sekali."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                        ],
                        extra=build_extra(
                            proof=proof,
                            awam_steps=awam_steps,
                            awam_summary=awam_summary,
                        ),
                    )
                )
                return findings

        # ---------------- Time-based test (double-confirmation) ------------------
        for payload in SLEEP_PAYLOADS:
            for param, mutated in iter_param_urls(url, "x" + payload):
                # Baseline (control) — request tanpa sleep
                ctrl_url = mutated.replace(payload, "ctrlbenign")
                t0 = time.monotonic()
                ctrl = client.get(ctrl_url)
                ctrl_elapsed = time.monotonic() - t0
                if ctrl is None or ctrl_elapsed >= SLEEP_S - 0.5:
                    # baseline already slow → skip
                    continue
                # First sleep run
                t0 = time.monotonic()
                resp = client.get(mutated)
                e1 = time.monotonic() - t0
                if resp is None or e1 < SLEEP_S - 0.5:
                    continue
                # Second sleep run (confirm)
                t0 = time.monotonic()
                resp2 = client.get(mutated)
                e2 = time.monotonic() - t0
                if resp2 is None or e2 < SLEEP_S - 0.5:
                    continue

                proof = ValidationProof(
                    method="time-based-double-confirm",
                    confirmed=True,
                    steps=[
                        f"Baseline: request kontrol selesai {ctrl_elapsed:.2f}s.",
                        f"Run #1 dengan `sleep {SLEEP_S}`: elapsed {e1:.2f}s.",
                        f"Run #2 dengan `sleep {SLEEP_S}`: elapsed {e2:.2f}s.",
                        f"Konsistensi: kedua run >= {SLEEP_S}s → command shell jalan.",
                    ],
                    samples=[f"ctrl={ctrl_elapsed:.2f}s e1={e1:.2f}s e2={e2:.2f}s"],
                )
                findings.append(
                    Finding(
                        module="cmdi",
                        title=f"Command Injection (time-based) pada `{param}`",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Respons tertunda ~{e1:.1f}s & ~{e2:.1f}s pada dua percobaan "
                            f"setelah menyuntikkan `sleep {SLEEP_S}`, sementara request "
                            f"kontrol selesai {ctrl_elapsed:.2f}s — indikasi kuat command "
                            "injection (sudah double-confirmed)."
                        ),
                        target=mutated,
                        evidence=f"ctrl={ctrl_elapsed:.2f}s e1={e1:.2f}s e2={e2:.2f}s payload={payload}",
                        cwe="CWE-78",
                        confidence="confirmed",
                        urls=[mutated],
                        remediation=(
                            "Hindari shell pass-through. Gunakan subprocess dengan list args "
                            "dan whitelist input."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                        ],
                        extra=build_extra(
                            proof=proof,
                            awam_steps=awam_steps,
                            awam_summary=awam_summary,
                        ),
                    )
                )
                return findings
    finally:
        client.close()
    return findings
