"""Command injection probes (time-based + marker-based)."""
from __future__ import annotations

import time

from cyberloka.active._helpers import append_param, candidate_urls, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

MARKER_PAYLOADS = [
    ";echo cyberlokaCMD",
    "|echo cyberlokaCMD",
    "&& echo cyberlokaCMD",
    "`echo cyberlokaCMD`",
    "$(echo cyberlokaCMD)",
]

# small sleep to keep impact low
SLEEP_S = 4
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
    try:
        urls = candidate_urls(target, config, "cmd", "ping")

        # Marker test
        marker_probes = [
            (scan_url, payload)
            for payload in MARKER_PAYLOADS
            for scan_url in urls
        ]
        for scan_url, payload in marker_probes:
            for param, mutated in iter_param_urls(scan_url, "x" + payload):
                resp = client.get(mutated)
                if resp is None:
                    continue
                text = resp.text or ""
                if "cyberlokaCMD" in text and "echo cyberlokaCMD" not in text:
                    findings.append(
                        Finding(
                            module="cmdi",
                            title=f"Command Injection (marker) pada `{param}`",
                            severity=Severity.CRITICAL,
                            confidence="confirmed",
                            description=(
                                "Output marker `cyberlokaCMD` muncul pada respons setelah "
                                "menyuntikkan command separator → command shell dieksekusi."
                            ),
                            target=mutated,
                            evidence=f"payload={payload}",
                            cwe="CWE-78",
                            remediation=(
                                "JANGAN passing input user ke shell (`os.system`, `exec`, "
                                "`subprocess(shell=True)`). Pakai API yang menerima list of args, "
                                "validasi whitelist parameter, atau hindari shell sama sekali."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                            ],
                        )
                    )
                    return findings

        # Time-based test
        sleep_probes = [
            (scan_url, payload)
            for payload in SLEEP_PAYLOADS
            for scan_url in urls
        ]
        for scan_url, payload in sleep_probes:
            for param, mutated in iter_param_urls(scan_url, "x" + payload):
                start = time.monotonic()
                resp = client.get(mutated)
                elapsed = time.monotonic() - start
                if resp is None:
                    continue
                if elapsed >= SLEEP_S - 0.5:
                    findings.append(
                        Finding(
                            module="cmdi",
                            title=f"Command Injection (time-based) pada `{param}`",
                            severity=Severity.CRITICAL,
                            confidence="firm",
                            description=(
                                f"Respons tertunda ~{elapsed:.1f}s setelah menyuntikkan "
                                f"`sleep {SLEEP_S}` — indikasi kuat command injection."
                            ),
                            target=mutated,
                            evidence=f"elapsed={elapsed:.2f}s payload={payload}",
                            cwe="CWE-78",
                            remediation=(
                                "Hindari shell pass-through. Gunakan subprocess dengan list args "
                                "dan whitelist input."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                            ],
                        )
                    )
                    return findings
    finally:
        client.close()
    return findings
