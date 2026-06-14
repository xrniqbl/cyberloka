"""XPath injection probe — verification-first.

Versi lama: kata "xpath"/"xml parser" di body → flag. Halaman yang menyebut kata itu
secara statis = false positive. Lama juga keliru menambah param `q` kedua (Flask
mengambil yang pertama) sehingga payload diabaikan. Kini: ganti nilai param ASLI,
error harus ABSEN di baseline, MUNCUL setelah payload pemecah, DAN kontrol benign
tetap bersih (error dipicu payload).
"""
from __future__ import annotations

from cyberloka.active._helpers import param_names, replace_param
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

PAYLOADS = ["' or '1'='1", "'] | //user/* | //a[", "*"]
ERROR_HINT = ("xpath", "xml parser", "xpathexception", "system.xml.xpath")


def _has_error(text: str | None) -> bool:
    low = (text or "").lower()
    return any(e in low for e in ERROR_HINT)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    client = HttpClient(config)
    try:
        for url in s.param_urls[:5]:
            for param in param_names(url):
                # Baseline + kontrol: input benign tidak boleh memunculkan error XPath.
                base = client.get(replace_param(url, param, "cyberlokabenign"))
                if base is None or _has_error(base.text):
                    continue
                for payload in PAYLOADS:
                    r = client.get(replace_param(url, param, payload))
                    if r is None or not _has_error(r.text):
                        continue
                    ctrl = client.get(replace_param(url, param, "cyberlokabenign2"))
                    if ctrl is not None and _has_error(ctrl.text):
                        continue  # error muncul untuk input apa pun → bukan dipicu payload
                    findings.append(Finding(
                        module="xpath_injection", target=replace_param(url, param, payload),
                        title=f"XPath injection TERVERIFIKASI pada `{param}`",
                        severity=Severity.HIGH,
                        confidence="confirmed",
                        description=("Error XPath ABSEN di baseline & untuk input benign, tapi MUNCUL "
                                     "setelah payload pemecah filter — input masuk ke ekspresi XPath."),
                        evidence=f"payload={payload!r}; error absen di baseline+kontrol",
                        cwe="CWE-643",
                        remediation="Pakai parametrik XPath (XQuery prepared) atau pindah ke JSON.",
                    ))
                    return findings
    finally:
        client.close()
    return findings
