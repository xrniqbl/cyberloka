"""HTTP Parameter Pollution probe."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    urls = (state.param_urls if state else []) + [target.base_url]
    seen_keys: set[tuple[str, str]] = set()
    client = HttpClient(config)
    try:
        for url in urls[:10]:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                continue
            k, v = params[0]
            if (parsed.netloc, k) in seen_keys:
                continue
            seen_keys.add((parsed.netloc, k))
            base = client.get(url)
            polluted = list(params) + [(k, "cyberloka-pollute")]
            mutated = urlunparse(parsed._replace(query=urlencode(polluted)))
            r = client.get(mutated)
            if base is None or r is None:
                continue
            base_len = len(base.text or "")
            r_len = len(r.text or "")
            if r.status_code != base.status_code or abs(r_len - base_len) > 50:
                findings.append(Finding(
                    module="hpp",
                    title=f"Parameter `{k}` rentan HTTP Parameter Pollution",
                    severity=Severity.LOW,
                    description=("Mengirim parameter dengan nama sama dua kali mengubah "
                                 "respons aplikasi. Dapat dipakai untuk melewati validasi "
                                 "atau WAF."),
                    target=mutated,
                    evidence=f"base status/len = {base.status_code}/{base_len}; "
                             f"polluted = {r.status_code}/{r_len}",
                    cwe="CWE-235", confidence="tentative",
                    remediation=("Normalisasi parameter ganda di server (pilih satu eksplisit), "
                                 "konsisten antar layer (web server, framework)."),
                ))
                break
    finally:
        client.close()
    return findings
