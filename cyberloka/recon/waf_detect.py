"""WAF / CDN fingerprint detection."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# (regex pattern, where: header|body|cookie, label)
WAF_SIGNATURES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"cloudflare", re.I), "header", "Cloudflare"),
    (re.compile(r"__cfduid|cf_clearance|__cf_bm", re.I), "cookie", "Cloudflare"),
    (re.compile(r"akamai|akamaighost", re.I), "header", "Akamai"),
    (re.compile(r"ak_bmsc", re.I), "cookie", "Akamai Bot Manager"),
    (re.compile(r"x-sucuri-id|x-sucuri-cache", re.I), "header", "Sucuri"),
    (re.compile(r"incapsula|x-iinfo|visid_incap_", re.I), "any", "Imperva Incapsula"),
    (re.compile(r"awselb|x-amz-cf-id|x-amz-cf-pop", re.I), "header", "AWS CloudFront/ELB"),
    (re.compile(r"x-amzn-requestid|x-amzn-trace-id", re.I), "header", "AWS API Gateway"),
    (re.compile(r"big-?ip|tsdomain|f5-bigip", re.I), "any", "F5 BIG-IP"),
    (re.compile(r"barracuda", re.I), "any", "Barracuda WAF"),
    (re.compile(r"fastly|x-served-by|x-cache-hits", re.I), "header", "Fastly"),
    (re.compile(r"x-azure-ref|azure", re.I), "header", "Azure Front Door"),
    (re.compile(r"x-cdn.*google|gws|gfe", re.I), "header", "Google Cloud / GFE"),
    (re.compile(r"mod_security|modsecurity", re.I), "any", "ModSecurity"),
    (re.compile(r"wzws-ray|safe-sec", re.I), "header", "Wangsu/CDN"),
    (re.compile(r"x-fireeye", re.I), "header", "FireEye"),
    (re.compile(r"x-sphinx", re.I), "header", "Cloudfront"),
]

# Mild but harmless probe to provoke WAF block-page
PROBE_PATHS = ["/?id=1' OR '1'='1", "/?q=<script>alert(1)</script>"]


def _scan_response(resp, evidence: list[str]) -> set[str]:
    found: set[str] = set()
    if resp is None:
        return found
    header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    cookie_blob = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
    body_blob = (resp.text or "")[:4096]
    for rgx, where, label in WAF_SIGNATURES:
        target_text = ""
        if where == "header":
            target_text = header_blob
        elif where == "cookie":
            target_text = cookie_blob
        elif where == "body":
            target_text = body_blob
        else:  # any
            target_text = header_blob + "\n" + cookie_blob + "\n" + body_blob
        if rgx.search(target_text):
            if label not in found:
                m = rgx.search(target_text)
                if m:
                    evidence.append(f"{label} via {where}: {m.group(0)[:80]}")
            found.add(label)
    return found


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    detected: set[str] = set()
    evidence: list[str] = []
    try:
        resp = client.get(target.base_url)
        detected |= _scan_response(resp, evidence)

        # Probe to see if WAF kicks in (block page, status 403/406/501)
        blocked = False
        for p in PROBE_PATHS:
            r = client.get(target.origin + p, allow_redirects=False)
            if r is not None and r.status_code in (403, 406, 419, 429, 501, 999):
                blocked = True
                detected |= _scan_response(r, evidence)
        if blocked and not detected:
            evidence.append("Probe diblokir (status 403/406/429) namun signature WAF tidak teridentifikasi.")
            detected.add("Unknown WAF")
    finally:
        client.close()

    if detected:
        findings.append(
            Finding(
                module="waf_detect",
                title=f"WAF / proxy terdeteksi: {', '.join(sorted(detected))}",
                severity=Severity.INFO,
                description=(
                    "Identifikasi WAF/CDN penting untuk perencanaan pengujian. "
                    "WAF bukan pengganti perbaikan kode — pastikan rule set up-to-date "
                    "dan tidak hanya bergantung pada virtual patching."
                ),
                target=target.base_url,
                evidence="\n".join(evidence) if evidence else "",
                remediation=(
                    "Verifikasi rule WAF tetap mendeteksi payload terbaru. Tetap perbaiki "
                    "bug pada aplikasi (defense in depth). Audit log WAF untuk anomali."
                ),
                references=["https://owasp.org/www-community/Web_Application_Firewall"],
                extra={"waf": sorted(detected)},
            )
        )
    else:
        findings.append(
            Finding(
                module="waf_detect",
                title="Tidak ada WAF/CDN yang terdeteksi",
                severity=Severity.LOW,
                description=(
                    "Tidak ada signature WAF/CDN umum yang terdeteksi. Aplikasi enterprise "
                    "publik biasanya memerlukan lapisan WAF/CDN untuk mitigasi DDoS dan "
                    "filtering payload generik."
                ),
                target=target.base_url,
                remediation=(
                    "Pertimbangkan deployment Cloudflare, AWS WAF, Akamai, atau ModSecurity "
                    "(via Nginx/Apache) untuk lapisan pertahanan tambahan."
                ),
            )
        )
    return findings
