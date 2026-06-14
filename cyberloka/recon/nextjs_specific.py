"""Next.js / React app specific recon."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core import probe
from cyberloka.core.config import ScanConfig

NEXT_PATHS = [
    "/_next/static/chunks/",
    "/_next/data/",
    "/__nextjs_original-stack-frame",
    "/api/",
]
BUILD_ID_RE = re.compile(r'/_next/data/([A-Za-z0-9_-]+)/')


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        body = r.text or ""
        is_next = "next.js" in (r.headers.get("X-Powered-By", "") or "").lower() or \
                  "_next/static" in body or "next/script" in body
        if not is_next:
            return findings

        # Build ID
        m = BUILD_ID_RE.search(body)
        if m:
            findings.append(Finding(
                module="nextjs_specific",
                title=f"Next.js build ID terekspos: `{m.group(1)}`",
                severity=Severity.INFO,
                description=("Build ID Next.js memungkinkan attacker memetakan endpoint "
                             "data (`/_next/data/<id>/<page>.json`) dan mengambil props server."),
                target=target.base_url, evidence=m.group(0),
                cwe="CWE-200",
                remediation=("Kurangi metadata yang ter-publish, dan pastikan getServerSideProps "
                             "tidak mengembalikan data sensitif tanpa otorisasi."),
            ))
            # Try fetching a known data route
            data_url = urljoin(target.base_url, f"/_next/data/{m.group(1)}/index.json")
            rd = probe.verify_real(client, target, data_url,
                                   validator=lambda c, b: probe.is_json_doc(c, b))
            if rd is not None:
                findings.append(Finding(
                    module="nextjs_specific",
                    title="Next.js _next/data JSON dapat di-fetch publik",
                    severity=Severity.LOW,
                    description=("Endpoint hydration data Next.js mengembalikan props server. "
                                 "Verifikasi tidak ada data sensitif di props."),
                    target=data_url,
                    evidence=f"len={len(rd.text or '')}",
                    cwe="CWE-200",
                ))

        # Source map
        for chunk_path in re.findall(r'/_next/static/chunks/([^"\']+\.js)', body)[:3]:
            map_url = urljoin(target.base_url, f"/_next/static/chunks/{chunk_path}.map")
            r2 = client.get(map_url)
            if r2 is not None and r2.status_code == 200 and \
                    ("sourcesContent" in (r2.text or "") or "sources" in (r2.text or "")):
                findings.append(Finding(
                    module="nextjs_specific",
                    title="Source map Next.js terekspos di production",
                    severity=Severity.MEDIUM,
                    description=("File `.map` membocorkan source TypeScript/JavaScript asli. "
                                 "Attacker dapat membaca logika bisnis & menemukan endpoint internal."),
                    target=map_url,
                    cwe="CWE-540",
                    remediation=("Set `productionBrowserSourceMaps: false` di `next.config.js` "
                                 "atau hapus file .map di build production."),
                ))
                break

        # Stack frame leak (dev mode)
        sf = probe.verify_real(client, target, urljoin(target.base_url, "/__nextjs_original-stack-frame"),
                               validator=lambda c, b: not probe.looks_like_html(b))
        if sf is not None:
            findings.append(Finding(
                module="nextjs_specific",
                title="Next.js dev endpoint aktif (`__nextjs_original-stack-frame`)",
                severity=Severity.HIGH,
                description="Endpoint development Next.js merespons di production = mode dev aktif.",
                target=str(sf.url), cwe="CWE-489",
                remediation="Pastikan `next start` (production), bukan `next dev`, dipakai di server.",
            ))
    finally:
        client.close()
    return findings
