"""Pull historical URLs from Wayback Machine + crt.sh subdomain enumeration."""
from __future__ import annotations

import json

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.is_ip:
        return findings
    host = target.host
    client = HttpClient(config)
    try:
        # crt.sh transparency
        r = client.get(f"https://crt.sh/?q=%25.{host}&output=json")
        ct_subs: set[str] = set()
        if r is not None and r.status_code == 200:
            try:
                data = json.loads(r.text or "[]")
                for row in data:
                    name = row.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line.endswith(host) and line != host and "*" not in line:
                            ct_subs.add(line)
            except json.JSONDecodeError:
                pass
        if ct_subs:
            findings.append(Finding(
                module="wayback",
                title=f"{len(ct_subs)} subdomain ditemukan via Certificate Transparency",
                severity=Severity.INFO,
                description=("Subdomain dari log CT (crt.sh) — dapat dipakai untuk "
                             "memperluas attack surface. Verifikasi apakah ada yang "
                             "tidak seharusnya publik."),
                target=host,
                evidence="\n".join(sorted(ct_subs)[:30]),
                confidence="confirmed",
                extra={"subdomains": sorted(ct_subs)},
            ))

        # Wayback Machine
        wb = client.get(f"https://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=json"
                        f"&fl=original&collapse=urlkey&limit=200")
        wb_urls: list[str] = []
        if wb is not None and wb.status_code == 200:
            try:
                data = json.loads(wb.text or "[]")
                wb_urls = [row[0] for row in data[1:] if row]
            except json.JSONDecodeError:
                pass
        if wb_urls:
            findings.append(Finding(
                module="wayback",
                title=f"{len(wb_urls)} URL historis ditemukan via Wayback Machine",
                severity=Severity.INFO,
                description=("URL dari arsip dapat membongkar endpoint lama (admin, debug, "
                             "API beta) yang masih hidup."),
                target=host,
                evidence="\n".join(wb_urls[:25]),
                confidence="confirmed",
            ))
    finally:
        client.close()
    return findings
