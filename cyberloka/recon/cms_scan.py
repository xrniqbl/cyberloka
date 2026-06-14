"""WordPress / Drupal / Joomla version + plugin enum."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core import probe
from cyberloka.core.config import ScanConfig

WP_PLUGIN_PATHS = [
    "/wp-content/plugins/akismet/readme.txt",
    "/wp-content/plugins/contact-form-7/readme.txt",
    "/wp-content/plugins/woocommerce/readme.txt",
    "/wp-content/plugins/elementor/readme.txt",
    "/wp-content/plugins/wordfence/readme.txt",
    "/wp-content/plugins/yoast-seo/readme.txt",
    "/wp-content/plugins/jetpack/readme.txt",
    "/wp-content/plugins/duplicator/readme.txt",
    "/wp-content/plugins/wp-file-manager/readme.txt",
]
WP_VERSION_PATHS = ["/readme.html", "/wp-includes/version.php", "/feed/"]
DRUPAL_PATHS = ["/CHANGELOG.txt", "/core/CHANGELOG.txt", "/?q=user/login"]
JOOMLA_PATHS = ["/administrator/manifests/files/joomla.xml"]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    try:
        nb = probe.negative_baseline(client, target)
        # Detect WP
        is_wp = False
        wp_version = None
        for p in WP_VERSION_PATHS:
            r = client.get(urljoin(base, p.lstrip("/")))
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if nb.looks_like_catchall(r.status_code, body):
                continue
            m = re.search(r"WordPress\s*([\d.]+)", body)
            if m:
                wp_version = m.group(1); is_wp = True; break

        if is_wp:
            sev = Severity.MEDIUM
            old = wp_version and wp_version.startswith(("3.", "4.", "5.0", "5.1", "5.2"))
            if old:
                sev = Severity.HIGH
            findings.append(Finding(
                module="cms_scan", target=base,
                title=f"WordPress terdeteksi (versi {wp_version or 'unknown'})",
                severity=sev,
                description="Versi WP yang lama biasanya punya CVE diketahui publik.",
                evidence=f"version={wp_version}", cwe="CWE-1395",
                remediation="Update ke versi terbaru, hapus readme.html, batasi /wp-admin via IP allowlist.",
            ))

            # Enumerasi plugin
            found_plugins = []
            for p in WP_PLUGIN_PATHS:
                r = client.get(urljoin(base, p.lstrip("/")))
                if r is None or r.status_code != 200:
                    continue
                body = r.text or ""
                if nb.looks_like_catchall(r.status_code, body):
                    continue
                m = re.search(r"Stable tag:\s*([\d.]+)", body)
                plugin_name = p.split("/")[3]
                if m:
                    found_plugins.append(f"{plugin_name} v{m.group(1)}")
            if found_plugins:
                findings.append(Finding(
                    module="cms_scan", target=base,
                    title=f"{len(found_plugins)} plugin WordPress terdeteksi",
                    severity=Severity.LOW,
                    description="Plugin & versi terlihat publik. Banyak plugin WP punya CVE; harus selalu update.",
                    evidence="\n".join(found_plugins), cwe="CWE-200",
                    remediation="Audit plugin terhadap WPScan DB. Hapus readme yang membocorkan versi.",
                ))

        # Drupal
        for p in DRUPAL_PATHS:
            r = client.get(urljoin(base, p.lstrip("/")))
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if nb.looks_like_catchall(r.status_code, body):
                continue
            m = re.search(r"Drupal\s*([\d.]+)", body)
            if m:
                findings.append(Finding(
                    module="cms_scan", target=urljoin(base, p.lstrip("/")),
                    title=f"Drupal terdeteksi (versi {m.group(1)})",
                    severity=Severity.MEDIUM,
                    description="Drupal lama punya CVE seperti Drupalgeddon (CVE-2018-7600).",
                    evidence=m.group(0), cwe="CWE-1395",
                    remediation="Update Drupal ke major release terbaru. Hapus CHANGELOG.txt publik.",
                ))
                break

        # Joomla
        for p in JOOMLA_PATHS:
            r = client.get(urljoin(base, p.lstrip("/")))
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if nb.looks_like_catchall(r.status_code, body):
                continue
            m = re.search(r"<version>([\d.]+)</version>", body)
            if m:
                findings.append(Finding(
                    module="cms_scan", target=urljoin(base, p.lstrip("/")),
                    title=f"Joomla terdeteksi (versi {m.group(1)})",
                    severity=Severity.MEDIUM,
                    description="Joomla manifest publik membocorkan versi.",
                    evidence=m.group(0), cwe="CWE-200",
                    remediation="Blokir akses ke /administrator/manifests/, update Joomla.",
                ))
                break
    finally:
        client.close()
    return findings
