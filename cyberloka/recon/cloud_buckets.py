"""Enumerate S3/GCS/Azure buckets with predictable names."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PREFIXES = ("", "www.", "static.", "uploads.", "media.", "assets.")
SUFFIXES = ("", "-prod", "-staging", "-dev", "-backup", "-data",
            "-uploads", "-static", "-media", "-private", "-public")

# (template_url, label)
TEMPLATES = [
    ("https://{name}.s3.amazonaws.com/", "S3"),
    ("https://s3.amazonaws.com/{name}/", "S3-path-style"),
    ("https://storage.googleapis.com/{name}/", "GCS"),
    ("https://{name}.blob.core.windows.net/", "Azure Blob"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.is_ip:
        return findings
    apex = target.host
    parts = apex.split(".")
    base = parts[-2] if len(parts) >= 2 else parts[0]

    candidates = set()
    for pfx in PREFIXES:
        for sfx in SUFFIXES:
            candidates.add(f"{pfx}{base}{sfx}")
    candidates = list(candidates)[:25]

    client = HttpClient(config)
    found: list[tuple[str, str, int, str]] = []
    try:
        for name in candidates:
            for tpl, label in TEMPLATES:
                url = tpl.format(name=name)
                r = client.get(url, allow_redirects=False)
                if r is None:
                    continue
                body = (r.text or "")[:500]
                # S3: 200 with ListBucketResult, or 403 Access Denied (exists, locked)
                if r.status_code == 200 and ("<ListBucketResult" in body or "<EnumerationResults" in body):
                    found.append((label, url, r.status_code, "PUBLIC LISTING"))
                elif r.status_code in (200, 403) and any(
                    sig in body for sig in (
                        "AccessDenied", "Listing of", "AllAccessDisabled", "ServiceUnavailable"
                    )
                ):
                    if r.status_code == 200:
                        found.append((label, url, r.status_code, "exists, possibly readable"))
                    else:
                        found.append((label, url, r.status_code, "exists, locked (still leaks name)"))
        if found:
            critical = [f for f in found if "PUBLIC LISTING" in f[3]]
            sev = Severity.CRITICAL if critical else Severity.MEDIUM
            findings.append(Finding(
                module="cloud_buckets", target=apex,
                title=f"{len(found)} bucket cloud terdeteksi terkait domain",
                severity=sev,
                description=("Bucket S3/GCS/Azure dengan nama mirip domain ditemukan. "
                             "Bucket dengan listing publik dapat membongkar database backup, "
                             "asset internal, atau PII pelanggan."),
                evidence="\n".join(f"[{f[0]}] {f[1]} -> {f[2]} {f[3]}" for f in found[:15]),
                cwe="CWE-538",
                remediation=("Set Block Public Access di setiap bucket. Audit policy dengan "
                             "`aws s3api get-bucket-policy`. Untuk bucket yang harus publik "
                             "(asset CDN), pastikan TIDAK ada file sensitif di dalamnya."),
                references=["https://aws.amazon.com/s3/features/block-public-access/"],
            ))
    finally:
        client.close()
    return findings
