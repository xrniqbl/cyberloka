"""S3 (or compatible) world-writable bucket detection.

Auto-validation: untuk hostname yang merupakan bucket S3 (mis. `*.s3.amazonaws.com`
atau `*.s3.<region>.amazonaws.com`), kirim PUT objek anonim, lalu GET. Bila
roundtrip sukses -> bucket world-writable terkonfirmasi.

Hanya jalan kalau target host menyerupai S3-compatible. Tidak akan
beraksi pada domain biasa.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

S3_HOST_RE = re.compile(
    r"\.s3[\.-][a-z0-9-]*\.?amazonaws\.com$|"
    r"\.r2\.cloudflarestorage\.com$|"
    r"\.digitaloceanspaces\.com$|"
    r"\.fra1\.digitaloceanspaces\.com$|"
    r"\.storage\.googleapis\.com$",
    re.I,
)


def _is_bucket(target: Target) -> bool:
    return bool(S3_HOST_RE.search(target.host or ""))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not _is_bucket(target):
        return findings

    client = HttpClient(config)
    obj_path = "cyblok-poc-write-check.txt"
    obj_url = urljoin(target.origin + "/", obj_path)
    body = b"CYBLOK_S3_WRITE_POC"

    try:
        # 1. Probe LIST (public read)
        r_list = client.get(target.origin + "/", allow_redirects=False)
        list_open = False
        if r_list is not None and r_list.status_code == 200:
            txt = r_list.text or ""
            if "<ListBucketResult" in txt or "<Contents>" in txt:
                list_open = True

        # 2. PUT object anonymously (no signed request)
        r_put = client.request("PUT", obj_url, data=body,
                               headers={"Content-Type": "text/plain"},
                               allow_redirects=False)
        if r_put is None:
            return findings
        if r_put.status_code not in (200, 201, 204):
            # Tidak bisa write -> tetap report list_open kalau ada
            if list_open:
                findings.append(_finding(target.origin, "world-readable",
                                         Severity.HIGH,
                                         "ListBucketResult balas 200 publik",
                                         confirm=True))
            return findings

        # 3. GET object kembali untuk konfirmasi
        r_get = client.get(obj_url, allow_redirects=False)
        if r_get is not None and r_get.status_code == 200 and \
                b"CYBLOK_S3_WRITE_POC" in (r_get.content or b""):
            findings.append(_finding(obj_url, "world-writable",
                                     Severity.CRITICAL,
                                     f"PUT {obj_url} -> {r_put.status_code}; "
                                     f"GET balas isi sama",
                                     confirm=True))
            # Best-effort cleanup (ignore failure)
            client.request("DELETE", obj_url, allow_redirects=False)
        elif list_open:
            findings.append(_finding(target.origin, "world-readable",
                                     Severity.HIGH,
                                     "ListBucketResult balas 200 publik",
                                     confirm=True))
    finally:
        client.close()
    return findings


def _finding(url: str, label: str, sev: Severity, evidence: str,
             confirm: bool) -> Finding:
    return Finding(
        module="s3_world_writable",
        title=f"S3-compatible bucket {label}: {url}",
        severity=sev,
        description=(
            "Bucket cloud storage publik mengizinkan akses anonim "
            f"({label}). World-writable = attacker dapat mengganti "
            "asset (JS/CSS/HTML/APK) -> supply-chain XSS dan defacement "
            "ke seluruh pengguna."
        ),
        target=url,
        urls=[url],
        evidence=evidence,
        cwe="CWE-732",
        confidence="confirmed" if confirm else "firm",
        remediation=(
            "Set bucket policy `Block Public Access` di AWS Console. "
            "Hapus statement `Effect: Allow, Principal: *` yang mengizinkan "
            "PUT/GET. Aktifkan ACL=private + signed URL untuk distribusi. "
            "Audit semua bucket dengan AWS Trusted Advisor / S3 Storage Lens."
        ),
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ],
    )
