"""Advanced CORS misconfig: arbitrary Origin reflect, suffix bypass."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state


def _test_origin(client: HttpClient, url: str, origin: str) -> tuple[str | None, str | None]:
    r = client.get(url, headers={"Origin": origin})
    if r is None:
        return None, None
    return r.headers.get("Access-Control-Allow-Origin"), r.headers.get("Access-Control-Allow-Credentials")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    apex = target.host
    legit = f"{target.scheme}://{apex}"
    test_urls = [target.base_url]
    s = get_state(config)
    if s:
        test_urls += [u for u in s.urls if "/api/" in u][:3]
    seen: set[str] = set()

    try:
        for url in test_urls:
            if url in seen:
                continue
            seen.add(url)

            # Test 1: arbitrary Origin
            evil = "https://cyberloka-evil.invalid"
            aco, acc = _test_origin(client, url, evil)
            if aco and aco == evil:
                sev = Severity.CRITICAL if (acc or "").lower() == "true" else Severity.HIGH
                findings.append(Finding(
                    module="cors_advanced", target=url,
                    title="CORS memantulkan Origin attacker",
                    severity=sev,
                    description=(f"Server membalas `Access-Control-Allow-Origin: {evil}`. "
                                 + ("Ditambah `Allow-Credentials: true` = cookie pelanggan "
                                    "bisa dicuri lewat JS attacker." if (acc or "").lower() == "true"
                                    else "Tanpa credentials, masih membuka API ke domain manapun.")),
                    evidence=f"ACAO={aco}; ACAC={acc}",
                    cwe="CWE-942",
                    remediation=("Whitelist origin secara eksplisit di server (jangan reflect). "
                                 "Jangan kirim `Allow-Credentials: true` dengan wildcard origin."),
                ))
                continue

            # Test 2: suffix bypass (https://target.com.evil.com)
            suffix_origin = f"https://{apex}.evil.invalid"
            aco2, _ = _test_origin(client, url, suffix_origin)
            if aco2 and aco2 == suffix_origin:
                findings.append(Finding(
                    module="cors_advanced", target=url,
                    title="CORS suffix-match bypass terdeteksi",
                    severity=Severity.HIGH,
                    description=(f"Server menerima Origin `{suffix_origin}` — biasanya karena "
                                 f"validasi pakai `endsWith({apex})` atau regex tanpa anchor."),
                    evidence=f"ACAO={aco2}",
                    cwe="CWE-942",
                    remediation="Validasi Origin dengan exact-match atau allowlist anchor (^...$).",
                ))

            # Test 3: null origin
            aco3, acc3 = _test_origin(client, url, "null")
            if aco3 == "null" and (acc3 or "").lower() == "true":
                findings.append(Finding(
                    module="cors_advanced", target=url,
                    title="CORS menerima Origin: null + credentials",
                    severity=Severity.HIGH,
                    description=("`Origin: null` dikirim oleh sandboxed iframe atau redirected "
                                 "request. Menerima null + credentials = exploitable lewat iframe."),
                    evidence=f"ACAO={aco3}; ACAC={acc3}",
                    cwe="CWE-942",
                    remediation="Tolak `Origin: null` di whitelist server.",
                ))
    finally:
        client.close()
    return findings
