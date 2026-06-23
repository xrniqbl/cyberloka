"""SAML metadata exposure (SP/IdP)."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = [
    "/saml/metadata", "/saml2/metadata", "/sso/saml/metadata",
    "/Shibboleth.sso/Metadata", "/idp/shibboleth",
    "/simplesaml/saml2/idp/metadata.php", "/simplesaml/module.php/saml/sp/metadata.php",
    "/auth/saml/metadata", "/api/saml/metadata", "/sso/metadata",
    "/saml/sso/metadata.xml",
]
SIGNATURES = (
    "<EntityDescriptor", "<md:EntityDescriptor",
    "urn:oasis:names:tc:SAML:2.0:metadata",
    "urn:oasis:names:tc:SAML:1.1:nameid-format",
    "<X509Certificate>",
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = (r.text or "")[:8192]
            ct = (r.headers.get("Content-Type") or "").lower()
            is_xml = "xml" in ct or "samlmetadata" in ct
            if not (is_xml and any(s in body for s in SIGNATURES)):
                continue
            # Cek apakah cert X509 ikut bocor
            has_cert = "<X509Certificate>" in body or "<ds:X509Certificate>" in body
            sev = Severity.HIGH if has_cert else Severity.MEDIUM
            findings.append(Finding(
                module="saml_metadata_exposed",
                title=f"SAML metadata terbuka publik: {path}",
                severity=sev,
                description=(
                    "Endpoint SAML mengembalikan dokumen metadata XML "
                    "berisi entityID + signing/encryption certificate. "
                    "Dokumen ini menjadi bahan baku serangan SAML "
                    "Signature Wrapping (XSW) untuk forge SAML response."
                ),
                target=url,
                urls=[url],
                evidence=f"GET {url} -> 200; XML SAML metadata{' + cert' if has_cert else ''}",
                cwe="CWE-200",
                confidence="confirmed",
                remediation=(
                    "Bila Anda memang IdP yang publish metadata, validasi "
                    "bahwa hanya signing cert yang disertakan (bukan key). "
                    "Untuk SP, jangan publish metadata kecuali memang perlu. "
                    "Pasang IP allowlist + basic-auth di endpoint metadata "
                    "internal. Pakai library SAML modern yang resistan XSW "
                    "(mis. python3-saml >= 1.10)."
                ),
                references=[
                    "https://research.aurainfosec.io/pentest/breaking-saml-by-being-whoever-you-want-to-be/",
                ],
            ))
            break
    finally:
        client.close()
    return findings
