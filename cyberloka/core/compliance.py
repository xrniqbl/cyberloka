"""Compliance mapping for findings.

Maps each finding to relevant clauses from major standards/regulations:

- OWASP Top 10 2021 (A01-A10)
- PCI-DSS v4.0 (relevant requirement IDs)
- UU PDP Indonesia (UU 27/2022, relevant pasal)
- ISO/IEC 27001:2022 Annex A controls
- NIST Cybersecurity Framework 2.0 (functions/categories)
- CIS Controls v8 (control IDs)

Mappings are made primarily by *module* (the type of check) with a secondary
override by *CWE* when more specific. They reflect industry consensus
(e.g. SQLi -> A03 Injection, missing TLS -> A02 Cryptographic Failures) but
the user should still review them per their compliance scope.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from cyberloka.core.finding import Finding, Severity


# ---------------------------------------------------------------------------
# Standard catalogue (id -> human label).
#
# These are the *only* IDs that downstream consumers should expect. If a
# specific finding does not relate to a clause in a standard, that standard
# key is simply omitted (rather than emitting a meaningless mapping).
# ---------------------------------------------------------------------------

OWASP_2021: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# PCI-DSS v4.0 (subset of requirements relevant to web app scanning)
PCI_DSS_V4: dict[str, str] = {
    "2.2": "Secure system configuration standards applied",
    "4.2.1": "Strong cryptography for cardholder data in transit",
    "6.2.4": "Secure coding to prevent injection / XSS / common bugs",
    "6.4.1": "Public-facing web apps protected against known attacks",
    "8.3": "Strong authentication factors and credentials",
    "10.2": "Audit log of system actions",
    "11.3.1": "Internal/external vulnerability scans performed",
    "12.10": "Incident response plan in place",
}

# UU PDP Indonesia (UU No. 27 Tahun 2022) — pasal yang sering relevan
UU_PDP: dict[str, str] = {
    "Pasal 16": "Pemrosesan data pribadi yang sah dan transparan",
    "Pasal 35": "Pelindungan data pribadi melalui langkah teknis & organisasional",
    "Pasal 36": "Kewajiban menjaga kerahasiaan data pribadi",
    "Pasal 39": "Kewajiban mencegah akses tidak sah",
    "Pasal 46": "Kewajiban memberitahukan kegagalan pelindungan data pribadi",
}

# ISO/IEC 27001:2022 Annex A (subset most often triggered by web scans)
ISO_27001: dict[str, str] = {
    "A.5.7": "Threat intelligence",
    "A.5.10": "Acceptable use of information and other associated assets",
    "A.5.14": "Information transfer",
    "A.5.15": "Access control",
    "A.5.23": "Information security for use of cloud services",
    "A.5.34": "Privacy and protection of PII",
    "A.8.5": "Secure authentication",
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.20": "Networks security",
    "A.8.21": "Security of network services",
    "A.8.23": "Web filtering",
    "A.8.24": "Use of cryptography",
    "A.8.25": "Secure development life cycle",
    "A.8.26": "Application security requirements",
    "A.8.28": "Secure coding",
    "A.8.29": "Security testing in development and acceptance",
}

# NIST CSF 2.0 (Function.Category notation)
NIST_CSF: dict[str, str] = {
    "GV.OC": "Governance: Organizational Context",
    "ID.AM": "Identify: Asset Management",
    "ID.RA": "Identify: Risk Assessment",
    "PR.AA": "Protect: Identity Management, Authentication & Access Control",
    "PR.DS": "Protect: Data Security",
    "PR.PS": "Protect: Platform Security",
    "PR.IR": "Protect: Technology Infrastructure Resilience",
    "DE.CM": "Detect: Continuous Monitoring",
    "RS.MA": "Respond: Incident Management",
}

# CIS Controls v8 (control IDs)
CIS_V8: dict[str, str] = {
    "3": "Data Protection",
    "4": "Secure Configuration of Enterprise Assets and Software",
    "5": "Account Management",
    "6": "Access Control Management",
    "7": "Continuous Vulnerability Management",
    "8": "Audit Log Management",
    "12": "Network Infrastructure Management",
    "13": "Network Monitoring and Defense",
    "16": "Application Software Security",
}


# ---------------------------------------------------------------------------
# Per-module mapping. Each tuple is (standard_id, label_lookup_dict).
# ---------------------------------------------------------------------------

# Default mapping per detection module. Keys are findings' `module` attribute.
_MODULE_MAP: dict[str, dict[str, list[str]]] = {
    "sqli": {
        "owasp_2021": ["A03"],
        "pci_dss_v4": ["6.2.4", "6.4.1", "11.3.1"],
        "iso_27001": ["A.8.25", "A.8.26", "A.8.28", "A.8.29"],
        "nist_csf": ["PR.PS", "ID.RA"],
        "cis_v8": ["16", "7"],
        "uu_pdp": ["Pasal 35", "Pasal 39"],
    },
    "xss": {
        "owasp_2021": ["A03"],
        "pci_dss_v4": ["6.2.4", "6.4.1"],
        "iso_27001": ["A.8.26", "A.8.28"],
        "nist_csf": ["PR.PS"],
        "cis_v8": ["16"],
        "uu_pdp": ["Pasal 35"],
    },
    "lfi": {
        "owasp_2021": ["A01", "A03"],
        "pci_dss_v4": ["6.2.4", "6.4.1"],
        "iso_27001": ["A.5.15", "A.8.26"],
        "nist_csf": ["PR.AA", "PR.PS"],
        "cis_v8": ["6", "16"],
        "uu_pdp": ["Pasal 35", "Pasal 39"],
    },
    "cmdi": {
        "owasp_2021": ["A03"],
        "pci_dss_v4": ["6.2.4", "6.4.1"],
        "iso_27001": ["A.8.26", "A.8.28"],
        "nist_csf": ["PR.PS"],
        "cis_v8": ["16"],
        "uu_pdp": ["Pasal 35", "Pasal 39"],
    },
    "redirect": {
        "owasp_2021": ["A01"],
        "pci_dss_v4": ["6.2.4"],
        "iso_27001": ["A.8.26"],
        "nist_csf": ["PR.PS"],
        "cis_v8": ["16"],
    },
    "dirlist": {
        "owasp_2021": ["A05", "A01"],
        "pci_dss_v4": ["2.2", "6.4.1"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.PS"],
        "cis_v8": ["4"],
    },
    "headers": {
        "owasp_2021": ["A05"],
        "pci_dss_v4": ["2.2", "6.4.1"],
        "iso_27001": ["A.8.9", "A.8.21"],
        "nist_csf": ["PR.PS"],
        "cis_v8": ["4", "16"],
    },
    "cookies": {
        "owasp_2021": ["A05", "A07"],
        "pci_dss_v4": ["6.4.1", "8.3"],
        "iso_27001": ["A.8.5", "A.8.9"],
        "nist_csf": ["PR.AA"],
        "cis_v8": ["5", "6"],
        "uu_pdp": ["Pasal 35"],
    },
    "tls": {
        "owasp_2021": ["A02"],
        "pci_dss_v4": ["4.2.1", "2.2"],
        "iso_27001": ["A.5.14", "A.8.20", "A.8.24"],
        "nist_csf": ["PR.DS"],
        "cis_v8": ["3", "12"],
        "uu_pdp": ["Pasal 35", "Pasal 36"],
    },
    "cors": {
        "owasp_2021": ["A05", "A01"],
        "pci_dss_v4": ["6.4.1", "2.2"],
        "iso_27001": ["A.8.21", "A.8.26"],
        "nist_csf": ["PR.PS"],
        "cis_v8": ["16", "4"],
    },
    "clickjacking": {
        "owasp_2021": ["A05"],
        "pci_dss_v4": ["6.4.1"],
        "iso_27001": ["A.8.9", "A.8.26"],
        "nist_csf": ["PR.PS"],
        "cis_v8": ["16"],
    },
    "methods": {
        "owasp_2021": ["A05"],
        "pci_dss_v4": ["2.2", "6.4.1"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.PS"],
        "cis_v8": ["4"],
    },
    "sensitive_files": {
        "owasp_2021": ["A01", "A05"],
        "pci_dss_v4": ["2.2", "6.4.1"],
        "iso_27001": ["A.5.15", "A.8.9"],
        "nist_csf": ["PR.DS", "PR.AA"],
        "cis_v8": ["3", "4"],
        "uu_pdp": ["Pasal 35", "Pasal 39"],
    },
    "robots": {
        "owasp_2021": ["A01"],
        "iso_27001": ["A.5.10"],
        "nist_csf": ["ID.AM"],
        "cis_v8": ["4"],
    },
    "fingerprint": {
        "owasp_2021": ["A06"],
        "pci_dss_v4": ["6.4.1", "11.3.1"],
        "iso_27001": ["A.8.8"],
        "nist_csf": ["ID.AM", "ID.RA"],
        "cis_v8": ["7"],
    },
    "ports": {
        "owasp_2021": ["A05"],
        "pci_dss_v4": ["1.2", "2.2"],
        "iso_27001": ["A.8.20", "A.8.21"],
        "nist_csf": ["PR.IR"],
        "cis_v8": ["12", "13"],
    },
    "subdomains": {
        "owasp_2021": ["A05"],
        "iso_27001": ["A.8.9"],
        "nist_csf": ["ID.AM"],
        "cis_v8": ["4"],
    },
    "dns": {
        "owasp_2021": ["A05"],
        "iso_27001": ["A.8.20", "A.8.21"],
        "nist_csf": ["PR.IR"],
        "cis_v8": ["12"],
    },
    "whois": {
        "owasp_2021": ["A05"],
        "iso_27001": ["A.5.10"],
        "nist_csf": ["ID.AM"],
        "cis_v8": ["4"],
    },
    "rate_limit": {
        "owasp_2021": ["A04", "A07"],
        "pci_dss_v4": ["8.3"],
        "iso_27001": ["A.8.5", "A.8.26"],
        "nist_csf": ["PR.AA"],
        "cis_v8": ["5", "6"],
    },
    "burst": {
        "owasp_2021": ["A04"],
        "iso_27001": ["A.8.21"],
        "nist_csf": ["PR.IR", "DE.CM"],
        "cis_v8": ["13"],
    },
}

# Optional CWE-specific overrides (more precise than module default).
_CWE_MAP: dict[str, dict[str, list[str]]] = {
    "CWE-89": {  # SQL Injection
        "owasp_2021": ["A03"],
    },
    "CWE-79": {  # XSS
        "owasp_2021": ["A03"],
    },
    "CWE-78": {  # OS Command Injection
        "owasp_2021": ["A03"],
    },
    "CWE-22": {  # Path Traversal
        "owasp_2021": ["A01"],
    },
    "CWE-200": {  # Information Exposure
        "owasp_2021": ["A01", "A05"],
        "uu_pdp": ["Pasal 35", "Pasal 39", "Pasal 46"],
    },
    "CWE-352": {  # CSRF
        "owasp_2021": ["A01"],
    },
    "CWE-601": {  # Open Redirect
        "owasp_2021": ["A01"],
    },
    "CWE-918": {  # SSRF
        "owasp_2021": ["A10"],
    },
}


@dataclass
class ComplianceMapping:
    """Resolved mapping for a single finding."""

    owasp_2021: list[str]
    pci_dss_v4: list[str]
    iso_27001: list[str]
    nist_csf: list[str]
    cis_v8: list[str]
    uu_pdp: list[str]

    def to_dict(self) -> dict:
        return {
            "owasp_2021": [
                {"id": c, "label": OWASP_2021.get(c, "")} for c in self.owasp_2021
            ],
            "pci_dss_v4": [
                {"id": c, "label": PCI_DSS_V4.get(c, "")} for c in self.pci_dss_v4
            ],
            "iso_27001": [
                {"id": c, "label": ISO_27001.get(c, "")} for c in self.iso_27001
            ],
            "nist_csf": [
                {"id": c, "label": NIST_CSF.get(c, "")} for c in self.nist_csf
            ],
            "cis_v8": [
                {"id": c, "label": CIS_V8.get(c, "")} for c in self.cis_v8
            ],
            "uu_pdp": [
                {"id": c, "label": UU_PDP.get(c, "")} for c in self.uu_pdp
            ],
        }

    def as_flat_tags(self) -> list[str]:
        """Return a flat list like ['OWASP:A03', 'PCI:6.2.4', ...]."""
        out: list[str] = []
        out += [f"OWASP:{c}" for c in self.owasp_2021]
        out += [f"PCI:{c}" for c in self.pci_dss_v4]
        out += [f"ISO:{c}" for c in self.iso_27001]
        out += [f"NIST:{c}" for c in self.nist_csf]
        out += [f"CIS:{c}" for c in self.cis_v8]
        out += [f"UU-PDP:{c}" for c in self.uu_pdp]
        return out


def _merge(*sources: dict[str, list[str]]) -> dict[str, list[str]]:
    keys = ("owasp_2021", "pci_dss_v4", "iso_27001", "nist_csf", "cis_v8", "uu_pdp")
    merged: dict[str, list[str]] = {k: [] for k in keys}
    for src in sources:
        if not src:
            continue
        for k in keys:
            for item in src.get(k, []):
                if item not in merged[k]:
                    merged[k].append(item)
    return merged


def map_finding(finding: Finding) -> ComplianceMapping:
    """Resolve compliance mapping for a single finding."""
    base = _MODULE_MAP.get(finding.module, {})
    cwe_extra = _CWE_MAP.get(finding.cwe or "", {})
    merged = _merge(base, cwe_extra)
    return ComplianceMapping(
        owasp_2021=merged["owasp_2021"],
        pci_dss_v4=merged["pci_dss_v4"],
        iso_27001=merged["iso_27001"],
        nist_csf=merged["nist_csf"],
        cis_v8=merged["cis_v8"],
        uu_pdp=merged["uu_pdp"],
    )


def annotate_with_compliance(findings: Iterable[Finding]) -> list[dict]:
    """Return finding dicts enriched with `compliance` key."""
    out: list[dict] = []
    for f in findings:
        d = f.to_dict()
        d["compliance"] = map_finding(f).to_dict()
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Aggregate compliance summary across the whole scan.
# ---------------------------------------------------------------------------


_FRAMEWORK_LABELS: dict[str, dict[str, str]] = {
    "owasp_2021": OWASP_2021,
    "pci_dss_v4": PCI_DSS_V4,
    "iso_27001": ISO_27001,
    "nist_csf": NIST_CSF,
    "cis_v8": CIS_V8,
    "uu_pdp": UU_PDP,
}


def compliance_summary(findings: Iterable[Finding]) -> dict[str, list[dict]]:
    """Aggregate which clauses are triggered, with counts, weighted by severity."""
    weight = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    # framework -> clause_id -> {"count": n, "weight": w, "severities": Counter}
    accum: dict[str, dict[str, dict]] = {fw: {} for fw in _FRAMEWORK_LABELS}

    for f in findings:
        m = map_finding(f)
        clause_dict = {
            "owasp_2021": m.owasp_2021,
            "pci_dss_v4": m.pci_dss_v4,
            "iso_27001": m.iso_27001,
            "nist_csf": m.nist_csf,
            "cis_v8": m.cis_v8,
            "uu_pdp": m.uu_pdp,
        }
        for fw, clauses in clause_dict.items():
            for c in clauses:
                slot = accum[fw].setdefault(
                    c,
                    {"count": 0, "weight": 0, "severities": Counter()},
                )
                slot["count"] += 1
                slot["weight"] += weight[f.severity]
                slot["severities"][f.severity.value] += 1

    # Render to ordered list per framework.
    out: dict[str, list[dict]] = {}
    for fw, slots in accum.items():
        labels = _FRAMEWORK_LABELS[fw]
        rows = [
            {
                "id": clause_id,
                "label": labels.get(clause_id, ""),
                "count": data["count"],
                "weight": data["weight"],
                "severities": dict(data["severities"]),
            }
            for clause_id, data in slots.items()
        ]
        rows.sort(key=lambda r: (-r["weight"], -r["count"], r["id"]))
        out[fw] = rows
    return out
