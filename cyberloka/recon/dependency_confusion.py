"""Dependency confusion check via exposed package.json/composer.json."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = ["/package.json", "/composer.json", "/Pipfile", "/pyproject.toml"]
INTERNAL_HINTS = re.compile(r"(@[a-z0-9-]+/[a-z0-9-]+|company-internal|internal-)", re.I)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    try:
        for p in PATHS:
            url = urljoin(base, p.lstrip("/"))
            r = client.get(url)
            if r is None or r.status_code != 200:
                continue
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "html" in ctype:
                continue
            body = r.text or ""
            if not body or len(body) > 100000:
                continue

            internal_pkgs: list[str] = []
            try:
                if p.endswith(".json"):
                    data = json.loads(body)
                    deps = {}
                    deps.update(data.get("dependencies") or {})
                    deps.update(data.get("devDependencies") or {})
                    deps.update(data.get("require") or {})
                    deps.update(data.get("require-dev") or {})
                    for name in deps:
                        if INTERNAL_HINTS.search(name):
                            internal_pkgs.append(name)
                elif p.endswith(".toml") or p.endswith("Pipfile"):
                    for line in body.splitlines():
                        m = re.match(r'^\s*"?([@\w/-]+)"?\s*=', line)
                        if m and INTERNAL_HINTS.search(m.group(1)):
                            internal_pkgs.append(m.group(1))
            except (ValueError, json.JSONDecodeError):
                continue

            if internal_pkgs:
                findings.append(Finding(
                    module="dependency_confusion", target=url,
                    title=f"{len(internal_pkgs)} kemungkinan paket internal di {p}",
                    severity=Severity.HIGH,
                    description=("Manifest paket terbuka publik dan memuat scoped/internal package. "
                                 "Jika nama tersebut belum di-claim di npm/Packagist, "
                                 "attacker dapat publish paket dengan nama sama versi lebih "
                                 "tinggi → masuk ke build pipeline (dependency confusion)."),
                    evidence="\n".join(internal_pkgs[:10]),
                    cwe="CWE-829",
                    remediation=("(1) Claim semua nama scoped @company/* di npm. "
                                 "(2) Pakai private registry dengan upstream priority. "
                                 "(3) Set scope di .npmrc: `@company:registry=...`. "
                                 "(4) Jangan publish package.json ke webroot."),
                    references=["https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610"],
                ))
            elif p.endswith(".json") and r.status_code == 200:
                # File manifest publik = info disclosure
                findings.append(Finding(
                    module="dependency_confusion", target=url,
                    title=f"Manifest {p} terekspos publik",
                    severity=Severity.LOW,
                    description="File manifest dependency seharusnya tidak ada di webroot.",
                    evidence=f"len={len(body)}", cwe="CWE-538",
                    remediation="Pindahkan ke folder build, exclude dari webroot.",
                ))
    finally:
        client.close()
    return findings
