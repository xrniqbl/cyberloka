"""Scan response body / linked JS for leaked secrets / API keys."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# (name, regex, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("AWS Secret Access Key", re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^a-z0-9]{0,3}([A-Za-z0-9/+=]{40})"), Severity.CRITICAL),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), Severity.HIGH),
    ("Google OAuth Token", re.compile(r"ya29\.[0-9A-Za-z_\-]+"), Severity.HIGH),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}"), Severity.CRITICAL),
    ("Stripe Restricted Key", re.compile(r"rk_live_[0-9a-zA-Z]{24}"), Severity.CRITICAL),
    ("GitHub Personal Token", re.compile(r"ghp_[0-9A-Za-z]{36}"), Severity.CRITICAL),
    ("GitHub OAuth Token", re.compile(r"gho_[0-9A-Za-z]{36}"), Severity.HIGH),
    ("Slack Token", re.compile(r"xox[abprs]-[0-9A-Za-z\-]{10,48}"), Severity.HIGH),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), Severity.HIGH),
    ("Mailgun Key", re.compile(r"key-[0-9a-zA-Z]{32}"), Severity.HIGH),
    ("SendGrid Key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), Severity.HIGH),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), Severity.HIGH),
    ("Heroku API Key", re.compile(r"(?i)heroku.{0,20}[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}"), Severity.HIGH),
    ("Firebase URL", re.compile(r"https?://[a-z0-9-]+\.firebaseio\.com"), Severity.MEDIUM),
    ("Private Key (PEM)", re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) ?KEY-----"), Severity.CRITICAL),
    ("Generic API Token", re.compile(r"(?i)(api[_-]?key|apikey|token|secret)[\"' :=]{1,5}[\"']?([A-Za-z0-9_\-]{24,})"), Severity.MEDIUM),
    ("JDBC URL with password", re.compile(r"jdbc:[a-z]+://[^\s\"']*?password=[^&\s\"']+"), Severity.CRITICAL),
    ("MongoDB URI with password", re.compile(r"mongodb(\+srv)?://[^\s\"':@]+:[^\s\"'@]+@"), Severity.CRITICAL),
]

JS_MIME_HINTS = ("javascript", "ecmascript", "json")


def _scan(text: str, source: str, target: str, base_url: str) -> list[Finding]:
    out: list[Finding] = []
    for name, rgx, sev in SECRET_PATTERNS:
        for m in rgx.finditer(text):
            evidence = m.group(0)[:160]
            out.append(
                Finding(
                    module="secrets",
                    title=f"Potensi secret bocor: {name}",
                    severity=sev,
                    description=(
                        f"Pattern '{name}' terdeteksi di {source}. Jika ini adalah secret "
                        "yang sah, segera rotate dan hapus dari source publik."
                    ),
                    target=target or base_url,
                    evidence=truncate(evidence, 160),
                    cwe="CWE-798",
                    remediation=(
                        "Jangan menyimpan secret di kode frontend. Gunakan secret manager "
                        "(AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager). "
                        "Setelah ditemukan: revoke key, rotate, audit penggunaan."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                    ],
                )
            )
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen: set[str] = set()
    try:
        resp = client.get(target.base_url)
        if resp is None or not resp.text:
            return findings
        # Scan main HTML
        for f in _scan(resp.text, "HTML body", target.base_url, target.base_url):
            key = (f.title, f.evidence)
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)

        # Collect JS resources
        soup = BeautifulSoup(resp.text, "html.parser")
        js_urls: list[str] = []
        for s in soup.find_all("script", src=True):
            js_urls.append(urljoin(target.base_url, s["src"]))
        # Limit to avoid noise
        js_urls = list(dict.fromkeys(js_urls))[:25]

        def fetch(u: str):
            r = client.get(u, allow_redirects=True)
            if r is None:
                return None
            ctype = r.headers.get("Content-Type", "").lower()
            if not any(h in ctype for h in JS_MIME_HINTS) and not u.endswith((".js", ".mjs", ".json")):
                return None
            return u, r.text or ""

        with ThreadPoolExecutor(max_workers=min(8, config.threads)) as ex:
            futures = [ex.submit(fetch, u) for u in js_urls]
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                u, body = res
                for f in _scan(body, f"JS asset: {u}", u, target.base_url):
                    key = (f.title, f.evidence)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(f)
    finally:
        client.close()
    return findings
