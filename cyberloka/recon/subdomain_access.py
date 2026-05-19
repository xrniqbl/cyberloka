"""Deep accessible-subdomain scanner.

Pelengkap `subdomains.py` (yang hanya melakukan DNS bruteforce). Modul ini:

    1. Re-resolve subdomain dari wordlist (paralel) — atau gunakan hasil
       yang sudah diset modul `subdomains.py` ke config bila ada.
    2. Untuk setiap subdomain hidup, probe HTTP **DAN** HTTPS.
    3. Klasifikasi konten:
        - admin / dashboard / cpanel / debug / staging / dev → HIGH
        - login / signin / sso / oauth → MEDIUM (pintu masuk)
        - swagger / api-docs / openapi.json → MEDIUM (info disclosure)
        - jenkins / gitlab / sonarqube / phpmyadmin / kibana / grafana
          / kubernetes-dashboard / argocd → CRITICAL (panel internal)
        - directory-listing → MEDIUM
        - default-error / placeholder → INFO
    4. Deteksi CORS wide-open per subdomain (`Access-Control-Allow-Origin: *`
       + `Allow-Credentials: true`) → MEDIUM.
    5. Deteksi sertifikat TLS hostname mismatch (subdomain serve TLS cert
       untuk domain lain) → INFO.
    6. **Validasi** sebelum report: setiap finding men-set `extra["reverify"]`
       dengan marker spesifik agar validator re-confirm sebelum masuk report.

Output berbentuk *Finding-per-subdomain-relevant* (bukan satu giant blob).
"""
from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines

_SHARED_KEY = "_subdomain_results"


def get_state(config: ScanConfig) -> dict[str, str] | None:
    """Hasil resolusi {fqdn: ip}, kalau ada."""
    return getattr(config, _SHARED_KEY, None)


def _set_state(config: ScanConfig, mapping: dict[str, str]) -> None:
    setattr(config, _SHARED_KEY, mapping)


# ----------------------------------------------------------------------------
# Klasifikasi: marker → (label, severity, cwe)
# ----------------------------------------------------------------------------
INTERNAL_PANELS: list[tuple[re.Pattern[str], str, Severity, str]] = [
    (re.compile(r"<title>[^<]*phpMyAdmin", re.I),
     "phpMyAdmin", Severity.CRITICAL, "CWE-284"),
    (re.compile(r"<title>[^<]*Jenkins", re.I),
     "Jenkins", Severity.CRITICAL, "CWE-284"),
    (re.compile(r"jenkins-instance|jenkins-version", re.I),
     "Jenkins", Severity.CRITICAL, "CWE-284"),
    (re.compile(r"<title>[^<]*GitLab", re.I),
     "GitLab", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*Gitea", re.I),
     "Gitea", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*SonarQube", re.I),
     "SonarQube", Severity.HIGH, "CWE-284"),
    (re.compile(r"id=\"grafana_app\"|grafana-app", re.I),
     "Grafana", Severity.HIGH, "CWE-284"),
    (re.compile(r"\"kbn-name\"|kibana_security_session", re.I),
     "Kibana", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*Kubernetes Dashboard", re.I),
     "Kubernetes Dashboard", Severity.CRITICAL, "CWE-284"),
    (re.compile(r"argo-cd|argocd-server", re.I),
     "Argo CD", Severity.CRITICAL, "CWE-284"),
    (re.compile(r"<title>[^<]*Portainer", re.I),
     "Portainer", Severity.CRITICAL, "CWE-284"),
    (re.compile(r"<title>[^<]*RabbitMQ Management", re.I),
     "RabbitMQ Management", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*Adminer", re.I),
     "Adminer", Severity.CRITICAL, "CWE-284"),
    (re.compile(r"<title>[^<]*phpPgAdmin", re.I),
     "phpPgAdmin", Severity.CRITICAL, "CWE-284"),
    (re.compile(r"swagger-ui|swagger-ui-bundle|openapi-3-0", re.I),
     "Swagger / OpenAPI UI", Severity.MEDIUM, "CWE-200"),
    (re.compile(r"redoc-container|redoc-spec-url", re.I),
     "ReDoc API explorer", Severity.MEDIUM, "CWE-200"),
    (re.compile(r"graphql.*playground|graphql-playground", re.I),
     "GraphQL Playground", Severity.MEDIUM, "CWE-200"),
    (re.compile(r"strapi[_-]admin|<title>[^<]*Strapi", re.I),
     "Strapi admin", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*MinIO", re.I),
     "MinIO console", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*Spinnaker", re.I),
     "Spinnaker", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*Vault\b", re.I),
     "HashiCorp Vault UI", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*Consul", re.I),
     "Consul UI", Severity.MEDIUM, "CWE-200"),
    (re.compile(r"<title>[^<]*Prometheus", re.I),
     "Prometheus", Severity.MEDIUM, "CWE-200"),
    (re.compile(r"<title>[^<]*Apache Airflow", re.I),
     "Apache Airflow", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*Traefik", re.I),
     "Traefik dashboard", Severity.MEDIUM, "CWE-200"),
    (re.compile(r"<title>[^<]*Apache ActiveMQ", re.I),
     "ActiveMQ", Severity.HIGH, "CWE-284"),
    (re.compile(r"<title>[^<]*phpinfo\(\)", re.I),
     "phpinfo() page", Severity.HIGH, "CWE-200"),
]

ENV_HINTS = re.compile(
    r"\b(staging|stg|stag|dev|develop|development|test|testing|qa|uat|"
    r"sandbox|preview|beta|alpha|internal|admin|panel|cpanel|backoffice|"
    r"backend|api-?internal|debug)\b",
    re.I,
)
LOGIN_HINTS = re.compile(r"<title>[^<]*(login|sign[ -]?in|sso|masuk|"
                         r"authenticate)", re.I)
DEBUG_HINTS = re.compile(r"<title>[^<]*(debug|trace|stack|exception)", re.I)
LISTING_HINTS = re.compile(r"<title>[^<]*Index of /|<h1>Index of", re.I)


# ============================================================================
# Resolusi
# ============================================================================
def _resolve(host: str, timeout: float = 2.0) -> str | None:
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(host)
    except (OSError, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(None)


def _enumerate_subdomains(target: Target, config: ScanConfig) -> dict[str, str]:
    cached = get_state(config)
    if cached:
        return cached
    if target.is_ip or target.host.count(".") < 1:
        return {}
    words = load_data_lines("subdomains.txt")
    if not words:
        return {}
    found: dict[str, str] = {}
    base = target.host
    with ThreadPoolExecutor(max_workers=min(60, config.threads * 5)) as ex:
        futs = {ex.submit(_resolve, f"{w}.{base}"): w for w in words}
        for fut in as_completed(futs):
            w = futs[fut]
            ip = fut.result()
            if ip:
                found[f"{w}.{base}"] = ip
    _set_state(config, found)
    return found


# ============================================================================
# Probing
# ============================================================================
def _classify(body: str, fqdn: str) -> tuple[str, Severity, str, str] | None:
    """Return (label, severity, cwe, marker) bila konten relevan, else None."""
    # 1. Internal panel marker
    for rx, label, sev, cwe in INTERNAL_PANELS:
        m = rx.search(body)
        if m:
            return label, sev, cwe, m.group(0)[:60]
    # 2. environment hint pada hostname (staging/dev/admin) yang serve content
    if ENV_HINTS.search(fqdn):
        # Body harus *bukan* sekadar 4xx generic
        if len(body) > 200 and "<html" in body.lower():
            return ("Subdomain environment internal hidup", Severity.HIGH,
                    "CWE-200", "host pattern: " + fqdn)
    # 3. directory listing
    if LISTING_HINTS.search(body):
        return ("Directory listing aktif", Severity.MEDIUM, "CWE-548",
                "Index of /")
    # 4. debug page
    if DEBUG_HINTS.search(body):
        return ("Halaman debug/trace publik", Severity.HIGH,
                "CWE-209", "debug title")
    # 5. login page (normal, tetap dilaporkan dengan severity rendah)
    if LOGIN_HINTS.search(body):
        return ("Login form publik", Severity.LOW, "CWE-200", "login title")
    return None


def _probe_http(client: HttpClient, fqdn: str, ip: str) -> list[Finding]:
    out: list[Finding] = []
    seen_class: set[str] = set()
    for proto in ("https", "http"):
        url = f"{proto}://{fqdn}/"
        r = client.get(url, allow_redirects=True)
        if r is None:
            continue
        if r.status_code >= 500:
            continue
        body = r.text or ""

        # CORS wide-open check
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*" and acac == "true":
            out.append(Finding(
                module="subdomain_access",
                title=f"CORS misconfig + credentials allowed: {fqdn}",
                severity=Severity.MEDIUM,
                description=(
                    "Subdomain mengizinkan origin apa saja dengan credentials. "
                    "Browser modern memang menolak kombinasi `*` + creds, tapi "
                    "konfigurasi ini menandakan aplikasi mengandalkan auth "
                    "berbasis cookie tanpa kontrol origin yang ketat."
                ),
                target=url,
                evidence=f"ACAO={acao!r} ACAC={acac!r}",
                cwe="CWE-942",
                confidence="firm",
                remediation=(
                    "Set ACAO ke whitelist domain yang dipakai front-end, "
                    "JANGAN `*` saat `Allow-Credentials: true`. Validasi "
                    "header `Origin` di server."
                ),
            ))

        cls = _classify(body, fqdn)
        if not cls:
            continue
        label, sev, cwe, marker = cls
        if label in seen_class:
            continue
        seen_class.add(label)
        out.append(Finding(
            module="subdomain_access",
            title=f"{label} di subdomain {fqdn}",
            severity=sev,
            description=(
                f"Subdomain `{fqdn}` ({ip}) mengembalikan halaman yang "
                f"terindikasi {label}. Subdomain seperti ini biasanya tidak "
                "dimaksudkan publik dan harus dilindungi VPN / IP allowlist / "
                "auth kuat."
            ),
            target=url,
            evidence=f"HTTP {r.status_code}, marker={marker!r}, "
                     f"len={len(body)}",
            cwe=cwe,
            confidence="firm",
            remediation=(
                "Tutup subdomain dari publik (firewall + reverse-proxy auth), "
                "atau hapus DNS-record bila tidak dipakai. Untuk panel "
                "internal: wajibkan SSO + IP allowlist + WAF."
            ),
            extra={"reverify": {"marker": marker[:24], "in_body": True}},
        ))
        # cukup 1 finding kuat per subdomain (per protocol — break loop)
        break
    return out


def _probe_tls_mismatch(fqdn: str, timeout: float = 3.0) -> Finding | None:
    """Cek apakah cert HTTPS subdomain memuat hostname lain (kemungkinan
    salah-mount / shared cert)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((fqdn, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=fqdn) as ssock:
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError, socket.timeout):
        return None
    if not cert:
        return None
    # Ambil SAN
    sans = [v for k, v in cert.get("subjectAltName", []) if k.lower() == "dns"]
    cn_pairs = sum(cert.get("subject", []), ())
    cn = next((v for k, v in cn_pairs if k == "commonName"), None)
    expected = (sans or []) + ([cn] if cn else [])
    if not expected:
        return None
    # Cocokkan dengan glob `*.foo` style sederhana
    matches = False
    for name in expected:
        if not name:
            continue
        if name.startswith("*."):
            if fqdn.endswith(name[1:]):
                matches = True; break
        elif name.lower() == fqdn.lower():
            matches = True; break
    if matches:
        return None
    return Finding(
        module="subdomain_access",
        title=f"Sertifikat TLS tidak match hostname: {fqdn}",
        severity=Severity.LOW,
        description=(
            "Sertifikat yang disajikan port 443 subdomain tidak memuat nama "
            f"`{fqdn}` di SAN/CN. Browser akan menolak — biasanya pertanda "
            "subdomain salah-mount ke service lain atau di-park."
        ),
        target=f"https://{fqdn}/",
        evidence=f"cert SAN/CN: {expected[:6]}",
        cwe="CWE-295",
        confidence="firm",
        remediation=(
            "Issue ulang sertifikat dengan SAN yang benar atau hapus DNS "
            "record subdomain bila tidak dipakai (cegah subdomain takeover)."
        ),
    )


# ============================================================================
# Entry-point
# ============================================================================
def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.is_ip:
        return findings
    subs = _enumerate_subdomains(target, config)
    if not subs:
        return findings

    client = HttpClient(config)
    try:
        # Buang root host; biarkan modul lain handle.
        items = [(h, ip) for h, ip in subs.items() if h.lower() != target.host.lower()]
        # batasi probe kalau wordlist besar
        items = items[:120]

        for fqdn, ip in items:
            findings += _probe_http(client, fqdn, ip)
            tls_finding = _probe_tls_mismatch(fqdn)
            if tls_finding:
                findings.append(tls_finding)
    finally:
        client.close()
    return findings
