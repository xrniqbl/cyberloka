"""Sensitive file exposure scanner with deep verification.

Why this exists
---------------
Cuma melihat status 200 menghasilkan banyak false positive — banyak situs (SPA
React/Vue, Laravel, WordPress dengan custom 404, framework yang melakukan
catch-all rewrite) mengembalikan ``200 OK`` untuk path apa pun.

Pipeline verifikasi:

1. **Baseline soft-404**: kirim 2 request ke path acak yang pasti tidak ada.
   Simpan signature (status, panjang body, sha1, title). Bila respons kandidat
   identik atau sangat mirip dengan baseline, abaikan — ini bukan file nyata.
2. **Homepage signature**: kalau body kandidat == homepage, juga skip.
3. **Content-type / size guard**: file biner kecil 0-byte atau HTML generik
   yang tidak punya ciri file dimaksud → skip.
4. **Per-pattern content signature**: setiap kategori file (`.env`, `.git/...`,
   `wp-config.php`, dump SQL, kunci privat, ...) memiliki regex/keyword yang
   wajib muncul agar dianggap **confirmed**. Kalau hanya status 200 + tipe
   plausible tetapi tanpa signature, severity diturunkan ke INFO/LOW dan
   confidence ``tentative``.

Output Finding membawa ``confidence`` yang akurat sehingga laporan tidak
melaporkan endpoint yang sebenarnya aman sebagai celah kritis.
"""
from __future__ import annotations

import hashlib
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines, truncate

# ---------------------------------------------------------------------------
# Content signatures - what the *real* file content looks like.
# ---------------------------------------------------------------------------
# (path-substring, severity-when-confirmed, regex that MUST match the body)
SIGNATURES: list[tuple[str, Severity, re.Pattern[str], str]] = [
    # Env / dotfiles ---------------------------------------------------------
    (".env",            Severity.CRITICAL,
     re.compile(r"(?im)^\s*(APP_KEY|APP_SECRET|DB_PASSWORD|DB_USERNAME|DB_HOST|"
                r"AWS_(ACCESS|SECRET)|MAIL_PASSWORD|JWT_SECRET|SECRET_KEY)\s*="),
     "Env-style key=value pair (DB_PASSWORD/APP_KEY/...) ditemukan."),

    # Git --------------------------------------------------------------------
    (".git/config",     Severity.CRITICAL,
     re.compile(r"(?im)^\s*\[(core|remote\b|branch\b)\]"),
     "Header [core]/[remote] khas file .git/config."),
    (".git/HEAD",       Severity.CRITICAL,
     re.compile(r"(?im)^ref:\s+refs/heads/"),
     "Tag 'ref: refs/heads/...' khas .git/HEAD."),
    (".git/index",      Severity.CRITICAL,
     re.compile(rb"^DIRC".decode("latin1")),
     "Magic bytes 'DIRC' khas git index."),

    # Database dumps & backups ----------------------------------------------
    (".sql",            Severity.HIGH,
     re.compile(r"(?im)\b(CREATE\s+TABLE|INSERT\s+INTO|--\s+(MySQL|PostgreSQL)\s+dump|"
                r"DROP\s+TABLE\s+IF\s+EXISTS)"),
     "Statement DDL/DML khas dump SQL."),
    ("dump.sql",        Severity.HIGH,
     re.compile(r"(?im)\b(CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL\s+dump)"),
     "Statement DDL/DML khas dump SQL."),
    ("backup",          Severity.HIGH,
     re.compile(r"(?im)\b(CREATE\s+TABLE|INSERT\s+INTO|BEGIN\s+TRANSACTION|PK\x03\x04|"
                r"-----BEGIN)"),
     "Konten backup (SQL/zip/tar/key) terdeteksi."),

    # PHP info / admin tools -------------------------------------------------
    ("phpinfo",         Severity.HIGH,
     re.compile(r"<title>\s*phpinfo\(\)\s*</title>|PHP Version\s+\d", re.I),
     "Output phpinfo() ditemukan."),
    ("phpmyadmin",      Severity.MEDIUM,
     re.compile(r"phpMyAdmin", re.I),
     "Halaman phpMyAdmin ditemukan."),
    ("adminer",         Severity.MEDIUM,
     re.compile(r"(?i)<title>\s*Login\s*-\s*Adminer", re.I),
     "Halaman Adminer login ditemukan."),
    ("server-status",   Severity.MEDIUM,
     re.compile(r"(?i)apache\s+server\s+status|<title>\s*Apache Status"),
     "Apache mod_status terbuka."),
    ("server-info",     Severity.MEDIUM,
     re.compile(r"(?i)apache\s+server\s+information"),
     "Apache mod_info terbuka."),

    # CMS configs ------------------------------------------------------------
    ("wp-config",       Severity.CRITICAL,
     re.compile(r"(?im)define\(\s*['\"](DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY)"),
     "Konstanta DB_NAME/DB_USER/AUTH_KEY khas wp-config.php."),
    ("configuration.php", Severity.CRITICAL,
     re.compile(r"(?im)\$\w+\s*=\s*['\"][^'\"]*['\"]\s*;.*(password|host|user)", re.I),
     "Variabel konfigurasi Joomla khas."),

    # Dependency lockfiles --------------------------------------------------
    ("composer.json",   Severity.LOW,
     re.compile(r'(?s)"name"\s*:\s*"[^"]+"\s*,'),
     "Manifest composer.json valid."),
    ("composer.lock",   Severity.MEDIUM,
     re.compile(r'(?s)"_readme"|"packages"\s*:\s*\['),
     "composer.lock valid → membocorkan dependency & versi."),
    ("package.json",    Severity.LOW,
     re.compile(r'(?s)"name"\s*:\s*"[^"]+"'),
     "Manifest package.json valid."),
    ("package-lock.json", Severity.LOW,
     re.compile(r'(?s)"lockfileVersion"\s*:'),
     "package-lock.json valid → membocorkan versi paket."),
    ("yarn.lock",       Severity.LOW,
     re.compile(r"(?m)^# yarn lockfile|^[\w@/-]+@[^:]+:\s*$"),
     "yarn.lock valid → membocorkan versi paket."),

    # Web server configs ----------------------------------------------------
    ("web.config",      Severity.HIGH,
     re.compile(r"(?is)<configuration\b.*<system\.webServer|<configuration\b"),
     "File IIS web.config (XML <configuration>)."),
    (".htaccess",       Severity.MEDIUM,
     re.compile(r"(?im)^(RewriteEngine|RewriteRule|Options\s|<IfModule|AuthType)"),
     "Direktif Apache .htaccess."),
    (".htpasswd",       Severity.HIGH,
     re.compile(r"^[\w.-]+:\$(?:apr1|2[ay]|6)\$", re.M),
     "Hash bcrypt/MD5 khas .htpasswd."),

    # Private keys / credentials --------------------------------------------
    ("id_rsa",          Severity.CRITICAL,
     re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA |)PRIVATE KEY-----"),
     "Header PEM private key."),
    ("id_dsa",          Severity.CRITICAL,
     re.compile(r"-----BEGIN (DSA |)PRIVATE KEY-----"),
     "Header PEM private key."),
    (".pem",            Severity.CRITICAL,
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
     "Header PEM private key."),
    (".ppk",            Severity.CRITICAL,
     re.compile(r"^PuTTY-User-Key-File-", re.M),
     "Format PuTTY private key (.ppk)."),
    ("credentials",     Severity.CRITICAL,
     re.compile(r"(?im)\[(default|profile\b)|aws_access_key_id\s*="),
     "Format AWS shared credentials."),

    # IDE / editor leaks ----------------------------------------------------
    (".idea/workspace.xml", Severity.LOW,
     re.compile(r'<\?xml[^>]+\?>\s*<project'),
     "File project JetBrains."),
    (".vscode/settings.json", Severity.LOW,
     re.compile(r'(?s)\{\s*"[\w.-]+"\s*:'),
     "File konfigurasi VS Code."),
    (".DS_Store",       Severity.LOW,
     # binary magic
     re.compile(r"^\x00\x00\x00\x01Bud1", re.S),
     "Magic Apple .DS_Store."),

    # CI / build leaks -------------------------------------------------------
    (".gitlab-ci.yml",  Severity.LOW,
     re.compile(r"(?im)^(stages|image|services|before_script):"),
     "File pipeline GitLab CI."),
    (".travis.yml",     Severity.LOW,
     re.compile(r"(?im)^(language|script|jobs|deploy):"),
     "File pipeline Travis."),
    ("Dockerfile",      Severity.LOW,
     re.compile(r"(?m)^(FROM|RUN|COPY|CMD|ENV)\b"),
     "Dockerfile."),

    # Log files --------------------------------------------------------------
    (".log",            Severity.MEDIUM,
     re.compile(r"(?im)\b(error|warning|stack trace|exception|fatal|debug)\b"),
     "Konten file log."),

    # Robots / sitemaps already handled by other module - ignore here.
]

# Generic "looks like a real file" check: short non-HTML payload with
# distinctive characters. Used as a soft fallback.
HTML_TAG_RE = re.compile(r"<html|<!doctype html", re.I)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.I | re.S)


@dataclass
class _Baseline:
    """Soft-404 fingerprint."""

    status: int
    length: int
    sha1: str
    title: str


# ---------------------------------------------------------------------------
def _fingerprint(text: str) -> tuple[int, str, str]:
    if text is None:
        text = ""
    sha1 = hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()
    m = TITLE_RE.search(text or "")
    title = m.group(1).strip() if m else ""
    return len(text), sha1, title


def _baselines(client: HttpClient, origin: str) -> tuple[list[_Baseline], _Baseline | None]:
    """Probe two impossible paths and the homepage to learn soft-404 behavior."""
    baselines: list[_Baseline] = []
    for probe in (
        f"/cyberloka-{os.urandom(6).hex()}-doesnotexist.html",
        f"/{os.urandom(8).hex()}/{os.urandom(6).hex()}.txt",
    ):
        url = urljoin(origin + "/", probe.lstrip("/"))
        resp = client.get(url, allow_redirects=False)
        if resp is None:
            continue
        length, sha1, title = _fingerprint(resp.text or "")
        baselines.append(_Baseline(resp.status_code, length, sha1, title))

    home_resp = client.get(origin + "/", allow_redirects=True)
    home_bl: _Baseline | None = None
    if home_resp is not None:
        length, sha1, title = _fingerprint(home_resp.text or "")
        home_bl = _Baseline(home_resp.status_code, length, sha1, title)
    return baselines, home_bl


def _looks_like_baseline(text: str, status: int, baselines: list[_Baseline]) -> bool:
    """True when the candidate response is indistinguishable from soft-404."""
    if not baselines:
        return False
    length, sha1, title = _fingerprint(text or "")
    for b in baselines:
        if b.status != status:
            continue
        if sha1 == b.sha1:
            return True
        # Allow ~5% length jitter (CSRF tokens, timestamps).
        if b.length and abs(length - b.length) <= max(64, b.length * 0.05) and (
            title == b.title or (title and b.title and title == b.title)
        ):
            return True
    return False


def _match_signature(
    path_lower: str, body: str, content_type: str
) -> tuple[Severity, re.Pattern[str] | None, str] | None:
    """Return (severity, matched_regex, why) when a specific signature matches.

    None means: status was 200 but content does not look like the real file -
    treat as not vulnerable (or downgrade to INFO upstream).
    """
    for marker, sev, regex, why in SIGNATURES:
        if marker not in path_lower:
            continue
        if regex.search(body or ""):
            return sev, regex, why
    # No signature matched; check generic "real file" hints.
    # If response is plain text / json / xml AND not just the homepage HTML, it
    # may still be interesting at lower severity.
    ct = (content_type or "").lower()
    is_html = "html" in ct or HTML_TAG_RE.search(body or "")
    if not is_html and body and len(body.strip()) >= 4:
        return Severity.LOW, None, "Konten non-HTML pada path sensitif (tidak punya signature spesifik)."
    return None


def _check(
    client: HttpClient,
    origin: str,
    path: str,
    baselines: list[_Baseline],
    home_bl: _Baseline | None,
):
    url = urljoin(origin + "/", path.lstrip("/"))
    resp = client.get(url, allow_redirects=False)
    if resp is None:
        return None
    if resp.status_code in (401, 403):
        # The path exists but is protected - useful info, but not a vuln.
        return ("protected", url, resp.status_code, "")
    if resp.status_code != 200 or not resp.content:
        return None

    body = resp.text or ""
    ctype = resp.headers.get("Content-Type", "")

    # Soft-404 detection
    if _looks_like_baseline(body, resp.status_code, baselines):
        return None
    # Same as homepage -> SPA catch-all
    if home_bl is not None:
        length, sha1, _ = _fingerprint(body)
        if sha1 == home_bl.sha1 or (
            home_bl.length and abs(length - home_bl.length) <= max(32, home_bl.length * 0.02)
            and "html" in ctype.lower()
        ):
            return None

    sig = _match_signature(path.lower(), body, ctype)
    if sig is None:
        # 200 OK but no signature -> very likely a generic page. Skip.
        return None

    sev, regex, why = sig
    matched = ""
    if regex is not None:
        m = regex.search(body)
        if m:
            matched = truncate(m.group(0), 160)
    confidence = "confirmed" if regex is not None else "tentative"

    # Adjust severity based on path keywords for unknown extensions
    plower = url.lower()
    if regex is None and any(s in plower for s in ("backup", "old", "bak", "swp", "~")):
        sev = Severity.MEDIUM
    return (
        "exposed",
        url,
        resp.status_code,
        f"Content-Type: {ctype}\nSignature: {why}\nMatch: {matched}\nLength: {len(body)} bytes\n\n"
        + truncate(body, 320),
        sev,
        confidence,
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    paths = load_data_lines("sensitive_paths.txt")
    if not paths:
        return findings

    client = HttpClient(config)
    try:
        baselines, home_bl = _baselines(client, target.origin)
        # If both baselines also returned 200, we are dealing with a strict
        # SPA - we can still proceed because the fingerprint comparison handles
        # it. If however the homepage itself looks identical to a 'not found',
        # we still trust signature matching.

        with ThreadPoolExecutor(max_workers=min(20, max(1, config.threads * 2))) as ex:
            futures = [
                ex.submit(_check, client, target.origin, p, baselines, home_bl)
                for p in paths
            ]
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                kind = res[0]

                if kind == "protected":
                    _, url, status, _ = res
                    findings.append(
                        Finding(
                            module="sensitive_files",
                            title=f"Path sensitif terdeteksi (terlindungi): {url}",
                            severity=Severity.INFO,
                            description=(
                                "Endpoint ini ada (server merespons 401/403) tetapi "
                                "membutuhkan otentikasi. Bukan celah, hanya catatan recon."
                            ),
                            target=url,
                            evidence=f"HTTP {status}",
                            confidence="firm",
                            remediation=(
                                "Periksa apakah path memang perlu diakses publik. "
                                "Sembunyikan dari akses anonim bila tidak."
                            ),
                            references=[
                                "https://owasp.org/www-project-top-ten/",
                            ],
                        )
                    )
                    continue

                if kind == "exposed":
                    _, url, status, ev, sev, confidence = res
                    findings.append(
                        Finding(
                            module="sensitive_files",
                            title=f"File/path sensitif terverifikasi: {url}",
                            severity=sev,
                            description=(
                                "Endpoint mengembalikan konten yang sesuai signature file "
                                "sensitif (kredensial / source / backup / config / kunci). "
                                "Soft-404 baseline & homepage signature sudah dipakai untuk "
                                "menyaring false positive."
                            ),
                            target=url,
                            evidence=ev,
                            confidence=confidence,
                            cwe="CWE-538",
                            remediation=(
                                "Hapus file dari root web atau blokir di web server "
                                "(`location ~ /\\.git { deny all; }` di Nginx, "
                                "`<FilesMatch> Require all denied </FilesMatch>` di Apache). "
                                "Pastikan deploy artifact tidak mengikutkan file dev/backup. "
                                "Jika kredensial sudah ter-ekspos, **rotasi semuanya** "
                                "(token API, password DB, kunci privat)."
                            ),
                            references=[
                                "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                                "https://cwe.mitre.org/data/definitions/538.html",
                            ],
                        )
                    )
    finally:
        client.close()
    return findings
