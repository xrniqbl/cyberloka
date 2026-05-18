"""Sensitive file exposure scanner — deep verification.

Mengapa ditulis ulang?
----------------------
Versi sebelumnya hanya cek status 200 → banyak false positive di SPA
(React/Vue/Next.js) atau aplikasi yang punya catch-all routing — endpoint
seperti ``/.env`` atau ``/wp-config.php`` mengembalikan 200 hanya karena
server mem-fallback ke index. Endpoint itu sebenarnya **aman**, tetapi
tetap dilaporkan sebagai celah kritis.

Pipeline akurasi sekarang:

1. **Soft-404 baseline.** Kirim 2 request ke path acak yang pasti tidak
   ada (mis. ``/cyberloka-<hex>-doesnotexist.html``). Simpan sidik jari
   (status, panjang body, sha1, ``<title>``). Selanjutnya bila respon
   kandidat identik / sangat mirip → diabaikan.

2. **Homepage signature.** Kalau body kandidat sama dengan homepage →
   itu cuma SPA fallback → diabaikan.

3. **Content-type guard.** Body 0 byte / pure HTML generic tanpa ciri
   file dimaksud → tidak dilaporkan sebagai vuln.

4. **Per-pattern content signature.** Setiap kategori punya regex /
   keyword yang **wajib muncul** untuk dianggap CONFIRMED:

   - ``.env``       → DB_PASSWORD/APP_KEY/AWS_SECRET=...
   - ``.git/config``→ ``[core]`` / ``[remote ...]``
   - ``.git/HEAD``  → ``ref: refs/heads/...``
   - ``.git/index`` → magic ``DIRC``
   - ``*.sql``      → CREATE TABLE / INSERT INTO / -- MySQL dump
   - ``wp-config``  → ``define('DB_NAME'``...
   - ``web.config`` → ``<configuration>...<system.webServer``
   - ``.htaccess``  → ``RewriteEngine`` / ``Options``
   - ``.htpasswd``  → ``user:$apr1$...``
   - private keys   → ``-----BEGIN ... PRIVATE KEY-----``
   - ``credentials``→ ``aws_access_key_id``
   - ``phpinfo``    → ``<title>phpinfo()``
   - dll. (33+ signature spesifik per kategori file)

5. **Confidence.** ``confirmed`` (signature match), ``firm`` (response
   non-HTML pendek pada path sensitif), ``tentative`` (turunan).

6. **401 / 403** → INFO ``protected`` (ada tapi terlindungi — bukan vuln,
   hanya recon).

Dengan begini, laporan tidak lagi men-flag endpoint yang sebenarnya
aman hanya karena merespon 200.
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
# (path-substring, severity-when-confirmed, regex, why)
# ---------------------------------------------------------------------------
SIGNATURES: list[tuple[str, Severity, "re.Pattern[str]", str]] = [
    # Env / dotfiles ---------------------------------------------------------
    (".env", Severity.CRITICAL,
     re.compile(r"(?im)^\s*(APP_KEY|APP_SECRET|DB_PASSWORD|DB_USERNAME|DB_HOST|"
                r"AWS_(ACCESS|SECRET)|MAIL_PASSWORD|JWT_SECRET|SECRET_KEY|"
                r"STRIPE_SECRET|MIDTRANS_(SERVER|CLIENT)_KEY)\s*="),
     "Env-style key=value pair (DB_PASSWORD/APP_KEY/...) ditemukan."),

    # Git --------------------------------------------------------------------
    (".git/config", Severity.CRITICAL,
     re.compile(r"(?im)^\s*\[(core|remote\b|branch\b)\]"),
     "Header [core]/[remote] khas file .git/config."),
    (".git/HEAD", Severity.CRITICAL,
     re.compile(r"(?im)^ref:\s+refs/heads/"),
     "Tag 'ref: refs/heads/...' khas .git/HEAD."),
    (".git/index", Severity.CRITICAL,
     re.compile(r"^DIRC", re.M),
     "Magic bytes 'DIRC' khas git index."),
    (".git/logs", Severity.CRITICAL,
     re.compile(r"\b[0-9a-f]{40}\s+[0-9a-f]{40}\b"),
     "Hash 40-char khas git log."),

    # Database dumps & backups ----------------------------------------------
    (".sql", Severity.HIGH,
     re.compile(r"(?im)\b(CREATE\s+TABLE|INSERT\s+INTO|--\s+(MySQL|PostgreSQL)\s+dump|"
                r"DROP\s+TABLE\s+IF\s+EXISTS|--\s+phpMyAdmin\s+SQL)"),
     "Statement DDL/DML khas dump SQL."),
    ("dump", Severity.HIGH,
     re.compile(r"(?im)\b(CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL\s+dump)"),
     "Statement DDL/DML khas dump SQL."),
    ("backup", Severity.HIGH,
     re.compile(r"(?im)\b(CREATE\s+TABLE|INSERT\s+INTO|BEGIN\s+TRANSACTION|"
                r"-----BEGIN)|^PK\x03\x04", re.S),
     "Konten backup (SQL/zip/tar/key) terdeteksi."),

    # PHP info / admin tools -------------------------------------------------
    ("phpinfo", Severity.HIGH,
     re.compile(r"<title>\s*phpinfo\(\)\s*</title>|PHP Version\s+\d", re.I),
     "Output phpinfo() ditemukan."),
    ("phpmyadmin", Severity.MEDIUM,
     re.compile(r"phpMyAdmin", re.I),
     "Halaman phpMyAdmin ditemukan."),
    ("adminer", Severity.MEDIUM,
     re.compile(r"<title>\s*Login\s*-\s*Adminer", re.I),
     "Halaman Adminer login ditemukan."),
    ("server-status", Severity.MEDIUM,
     re.compile(r"apache\s+server\s+status|<title>\s*Apache Status", re.I),
     "Apache mod_status terbuka."),
    ("server-info", Severity.MEDIUM,
     re.compile(r"apache\s+server\s+information", re.I),
     "Apache mod_info terbuka."),

    # CMS configs ------------------------------------------------------------
    ("wp-config", Severity.CRITICAL,
     re.compile(r"(?im)define\(\s*['\"](DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY)"),
     "Konstanta DB_NAME/DB_USER/AUTH_KEY khas wp-config.php."),
    ("configuration.php", Severity.CRITICAL,
     re.compile(r"(?im)\$\w+\s*=\s*['\"][^'\"]*['\"]\s*;.*(password|host|user)"),
     "Variabel konfigurasi Joomla khas."),
    ("settings.py", Severity.HIGH,
     re.compile(r"(?im)^(SECRET_KEY|DEBUG|DATABASES|ALLOWED_HOSTS)\s*="),
     "settings.py Django dengan SECRET_KEY/DATABASES."),

    # Dependency lockfiles --------------------------------------------------
    ("composer.json", Severity.LOW,
     re.compile(r'"name"\s*:\s*"[^"]+"\s*,', re.S),
     "Manifest composer.json valid."),
    ("composer.lock", Severity.MEDIUM,
     re.compile(r'"_readme"|"packages"\s*:\s*\[', re.S),
     "composer.lock valid → membocorkan dependency & versi."),
    ("package.json", Severity.LOW,
     re.compile(r'"name"\s*:\s*"[^"]+"', re.S),
     "Manifest package.json valid."),
    ("package-lock.json", Severity.LOW,
     re.compile(r'"lockfileVersion"\s*:'),
     "package-lock.json valid → membocorkan versi paket."),
    ("yarn.lock", Severity.LOW,
     re.compile(r"^# yarn lockfile|^[\w@/-]+@[^:]+:\s*$", re.M),
     "yarn.lock valid → membocorkan versi paket."),

    # Web server configs ----------------------------------------------------
    ("web.config", Severity.HIGH,
     re.compile(r"<configuration\b.*<system\.webServer|<configuration\b", re.S | re.I),
     "File IIS web.config (XML <configuration>)."),
    (".htaccess", Severity.MEDIUM,
     re.compile(r"(?im)^(RewriteEngine|RewriteRule|Options\s|<IfModule|AuthType)"),
     "Direktif Apache .htaccess."),
    (".htpasswd", Severity.HIGH,
     re.compile(r"^[\w.-]+:\$(?:apr1|2[ay]|6)\$", re.M),
     "Hash bcrypt/MD5 khas .htpasswd."),

    # Private keys / credentials --------------------------------------------
    ("id_rsa", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
     "Header PEM private key."),
    ("id_dsa", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:DSA )?PRIVATE KEY-----"),
     "Header PEM private key."),
    (".pem", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Header PEM private key."),
    (".ppk", Severity.CRITICAL,
     re.compile(r"^PuTTY-User-Key-File-", re.M),
     "Format PuTTY private key (.ppk)."),
    ("credentials", Severity.CRITICAL,
     re.compile(r"(?im)\[(default|profile\b)|aws_access_key_id\s*="),
     "Format AWS shared credentials."),
    ("aws", Severity.CRITICAL,
     re.compile(r"(?im)aws_access_key_id\s*=|AKIA[0-9A-Z]{16}"),
     "AWS access key ditemukan."),

    # IDE / editor leaks ----------------------------------------------------
    (".idea/workspace.xml", Severity.LOW,
     re.compile(r'<\?xml[^>]+\?>\s*<project'),
     "File project JetBrains."),
    (".vscode/settings.json", Severity.LOW,
     re.compile(r'\{\s*"[\w.-]+"\s*:', re.S),
     "File konfigurasi VS Code."),
    (".DS_Store", Severity.LOW,
     re.compile(r"\x00\x00\x00\x01Bud1", re.S),
     "Magic Apple .DS_Store."),

    # CI / build leaks -------------------------------------------------------
    (".gitlab-ci.yml", Severity.LOW,
     re.compile(r"(?im)^(stages|image|services|before_script):"),
     "File pipeline GitLab CI."),
    (".travis.yml", Severity.LOW,
     re.compile(r"(?im)^(language|script|jobs|deploy):"),
     "File pipeline Travis."),
    ("Dockerfile", Severity.LOW,
     re.compile(r"(?m)^(FROM|RUN|COPY|CMD|ENV)\b"),
     "Dockerfile."),

    # Log files --------------------------------------------------------------
    (".log", Severity.MEDIUM,
     re.compile(r"(?im)\b(error|warning|stack trace|exception|fatal|debug)\b"),
     "Konten file log."),
]

HTML_TAG_RE = re.compile(r"<html|<!doctype html", re.I)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.I | re.S)


@dataclass
class _Baseline:
    status: int
    length: int
    sha1: str
    title: str


def _fingerprint(text: str) -> tuple[int, str, str]:
    if text is None:
        text = ""
    sha1 = hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()
    m = TITLE_RE.search(text or "")
    title = m.group(1).strip() if m else ""
    return len(text), sha1, title


def _baselines(client: HttpClient, origin: str) -> tuple[list[_Baseline], _Baseline | None]:
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
    if not baselines:
        return False
    length, sha1, title = _fingerprint(text or "")
    for b in baselines:
        if b.status != status:
            continue
        if sha1 == b.sha1:
            return True
        if b.length and abs(length - b.length) <= max(64, b.length * 0.05) and (
            title == b.title
        ):
            return True
    return False


def _match_signature(
    path_lower: str, body: str, content_type: str
) -> tuple[Severity, "re.Pattern[str] | None", str] | None:
    for marker, sev, regex, why in SIGNATURES:
        if marker.lower() not in path_lower:
            continue
        if regex.search(body or ""):
            return sev, regex, why

    # Generic heuristic: non-HTML & not just blank
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
        return ("protected", url, resp.status_code, "")
    if resp.status_code != 200 or not resp.content:
        return None

    body = resp.text or ""
    ctype = resp.headers.get("Content-Type", "")

    # Soft-404
    if _looks_like_baseline(body, resp.status_code, baselines):
        return None

    # Homepage / SPA catch-all
    if home_bl is not None:
        length, sha1, _ = _fingerprint(body)
        if sha1 == home_bl.sha1 or (
            home_bl.length
            and abs(length - home_bl.length) <= max(32, home_bl.length * 0.02)
            and "html" in ctype.lower()
        ):
            return None

    sig = _match_signature(path.lower(), body, ctype)
    if sig is None:
        return None

    sev, regex, why = sig
    matched = ""
    if regex is not None:
        m = regex.search(body)
        if m:
            matched = truncate(m.group(0), 160)
    confidence = "confirmed" if regex is not None else "tentative"

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
                                "membutuhkan otentikasi. Bukan celah, hanya catatan "
                                "untuk fase recon."
                            ),
                            target=url,
                            evidence=f"HTTP {status}",
                            confidence="firm",
                            urls=[url],
                            remediation=(
                                "Periksa apakah path memang perlu diakses publik. "
                                "Sembunyikan dari akses anonim bila tidak."
                            ),
                            references=["https://owasp.org/www-project-top-ten/"],
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
                                "Endpoint mengembalikan konten yang COCOK signature file "
                                "sensitif (kredensial / source / backup / config / kunci). "
                                "Soft-404 baseline & homepage signature sudah dipakai untuk "
                                "menyaring false positive — ini bukan sekadar 200=OK."
                            ),
                            target=url,
                            evidence=ev,
                            confidence=confidence,
                            cwe="CWE-538",
                            urls=[url],
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
