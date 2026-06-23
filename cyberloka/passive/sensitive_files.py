"""Sensitive file exposure scanner — strict-validation v0.10.6.

PERUBAHAN PENTING (v0.10.6, perbaikan false-positive):
  Versi lama menyimpulkan "file sensitif ter-ekspos" hanya dari ``HTTP 200``
  + nama path cocok (mis. path mengandung ``.env``). Itu CONTENT-BLIND:
  banyak situs (Next.js/Nuxt/Remix/Angular SPA) membalas halaman HTML untuk
  path apa pun, sehingga ``/.env`` yang sebetulnya hanya mengembalikan
  beranda HTML dilaporkan KRITIS + ``confirmed`` (TERVALIDASI AKTIF) padahal
  TIDAK ADA isi ``.env`` sama sekali.

  Sekarang modul WAJIB membuktikan bahwa body benar-benar file yang dimaksud
  (selaras dengan ``git_repo_dump`` yang mem-parse ``.git/HEAD``):

    1. Catch-all guard: bandingkan dengan path random (control). Identik ⇒ tolak.
    2. Validasi tanda-tangan konten per tipe file:
         - ``.env``      → minimal 2 baris ``KEY=VALUE`` dan BUKAN HTML.
         - private key   → blok ``-----BEGIN ... PRIVATE KEY-----``.
         - .git/*        → ``ref: refs/`` / 40-hex / ``[core]``.
         - .aws/creds    → ``aws_access_key_id`` / ``[default]``.
         - .htpasswd     → ``user:$apr1$...`` hash.
         - dump/backup   → keyword SQL atau signature arsip (PK / gzip).
         - phpinfo/admin → marker khas panel (BUKAN beranda SPA).
         - json/yaml/log → parse/shape valid & bukan HTML.
    3. Keputusan:
         * Konten cocok signature        → severity penuh, ``confirmed``.
         * Body HTML/SPA & tak cocok      → DITOLAK (tidak ada finding).
         * Non-HTML tapi tak dikenali     → INFO ``tentative`` (verifikasi manual),
                                            TIDAK PERNAH CRITICAL-confirmed.
    4. ``robots.txt``/``sitemap.xml``/``security.txt`` = file publik wajar ⇒ skip.
"""
from __future__ import annotations

import json
import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines, truncate
from cyberloka.reporting.awam import get_awam

# ---------------------------------------------------------------------------
# Content signatures
# ---------------------------------------------------------------------------

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s*=", re.M)
_PRIV_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
)
_HTPASSWD = re.compile(
    r"^[^:\s]+:(?:\$(?:apr1|2[aby]|6|5|1)\$|\{SHA\}|[A-Za-z0-9./]{13}$)", re.M
)
_SQL_KW = re.compile(
    r"\b(?:CREATE TABLE|INSERT INTO|DROP TABLE|ALTER TABLE|"
    r"MySQL dump|PostgreSQL database dump|LOCK TABLES)\b",
    re.I,
)
_GIT_HEAD = re.compile(r"^\s*(?:ref:\s*refs/|[0-9a-f]{40}\s*$)", re.M)
_LOG_LINE = re.compile(
    r"\b(?:ERROR|WARN|WARNING|INFO|DEBUG|Exception|Traceback)\b|\[\d{4}-\d{2}-\d{2}"
)
_SHELL_CMD = re.compile(
    r"(?m)^\s*(?:cd|ls|sudo|cat|ssh|scp|mysql|psql|git|npm|yarn|curl|wget|"
    r"export|rm|cp|mv|vi|nano|docker|kubectl)\b"
)
_DSSTORE_SIG = b"\x00\x00\x00\x01Bud1"


def _is_html(text: str, ctype: str) -> bool:
    """True bila response adalah halaman HTML (bukan file plain/biner)."""
    if "text/html" in (ctype or "").lower():
        return True
    return looks_like_html_shell(text or "")


def _classify(path: str) -> str:
    """Petakan path → kategori file untuk memilih validator konten."""
    p = path.lower().strip("/")
    name = p.rsplit("/", 1)[-1]

    if p.startswith(".git/"):
        return "git"
    if name == ".gitignore":
        return "gitignore"
    if name.startswith(".env"):
        return "env"
    if name == ".npmrc" or p.endswith(".npm/_authtoken"):
        return "npmrc"
    if p.endswith(".aws/credentials"):
        return "aws"
    if name == ".htpasswd":
        return "htpasswd"
    if name == "id_rsa" or p.endswith(".ssh/id_rsa"):
        return "privkey"
    if name == "id_rsa.pub" or p.endswith(".ssh/authorized_keys"):
        return "pubkey"
    if name == ".bash_history":
        return "history"
    if name == ".ds_store":
        return "dsstore"
    if name.endswith(".sql") or name in ("backup.zip", "backup.tar.gz"):
        return "dump"
    if name in ("config.php.bak", "config.php~", "wp-config.php.bak"):
        return "php_config_bak"
    if name in ("phpinfo.php", "info.php", "test.php"):
        return "phpinfo"
    if name == "adminer.php":
        return "adminer"
    if "phpmyadmin" in p or p in ("pma",):
        return "phpmyadmin"
    if name in ("server-status", "server-info"):
        return "apache_status"
    if name == "web.config":
        return "webconfig"
    if name in ("docker-compose.yml", "dockerfile", ".dockerignore"):
        return "docker"
    if name in ("package.json", "package-lock.json", "composer.json",
                "composer.lock", "config.json"):
        return "json_config"
    if name in ("config.yml", "config.yaml"):
        return "yaml_config"
    if name == "yarn.lock":
        return "lock"
    if name in ("debug.log", "error.log", "access.log"):
        return "log"
    if (name in ("robots.txt", "sitemap.xml", "crossdomain.xml",
                 "clientaccesspolicy.xml")
            or p.endswith(".well-known/security.txt")):
        return "public"
    if p in ("admin", "administrator", "manage", "console"):
        return "admin_panel"
    return "generic"


# Kategori yang memang berbentuk halaman HTML — di sini HTML BUKAN tanda
# false-positive; validator memeriksa marker khusus panel/diagnostik.
_HTML_NATIVE = {"phpinfo", "adminer", "phpmyadmin", "admin_panel"}

# Severity untuk finding yang KONTENNYA tervalidasi (confirmed).
_SEV_CONFIRMED: dict[str, Severity] = {
    "env": Severity.CRITICAL,
    "npmrc": Severity.CRITICAL,
    "aws": Severity.CRITICAL,
    "htpasswd": Severity.CRITICAL,
    "privkey": Severity.CRITICAL,
    "git": Severity.CRITICAL,
    "php_config_bak": Severity.CRITICAL,
    "dump": Severity.HIGH,
    "phpinfo": Severity.HIGH,
    "adminer": Severity.HIGH,
    "phpmyadmin": Severity.HIGH,
    "apache_status": Severity.HIGH,
    "webconfig": Severity.MEDIUM,
    "docker": Severity.MEDIUM,
    "log": Severity.MEDIUM,
    "json_config": Severity.MEDIUM,
    "yaml_config": Severity.MEDIUM,
    "lock": Severity.LOW,
    "pubkey": Severity.LOW,
    "history": Severity.MEDIUM,
    "dsstore": Severity.LOW,
    "gitignore": Severity.LOW,
    "admin_panel": Severity.MEDIUM,
}


def _content_matches(cat: str, text: str, raw: bytes, ctype: str) -> bool:
    """Buktikan body benar-benar file/halaman yang dimaksud kategori ``cat``."""
    t = text or ""
    html = _is_html(t, ctype)

    if cat == "env":
        return (not html) and len(_ENV_LINE.findall(t)) >= 2
    if cat == "npmrc":
        low = t.lower()
        return (not html) and (
            "_authtoken" in low or "//registry" in low or "_auth=" in low
            or "_password" in low
        )
    if cat == "aws":
        low = t.lower()
        return (not html) and (
            "aws_access_key_id" in low or "aws_secret_access_key" in low
            or "[default]" in low
        )
    if cat == "htpasswd":
        return (not html) and bool(_HTPASSWD.search(t))
    if cat == "privkey":
        return bool(_PRIV_KEY.search(t))
    if cat == "pubkey":
        return t.strip().startswith(
            ("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2", "ssh-dss ")
        )
    if cat == "git":
        return bool(_GIT_HEAD.search(t)) or "[core]" in t or "[remote " in t
    if cat == "gitignore":
        # File teks pola ignore (bukan HTML). Nilai rendah tapi valid.
        if html or not t.strip():
            return False
        return bool(re.search(r"(?m)^[!#]?[\w*./-]+\s*$", t))
    if cat == "history":
        return (not html) and bool(_SHELL_CMD.search(t))
    if cat == "dsstore":
        return raw[:8] == _DSSTORE_SIG
    if cat == "dump":
        if raw[:2] == b"PK" or raw[:2] == b"\x1f\x8b":  # zip / gzip arsip
            return True
        return (not html) and bool(_SQL_KW.search(t))
    if cat == "php_config_bak":
        low = t.lower()
        return "<?php" in low and (
            "define(" in low or "db_password" in low or "dbpassword" in low
            or "$db" in low or "password" in low
        )
    if cat == "phpinfo":
        low = t.lower()
        return ("phpinfo()" in low or "<title>phpinfo()" in low
                or ("php version" in low and "configuration" in low))
    if cat == "adminer":
        low = t.lower()
        return "adminer" in low and ("login" in low or "<form" in low)
    if cat == "phpmyadmin":
        return "phpmyadmin" in t.lower()
    if cat == "apache_status":
        low = t.lower()
        return "apache server status" in low or "server uptime" in low
    if cat == "webconfig":
        return "<configuration" in t.lower()
    if cat == "docker":
        if html:
            return False
        first = t.split("\n", 1)[0].lower()
        low = t.lower()
        return (first.startswith("from ") or bool(re.search(r"(?m)^FROM\s+\S+", t))
                or "services:" in low or "image:" in low
                or re.search(r"(?m)^version:\s*['\"]?\d", t) is not None)
    if cat == "json_config":
        if html:
            return False
        try:
            obj = json.loads(t)
        except Exception:
            return False
        return isinstance(obj, (dict, list)) and bool(t.strip())
    if cat == "yaml_config":
        return (not html) and bool(re.search(r"(?m)^[A-Za-z0-9_.-]+\s*:\s*\S", t))
    if cat == "lock":
        low = t.lower()
        return (not html) and (
            "# yarn lockfile" in low or "__metadata" in t or 'resolved "' in t
        )
    if cat == "log":
        return (not html) and bool(_LOG_LINE.search(t))
    if cat == "admin_panel":
        low = t.lower()
        # Panel admin = HTML, tapi harus ada form login / kata kunci admin —
        # bukan sekadar beranda publik (catch-all sudah menyaring beranda).
        return ("login" in low or "password" in low or "sign in" in low
                or "dashboard" in low) and ("<form" in low or "<input" in low)
    return False


def _check(client: HttpClient, base: str, path: str,
           ctrl_signature: tuple[int, str] | None):
    url = urljoin(base, path)
    resp = client.get(url, allow_redirects=False)
    if resp is None or resp.status_code != 200 or not resp.content:
        return None
    body = resp.text or ""
    raw = resp.content or b""
    ctype = resp.headers.get("Content-Type", "")

    # Catch-all guard: response identik dengan path random ⇒ server selalu
    # balas hal yang sama untuk path apa pun ⇒ bukan file spesifik.
    if ctrl_signature is not None:
        c_len, c_first = ctrl_signature
        if abs(len(body) - c_len) <= 16 and body[:64] == c_first[:64]:
            return None

    cat = _classify(path)
    if cat == "public":
        return None  # robots/sitemap/security.txt = publik wajar, bukan celah

    matched = _content_matches(cat, body, raw, ctype)
    is_html = _is_html(body, ctype)
    return url, path, cat, matched, is_html, ctype, body, raw


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    paths = load_data_lines("sensitive_paths.txt")
    if not paths:
        return findings
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("sensitive_files")
    try:
        ctrl_url = urljoin(
            target.origin + "/", f"cyberloka_{secrets.token_hex(6)}_404.txt"
        )
        ctrl = client.get(ctrl_url, allow_redirects=False)
        ctrl_sig = None
        if ctrl is not None and ctrl.status_code == 200 and ctrl.content:
            ctrl_sig = (len(ctrl.text or ""), (ctrl.text or "")[:128])

        with ThreadPoolExecutor(max_workers=min(20, config.threads * 2)) as ex:
            futures = [
                ex.submit(_check, client, target.origin + "/", p, ctrl_sig)
                for p in paths
            ]
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                url, path, cat, matched, is_html, ctype, body, raw = res

                ev = f"{ctype} | {truncate(body, 200)}"

                if matched:
                    # --- Konten tervalidasi: finding sah & confirmed. -------
                    sev = _SEV_CONFIRMED.get(cat, Severity.MEDIUM)
                    confidence = "confirmed"
                    proof = ValidationProof(
                        method="content-signature-match",
                        confirmed=True,
                        steps=[
                            f"GET {url} → 200.",
                            ("Kontrol path random TIDAK identik (bukan catch-all 200)."
                             if ctrl_sig else "Tidak ada control-fetch (kontrol gagal)."),
                            f"Konten cocok tanda-tangan tipe '{cat}' — "
                            f"terbukti file sensitif asli, bukan halaman HTML.",
                        ],
                        samples=[truncate(ev, 200)],
                        notes=f"category={cat}; content signature matched",
                    )
                    desc = (
                        f"Endpoint mengembalikan 200 OK dan KONTENNYA terverifikasi "
                        f"sebagai file/halaman sensitif tipe '{cat}' (bukan SPA HTML "
                        f"fallback). Berpotensi membocorkan kredensial/source/konfigurasi."
                    )
                elif cat in _HTML_NATIVE or is_html:
                    # --- HTML/SPA shell tapi konten tak cocok signature. ----
                    # Inilah akar false-positive lama (mis. Next.js balas beranda
                    # untuk /.env). TOLAK: jangan keluarkan finding.
                    continue
                else:
                    # --- Non-HTML, data-ish, tapi signature tak dikenali. ---
                    # Mungkin file menarik; turunkan ke INFO + tentative.
                    sev = Severity.INFO
                    confidence = "tentative"
                    proof = ValidationProof(
                        method="status-200+control-diff (content unverified)",
                        confirmed=False,
                        steps=[
                            f"GET {url} → 200, Content-Type={ctype or 'n/a'}.",
                            ("Kontrol path random TIDAK identik."
                             if ctrl_sig else "Tidak ada control-fetch (kontrol gagal)."),
                            "Body BUKAN HTML, tetapi tidak cocok tanda-tangan file "
                            "sensitif yang dikenali — perlu verifikasi manual.",
                        ],
                        samples=[truncate(ev, 200)],
                        notes=f"category={cat}; signature NOT matched — manual review",
                    )
                    desc = (
                        "Endpoint mengembalikan 200 OK non-HTML yang berbeda dari "
                        "kontrol, tetapi isinya tidak terverifikasi sebagai file "
                        "sensitif tertentu. Diturunkan ke INFO — verifikasi manual."
                    )

                findings.append(
                    Finding(
                        module="sensitive_files",
                        title=f"File/path sensitif ter-ekspos: {url}",
                        severity=sev,
                        description=desc,
                        target=url,
                        urls=[url],
                        evidence=ev,
                        confidence=confidence,
                        remediation=(
                            "Hapus file dari root web atau blokir lewat web server "
                            "(`location ~ /\\.(env|git|htpasswd) { deny all; }` di Nginx). "
                            "Pastikan deploy artifact tidak mengikutkan file dev/backup/rahasia."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                        ],
                        extra=build_extra(
                            proof=proof,
                            awam_steps=awam_steps,
                            awam_summary=awam_summary,
                        ),
                    )
                )
    finally:
        client.close()
    return findings
