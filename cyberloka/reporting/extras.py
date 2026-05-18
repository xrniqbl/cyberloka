"""Mapping standar industri per modul (Bahasa Indonesia).

Dipakai oleh PDF reporter untuk memperkaya konten report:
  - OWASP Top 10 2021
  - MITRE ATT&CK technique
  - Dampak bisnis
  - Langkah reproduksi manual
  - Daftar istilah / glossary
"""
from __future__ import annotations

# --------------------------- OWASP Top 10 2021 ---------------------------
OWASP_MAP: dict[str, str] = {
    "headers": "A05:2021 Security Misconfiguration",
    "tls": "A02:2021 Cryptographic Failures",
    "cookies": "A07:2021 Identification & Authentication Failures",
    "cors": "A05:2021 Security Misconfiguration",
    "clickjacking": "A05:2021 Security Misconfiguration",
    "methods": "A05:2021 Security Misconfiguration",
    "sensitive_files": "A05:2021 Security Misconfiguration",
    "robots": "A05:2021 Security Misconfiguration",
    "api_discovery": "A05:2021 Security Misconfiguration",
    "graphql": "A09:2021 Security Logging & Monitoring Failures",
    "csrf": "A01:2021 Broken Access Control",
    "jwt": "A02:2021 Cryptographic Failures",
    "secrets": "A02:2021 Cryptographic Failures",
    "mixed_content": "A02:2021 Cryptographic Failures",
    "info_disclosure": "A05:2021 Security Misconfiguration",
    "cache": "A04:2021 Insecure Design",
    "waf_detect": "Informasional",
    "dns": "Informasional",
    "whois": "Informasional",
    "ports": "A05:2021 Security Misconfiguration",
    "subdomains": "Informasional",
    "fingerprint": "A06:2021 Vulnerable & Outdated Components",
    "subdomain_takeover": "A05:2021 Security Misconfiguration",
    "sqli": "A03:2021 Injection",
    "xss": "A03:2021 Injection",
    "redirect": "A01:2021 Broken Access Control",
    "lfi": "A01:2021 Broken Access Control",
    "cmdi": "A03:2021 Injection",
    "dirlist": "A05:2021 Security Misconfiguration",
    "host_header": "A05:2021 Security Misconfiguration",
    "ssrf": "A10:2021 Server-Side Request Forgery (SSRF)",
    "rate_limit": "A07:2021 Identification & Authentication Failures",
    "burst": "A04:2021 Insecure Design",
}

# --------------------------- MITRE ATT&CK --------------------------------
MITRE_MAP: dict[str, str] = {
    "headers": "T1190 Exploit Public-Facing Application",
    "tls": "T1040 Network Sniffing",
    "cookies": "T1539 Steal Web Session Cookie",
    "cors": "T1190 Exploit Public-Facing Application",
    "clickjacking": "T1204 User Execution",
    "methods": "T1190 Exploit Public-Facing Application",
    "sensitive_files": "T1083 File and Directory Discovery",
    "robots": "T1083 File and Directory Discovery",
    "api_discovery": "T1190 / T1083",
    "graphql": "T1190 Exploit Public-Facing Application",
    "csrf": "T1204 User Execution",
    "jwt": "T1606 Forge Web Credentials",
    "secrets": "T1552 Unsecured Credentials",
    "mixed_content": "T1557 Adversary-in-the-Middle",
    "info_disclosure": "T1592 Gather Victim Host Information",
    "cache": "T1530 Data from Cloud Storage",
    "waf_detect": "T1592 (Recon)",
    "dns": "T1590 Gather Victim Network Information",
    "whois": "T1591 Gather Victim Org Information",
    "ports": "T1046 Network Service Discovery",
    "subdomains": "T1590.005 IP Addresses",
    "fingerprint": "T1592.002 Software",
    "subdomain_takeover": "T1584 Compromise Infrastructure",
    "sqli": "T1190 Exploit Public-Facing Application",
    "xss": "T1059.007 JavaScript",
    "redirect": "T1566 Phishing",
    "lfi": "T1083 / T1005 Data from Local System",
    "cmdi": "T1059 Command and Scripting Interpreter",
    "dirlist": "T1083 File and Directory Discovery",
    "host_header": "T1190 Exploit Public-Facing Application",
    "ssrf": "T1090 Proxy / T1552 Unsecured Credentials",
    "rate_limit": "T1110 Brute Force",
    "burst": "T1499 Endpoint Denial of Service",
}

# --------------------------- Dampak Bisnis -------------------------------
IMPACT_MAP: dict[str, str] = {
    "sensitive_files": (
        "Pencurian source code, kredensial database, dan kunci API. Bisa menjadi "
        "pintu masuk ke pelanggaran data berskala besar dan pelanggaran UU PDP."
    ),
    "sqli": (
        "Akses langsung ke seluruh basis data (kredensial pengguna, data pelanggan, "
        "transaksi finansial). Potensi denda regulator (GDPR, UU PDP), tuntutan hukum, "
        "dan kehilangan kepercayaan pelanggan."
    ),
    "xss": (
        "Pengambilalihan akun pengguna, pencurian token sesi, defacement halaman, "
        "distribusi malware kepada pelanggan menggunakan domain yang dipercaya."
    ),
    "cmdi": (
        "Eksekusi kode arbitrer di server: deploy ransomware, exfiltrasi seluruh data, "
        "lateral movement ke sistem internal lain (DB, file server, AD)."
    ),
    "lfi": (
        "Pencurian file konfigurasi & kredensial; sering menjadi jalan menuju RCE "
        "(log poisoning di PHP, environment dump)."
    ),
    "ssrf": (
        "Akses ke jaringan internal & cloud metadata service (IAM credentials AWS/GCP) "
        "- pengambilalihan akun cloud organisasi dan seluruh resource di dalamnya."
    ),
    "subdomain_takeover": (
        "Phishing & distribusi malware dari subdomain Anda yang sah. Perusakan "
        "reputasi merek dan potensi pencurian cookie ber-scope domain induk."
    ),
    "secrets": (
        "Penyalahgunaan akun cloud / vendor pihak ketiga (Stripe, AWS, Mailgun). "
        "Biaya tak terduga, pelanggaran kontrak SLA, kebocoran data pelanggan."
    ),
    "jwt": (
        "Impersonasi pengguna mana pun termasuk admin tanpa kredensial. Pelanggaran "
        "kontrol akses massal, fraud transaksi, kebocoran data privat."
    ),
    "host_header": (
        "Account takeover via password-reset hijack. Cache poisoning di CDN yang "
        "berdampak ke seluruh pengguna (defacement / phishing skala besar)."
    ),
    "rate_limit": (
        "Serangan credential stuffing massal menggunakan database leak publik. "
        "Pengambilalihan ribuan akun dalam hitungan jam."
    ),
    "csrf": (
        "Eksekusi aksi sensitif (transfer dana, ubah email/password, approve order) "
        "tanpa sepengetahuan pengguna - biaya finansial langsung & komplain pelanggan."
    ),
    "redirect": (
        "Phishing brand impersonation. Penurunan kepercayaan pengguna & potensi "
        "pencurian token OAuth dari alur login."
    ),
    "api_discovery": (
        "Pemetaan permukaan serangan internal. Pada Spring Actuator/H2/Tomcat manager: "
        "potensi RCE langsung dengan satu request."
    ),
    "graphql": (
        "Pemetaan API internal lengkap. Over-fetching data sensitif (BOLA). "
        "Denial of Service via deeply-nested query."
    ),
    "tls": (
        "Pencurian sesi pengguna via MITM (terutama di public Wi-Fi). Pelanggaran "
        "kepatuhan PCI-DSS untuk merchant; potensi pencabutan akses payment gateway."
    ),
    "headers": (
        "Tidak langsung berdampak, namun memperbesar dampak XSS, clickjacking, dan "
        "MITM. Wajib untuk audit ISO 27001 & PCI-DSS."
    ),
    "cookies": (
        "Kebocoran session token via XSS atau koneksi tidak aman -> account takeover."
    ),
    "cors": (
        "Eksfiltrasi data API lintas-origin oleh situs jahat: data pribadi, riwayat "
        "transaksi, profil pengguna."
    ),
    "clickjacking": (
        "Pengguna menjalankan aksi sensitif tanpa sadar (transfer, approve, "
        "ubah setting kritis)."
    ),
    "info_disclosure": (
        "Mempercepat reconnaissance attacker. Pada Werkzeug/Flask debug page: RCE "
        "langsung via debug console."
    ),
    "cache": (
        "Kebocoran data privat satu pengguna ke pengguna lain melalui shared cache "
        "(CDN/proxy). Pelanggaran privasi serius."
    ),
    "mixed_content": (
        "MITM dapat menyuntikkan JavaScript jahat di context HTTPS - efektivitas "
        "attack setara XSS namun lebih mudah dilakukan di jaringan publik."
    ),
    "methods": (
        "Method PUT yang salah konfig dapat dipakai upload webshell langsung. "
        "TRACE memungkinkan Cross-Site Tracing untuk mencuri cookie HttpOnly."
    ),
    "dirlist": (
        "Penemuan file backup & konfigurasi yang seharusnya tidak terbuka publik."
    ),
    "robots": "Pemetaan path admin / staging.",
    "fingerprint": (
        "Pencocokan langsung dengan database CVE - 1-day exploit dapat digunakan "
        "secepat publikasi advisory."
    ),
    "ports": (
        "Eksposur service non-HTTP (database, cache, message broker) ke internet. "
        "Banyak service tanpa auth default - kebocoran data tanpa eksploitasi rumit."
    ),
    "dns": "Pemetaan infrastruktur target untuk perencanaan serangan lanjutan.",
    "whois": "Spear-phishing administrator menggunakan data kontak publik.",
    "subdomains": "Penemuan subdomain dengan postur keamanan terlemah sebagai pintu masuk.",
    "waf_detect": "Penyesuaian payload untuk mem-bypass WAF (encoding, fragmentation).",
    "burst": "Indikator awal kerentanan DoS - biaya cloud naik drastis saat dieksploitasi.",
}

# --------------------------- Cara Reproduksi -----------------------------
# Placeholder {url} dan {host} akan diganti otomatis oleh reporter.
REPRO_MAP: dict[str, str] = {
    "headers": (
        "curl -I {url}\n"
        "# Periksa response header. Header keamanan yang minimal harus ada:\n"
        "#   Strict-Transport-Security, Content-Security-Policy,\n"
        "#   X-Content-Type-Options, X-Frame-Options atau frame-ancestors,\n"
        "#   Referrer-Policy, Permissions-Policy."
    ),
    "tls": (
        "openssl s_client -connect {host}:443 -tls1_2 -servername {host}\n"
        "openssl s_client -connect {host}:443 -tls1     # WAJIB GAGAL\n"
        "# Atau pakai testssl.sh: ./testssl.sh {host}"
    ),
    "cookies": (
        "curl -i {url}\n"
        "# Periksa baris Set-Cookie. Cookie session WAJIB punya:\n"
        "#   Secure;  HttpOnly;  SameSite=Lax (atau Strict)."
    ),
    "cors": (
        "curl -i -H \"Origin: https://evil.example.com\" {url}\n"
        "# Jika Access-Control-Allow-Origin memantulkan origin attacker\n"
        "# DAN Access-Control-Allow-Credentials: true -> exploitable."
    ),
    "clickjacking": (
        "Simpan HTML berikut & buka di browser:\n"
        "  <iframe src=\"{url}\" width=800 height=600></iframe>\n"
        "# Jika frame tampil (tidak diblokir), vulnerable terhadap clickjacking."
    ),
    "methods": (
        "curl -X TRACE {url}\n"
        "curl -X PUT {url} -d 'test'\n"
        "curl -X DELETE {url}\n"
        "curl -X OPTIONS -i {url}     # lihat header Allow"
    ),
    "sensitive_files": (
        "curl -I {url}\n"
        "# Status 200 + content non-HTML = file betul ter-expose.\n"
        "# Untuk .git/HEAD: pastikan isi diawali 'ref: refs/heads/...'"
    ),
    "robots": "curl {url}/robots.txt\ncurl {url}/sitemap.xml",
    "api_discovery": (
        "Buka {url} di browser.\n"
        "# Khusus Spring Actuator, cek juga:\n"
        "#   /actuator/env  /actuator/heapdump  /actuator/mappings\n"
        "# /env dan /heapdump = CRITICAL bila terbuka."
    ),
    "graphql": (
        "curl -X POST {url} -H 'Content-Type: application/json' \\\n"
        "  -d '{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}'\n"
        "# Bila response berisi daftar types, introspection terbuka."
    ),
    "csrf": (
        "1. Pakai Burp Suite untuk capture request POST ke {url}.\n"
        "2. Buat halaman HTML attacker dengan form auto-submit ke endpoint tsb.\n"
        "3. Buka di browser yang sedang login. Bila aksi tereksekusi -> CSRF.\n"
        "# Verifikasi cepat: hapus header CSRF token & resend di Burp Repeater."
    ),
    "jwt": (
        "1. Decode token di https://jwt.io.\n"
        "2. Bila header.alg = none -> langsung modifikasi payload, hapus signature.\n"
        "3. Bila alg = HS256 -> brute-force secret pakai:\n"
        "   hashcat -m 16500 token.txt rockyou.txt\n"
        "4. Cek klaim exp; bila expired tetap diterima -> bug."
    ),
    "secrets": (
        "Buka source HTML/JS di {url}. Cari pola:\n"
        "  AKIA[A-Z0-9]{{16}}        (AWS Access Key)\n"
        "  AIza[A-Za-z0-9_-]{{35}}   (Google API Key)\n"
        "  sk_live_[A-Za-z0-9]{{24}} (Stripe live key)\n"
        "  ghp_[A-Za-z0-9]{{36}}     (GitHub PAT)\n"
        "Gunakan tool gitleaks/trufflehog untuk otomatisasi."
    ),
    "mixed_content": (
        "1. Buka {url} di Chrome.\n"
        "2. Tekan F12 -> tab Console -> filter 'Mixed Content'.\n"
        "3. Atau jalankan: chrome --enable-logging --v=1"
    ),
    "info_disclosure": (
        "1. Buka {url}, view source, cari komentar HTML berisi TODO/PASSWORD.\n"
        "2. Picu error: tambah karakter aneh di parameter URL.\n"
        "   Contoh: {url}?id=' atau {url}?id=null\n"
        "3. Bila muncul stack trace / Werkzeug debugger -> info disclosure."
    ),
    "cache": (
        "curl -i {url}\n"
        "# Halaman dengan cookie session WAJIB Cache-Control: no-store.\n"
        "# Untuk verifikasi CDN: pakai 2 user berbeda dari 2 IP berbeda."
    ),
    "waf_detect": (
        "curl -i \"{url}/?q=1' OR '1'='1\"\n"
        "# Status 403/406/429 dengan body unik -> WAF aktif.\n"
        "# Identifikasi vendor via wafw00f: wafw00f {url}"
    ),
    "dns": (
        "dig {host} ANY\n"
        "dig {host} TXT\n"
        "dig {host} MX\n"
        "nslookup -type=ANY {host}"
    ),
    "whois": "whois {host}",
    "ports": (
        "nmap -sV -p- --min-rate=1000 {host}\n"
        "# Untuk service seperti Redis/Mongo/Elastic, coba auth-less connect:\n"
        "redis-cli -h {host}\nmongosh --host {host}\ncurl http://{host}:9200/"
    ),
    "subdomains": (
        "subfinder -d {host} -all\n"
        "amass enum -d {host}\n"
        "# Atau: curl 'https://crt.sh/?q=%25.{host}&output=json'"
    ),
    "fingerprint": (
        "curl -I {url}\n"
        "# Catat header Server, X-Powered-By, X-Generator.\n"
        "# Cocokkan dengan https://nvd.nist.gov atau https://github.com/advisories"
    ),
    "subdomain_takeover": (
        "dig CNAME {host}\n"
        "curl -i https://{host}/\n"
        "# CNAME mengarah ke vendor pihak ketiga + body 'No such bucket' / "
        "'There is no app' = takeover candidate.\n"
        "# Lihat daftar fingerprint: https://github.com/EdOverflow/can-i-take-over-xyz"
    ),
    "sqli": (
        "curl \"{url}\"\n"
        "curl \"{url}'\"            # tambahkan tanda kutip\n"
        "curl \"{url}' OR '1'='1\"\n"
        "# Bandingkan length & status. Beda signifikan -> indikasi SQLi.\n"
        "# Verifikasi pakai sqlmap (HARUS dengan izin tertulis):\n"
        "  sqlmap -u \"{url}\" --batch --risk=1 --level=2"
    ),
    "xss": (
        "Buka {url} dengan parameter berisi:\n"
        "  <script>alert(document.domain)</script>\n"
        "Bila alert muncul -> Reflected XSS terkonfirmasi.\n"
        "# Untuk stored XSS: simpan payload di form, akses sebagai user lain."
    ),
    "redirect": (
        "curl -I \"{url}\"\n"
        "# Periksa Location header.\n"
        "# Tes payload: ?next=//evil.example.com  ?return=https://evil.com"
    ),
    "lfi": (
        "curl \"{url}/../../../../etc/passwd\"\n"
        "curl \"{url}?file=../../../../etc/passwd%00\"\n"
        "# Bila body berisi root:x:0:0 -> LFI confirmed."
    ),
    "cmdi": (
        "Tambahkan ke parameter:\n"
        "  ;sleep 5     |sleep 5     `sleep 5`     $(sleep 5)\n"
        "# Bila respons tertunda 5 detik -> command injection.\n"
        "# Untuk verifikasi out-of-band: pakai Burp Collaborator."
    ),
    "dirlist": (
        "Buka {url} di browser.\n"
        "# Bila tampil daftar file/folder dengan link, dirlist aktif."
    ),
    "host_header": (
        "curl -H \"Host: evil.example.com\" {url}\n"
        "curl -H \"X-Forwarded-Host: evil.example.com\" {url}\n"
        "# Periksa:\n"
        "#   - Location header memantulkan evil.example.com -> HIGH (open redirect)\n"
        "#   - body memantulkan evil.example.com           -> MEDIUM (cache poisoning)"
    ),
    "ssrf": (
        "Ambil parameter URL/callback/webhook di {url}, ganti nilainya:\n"
        "  http://127.0.0.1:80/\n"
        "  http://169.254.169.254/latest/meta-data/    (AWS - khusus pengujian sah)\n"
        "  file:///etc/passwd\n"
        "# Respons unik / berisi konten internal -> SSRF terkonfirmasi."
    ),
    "rate_limit": (
        "1. Otomatisasi 20 percobaan login dengan password salah ke endpoint login.\n"
        "2. Bila tidak ada lockout/CAPTCHA setelah N percobaan -> rate-limit absen.\n"
        "# Cyberloka modul rate_limit melakukan ini dengan aman & terkontrol."
    ),
    "burst": (
        "Kirim 100 request paralel ke {url} (mis. dengan ab atau hey).\n"
        "Bila semua diterima tanpa pelambatan -> edge tidak punya rate-limit."
    ),
}

# --------------------------- Glossary ------------------------------------
GLOSSARY: list[tuple[str, str]] = [
    ("CSP", "Content-Security-Policy. Header yang membatasi sumber resource yang boleh dimuat halaman web."),
    ("HSTS", "HTTP Strict Transport Security. Memaksa browser untuk selalu terhubung via HTTPS."),
    ("CORS", "Cross-Origin Resource Sharing. Mekanisme browser untuk mengizinkan/menolak request lintas origin."),
    ("CSRF", "Cross-Site Request Forgery. Serangan yang memanfaatkan sesi user korban untuk melakukan aksi tanpa sepengetahuan."),
    ("XSS", "Cross-Site Scripting. Penyisipan JavaScript jahat ke halaman korban."),
    ("SQLi", "SQL Injection. Manipulasi query database via input user."),
    ("SSRF", "Server-Side Request Forgery. Server dipaksa mem-fetch URL atas nama attacker."),
    ("LFI", "Local File Inclusion. Pembacaan file di server via parameter yang tidak divalidasi."),
    ("RCE", "Remote Code Execution. Eksekusi kode arbitrer di server target."),
    ("WAF", "Web Application Firewall. Filter HTTP berbasis rule untuk menahan payload jahat."),
    ("CVE", "Common Vulnerabilities and Exposures. Identifier unik untuk kerentanan publik."),
    ("CWE", "Common Weakness Enumeration. Klasifikasi pola kerentanan."),
    ("CVSS", "Common Vulnerability Scoring System. Sistem skor severity standar industri."),
    ("OWASP", "Open Worldwide Application Security Project. Komunitas non-profit standar keamanan aplikasi."),
    ("MITRE ATT&CK", "Knowledge base teknik & taktik penyerang yang dirilis MITRE Corp."),
    ("PCI-DSS", "Payment Card Industry Data Security Standard. Wajib untuk merchant yang memproses kartu pembayaran."),
    ("UU PDP", "Undang-Undang Pelindungan Data Pribadi (Indonesia, UU 27/2022)."),
    ("JWT", "JSON Web Token. Standar token compact untuk authentication & authorization."),
    ("BOLA", "Broken Object Level Authorization. Cacat otorisasi tingkat objek di API."),
    ("IoC", "Indicator of Compromise. Artefak teknis yang menandakan terjadinya kompromi."),
    ("MITM", "Man-in-the-Middle / Adversary-in-the-Middle. Penyusup yang membaca/memodifikasi lalu lintas."),
    ("Same-Origin Policy", "Aturan keamanan browser yang membatasi script mengakses resource dari origin lain."),
    ("Defense in Depth", "Strategi keamanan berlapis: tidak bergantung satu kontrol saja."),
    ("Zero Trust", "Model keamanan yang tidak otomatis mempercayai entitas internal maupun eksternal."),
]
