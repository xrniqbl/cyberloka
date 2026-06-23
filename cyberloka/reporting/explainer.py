"""Plain-Indonesian explainer for findings & modules.

Maps each scanner module name to a non-technical description (`friendly_name`,
`what_it_means`, `business_impact`, `category_id`) so that HTML/JSON reports
can be read by non-technical stakeholders (managers, business owners, clients).
"""
from __future__ import annotations

from typing import Any

# Categories used in the report grouping.
CATEGORIES = {
    "data": "Keamanan Data Pelanggan",
    "login": "Keamanan Login & Akun",
    "uang": "Risiko Keuangan & Penipuan",
    "infra": "Konfigurasi Server & Infrastruktur",
    "email": "Keamanan Email & Domain",
    "kode": "Keamanan Kode Aplikasi",
    "info": "Kebocoran Informasi",
    "lain": "Lainnya",
}

# module name -> friendly metadata
EXPLAIN: dict[str, dict[str, str]] = {
    # ============ RECON ============
    "dns": {
        "friendly_name": "Pemeriksaan Catatan Domain (DNS)",
        "what_it_means": (
            "Kami memeriksa catatan domain seperti A, MX, NS, dan TXT untuk "
            "memastikan nama domain Anda dikonfigurasi dengan benar dan tidak "
            "membocorkan informasi yang sensitif."
        ),
        "business_impact": (
            "Catatan domain yang salah dapat membuat email perusahaan masuk "
            "spam, atau membantu penyerang memetakan infrastruktur Anda."
        ),
        "category": "infra",
    },
    "whois": {
        "friendly_name": "Pemeriksaan Pemilik Domain (WHOIS)",
        "what_it_means": (
            "Kami melihat siapa yang terdaftar sebagai pemilik domain dan "
            "kapan domain akan kedaluwarsa."
        ),
        "business_impact": (
            "Domain yang akan habis tanpa diperpanjang dapat hilang dan "
            "dibeli orang lain. Email pemilik yang terbuka publik dapat "
            "disalahgunakan untuk phishing."
        ),
        "category": "infra",
    },
    "ports": {
        "friendly_name": "Pemeriksaan Pintu Masuk Server (Port Terbuka)",
        "what_it_means": (
            "Kami memeriksa 'pintu' jaringan mana saja di server Anda yang "
            "terbuka dari internet."
        ),
        "business_impact": (
            "Pintu yang seharusnya tertutup tetapi terbuka dapat dipakai "
            "penyerang untuk masuk ke server."
        ),
        "category": "infra",
    },
    "fingerprint": {
        "friendly_name": "Identifikasi Teknologi Website",
        "what_it_means": (
            "Kami mendeteksi server, framework, dan library yang dipakai "
            "(misalnya Cloudflare, Next.js, React)."
        ),
        "business_impact": (
            "Versi software yang lama dan dipublikasikan jelas memudahkan "
            "penyerang mencari kerentanan yang sudah diketahui."
        ),
        "category": "info",
    },
    "subdomains": {
        "friendly_name": "Pencarian Sub-domain",
        "what_it_means": (
            "Kami mencari sub-domain seperti admin.example.com, dev.example.com, "
            "yang mungkin tidak Anda sadari masih hidup."
        ),
        "business_impact": (
            "Sub-domain dev/staging yang lupa dimatikan sering jadi pintu "
            "masuk peretasan karena pengamanannya lemah."
        ),
        "category": "infra",
    },
    "subdomain_takeover": {
        "friendly_name": "Pengambilalihan Sub-domain Terlantar",
        "what_it_means": (
            "Kami memeriksa sub-domain yang masih mengarah ke layanan cloud "
            "(GitHub Pages, S3, Heroku) yang sudah dihapus — sehingga "
            "siapa pun bisa mengklaimnya."
        ),
        "business_impact": (
            "Penyerang dapat membuat halaman palsu di sub-domain Anda untuk "
            "menipu pelanggan (phishing) seakan-akan resmi dari perusahaan Anda."
        ),
        "category": "data",
    },
    "api_discovery": {
        "friendly_name": "Pencarian Endpoint API",
        "what_it_means": (
            "Kami memeriksa apakah ada dokumentasi API publik (Swagger, "
            "OpenAPI, GraphQL) yang seharusnya dibatasi."
        ),
        "business_impact": (
            "Dokumentasi API publik memberi penyerang peta lengkap untuk "
            "mencoba semua endpoint Anda."
        ),
        "category": "info",
    },
    "crawler": {
        "friendly_name": "Pemetaan Halaman Website",
        "what_it_means": (
            "Kami menelusuri semua halaman dan formulir di website Anda agar "
            "modul lain dapat memeriksa parameter & form yang ada."
        ),
        "business_impact": (
            "Tahap penting untuk memastikan semua halaman terjangkau pengujian, "
            "bukan hanya halaman utama."
        ),
        "category": "info",
    },
    "email_security": {
        "friendly_name": "Keamanan Email Domain (SPF/DKIM/DMARC/CAA/DNSSEC)",
        "what_it_means": (
            "Kami memeriksa proteksi email perusahaan: apakah hanya server "
            "yang berhak yang boleh mengirim email atas nama domain Anda."
        ),
        "business_impact": (
            "Tanpa proteksi ini, penyerang dapat mengirim email phishing "
            "ke pelanggan Anda yang terlihat datang dari email resmi perusahaan. "
            "Ini berisiko hilangnya kepercayaan pelanggan dan kerugian finansial."
        ),
        "category": "email",
    },
    "nextjs_specific": {
        "friendly_name": "Pemeriksaan Khusus Next.js",
        "what_it_means": (
            "Kami memeriksa kebocoran data spesifik aplikasi Next.js seperti "
            "build ID, source map, dan endpoint development."
        ),
        "business_impact": (
            "Source map yang bocor memungkinkan penyerang membaca kode sumber "
            "asli aplikasi Anda — termasuk logika bisnis dan rahasia."
        ),
        "category": "kode",
    },
    "cf_origin": {
        "friendly_name": "Pencarian IP Asli di Balik Cloudflare",
        "what_it_means": (
            "Cloudflare menyembunyikan IP server asli Anda. Kami memeriksa "
            "apakah ada sub-domain yang malah membongkar IP asli tersebut."
        ),
        "business_impact": (
            "Jika IP asli ditemukan, penyerang bisa melewati proteksi "
            "Cloudflare dan menyerang server langsung."
        ),
        "category": "infra",
    },
    "wayback": {
        "friendly_name": "Pencarian URL Lama (Wayback Machine + crt.sh)",
        "what_it_means": (
            "Kami melihat arsip historis untuk menemukan URL & sub-domain "
            "yang dulu publik."
        ),
        "business_impact": (
            "URL lama yang masih hidup tapi tidak dipantau (misal /admin-old) "
            "sering jadi titik lemah."
        ),
        "category": "info",
    },
    "framework_default": {
        "friendly_name": "Pemeriksaan Halaman Default Framework",
        "what_it_means": (
            "Kami memeriksa halaman/admin default yang khas framework "
            "(WordPress admin, Spring actuator, phpMyAdmin, Tomcat, dll.)."
        ),
        "business_impact": (
            "Halaman ini sering punya kredensial default atau tidak butuh "
            "login — pintu masuk klasik untuk peretasan."
        ),
        "category": "infra",
    },
    "graphql_deep": {
        "friendly_name": "Pemeriksaan Mendalam GraphQL",
        "what_it_means": (
            "Kami memeriksa apakah API GraphQL Anda membocorkan skema lengkap "
            "(introspection) atau memberi saran field saat salah ketik."
        ),
        "business_impact": (
            "Skema GraphQL yang bocor = peta lengkap ke seluruh data backend Anda."
        ),
        "category": "info",
    },
    "source_leak": {
        "friendly_name": "Kebocoran File Sensitif (.git, .env, backup)",
        "what_it_means": (
            "Kami memeriksa apakah ada file rahasia seperti .git, .env, "
            "kunci SSH, atau dump database yang bisa diunduh publik."
        ),
        "business_impact": (
            "File-file ini biasanya berisi password database, kunci API, "
            "dan kredensial lain. Sangat kritikal — bisa langsung membongkar "
            "seluruh sistem."
        ),
        "category": "data",
    },
    # ============ PASSIVE ============
    "headers": {
        "friendly_name": "Pemeriksaan Header Keamanan HTTP",
        "what_it_means": (
            "Kami memeriksa apakah website Anda mengirim header keamanan "
            "yang melindungi browser pengunjung (HSTS, X-Frame-Options, dll)."
        ),
        "business_impact": (
            "Tanpa header ini, browser pengunjung lebih rentan terhadap "
            "serangan clickjacking, MITM, dan XSS."
        ),
        "category": "infra",
    },
    "tls": {
        "friendly_name": "Pemeriksaan Sertifikat HTTPS / TLS",
        "what_it_means": (
            "Kami memeriksa sertifikat HTTPS website Anda: validitas, "
            "tanggal kedaluwarsa, kekuatan enkripsi."
        ),
        "business_impact": (
            "Sertifikat kedaluwarsa = browser menolak / memperingatkan pengunjung. "
            "Enkripsi lemah = data pelanggan bisa disadap di jaringan publik."
        ),
        "category": "infra",
    },
    "cookies": {
        "friendly_name": "Pemeriksaan Cookie Login",
        "what_it_means": (
            "Kami memeriksa apakah cookie sesi (yang menyimpan login) memakai "
            "atribut keamanan minimum (Secure, HttpOnly, SameSite)."
        ),
        "business_impact": (
            "Cookie tanpa proteksi dapat dicuri oleh script jahat atau "
            "disadap di Wi-Fi publik — penyerang bisa login sebagai pelanggan."
        ),
        "category": "login",
    },
    "cors": {
        "friendly_name": "Konfigurasi Akses Lintas Domain (CORS)",
        "what_it_means": (
            "Kami memeriksa apakah API website Anda mengizinkan akses dari "
            "domain yang seharusnya tidak."
        ),
        "business_impact": (
            "CORS terlalu longgar = website lain bisa membaca data pelanggan "
            "Anda dari browser mereka."
        ),
        "category": "data",
    },
    "clickjacking": {
        "friendly_name": "Perlindungan Clickjacking",
        "what_it_means": (
            "Kami memeriksa apakah halaman Anda dapat di-embed di website lain "
            "(seperti iframe transparan untuk menipu klik pengguna)."
        ),
        "business_impact": (
            "Penyerang dapat membuat halaman palsu yang memuat halaman Anda "
            "untuk menipu pelanggan klik tombol berbahaya."
        ),
        "category": "data",
    },
    "methods": {
        "friendly_name": "Metode HTTP Tidak Aman",
        "what_it_means": (
            "Kami memeriksa apakah server menerima metode tidak biasa seperti "
            "TRACE, PUT, DELETE yang seharusnya dimatikan."
        ),
        "business_impact": (
            "Metode ini dapat dipakai untuk mengubah/menghapus data atau "
            "membaca cookie pengunjung."
        ),
        "category": "infra",
    },
    "sensitive_files": {
        "friendly_name": "File Sensitif Terbuka",
        "what_it_means": (
            "Kami memeriksa apakah ada file seperti backup, log, atau "
            "konfigurasi yang seharusnya tidak publik."
        ),
        "business_impact": (
            "File ini sering berisi data internal, password, atau "
            "informasi sistem yang membantu penyerang."
        ),
        "category": "data",
    },
    "robots": {
        "friendly_name": "Pemeriksaan robots.txt & Sitemap",
        "what_it_means": (
            "Kami memeriksa file robots.txt dan sitemap untuk melihat path "
            "yang Anda eksplisit sembunyikan dari Google."
        ),
        "business_impact": (
            "Path 'tersembunyi' di robots.txt sering menjadi target "
            "penyerang karena justru mengungkap admin panel atau API internal."
        ),
        "category": "info",
    },
    "outdated_libs": {
        "friendly_name": "Library JavaScript Kedaluwarsa",
        "what_it_means": (
            "Kami memeriksa versi library frontend (jQuery, Lodash, AngularJS, "
            "Vue, Bootstrap) terhadap database kerentanan."
        ),
        "business_impact": (
            "Library lama = punya CVE yang sudah diketahui publik. Penyerang "
            "tinggal pakai exploit yang sudah ada."
        ),
        "category": "kode",
    },
    "mixed_content": {
        "friendly_name": "Konten HTTP di Halaman HTTPS",
        "what_it_means": (
            "Kami memeriksa halaman HTTPS yang masih memuat resource "
            "(gambar/script) lewat HTTP tidak aman."
        ),
        "business_impact": (
            "Browser memberi peringatan 'Not Secure' dan menurunkan kepercayaan "
            "pengunjung. Resource HTTP juga bisa dimodifikasi penyerang."
        ),
        "category": "infra",
    },
    "jwt": {
        "friendly_name": "Pemeriksaan Token JWT",
        "what_it_means": (
            "JWT adalah token login modern. Kami memeriksa apakah token-nya "
            "dikonfigurasi aman (algoritma, masa berlaku)."
        ),
        "business_impact": (
            "Token JWT yang lemah dapat dipalsu — penyerang bisa login "
            "sebagai user mana pun, termasuk admin."
        ),
        "category": "login",
    },
    "csp_evaluator": {
        "friendly_name": "Kekuatan Content-Security-Policy",
        "what_it_means": (
            "CSP adalah aturan keamanan untuk browser. Kami menilai apakah "
            "aturan Anda cukup ketat untuk mencegah XSS."
        ),
        "business_impact": (
            "CSP longgar = kalau ada bug XSS, penyerang langsung bisa "
            "mencuri data pelanggan."
        ),
        "category": "kode",
    },
    "captcha_check": {
        "friendly_name": "Captcha pada Form Sensitif",
        "what_it_means": (
            "Kami memeriksa apakah form penting (login, register, voucher) "
            "memakai reCAPTCHA / hCaptcha / Turnstile untuk mencegah bot."
        ),
        "business_impact": (
            "Tanpa captcha, bot bisa brute-force login atau spam voucher "
            "secara otomatis."
        ),
        "category": "login",
    },
    # ============ ACTIVE ============
    "csrf": {
        "friendly_name": "Perlindungan Cross-Site Request Forgery (CSRF)",
        "what_it_means": (
            "Kami memeriksa apakah form penting memiliki token anti-CSRF "
            "yang mencegah aksi atas nama korban dari situs lain."
        ),
        "business_impact": (
            "Penyerang dapat membuat halaman jahat yang menjebak pengunjung "
            "yang sedang login melakukan transfer/update data tanpa sadar."
        ),
        "category": "login",
    },
    "sqli": {
        "friendly_name": "SQL Injection (Akses Database Tidak Sah)",
        "what_it_means": (
            "Kami mencoba menyuntikkan kode database lewat parameter URL/form "
            "untuk melihat apakah server merespons dengan error database."
        ),
        "business_impact": (
            "SQL Injection adalah salah satu kerentanan paling berbahaya. "
            "Penyerang dapat membaca/mengubah/menghapus seluruh database "
            "Anda — termasuk semua data pelanggan, password, transaksi."
        ),
        "category": "data",
    },
    "xss": {
        "friendly_name": "Cross-Site Scripting / XSS (Script Berbahaya)",
        "what_it_means": (
            "Kami mencoba menyuntikkan kode JavaScript lewat parameter URL "
            "untuk melihat apakah dipantulkan ke halaman."
        ),
        "business_impact": (
            "XSS memungkinkan penyerang menjalankan kode di browser pengunjung — "
            "mencuri cookie login, defacement halaman, atau menampilkan form "
            "phishing palsu."
        ),
        "category": "data",
    },
    "redirect": {
        "friendly_name": "Open Redirect (Pengalihan Tidak Aman)",
        "what_it_means": (
            "Kami memeriksa apakah URL bisa dipakai untuk mengalihkan pengunjung "
            "ke domain pihak ketiga."
        ),
        "business_impact": (
            "Penyerang membuat link 'aman' yang awalnya ke domain Anda lalu "
            "redirect ke situs phishing — pelanggan tertipu karena URL awal terpercaya."
        ),
        "category": "data",
    },
    "lfi": {
        "friendly_name": "Local File Inclusion (Akses File Server)",
        "what_it_means": (
            "Kami mencoba menyuntikkan path file (../../etc/passwd) untuk "
            "melihat apakah server membaca file dari sistem operasi."
        ),
        "business_impact": (
            "Penyerang dapat membaca file konfigurasi server, password, "
            "kode sumber aplikasi."
        ),
        "category": "infra",
    },
    "cmdi": {
        "friendly_name": "Command Injection (Perintah Sistem Operasi)",
        "what_it_means": (
            "Kami memeriksa apakah parameter dieksekusi sebagai perintah "
            "shell di server."
        ),
        "business_impact": (
            "Sangat kritikal — penyerang dapat menjalankan perintah apa pun "
            "di server: hapus data, install backdoor, ambil alih total."
        ),
        "category": "infra",
    },
    "dirlist": {
        "friendly_name": "Directory Listing Terbuka",
        "what_it_means": (
            "Kami memeriksa apakah ada folder yang menampilkan daftar isi "
            "saat dibuka di browser."
        ),
        "business_impact": (
            "Penyerang dapat menelusuri seluruh file di server termasuk "
            "backup, file rahasia, atau script internal."
        ),
        "category": "info",
    },
    "ssrf": {
        "friendly_name": "Server-Side Request Forgery (SSRF)",
        "what_it_means": (
            "Kami memeriksa apakah server bisa dipaksa fetch URL pilihan "
            "penyerang (termasuk endpoint internal)."
        ),
        "business_impact": (
            "Penyerang dapat mengakses service internal di belakang firewall, "
            "termasuk metadata cloud (AWS/GCP) yang bisa membongkar kredensial server."
        ),
        "category": "infra",
    },
    "ssrf_metadata": {
        "friendly_name": "SSRF ke Metadata Cloud",
        "what_it_means": (
            "Pemeriksaan khusus apakah SSRF mencapai endpoint metadata cloud "
            "yang menyimpan kredensial server."
        ),
        "business_impact": (
            "Sangat kritikal. Jika berhasil, penyerang mendapat IAM token AWS/GCP/Azure "
            "Anda dan bisa mengambil alih akun cloud Anda."
        ),
        "category": "infra",
    },
    "ssti": {
        "friendly_name": "Server-Side Template Injection (SSTI)",
        "what_it_means": (
            "Kami menyuntik sintaks template (Jinja, Twig, ERB) untuk melihat "
            "apakah server mengevaluasinya."
        ),
        "business_impact": (
            "SSTI biasanya berujung pada Remote Code Execution — server "
            "Anda diambil alih total."
        ),
        "category": "infra",
    },
    "xxe": {
        "friendly_name": "XML External Entity (XXE)",
        "what_it_means": (
            "Kami menyuntik file XML khusus pada endpoint yang menerima XML "
            "untuk melihat apakah parser memproses external entity."
        ),
        "business_impact": (
            "Berpotensi membaca file lokal (config, password) dan menjalankan "
            "permintaan internal (SSRF)."
        ),
        "category": "infra",
    },
    "forms": {
        "friendly_name": "Pengujian Form Otomatis",
        "what_it_means": (
            "Kami menyuntik payload SQLi/XSS ke form yang ditemukan crawler "
            "untuk verifikasi keamanan input."
        ),
        "business_impact": (
            "Sama dengan SQLi & XSS — kebocoran data pelanggan / pengambilalihan "
            "akun."
        ),
        "category": "data",
    },
    "session": {
        "friendly_name": "Keamanan Sesi Login",
        "what_it_means": (
            "Kami memeriksa form login, atribut cookie sesi, panjang session ID, "
            "session fixation, dan account enumeration."
        ),
        "business_impact": (
            "Sesi yang lemah memudahkan pengambilalihan akun pelanggan — risiko "
            "kehilangan trust dan kerugian finansial."
        ),
        "category": "login",
    },
    "voucher": {
        "friendly_name": "Pengujian Sistem Voucher / Kupon",
        "what_it_means": (
            "Kami coba kode voucher umum (TEST, FREE, WELCOME) dan pengujian "
            "stack-abuse pada endpoint redeem."
        ),
        "business_impact": (
            "Voucher bug = kerugian langsung. Kode test yang lupa dimatikan "
            "atau voucher yang bisa dipakai berkali-kali = bocor cashback / promo."
        ),
        "category": "uang",
    },
    "payment": {
        "friendly_name": "Pengujian Sistem Pembayaran",
        "what_it_means": (
            "Kami memeriksa parameter harga yang bisa dimanipulasi, IDOR pada "
            "endpoint order, dan kebocoran kunci API gateway pembayaran "
            "(Midtrans/Stripe/Xendit/Doku)."
        ),
        "business_impact": (
            "Risiko paling tinggi untuk e-commerce — pelanggan bisa beli "
            "barang Rp 1 atau melihat invoice orang lain. Kunci gateway yang "
            "bocor bisa dipakai membuat transaksi palsu atas nama merchant."
        ),
        "category": "uang",
    },
    "otp_check": {
        "friendly_name": "Keamanan OTP / 2FA",
        "what_it_means": (
            "Kami memeriksa apakah endpoint OTP punya rate-limit dan panjang "
            "kode yang cukup (idealnya 6 digit)."
        ),
        "business_impact": (
            "OTP 4 digit tanpa rate-limit bisa di-brute-force dalam menit. "
            "Akun pelanggan + saldo bisa dirampas."
        ),
        "category": "login",
    },
    "password_reset": {
        "friendly_name": "Keamanan Reset Password",
        "what_it_means": (
            "Kami memeriksa apakah endpoint lupa password rentan account "
            "enumeration, token leak via Referer, atau dilayani via HTTP."
        ),
        "business_impact": (
            "Jalur reset password sering dimanfaatkan untuk takeover akun "
            "pelanggan. Token yang lemah = akun bisa diambil tanpa tahu password."
        ),
        "category": "login",
    },
    "file_upload": {
        "friendly_name": "Keamanan Form Upload File",
        "what_it_means": (
            "Kami coba upload file dengan ekstensi nakal (.php.jpg, .phtml, "
            "SVG XSS) untuk melihat apakah validasinya cukup."
        ),
        "business_impact": (
            "Upload yang lemah dapat berujung Remote Code Execution — penyerang "
            "upload script PHP/JS dan menjalankannya di server Anda."
        ),
        "category": "infra",
    },
    "idor_generic": {
        "friendly_name": "IDOR (Akses Data Orang Lain)",
        "what_it_means": (
            "Kami mencoba mengubah ID di URL/path (cth. /order/123 → /order/124) "
            "untuk melihat apakah server tetap memberi data."
        ),
        "business_impact": (
            "IDOR sering dipakai untuk membaca pesanan/invoice/data pelanggan "
            "lain. Pelanggaran serius UU PDP."
        ),
        "category": "data",
    },
    "host_header": {
        "friendly_name": "Host Header Injection",
        "what_it_means": (
            "Kami menyuntik header Host palsu untuk melihat apakah dipantulkan "
            "ke link reset password / redirect."
        ),
        "business_impact": (
            "Sering dipakai untuk meracuni link reset password — pelanggan klik "
            "link dari email resmi tapi diarahkan ke situs penyerang."
        ),
        "category": "login",
    },
    "cache_poison": {
        "friendly_name": "Web Cache Poisoning",
        "what_it_means": (
            "Kami coba header non-standar yang dipantulkan + dikache untuk "
            "melihat apakah konten bisa diracun untuk pengunjung lain."
        ),
        "business_impact": (
            "Penyerang dapat mengganti konten halaman utama untuk semua "
            "pengunjung. Risiko defacement massal."
        ),
        "category": "infra",
    },
    "hpp": {
        "friendly_name": "HTTP Parameter Pollution",
        "what_it_means": (
            "Kami kirim parameter dengan nama sama dua kali untuk melihat "
            "perilaku server."
        ),
        "business_impact": (
            "Bisa dipakai untuk melewati validasi atau WAF (firewall web)."
        ),
        "category": "kode",
    },
    "rfd": {
        "friendly_name": "Reflected File Download",
        "what_it_means": (
            "Pengujian apakah response API bisa diunduh sebagai file .bat/.cmd "
            "berisi perintah berbahaya."
        ),
        "business_impact": (
            "Pelanggan tertipu mengunduh file dari domain terpercaya, lalu "
            "menjalankannya — komputer pelanggan terinfeksi."
        ),
        "category": "data",
    },
    "dom_xss": {
        "friendly_name": "DOM-based XSS (di sisi browser)",
        "what_it_means": (
            "Kami menganalisa kode JavaScript untuk pola berbahaya yang "
            "menerima data dari URL tanpa sanitasi."
        ),
        "business_impact": (
            "Sama dengan XSS biasa — kode jahat dijalankan di browser "
            "pengunjung."
        ),
        "category": "data",
    },
    "oauth_check": {
        "friendly_name": "Keamanan OAuth / Login Sosial",
        "what_it_means": (
            "Kami memeriksa konfigurasi OAuth (Google/Facebook login): apakah "
            "memakai parameter `state`, PKCE, dan redirect_uri HTTPS."
        ),
        "business_impact": (
            "OAuth lemah dapat dimanfaatkan mencuri token login pelanggan."
        ),
        "category": "login",
    },
    "pii_leak": {
        "friendly_name": "Kebocoran Data Pribadi (NIK/HP/CC)",
        "what_it_means": (
            "Kami memindai response untuk pola nomor identitas Indonesia: "
            "NIK 16 digit, NPWP, nomor HP +62, kartu kredit."
        ),
        "business_impact": (
            "Kritikal untuk kepatuhan UU Perlindungan Data Pribadi (UU PDP). "
            "Kebocoran PII = denda regulasi + kehilangan trust pelanggan + "
            "potensi gugatan."
        ),
        "category": "data",
    },
    "db_pii_leak": {
        "friendly_name": "Kebocoran PII Massal dari Database (NIK/KK/Rekening/HP)",
        "what_it_means": (
            "Khusus untuk konteks 'data dari database bocor lewat URL/API "
            "publik'. Kami probe endpoint kandidat dump (mis. /api/users, "
            "/api/customers, /dump.json, /backup/users.csv) plus URL hasil "
            "crawl, lalu deteksi pola PII Indonesia: NIK (16 digit dengan "
            "kode provinsi BPS), nomor KK (16 digit dengan konteks "
            "'kartu keluarga'), nomor rekening bank (10-15 digit dengan "
            "konteks BCA/BNI/BRI/Mandiri/dll.), nomor HP +62/08, email, "
            "NPWP, dan kartu kredit (Luhn-validated). Threshold ketat "
            "(≥5 unik per jenis atau ≥3 jenis bersamaan) + negative-control "
            "fetch path random untuk hindari false-positive."
        ),
        "business_impact": (
            "Pelanggaran berat UU PDP No. 27/2022 — denda hingga 2% omzet "
            "tahunan + sanksi pidana. Untuk fintech tambah POJK 12/2018 / "
            "POJK 6/2022. Data NIK/KK + rekening yang bocor langsung dipakai "
            "untuk pinjol ilegal, penipuan TF, BI checking palsu, dan "
            "pemerasan. Reputasi brand hancur (kasus Tokopedia 2020, "
            "BPJS 2021, BSI 2023 jadi rujukan)."
        ),
        "category": "data",
    },
    "race_condition": {
        "friendly_name": "Race Condition (Voucher / Withdraw Ganda)",
        "what_it_means": (
            "Kami kirim 8 request paralel ke endpoint kritis (redeem voucher, "
            "withdraw saldo, klaim cashback) untuk melihat apakah ada locking."
        ),
        "business_impact": (
            "Klasik di e-commerce — voucher dipakai berkali-kali atau "
            "saldo ditarik double. Kerugian finansial langsung."
        ),
        "category": "uang",
    },
    "proto_pollution": {
        "friendly_name": "Prototype Pollution (Node.js)",
        "what_it_means": (
            "Pengujian apakah parameter __proto__ atau constructor[prototype] "
            "diproses oleh aplikasi Node.js."
        ),
        "business_impact": (
            "Berpotensi DoS, escalation privilege, atau RCE di aplikasi Node.js."
        ),
        "category": "kode",
    },
    "http_smuggling": {
        "friendly_name": "HTTP Request Smuggling",
        "what_it_means": (
            "Kami coba kombinasi header Content-Length + Transfer-Encoding "
            "yang dapat memecah parsing antara reverse-proxy dan backend."
        ),
        "business_impact": (
            "Smuggling sukses memungkinkan bypass otentikasi, hijack sesi "
            "pelanggan lain, atau cache poisoning."
        ),
        "category": "infra",
    },
    "ws_check": {
        "friendly_name": "Keamanan WebSocket",
        "what_it_means": (
            "Pengujian apakah endpoint WebSocket menerima koneksi dari domain "
            "tidak terpercaya (Cross-Site WebSocket Hijacking)."
        ),
        "business_impact": (
            "Penyerang dapat membuka koneksi WebSocket atas nama korban dan "
            "membaca/mengirim pesan internal."
        ),
        "category": "data",
    },
    "auth_bypass": {
        "friendly_name": "Bypass Login & Halaman Admin Terbuka",
        "what_it_means": (
            "Kami coba kombinasi password default umum (admin/admin, root/root, dll) "
            "pada form login, dan memeriksa apakah halaman admin/panel internal "
            "dapat diakses publik tanpa autentikasi."
        ),
        "business_impact": (
            "Bypass login = pengambilalihan akun admin total. Halaman admin yang "
            "terbuka publik = setengah jalan menuju takeover. Risiko paling "
            "kritikal untuk operasional bisnis."
        ),
        "category": "login",
    },
    "deep_login_audit": {
        "friendly_name": "Audit Login Mendalam (Default Credentials Tervalidasi)",
        "what_it_means": (
            "Modul ini memetakan semua form login (admin maupun user), mencoba "
            "kredensial paling umum dari daftar kebocoran publik, lalu memvalidasi "
            "OTOMATIS apakah login berhasil. Validasi memakai kombinasi banyak "
            "signal: redirect ke halaman privileged, Set-Cookie sesi, JSON token, "
            "perbedaan body vs baseline, dan probe ke endpoint privileged setelah "
            "login. Karena multi-signal, hasilnya tidak perlu cek manual."
        ),
        "business_impact": (
            "Kalau ada finding di sini, akun admin / user Anda dapat diambil alih "
            "oleh siapapun di internet hanya bermodal daftar password umum. "
            "Setelah login admin = kontrol penuh aplikasi. Setelah login user = "
            "akses data pribadi korban + dapat dipakai social engineering."
        ),
        "category": "login",
    },
    "root_access_check": {
        "friendly_name": "Akses Setara Root via Service Terbuka",
        "what_it_means": (
            "Kami memvalidasi otomatis apakah ada port publik yang menjalankan "
            "service kontrol-bidang (Docker daemon, Kubernetes API/kubelet, etcd, "
            "Redis, MongoDB, Elasticsearch, CouchDB, Jenkins script console, dll.) "
            "tanpa autentikasi. Validasi pakai signature respons API, bukan "
            "sekadar 'port terbuka', sehingga false-positive minimal."
        ),
        "business_impact": (
            "Service-service ini, kalau terbuka tanpa auth, = setara akses ROOT "
            "ke server / cluster. Attacker dapat membuat container privileged, "
            "exec ke pod, mengambil seluruh database, atau menjalankan kode "
            "Groovy via Jenkins. Ini biasanya jadi pintu masuk insiden ransomware "
            "/ data leak skala besar."
        ),
        "category": "infra",
    },
    # ============ 15 modul baru (multi-signal active validation) ============
    "wp_user_enum": {
        "friendly_name": "WordPress: Daftar Admin Terbongkar",
        "what_it_means": (
            "Kami memvalidasi apakah daftar username WordPress dapat di-enumerate "
            "publik via REST API (/wp-json/wp/v2/users), parameter ?author=N "
            "(redirect ke /author/<slug>/), dan login-oracle (pesan error berbeda "
            "untuk user valid vs invalid). Konfirmasi multi-jalur memastikan ini "
            "bukan false positive."
        ),
        "business_impact": (
            "Daftar username yang terbongkar mempersempit serangan brute-force - "
            "attacker hanya perlu cari password untuk username yang sudah dia "
            "tahu pasti ada. Klasik prelude untuk takeover wp-admin."
        ),
        "category": "login",
    },
    "wp_xmlrpc": {
        "friendly_name": "WordPress XML-RPC Aktif (DDoS / Brute-Force Amplifier)",
        "what_it_means": (
            "Kami memvalidasi /xmlrpc.php aktif + method berbahaya (pingback.ping, "
            "wp.getUsersBlogs, system.multicall) tersedia. Konfirmasi tambahan: "
            "probe pingback.ping dengan URL invalid - kalau dapat 'invalid URL' "
            "fault, berarti method benar-benar dieksekusi (aktif)."
        ),
        "business_impact": (
            "pingback.ping aktif = server Anda jadi alat DDoS reflection ke "
            "korban lain. wp.getUsersBlogs = 1 request HTTP berisi 1000 percobaan "
            "password (bypass rate-limit wp-login.php). IP server bisa ter-blacklist "
            "skala internasional kalau dipakai DDoS."
        ),
        "category": "infra",
    },
    "wp_admin_default": {
        "friendly_name": "WordPress wp-admin Tertembus dengan Default Credentials",
        "what_it_means": (
            "Kami coba kombinasi default umum (admin/admin, admin/password) ke "
            "wp-login.php dengan validasi 3 signal: cookie wordpress_logged_in_*, "
            "redirect ke /wp-admin/, dan halaman /wp-admin/profile.php memuat "
            "menu Logout. Tidak akan emit finding tanpa ketiga signal."
        ),
        "business_impact": (
            "Akses wp-admin = full content control + kemampuan upload theme/plugin "
            "yang biasanya berujung RCE (eksekusi kode di server). Setara ambil "
            "alih total website + kemungkinan server."
        ),
        "category": "login",
    },
    "basic_auth_default": {
        "friendly_name": "HTTP Basic Auth dengan Kredensial Default",
        "what_it_means": (
            "Kami probe path admin umum yang biasa di-protect dengan htpasswd "
            "(/admin, /server-status, /manager, /jenkins, dll.). Untuk yang "
            "respond 401 + WWW-Authenticate: Basic, coba kombinasi default "
            "dan validasi via response 200 + body bukan halaman login error."
        ),
        "business_impact": (
            "Basic Auth biasanya melindungi dashboard internal / management "
            "panel yang sangat sensitif. Default credentials = setara kunci master."
        ),
        "category": "login",
    },
    "swagger_walker": {
        "friendly_name": "Walker Swagger/OpenAPI: Uji Tiap Endpoint Tanpa Auth",
        "what_it_means": (
            "Kami parse spec OpenAPI/Swagger publik, lalu UJI tiap endpoint GET "
            "tanpa header Authorization. Kalau spec menyatakan endpoint butuh "
            "auth (security: bearer/apiKey) tapi tetap mengembalikan data nyata "
            "(JSON valid dengan key/value berisi), itu broken authentication "
            "yang tervalidasi - bukan teori dari 'swagger publik'."
        ),
        "business_impact": (
            "Broken auth pada endpoint API = attacker bisa baca data pelanggan, "
            "ubah konfigurasi, atau kirim transaksi atas nama orang lain. "
            "Pelanggaran besar UU PDP."
        ),
        "category": "data",
    },
    "prometheus_metrics_leak": {
        "friendly_name": "Metrics/Actuator Endpoint dengan Validasi Secret-Pattern",
        "what_it_means": (
            "Kami cek 16+ jalur metrics/debug (/metrics, /actuator/env, "
            "/actuator/heapdump, /debug/pprof, dll.). Validasi format response "
            "(Prometheus exposition, JSON Spring, binary heapdump). Kemudian "
            "scan body untuk pola kredensial REAL: AWS key, JDBC URL, MongoDB URI, "
            "private key, Bearer token. Finding kritikal hanya muncul kalau "
            "secret nyata terdeteksi."
        ),
        "business_impact": (
            "Heapdump berisi snapshot memory aplikasi - termasuk SEMUA password "
            "dan token yang sedang dipakai. Setara dengan kunci master. /actuator/env "
            "sering membocorkan database password dalam plaintext."
        ),
        "category": "data",
    },
    "git_repo_dump": {
        "friendly_name": ".git Repository Publik (Source Code Bocor)",
        "what_it_means": (
            "Kami validasi /.git/ exposure dengan PARSING konten: HEAD "
            "(regex 'ref: refs/heads/...'), config (section [core]/[remote]), "
            "index (DIRC binary signature), info/refs (smart HTTP). Kalau ada "
            "kredensial inline di URL remote (https://user:pass@host), "
            "dinaikkan ke CRITICAL. Bukan false-positive 200-page-fallback."
        ),
        "business_impact": (
            "Attacker bisa `git clone` repo Anda → seluruh source code + history "
            "commit (sering ada secret yang sempat di-commit lalu dihapus). "
            "Setara dengan code leak permanent."
        ),
        "category": "kode",
    },
    "tomcat_manager_default": {
        "friendly_name": "Tomcat / JBoss Manager Default Auth",
        "what_it_means": (
            "Kami validasi Tomcat /manager/html, /host-manager/html, JBoss "
            "/admin-console/, WildFly /console/ dengan kredensial default. "
            "Konfirmasi via marker body ('Tomcat Web Application Manager') + "
            "verifikasi tambahan via /manager/text/list yang return daftar app."
        ),
        "business_impact": (
            "Tomcat manager = bisa upload .war (web application archive) yang "
            "berisi webshell, lalu eksekusi sebagai user Tomcat (sering = root). "
            "Setara ROOT-equivalent access."
        ),
        "category": "infra",
    },
    "phpmyadmin_default": {
        "friendly_name": "phpMyAdmin Tertembus dengan Default DB Credentials",
        "what_it_means": (
            "Kami detect phpMyAdmin via title + form khas, lalu submit POST "
            "login dengan kombinasi root/root, root/(empty), admin/admin. "
            "Konfirmasi via cookie phpmyadmin_* + redirect ke index.php tanpa "
            "header auth + body tidak memuat 'cannot log in'."
        ),
        "business_impact": (
            "Akses phpMyAdmin = read/write/drop seluruh database production, "
            "termasuk tabel user/password aplikasi. Setara total breach data pelanggan."
        ),
        "category": "data",
    },
    "adminer_exposed": {
        "friendly_name": "Adminer Terbuka + Versi Rentan + Default DB Login",
        "what_it_means": (
            "Adminer single-file PHP DB tool yang sering disimpan di webroot. "
            "Modul detect via regex 'Adminer\\s+<version>', extract versi, "
            "compare dengan versi yang punya CVE. Lalu coba MySQL default login. "
            "Multi-finding: exposed (informasi), versi vulnerable, default login."
        ),
        "business_impact": (
            "Adminer versi lama punya SSRF/RCE CVE. Default DB login = akses "
            "penuh database. Klasik backdoor yang lupa dihapus setelah debug."
        ),
        "category": "data",
    },
    "kibana_unauth": {
        "friendly_name": "Kibana / Elasticsearch Tanpa Autentikasi",
        "what_it_means": (
            "Kami validasi Kibana via /api/status (JSON dengan version + status) "
            "dan Elasticsearch via /_cat/indices?format=json (array dengan key "
            "'index'). Detect indeks sensitif (logstash-*, auth*, user*) - "
            "menentukan severity finding."
        ),
        "business_impact": (
            "Kibana publik = web UI ke seluruh Elasticsearch, baca semua log/index. "
            "Insiden besar (miliaran record bocor) sering datang dari sini."
        ),
        "category": "data",
    },
    "grafana_default": {
        "friendly_name": "Grafana Default admin/admin + CVE-2021-43798",
        "what_it_means": (
            "Cek Grafana via /api/health (JSON version+database). Coba login "
            "default admin/admin dengan validasi cookie grafana_session + "
            "/api/user mengembalikan user yang sama. Cek juga versi vs "
            "CVE-2021-43798 (path traversal /etc/passwd)."
        ),
        "business_impact": (
            "Grafana admin = konfigur datasource (akses DB internal), buat "
            "alert webhook ke domain attacker (data exfiltrasi), atau jalankan "
            "query SQL ke datasource yang tersambung."
        ),
        "category": "infra",
    },
    "ftp_anonymous": {
        "friendly_name": "FTP Anonymous Login Aktif",
        "what_it_means": (
            "Validasi via raw socket: TCP connect port 21, kirim USER anonymous "
            "+ PASS, konfirmasi response 230. Lalu eksekusi PWD/SYST untuk "
            "memastikan akses nyata (bukan banner-only)."
        ),
        "business_impact": (
            "Attacker bisa download seluruh konten anonymous root dengan "
            "`wget -r ftp://anonymous:x@host/`. FTP juga plaintext - kalau ada "
            "user real, password mereka mengalir tanpa enkripsi."
        ),
        "category": "infra",
    },
    "idor_active_chain": {
        "friendly_name": "IDOR Aktif: Akses Data User Lain Tervalidasi",
        "what_it_means": (
            "Kami ambil URL dengan parameter ID numerik (?id=, /users/123) dari "
            "crawler, lalu kirim varian dengan ID berbeda (-1, +1, +2). Validasi "
            "multi-signal: response 200, struktur JSON sama tapi value berbeda, "
            "body length signifikan berbeda (>50 byte), tidak memuat 'not found'. "
            "Minimal 2 varian harus sukses untuk emit finding (bukan flukes)."
        ),
        "business_impact": (
            "IDOR berarti user A dapat membaca data user B. Pelanggaran besar "
            "UU PDP, dapat memunculkan gugatan + denda regulasi."
        ),
        "category": "data",
    },
    "websocket_auth_check": {
        "friendly_name": "WebSocket Cross-Origin Hijack (CSWSH)",
        "what_it_means": (
            "Kami buka koneksi WebSocket ke endpoint umum (/ws, /socket.io, "
            "/graphql, dll.) dengan dua Origin: domain sah dan attacker.invalid. "
            "Kalau keduanya sama-sama dapat 101 Switching Protocols (server tidak "
            "validasi Origin), itu CSWSH. Tambahan: kirim 1 frame ping - kalau "
            "server merespons, channel command terbuka."
        ),
        "business_impact": (
            "Halaman jahat di domain attacker bisa membuka WS ke server target "
            "DARI BROWSER korban yang sedang login - dan membaca/mengirim pesan "
            "sebagai korban. Setara hijack sesi real-time."
        ),
        "category": "data",
    },
    "balance": {
        "friendly_name": "Pengujian Manipulasi Saldo / E-wallet",
        "what_it_means": (
            "Kami coba kirim nilai abnormal (negatif, nol, integer overflow, "
            "desimal sangat kecil) ke endpoint saldo / wallet / withdraw / "
            "topup / cashback / poin."
        ),
        "business_impact": (
            "Jika validasi server lemah, attacker bisa withdraw saldo negatif "
            "(menambah saldo sendiri), bypass minimum withdraw, atau memicu "
            "kesalahan akumulasi poin. Kerugian finansial langsung dan masif."
        ),
        "category": "uang",
    },
    "env_leak": {
        "friendly_name": "Kebocoran Environment Variable & Stack Trace",
        "what_it_means": (
            "Kami memindai response untuk pola kunci API (AWS, Stripe, GitHub, "
            "Slack, SendGrid), URI database (MongoDB, Postgres, Redis), JWT secret, "
            "dan stack trace yang membongkar path file & versi framework. "
            "Juga memeriksa endpoint debug seperti /actuator/env dan /__debug__."
        ),
        "business_impact": (
            "Kunci API yang bocor = attacker langsung punya akses ke layanan "
            "cloud / payment / email Anda dengan kredensial yang sah. URI database "
            "= bisa membaca seluruh data pelanggan. Endpoint debug = peta lengkap "
            "konfigurasi internal."
        ),
        "category": "data",
    },
    "api_auth": {
        "friendly_name": "Keamanan API: Autentikasi, Mass Export, Rate-Limit",
        "what_it_means": (
            "Untuk setiap endpoint API yang ditemukan crawler, kami: "
            "(1) cek apakah API tetap balas data tanpa autentikasi (broken auth); "
            "(2) cek apakah listing API mengembalikan ratusan record tanpa pagination "
            "(potensi mass scraping); (3) kirim 20 request berturut-turut untuk "
            "menguji rate-limit."
        ),
        "business_impact": (
            "API tanpa auth = pelanggaran besar — siapa saja bisa membaca data "
            "pelanggan. Mass export = seluruh database bisa di-scrape dalam menit. "
            "Tanpa rate-limit = bot mudah brute-force atau DoS."
        ),
        "category": "data",
    },
    "mass_assignment": {
        "friendly_name": "Mass Assignment (Privilege Escalation lewat Form)",
        "what_it_means": (
            "Kami coba kirim field tambahan seperti `is_admin=true`, `role=admin`, "
            "`balance=9999999`, `verified=true` saat register/profile update, "
            "untuk melihat apakah server menerima dan menyimpannya."
        ),
        "business_impact": (
            "Akun biasa bisa langsung jadi admin saat register, atau saldo "
            "ditambah sendiri saat update profil. Bug klasik di framework yang "
            "auto-bind body ke model database tanpa filter."
        ),
        "category": "login",
    },
    "rate_limit": {
        "friendly_name": "Pengujian Rate-Limit Login",
        "what_it_means": (
            "Kami uji apakah endpoint login membatasi jumlah percobaan."
        ),
        "business_impact": (
            "Tanpa rate-limit, bot dapat brute-force password ribuan kali per menit."
        ),
        "category": "login",
    },
    "burst": {
        "friendly_name": "Pengujian Burst Request",
        "what_it_means": (
            "Kami kirim banyak request berturut-turut untuk melihat respons "
            "WAF/rate-limiter."
        ),
        "business_impact": (
            "Tanpa proteksi, penyerang dapat melakukan scraping / DoS ringan."
        ),
        "category": "infra",
    },
    # ============ TIER 1 — KRITIKAL ============
    "log_injection": {
        "friendly_name": "Log4Shell & Log Injection",
        "what_it_means": (
            "Kami kirim payload JNDI (`${jndi:ldap://...}`) lewat berbagai "
            "header (User-Agent, X-Forwarded-For, Referer) dan parameter URL."
        ),
        "business_impact": (
            "Log4Shell adalah salah satu CVE paling berbahaya — kalau server "
            "Java pakai log4j vulnerable, attacker dapat RCE root cuma dengan "
            "satu request HTTP. Banyak server belum patch."
        ),
        "category": "infra",
    },
    "jwt_confusion": {
        "friendly_name": "JWT Algorithm Confusion & KID Injection",
        "what_it_means": (
            "Kami coba forge token dengan algoritma berbeda (alg=none, RS256→HS256), "
            "dan periksa apakah field `kid` rentan path traversal/SQL injection."
        ),
        "business_impact": (
            "JWT yang lemah konfigurasinya = forge token admin = ambil alih "
            "semua akun pelanggan + admin. Sangat berbahaya untuk e-commerce."
        ),
        "category": "login",
    },
    "crlf_injection": {
        "friendly_name": "CRLF Injection / HTTP Response Splitting",
        "what_it_means": (
            "Kami sisipkan karakter newline (CR/LF) di parameter URL untuk "
            "melihat apakah dipantulkan ke header response."
        ),
        "business_impact": (
            "Berhasil = attacker dapat menambah header Set-Cookie sendiri, "
            "meracuni cache, atau XSS via header. Cookie pelanggan bisa dicuri."
        ),
        "category": "data",
    },
    "nosqli": {
        "friendly_name": "NoSQL Injection (MongoDB / CouchDB)",
        "what_it_means": (
            "Kami kirim operator MongoDB seperti `{\"$ne\":null}`, `{\"$regex\":\".*\"}` "
            "ke endpoint login dan API JSON."
        ),
        "business_impact": (
            "Kalau backend Node.js + MongoDB tidak filter input, payload `$ne` "
            "bisa bypass login total. Sangat umum di app modern."
        ),
        "category": "data",
    },
    "deserialization": {
        "friendly_name": "Insecure Deserialization (Java/PHP/Python/.NET)",
        "what_it_means": (
            "Kami pindai response untuk pola data terserialisasi: Java (rO0AB), "
            "PHP (`O:`), Python pickle, .NET ViewState."
        ),
        "business_impact": (
            "Insecure deserialization = RCE klasik. Salah satu CVE paling sering "
            "jadi PoC publik. Attacker dapat eksekusi kode arbitrary."
        ),
        "category": "infra",
    },
    "cloud_buckets": {
        "friendly_name": "Enumerasi S3 / GCS / Azure Bucket Publik",
        "what_it_means": (
            "Kami coba nama-nama bucket umum berdasarkan domain (cth. "
            "`<company>-backup`, `<company>-prod`) di S3, Google Cloud Storage, "
            "dan Azure Blob."
        ),
        "business_impact": (
            "Bucket publik dengan listing terbuka = sumber kebocoran data terbesar. "
            "Banyak insiden besar (Verizon, Pentagon, dll) berasal dari S3 yang salah konfigurasi."
        ),
        "category": "data",
    },
    # ============ TIER 2 — HIGH-PRIORITY ============
    "cms_scan": {
        "friendly_name": "Scan CMS (WordPress / Drupal / Joomla)",
        "what_it_means": (
            "Kami deteksi versi CMS dan plugin yang dipakai (mis. WP Plugin "
            "WooCommerce, Elementor, Wordfence) dengan membaca readme.txt."
        ),
        "business_impact": (
            "Plugin WP yang lama sering punya RCE/SQLi tanpa auth. Cek WPScan DB "
            "untuk versi yang vulnerable."
        ),
        "category": "kode",
    },
    "k8s_exposure": {
        "friendly_name": "Kubernetes API / Dashboard Terbuka",
        "what_it_means": (
            "Kami cek port 6443 (API server), 10250 (kubelet), 8443 (dashboard) "
            "untuk akses anonymous."
        ),
        "business_impact": (
            "Cluster Kubernetes terbuka = attacker bisa exec ke pod, baca semua "
            "secret, ambil alih cluster + bisa lateral move ke seluruh service."
        ),
        "category": "infra",
    },
    "webhook_signature": {
        "friendly_name": "Webhook Tanpa Verifikasi Signature",
        "what_it_means": (
            "Kami kirim payload payment-callback palsu (mis. Midtrans-style "
            "settlement notification) ke endpoint webhook umum."
        ),
        "business_impact": (
            "Webhook payment yang tidak verify signature = attacker bisa forge "
            "'transaksi sukses' palsu. Saldo masuk tanpa pembayaran asli. Klasik "
            "fraud e-commerce."
        ),
        "category": "uang",
    },
    "cors_advanced": {
        "friendly_name": "CORS Bypass Lanjutan (suffix, null origin)",
        "what_it_means": (
            "Kami coba berbagai trik origin: arbitrary domain, suffix bypass "
            "(`https://target.com.evil.com`), null origin."
        ),
        "business_impact": (
            "CORS misconfig + Allow-Credentials = cookie pelanggan dicuri lewat "
            "JavaScript di domain attacker."
        ),
        "category": "data",
    },
    "cache_control_audit": {
        "friendly_name": "Audit Cache-Control pada Halaman Sensitif",
        "what_it_means": (
            "Kami periksa header Cache-Control di halaman /account, /order, "
            "/cart, /admin — apakah memuat `no-store` atau `private`."
        ),
        "business_impact": (
            "Halaman sensitif yang ter-cache di Cloudflare/CDN = data pelanggan "
            "lain bisa dilihat. Pernah jadi insiden besar di banyak e-commerce."
        ),
        "category": "data",
    },
    "csv_injection": {
        "friendly_name": "CSV / Formula Injection",
        "what_it_means": (
            "Kami cek file CSV yang di-export — apakah ada cell yang dimulai "
            "dengan `=`, `+`, `-`, `@`, atau TAB."
        ),
        "business_impact": (
            "Saat dibuka di Excel, cell yang mulai `=` dieksekusi sebagai formula. "
            "Attacker bisa kirim data dengan `=cmd|...` untuk RCE di komputer staff."
        ),
        "category": "data",
    },
    "graphql_dos": {
        "friendly_name": "GraphQL DoS (depth & alias bombing)",
        "what_it_means": (
            "Kami kirim query nested 9 level dan 50 alias dalam satu request "
            "untuk lihat apakah server membatasi cost."
        ),
        "business_impact": (
            "Tanpa cost-analysis, satu request bisa membuat database down. "
            "Risiko outage produksi."
        ),
        "category": "infra",
    },
    "dependency_confusion": {
        "friendly_name": "Dependency Confusion via package.json",
        "what_it_means": (
            "Kami unduh package.json/composer.json dari webroot dan cek apakah "
            "ada paket scoped/internal yang bisa di-claim publik."
        ),
        "business_impact": (
            "Attacker publish paket dengan nama sama versi lebih tinggi → "
            "masuk ke build pipeline = supply chain attack. Klasik CVE 2021+."
        ),
        "category": "kode",
    },
    # ============ TIER 3 — HARDENING ============
    "cookie_scope": {
        "friendly_name": "Audit Scope Cookie",
        "what_it_means": (
            "Kami cek atribut Domain dan Path cookie — apakah terlalu lebar."
        ),
        "business_impact": (
            "Cookie dengan Domain=.example.com dikirim ke SEMUA subdomain. "
            "Subdomain takeover atau XSS di dev.example.com = curi cookie utama."
        ),
        "category": "login",
    },
    "sentry_dsn_leak": {
        "friendly_name": "Token Analytics di Bundle JS",
        "what_it_means": (
            "Kami pindai bundle JS untuk Sentry DSN, Mixpanel token, Datadog "
            "client token, Segment write key, Firebase config."
        ),
        "business_impact": (
            "Token client biasanya tidak fatal, tapi kalau yang bocor SECRET key "
            "(AWS, dll) — bisa langsung dipakai. Sentry DSN bisa di-spam attacker."
        ),
        "category": "info",
    },
    "server_timing_header": {
        "friendly_name": "Header Server-Timing Membocorkan Internal",
        "what_it_means": (
            "Header `Server-Timing` mengekspos waktu DB query, cache hit/miss."
        ),
        "business_impact": (
            "Membantu attacker timing attack dan memetakan arsitektur internal."
        ),
        "category": "info",
    },
    "xpath_injection": {
        "friendly_name": "XPath Injection",
        "what_it_means": (
            "Kami coba payload `' or '1'='1` di parameter yang mungkin ke XPath query."
        ),
        "business_impact": (
            "Bypass otentikasi XML-based, atau ekstrak data dari XML database."
        ),
        "category": "data",
    },
    "api_key_in_url": {
        "friendly_name": "API Key Lewat URL Query",
        "what_it_means": (
            "Kami cek URL yang ditemukan crawler — apakah ada parameter "
            "`api_key`, `token`, `password`, `jwt` di query string."
        ),
        "business_impact": (
            "Credential di URL bocor lewat: header Referer ke domain lain, log "
            "proxy, browser history, dan share URL."
        ),
        "category": "data",
    },
    "logout_csrf": {
        "friendly_name": "Logout Bisa Dipicu via GET",
        "what_it_means": (
            "Kami cek apakah endpoint logout bisa diakses lewat GET tanpa "
            "CSRF token — bisa dipicu via `<img src=...>` di domain lain."
        ),
        "business_impact": (
            "Bukan kerentanan kritikal, tapi mengganggu UX dan setup phishing."
        ),
        "category": "login",
    },
    "zip_slip": {
        "friendly_name": "Zip Slip (Path Traversal di Extract Zip)",
        "what_it_means": (
            "Kami upload zip dengan entry `../../../../tmp/file.txt` ke endpoint "
            "yang menerima upload zip."
        ),
        "business_impact": (
            "Berhasil = attacker bisa overwrite file critical (mis. authorized_keys, "
            "cron) → RCE root atau persistence."
        ),
        "category": "infra",
    },
    "ldap_injection": {
        "friendly_name": "LDAP Filter Injection",
        "what_it_means": (
            "Kami kirim karakter LDAP filter (`*)(`, `*`) pada form login enterprise."
        ),
        "business_impact": (
            "Berhasil = bypass otentikasi enterprise (Active Directory)."
        ),
        "category": "login",
    },
    "autocomplete_audit": {
        "friendly_name": "Form Sensitif tanpa autocomplete=off",
        "what_it_means": (
            "Kami cek input password/CC/CVV — apakah ada `autocomplete=\"off\"`."
        ),
        "business_impact": (
            "Browser simpan password/card di komputer publik = bocor di Wi-Fi cafe."
        ),
        "category": "login",
    },
    "captcha_bypass": {
        "friendly_name": "Captcha Bypass via Token Empty/Replay",
        "what_it_means": (
            "Kami coba submit form dengan captcha token kosong, '0', 'true', "
            "atau token duplikat."
        ),
        "business_impact": (
            "Server yang tidak verify token captcha ke API Google/hCaptcha = "
            "captcha jadi tidak guna. Bot bebas brute-force."
        ),
        "category": "login",
    },
    "xslt_injection": {
        "friendly_name": "XSLT Injection (sangat jarang tapi RCE)",
        "what_it_means": (
            "Kami kirim XSL stylesheet ke endpoint XML transformation."
        ),
        "business_impact": (
            "XSLT processor yang menerima stylesheet dari klien = RCE langsung."
        ),
        "category": "infra",
    },
    "rate_limit_bypass": {
        "friendly_name": "Rate-Limit Bypass via X-Forwarded-For Rotation",
        "what_it_means": (
            "Setelah deteksi rate-limit aktif, kami coba rotasi header "
            "X-Forwarded-For untuk lihat apakah server pakai header sebagai "
            "source IP."
        ),
        "business_impact": (
            "Bypass berhasil = brute-force tanpa batas. Login + OTP rentan."
        ),
        "category": "login",
    },
    "email_security_extended": {
        "friendly_name": "BIMI / MTA-STS / TLS-RPT",
        "what_it_means": (
            "Lapisan tambahan keamanan email modern: MTA-STS memaksa TLS, "
            "TLS-RPT untuk reporting, BIMI untuk logo brand."
        ),
        "business_impact": (
            "Tanpa MTA-STS, MITM downgrade SMTP mungkin. BIMI penting untuk "
            "brand visibility di Gmail."
        ),
        "category": "email",
    },
    "response_splitting": {
        "friendly_name": "HTTP Response Splitting via Redirect",
        "what_it_means": (
            "Kami sisipkan CRLF di parameter `redirect`/`next` untuk lihat "
            "apakah response Location membelah."
        ),
        "business_impact": (
            "Sama dengan CRLF injection — Set-Cookie attacker, cache poisoning."
        ),
        "category": "data",
    },
    "favicon_hash": {
        "friendly_name": "Hash Favicon untuk Identifikasi Vendor",
        "what_it_means": (
            "Kami hitung hash favicon — bisa dipakai cari instance lain "
            "dari framework yang sama via Shodan/FOFA."
        ),
        "business_impact": (
            "Kalau favicon = default framework, membocorkan teknologi internal."
        ),
        "category": "info",
    },
    "timing_attack": {
        "friendly_name": "Timing Attack pada Login",
        "what_it_means": (
            "Kami ukur waktu respons login untuk user valid vs invalid — "
            "jika berbeda >150ms, attacker bisa enumerasi akun."
        ),
        "business_impact": (
            "Account enumeration = persiapan untuk brute force terarah."
        ),
        "category": "login",
    },
    # ============ SOSMED-SPECIFIC ============
    "stored_xss": {
        "friendly_name": "Stored XSS pada Profile / Post (Wormable)",
        "what_it_means": (
            "Kami coba simpan tag <script> di field bio/profile/post lalu "
            "ambil ulang halaman untuk lihat apakah tag dieksekusi saat user "
            "lain mengunjungi profile."
        ),
        "business_impact": (
            "Jenis XSS paling berbahaya untuk sosmed — script yang ter-simpan "
            "di profile attacker akan mengeksekusi di browser SETIAP user yang "
            "melihat profile. Bisa membuat WORM yang menyebar otomatis "
            "(klasik: Samy worm 2005, 1 juta akun MySpace dalam 20 jam)."
        ),
        "category": "data",
    },
    "url_preview_ssrf": {
        "friendly_name": "SSRF lewat Link Preview / Open Graph Fetcher",
        "what_it_means": (
            "Sosmed otomatis fetch URL yang user paste untuk menampilkan "
            "thumbnail/judul. Kami probe apakah fetcher bisa dipaksa fetch "
            "endpoint metadata cloud (AWS/GCP) atau loopback."
        ),
        "business_impact": (
            "Kalau berhasil mencapai metadata cloud, attacker dapat IAM "
            "credentials → ambil alih seluruh infrastruktur cloud. "
            "Salah satu vektor sosmed paling sering kena (Discord, Slack, "
            "X pernah ada bug serupa)."
        ),
        "category": "infra",
    },
    "private_profile_bypass": {
        "friendly_name": "Private Profile Bypass via API",
        "what_it_means": (
            "User klik 'akun privat' di setting, tapi API publik tetap "
            "mengembalikan email/HP/alamat. Kami cek apakah filter privacy "
            "hanya berlaku di frontend."
        ),
        "business_impact": (
            "Pelanggaran serius UU PDP — data pribadi user yang berharap "
            "private bocor publik. Stalker, scammer, dan pengusaha data bisa "
            "scrape massal."
        ),
        "category": "data",
    },
    "media_persistence": {
        "friendly_name": "Media yang Dihapus Tetap Bisa Diakses",
        "what_it_means": (
            "Kami scan URL CDN untuk media yang punya cache panjang/permanen "
            "tanpa signed URL — indikator file akan tetap akses-able setelah "
            "user delete dari profile."
        ),
        "business_impact": (
            "User upload foto KTP, lalu hapus karena merasa salah upload. "
            "File tetap di CDN selama bertahun-tahun. Pelanggaran 'Right to "
            "be Forgotten' GDPR/UU PDP. Foto sensitif jadi 'permanent record'."
        ),
        "category": "data",
    },
    "exif_leak": {
        "friendly_name": "Kebocoran Lokasi GPS di Foto Profil/Post",
        "what_it_means": (
            "Kami download foto JPEG dari halaman publik dan parse metadata "
            "EXIF — apakah masih ada GPS, model kamera, tanggal-jam."
        ),
        "business_impact": (
            "Stalker download foto profil → extract koordinat GPS dengan "
            "exiftool → dapat alamat rumah korban. Banyak kasus KDRT, "
            "doxxing, dan penculikan dimulai dari sini."
        ),
        "category": "data",
    },
    "homoglyph_check": {
        "friendly_name": "Username Look-alike (Homoglyph Attack)",
        "what_it_means": (
            "Kami scan username yang muncul di halaman publik untuk "
            "karakter Cyrillic/Greek yang terlihat identik dengan huruf "
            "Latin (mis. @stаrbucks dengan 'а' Cyrillic)."
        ),
        "business_impact": (
            "Brand impersonation skala besar. Follower brand asli mengira "
            "akun homoglyph adalah official → klik link phishing → kredensial "
            "dicuri. Reputasi brand rusak."
        ),
        "category": "login",
    },
    "dm_privacy": {
        "friendly_name": "Kebocoran Direct Message (DM)",
        "what_it_means": (
            "Kami probe endpoint DM baik tanpa auth maupun dengan user_id "
            "berbeda — apakah server return pesan private user lain."
        ),
        "business_impact": (
            "Bocoran DM = headline berita. Pesan pribadi/bisnis/intim "
            "user bisa dibaca/dijual. Pelanggaran besar UU PDP & ITE. "
            "Trust pengguna ke platform hancur."
        ),
        "category": "data",
    },
    "social_csrf": {
        "friendly_name": "CSRF pada Tombol Follow / Like / Post",
        "what_it_means": (
            "Kami coba kirim POST cross-origin (dengan Origin attacker) ke "
            "endpoint follow/like/share — cek apakah ada CSRF guard."
        ),
        "business_impact": (
            "Attacker buat halaman jahat. Setiap user yang sedang login "
            "dan mengunjungi halaman jahat akan auto-follow attacker, "
            "auto-like spam, atau auto-post iklan. Mass scam dalam menit."
        ),
        "category": "login",
    },
    "oauth_takeover": {
        "friendly_name": "Pre-Account-Takeover via OAuth Email Match",
        "what_it_means": (
            "Site menyediakan registrasi email+password DAN OAuth login. "
            "Tanpa email verification ketat, attacker bisa register dengan "
            "email korban → korban login Google → akun di-merge ke akun "
            "yang dibuat attacker."
        ),
        "business_impact": (
            "Attacker punya kontrol penuh atas akun korban — bisa baca DM, "
            "post atas nama korban, akses semua data. Korban sendiri tidak "
            "tahu akunnya sudah dikontrol."
        ),
        "category": "login",
    },
    "unicode_bypass": {
        "friendly_name": "Content Moderation Bypass via Unicode Tricks",
        "what_it_means": (
            "Kami post konten dengan zero-width space, homoglyph, atau RTL "
            "override di tengah kata blacklist — cek apakah moderasi tetap "
            "menerima."
        ),
        "business_impact": (
            "Spam, phishing link, judi online, narkoba, pornografi, dan "
            "harassment lolos filter. Konten illegal menyebar bebas → user "
            "kabur, denda regulasi (Kominfo), kerusakan reputasi platform."
        ),
        "category": "data",
    },
}

# =====================================================================
# Cyberloka v0.10.0 — entri EXPLAIN untuk 30 modul scanner active baru
# (CRITICAL/HIGH dengan validasi otomatis). Dideklarasikan via .update()
# agar tidak mengganggu format dict utama di atas.
# =====================================================================
EXPLAIN.update({
    "apache_path_confusion": {
        "friendly_name": "Apache Path Confusion (CVE-2021-41773 / 42013)",
        "what_it_means": (
            "Kami uji apakah server Apache versi 2.4.49 / 2.4.50 dapat dipaksa "
            "membaca file di luar webroot lewat encoding `..%2e/` — file "
            "/etc/passwd di-validasi muncul di response."
        ),
        "business_impact": (
            "Sangat kritikal. Bila lolos, attacker dapat membaca seluruh file "
            "server (config, kunci SSH, source code) dan — bila mod_cgi aktif — "
            "langsung naik ke Remote Code Execution. Server sepenuhnya jatuh."
        ),
        "category": "infra",
    },
    "phpunit_rce": {
        "friendly_name": "PHPUnit eval-stdin RCE (CVE-2017-9841)",
        "what_it_means": (
            "Kami POST kode PHP ke endpoint `eval-stdin.php` di vendor/phpunit "
            "dan validasi marker md5(1) muncul di response — server "
            "mengeksekusi PHP arbitrer."
        ),
        "business_impact": (
            "Sangat kritikal. Vendor bocor di webroot = RCE instan tanpa "
            "auth. Attacker tinggal upload webshell -> takeover total dalam menit."
        ),
        "category": "infra",
    },
    "log4shell_probe": {
        "friendly_name": "Log4Shell JNDI Injection (CVE-2021-44228)",
        "what_it_means": (
            "Kami suntik payload `${jndi:ldap://...}` ke header umum (User-Agent, "
            "Referer, X-Forwarded-For) dan parameter — bila aplikasi Java pakai "
            "Log4j vulnerable, server akan kontak server LDAP attacker."
        ),
        "business_impact": (
            "Salah satu CVE paling berbahaya dalam sejarah. RCE root tanpa "
            "auth pada hampir semua aplikasi Java sebelum Desember 2021. "
            "Wajib patch ke 2.17+ atau set `log4j2.formatMsgNoLookups=true`."
        ),
        "category": "infra",
    },
    "spring_actuator_rce": {
        "friendly_name": "Spring Boot Actuator Terbuka",
        "what_it_means": (
            "Endpoint debug Spring Boot (/actuator/env, /actuator/heapdump, "
            "/actuator/jolokia) terbuka publik — kami validasi dengan parsing "
            "JSON khas Spring."
        ),
        "business_impact": (
            "Heapdump = dump memori berisi password DB, JWT secret, kunci API. "
            "Jolokia + chain Logback = RCE. Aktuator wajib di-protect basic-auth "
            "atau di-bind ke localhost."
        ),
        "category": "infra",
    },
    "gitlab_unauth_api": {
        "friendly_name": "GitLab API Tanpa Autentikasi",
        "what_it_means": (
            "Endpoint /api/v4/users dan /api/v4/projects mengembalikan data "
            "user/project tanpa token — biasanya karena setting "
            "`gitlab.signup_enabled` longgar atau internal projects tetap "
            "terlihat publik."
        ),
        "business_impact": (
            "Bocor email staf untuk phishing terarah. Source code internal "
            "(repo `internal`) bocor lengkap → kebocoran logika bisnis dan "
            "secret di history commit."
        ),
        "category": "data",
    },
    "jenkins_unauth_console": {
        "friendly_name": "Jenkins Script Console Tanpa Auth",
        "what_it_means": (
            "Endpoint /script atau /scriptText terbuka tanpa autentikasi → "
            "kami validasi keberadaan halaman 'Groovy script'."
        ),
        "business_impact": (
            "Akses Script Console = RCE pada master Jenkins, akses ke "
            "credential CI/CD (AWS, registry, deploy key) = supply-chain "
            "compromise. Pelanggan menerima rilis teracun."
        ),
        "category": "infra",
    },
    "wp_xmlrpc_amplify": {
        "friendly_name": "WordPress xmlrpc.php Brute & Amplification",
        "what_it_means": (
            "xmlrpc.php memuat method `system.multicall` (1000 percobaan/req) "
            "dan `pingback.ping` (DDoS amplifier). Kami validasi via "
            "`system.listMethods`."
        ),
        "business_impact": (
            "Brute-force ke wp-login akan terblok rate-limit, tapi via xmlrpc "
            "1 request = 1000 password. Pingback dipakai DDoS situs lain → "
            "masalah hukum + blacklist IP datacenter."
        ),
        "category": "login",
    },
    "drupalgeddon2": {
        "friendly_name": "Drupalgeddon2 (CVE-2018-7600)",
        "what_it_means": (
            "Kami probe form-render Drupal yang menerima `#post_render` array "
            "dan validasi marker eksekusi. Bila lolos = RCE pre-auth."
        ),
        "business_impact": (
            "RCE root pada Drupal 7/8 unpatched. Attacker pasang miner / "
            "webshell dalam menit. Wajib upgrade core."
        ),
        "category": "infra",
    },
    "bypass_403": {
        "friendly_name": "Bypass Halaman 403 / Forbidden",
        "what_it_means": (
            "Kami coba header `X-Original-URL`, `X-Rewrite-URL`, "
            "`X-Forwarded-For: 127.0.0.1` dan path tricks (`/admin/.`, "
            "`/admin/..;/`, `/admin%20`) untuk halaman yang awalnya 403."
        ),
        "business_impact": (
            "Reverse-proxy dan backend punya logika authorisasi yang berbeda "
            "→ attacker masuk ke /admin tanpa login. Pelanggaran kontrol "
            "akses parah."
        ),
        "category": "login",
    },
    "docker_remote_api": {
        "friendly_name": "Docker Remote API Terbuka",
        "what_it_means": (
            "Daemon Docker di-bind ke 0.0.0.0:2375 tanpa TLS/auth. Kami "
            "validasi via GET /version (JSON Docker)."
        ),
        "business_impact": (
            "Setara root SSH ke host. Attacker mount `/` ke container baru → "
            "tulis ssh key ke /root/.ssh → SSH root. Total takeover server "
            "fisik."
        ),
        "category": "infra",
    },
    "elasticsearch_unauth": {
        "friendly_name": "Elasticsearch Tanpa Autentikasi",
        "what_it_means": (
            "Endpoint /_cluster/health dan /_cat/indices terbuka publik. "
            "Biasanya berisi log produksi + PII."
        ),
        "business_impact": (
            "Kebocoran log eksekutif, email pelanggan, audit trail. Risiko "
            "denda UU PDP signifikan + hilangnya bukti forensik."
        ),
        "category": "data",
    },
    "prometheus_unauth": {
        "friendly_name": "Prometheus Metrics Terbuka",
        "what_it_means": (
            "/metrics dan /api/v1/targets terbuka. Memberi attacker peta "
            "service internal, hostname, versi software."
        ),
        "business_impact": (
            "Bukan kerentanan langsung, tapi blueprint sempurna untuk "
            "serangan presisi (SSRF / lateral movement)."
        ),
        "category": "info",
    },
    "grafana_default_login": {
        "friendly_name": "Grafana dengan Kredensial Default (admin/admin)",
        "what_it_means": (
            "Kami coba login admin/admin di /login Grafana. Validasi via "
            "cookie session yang muncul + akses /api/datasources."
        ),
        "business_impact": (
            "Datasource Grafana sering memuat connection string production "
            "(PostgreSQL, MySQL). Attacker baca DB credential langsung."
        ),
        "category": "infra",
    },
    "kibana_unauth": {
        "friendly_name": "Kibana Terbuka Publik",
        "what_it_means": (
            "/app/home Kibana atau /api/status balas tanpa auth → akses "
            "Discover UI ke Elasticsearch backend."
        ),
        "business_impact": (
            "Pakai Discover untuk query log + PII. Pakai Dev Tools untuk "
            "kueri raw ke Elasticsearch."
        ),
        "category": "data",
    },
    "solr_admin_unauth": {
        "friendly_name": "Apache Solr Admin Terbuka",
        "what_it_means": (
            "/solr/admin/cores tanpa auth → pintu ke RCE klasik via "
            "VelocityResponseWriter."
        ),
        "business_impact": (
            "Aktivasi Velocity + query velocity = arbitrary template = RCE. "
            "Index Solr juga sering berisi data pencarian sensitif."
        ),
        "category": "infra",
    },
    "adminer_exposed": {
        "friendly_name": "Adminer.php Tertinggal di Webroot",
        "what_it_means": (
            "Kami cek path umum (/adminer.php, /db/adminer.php) untuk tool DB "
            "single-file."
        ),
        "business_impact": (
            "Attacker brute-force ke DB lokal atau pakai Adminer SSRF untuk "
            "konek ke DB internal mana saja → akses langsung database."
        ),
        "category": "infra",
    },
    "phpmyadmin_exposed": {
        "friendly_name": "phpMyAdmin Terbuka Publik",
        "what_it_means": (
            "Path /phpmyadmin/, /pma/, /myadmin/ → pintu admin DB."
        ),
        "business_impact": (
            "Kombinasi credential lemah + CVE phpMyAdmin (CVE-2018-12613 "
            "LFI, dll.) = RCE klasik via SQL `INTO OUTFILE`."
        ),
        "category": "infra",
    },
    "iis_shortname": {
        "friendly_name": "IIS Short-Name Disclosure (8.3 Tilde)",
        "what_it_means": (
            "IIS lama menjawab beda untuk path 8.3 tilde valid vs invalid. "
            "Kami validasi via beda 404/400."
        ),
        "business_impact": (
            "Kebocoran nama file backup dan konfigurasi internal. Chain ke "
            "download file sensitif yang nama lengkapnya tidak diketahui "
            "publik."
        ),
        "category": "info",
    },
    "cache_deception": {
        "friendly_name": "Web Cache Deception",
        "what_it_means": (
            "Kami cek apakah path privat ditambah `.css` tetap mengembalikan "
            "data privat user TAPI ditandai `cf-cache-status: HIT`."
        ),
        "business_impact": (
            "Attacker pancing korban buka URL `/profile/x.css`. CDN menyimpan "
            "halaman privat sebagai static. Attacker akses URL yang sama → "
            "dapat data PII korban dari cache."
        ),
        "category": "data",
    },
    "cors_null_origin": {
        "friendly_name": "CORS Refleksi Origin: null",
        "what_it_means": (
            "Kami kirim `Origin: null` dengan credentials. Server balas "
            "`Access-Control-Allow-Origin: null` + `Allow-Credentials: true`."
        ),
        "business_impact": (
            "Halaman sandboxed iframe attacker bisa kirim XHR cross-origin "
            "dengan cookie korban → eksfiltrasi data API privat."
        ),
        "category": "data",
    },
    "smtp_header_injection": {
        "friendly_name": "SMTP Header Injection di Form Email",
        "what_it_means": (
            "Form kontak/share menerima newline (`%0d%0a`) di field email → "
            "attacker tambahkan `Bcc:` / `From:` / body sendiri."
        ),
        "business_impact": (
            "Phishing dari domain resmi perusahaan. SPF/DKIM lulus karena "
            "email memang dikirim server target. Korban tertipu massal."
        ),
        "category": "email",
    },
    "oauth_redirect_bypass": {
        "friendly_name": "OAuth redirect_uri Whitelist Lemah",
        "what_it_means": (
            "Kami coba variasi `redirect_uri` (sub-domain attacker, scheme "
            "trick, double-slash). Validasi via header Location."
        ),
        "business_impact": (
            "Code OAuth dialihkan ke attacker → exchange jadi access token → "
            "takeover akun korban."
        ),
        "category": "login",
    },
    "s3_world_writable": {
        "friendly_name": "S3 Bucket Tertulis Publik (World Writable)",
        "what_it_means": (
            "Kami coba PUT objek anonim ke bucket. Bila berhasil di-GET "
            "kembali = WRITE publik."
        ),
        "business_impact": (
            "Attacker ganti index.html, asset JS/CSS, atau file APK → "
            "supply-chain XSS / malware di seluruh pelanggan. Reputasi "
            "perusahaan bisa hancur dalam jam."
        ),
        "category": "infra",
    },
    "firebase_open_db": {
        "friendly_name": "Firebase Realtime Database Tanpa Aturan",
        "what_it_means": (
            "Kami probe `<project>.firebaseio.com/.json`. 200 + JSON "
            "lengkap = `\".read\":true` (rules default test)."
        ),
        "business_impact": (
            "Database realtime sepenuhnya terbuka untuk dibaca/ditulis "
            "anonim. Klasik di app mobile yang lupa set rules production."
        ),
        "category": "data",
    },
    "csti_template": {
        "friendly_name": "Client-Side Template Injection (CSTI)",
        "what_it_means": (
            "Kami suntik `{{7*7}}` ke parameter reflektif di aplikasi "
            "AngularJS/Vue dan validasi `49` muncul di body."
        ),
        "business_impact": (
            "XSS yang lolos CSP standar (eval di sandbox AngularJS). "
            "Sangat berbahaya karena CSP biasanya jadi pertahanan terakhir."
        ),
        "category": "kode",
    },
    "api_version_downgrade": {
        "friendly_name": "API Versi Lama Tanpa Otorisasi",
        "what_it_means": (
            "Endpoint /api/v1/, /api/old/, /api/legacy/ kadang masih hidup "
            "tapi dengan kontrol akses lebih lemah dibanding versi terbaru."
        ),
        "business_impact": (
            "Bypass auth menyeluruh hanya dengan ganti prefix versi. Pelanggan "
            "yang seharusnya dilindungi versi v3 dengan auth kuat masih "
            "diakses via v1 anonim."
        ),
        "category": "login",
    },
    "grpc_reflection": {
        "friendly_name": "gRPC Reflection Aktif di Production",
        "what_it_means": (
            "`grpcurl list` dijawab dengan daftar service → reflection "
            "diaktifkan di production."
        ),
        "business_impact": (
            "Attacker dapat full schema gRPC tanpa proto file. Method admin "
            "(DeleteUser, GrantRole) terlihat dan sering tidak di-protect "
            "karena 'kan internal'."
        ),
        "category": "info",
    },
    "saml_metadata_exposed": {
        "friendly_name": "SAML Metadata Terbuka Publik",
        "what_it_means": (
            "/saml/metadata, /Shibboleth.sso/Metadata mengembalikan XML "
            "berisi entityID + signing certificate."
        ),
        "business_impact": (
            "Bahan baku untuk serangan SAML signature wrapping (XSW) → forge "
            "SAML response sebagai user mana pun → takeover SSO."
        ),
        "category": "login",
    },
    "webdav_writable": {
        "friendly_name": "WebDAV Method PUT Aktif",
        "what_it_means": (
            "Kami probe PROPFIND + PUT + GET roundtrip. Bila sukses = "
            "WebDAV bisa upload file arbitrer."
        ),
        "business_impact": (
            "PUT shell.aspx (IIS) / shell.jsp (Tomcat) langsung jadi RCE. "
            "Ekstensi script harus di-deny eksplisit di config WebDAV."
        ),
        "category": "infra",
    },
    "nginx_off_by_slash": {
        "friendly_name": "Nginx Alias Off-by-Slash Path Traversal",
        "what_it_means": (
            "Konfigurasi `alias /var/www/static;` (tanpa trailing slash) "
            "ditambah `location /static/` memungkinkan `/static../` keluar "
            "dari directory."
        ),
        "business_impact": (
            "File disclosure sampai /etc/passwd, .env, kunci SSH user web. "
            "Chain ke takeover lebih lanjut."
        ),
        "category": "infra",
    },
})


# =====================================================================
# (Akhir blok update v0.10.0)
# =====================================================================


# Action-plan time bucket per severity (untuk action plan di laporan).
SEVERITY_ACTION = {
    "critical": {
        "title": "Segera (1-7 hari)",
        "color": "#dc2626",
        "explainer": (
            "Temuan kritikal harus diperbaiki dalam 1 minggu. Risiko tinggi "
            "dapat disalahgunakan kapan saja oleh penyerang."
        ),
    },
    "high": {
        "title": "Minggu Ini (7-14 hari)",
        "color": "#ea580c",
        "explainer": (
            "Temuan tingkat tinggi: risiko nyata, harus diperbaiki sebelum "
            "rilis berikutnya."
        ),
    },
    "medium": {
        "title": "Bulan Ini (30 hari)",
        "color": "#d97706",
        "explainer": (
            "Risiko menengah. Masuk ke siklus rilis terdekat — bukan emergency, "
            "tapi tidak boleh ditunda lebih dari satu bulan."
        ),
    },
    "low": {
        "title": "Hardening (90 hari)",
        "color": "#2563eb",
        "explainer": (
            "Praktik baik untuk hardening. Tidak ada eksploitasi langsung, "
            "tapi sebaiknya diperbaiki untuk standar keamanan yang lebih baik."
        ),
    },
    "info": {
        "title": "Informasi (catat saja)",
        "color": "#64748b",
        "explainer": (
            "Hanya informasi tentang infrastruktur Anda. Bukan kerentanan, "
            "tapi membantu memetakan attack surface."
        ),
    },
}

# Glosarium istilah teknis untuk pembaca awam
GLOSSARY: list[tuple[str, str]] = [
    ("API",
     "Antarmuka untuk aplikasi lain berinteraksi dengan website Anda — "
     "biasanya tidak terlihat di browser."),
    ("Brute-force",
     "Mencoba ribuan kombinasi password/OTP secara otomatis."),
    ("CDN (Cloudflare)",
     "Layanan yang memperantarai trafik website agar lebih cepat & aman."),
    ("Cookie",
     "Data kecil yang disimpan browser untuk menjaga login pengguna."),
    ("CSRF",
     "Serangan yang memaksa pengguna login melakukan aksi tanpa sadar dari situs lain."),
    ("CWE",
     "Common Weakness Enumeration — sistem klasifikasi kelemahan keamanan standar internasional."),
    ("DNS",
     "Sistem yang menerjemahkan nama domain (example.com) menjadi alamat IP."),
    ("Header HTTP",
     "Metadata yang dikirim browser/server saat berkomunikasi (versi, jenis konten, dll)."),
    ("HTTPS / TLS",
     "Versi HTTP yang dienkripsi sehingga data tidak bisa disadap."),
    ("IDOR",
     "Insecure Direct Object Reference — bug di mana pengguna bisa membaca data pengguna lain dengan mengubah ID di URL."),
    ("JWT",
     "JSON Web Token — format token modern untuk autentikasi."),
    ("OWASP",
     "Open Web Application Security Project — komunitas global standar keamanan web."),
    ("Payload",
     "Data uji yang dikirim untuk memeriksa kerentanan."),
    ("PII",
     "Personally Identifiable Information — data yang dapat mengidentifikasi seseorang (NIK, HP, email)."),
    ("Phishing",
     "Penipuan yang menyamar sebagai pihak terpercaya untuk mencuri data login."),
    ("RCE",
     "Remote Code Execution — penyerang dapat menjalankan perintah di server Anda."),
    ("SQLi (SQL Injection)",
     "Penyuntikan kode database lewat input pengguna."),
    ("SSRF",
     "Server-Side Request Forgery — server dipaksa fetch URL pilihan penyerang."),
    ("SSTI",
     "Server-Side Template Injection — penyuntikan kode template di sisi server."),
    ("UU PDP",
     "Undang-Undang Perlindungan Data Pribadi (No. 27/2022) — wajib diikuti operator data Indonesia."),
    ("WAF",
     "Web Application Firewall — saringan keamanan di depan website (mis. Cloudflare WAF)."),
    ("XSS",
     "Cross-Site Scripting — penyuntikan script jahat ke halaman, dijalankan di browser pengunjung."),
]


def explain_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Enrich a finding dict with friendly fields. Returns a new dict."""
    out = dict(finding)
    module = (finding.get("module") or "").lower()
    info = EXPLAIN.get(module, {})
    out["friendly_name"] = info.get("friendly_name") or finding.get("title", "")
    out["what_it_means"] = info.get("what_it_means", "")
    out["business_impact"] = info.get("business_impact", "")
    out["category_id"] = info.get("category", "lain")
    out["category_name"] = CATEGORIES.get(out["category_id"], "Lainnya")
    return out


def explain_module(name: str) -> dict[str, str]:
    """Return friendly metadata for a module name (or empty dict)."""
    info = EXPLAIN.get(name, {})
    return {
        "friendly_name": info.get("friendly_name", name),
        "what_it_means": info.get("what_it_means", ""),
        "business_impact": info.get("business_impact", ""),
        "category_id": info.get("category", "lain"),
        "category_name": CATEGORIES.get(info.get("category", "lain"), "Lainnya"),
    }


def categorize_findings(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by friendly category."""
    out: dict[str, list[dict]] = {k: [] for k in CATEGORIES}
    for f in findings:
        cat = explain_finding(f)["category_id"]
        out.setdefault(cat, []).append(f)
    # Drop empty categories.
    return {k: v for k, v in out.items() if v}


def build_executive_summary(
    findings: list[dict],
    risk_score: int,
    risk_label: str,
    target_url: str,
) -> dict[str, Any]:
    """Generate plain-Indonesian executive summary."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

    # Verdict in plain language
    if counts["critical"] > 0:
        verdict = "Memerlukan Tindakan Segera"
        verdict_text = (
            f"Pemeriksaan menemukan {counts['critical']} masalah berdampak sangat tinggi. "
            "Risiko ini perlu ditangani dalam 1 minggu untuk mencegah potensi "
            "kebocoran data atau pengambilalihan sistem."
        )
        verdict_color = "#dc2626"
    elif counts["high"] > 0:
        verdict = "Perhatian Tinggi"
        verdict_text = (
            f"Tidak ada masalah kritikal, tetapi ada {counts['high']} temuan tingkat tinggi "
            "yang harus dijadwalkan perbaikannya dalam waktu dekat."
        )
        verdict_color = "#ea580c"
    elif counts["medium"] > 0:
        verdict = "Posture Cukup Baik"
        verdict_text = (
            f"Tidak ada risiko kritikal/tinggi. Ada {counts['medium']} temuan tingkat "
            "menengah yang masuk dalam siklus rilis terdekat."
        )
        verdict_color = "#d97706"
    elif counts["low"] > 0 or counts["info"] > 0:
        verdict = "Posture Baik"
        verdict_text = (
            "Tidak ditemukan kerentanan signifikan. Hanya catatan untuk hardening "
            "lebih lanjut yang bersifat opsional."
        )
        verdict_color = "#2563eb"
    else:
        verdict = "Sangat Baik"
        verdict_text = "Tidak ada finding terdeteksi pada modul yang dipilih."
        verdict_color = "#16a34a"

    # Top 5 most important findings
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top = sorted(
        findings,
        key=lambda f: (sev_order.get(f.get("severity", "info"), 4), -(f.get("risk_score", 0)))
    )[:5]
    top_friendly = [explain_finding(f) for f in top]

    return {
        "target": target_url,
        "verdict": verdict,
        "verdict_text": verdict_text,
        "verdict_color": verdict_color,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "counts": counts,
        "top_findings": top_friendly,
    }
