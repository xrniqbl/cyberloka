"""Penjelasan 'Bahasa Awam' (layman) cara akses tiap celah, step-by-step.

Sasaran pembaca: pemilik bisnis / pelanggan / staff non-teknis.

Field yang di-expose:
  * ``AWAM_STEPS[module]`` — daftar langkah singkat (max ~6 langkah) yang
    menggambarkan bagaimana penyerang akan masuk lewat celah tersebut.
  * ``AWAM_SUMMARY[module]`` — satu kalimat ringkas untuk header.

Pesan: TIDAK menggunakan jargon teknis berlebihan. Gunakan analogi rumah/
toko sebanyak mungkin agar mudah dimengerti.
"""
from __future__ import annotations

from typing import Iterable

# ---------------------------------------------------------------------------
# Kalimat ringkas — dipakai sebagai header di laporan
# ---------------------------------------------------------------------------
AWAM_SUMMARY: dict[str, str] = {
    "lfi": (
        "Penyerang dapat membaca isi file penting di server (mis. daftar "
        "pengguna, password) hanya dengan mengubah alamat (URL) di browser."
    ),
    "cmdi": (
        "Penyerang dapat menjalankan perintah apa pun di server Anda dengan "
        "menyisipkan teks khusus pada formulir / URL — sama seperti memberi "
        "perintah ke staf di kasir."
    ),
    "sqli": (
        "Penyerang dapat 'berbicara langsung' ke database Anda lewat formulir "
        "atau URL, lalu membaca / mengubah seluruh isi database (data pelanggan, "
        "password, transaksi)."
    ),
    "dirlist": (
        "Folder di server Anda terbuka seperti folder di komputer — siapa pun "
        "yang membuka alamat folder akan melihat daftar lengkap file."
    ),
    "source_leak": (
        "File penting (kode, kunci, backup) bisa diunduh langsung lewat browser "
        "tanpa perlu login — seperti meninggalkan brankas terbuka di trotoar."
    ),
    "sensitive_files": (
        "File rahasia (.env, backup database, kunci) terbuka publik dan bisa "
        "diunduh siapa saja yang menebak alamatnya."
    ),
    "env_leak": (
        "Kunci dan password penting (API, database) bocor di halaman publik atau "
        "di pesan error — seperti kunci toko tertinggal di etalase."
    ),
    "idor_generic": (
        "Pelanggan A bisa membaca data pelanggan B hanya dengan mengganti angka "
        "di URL (mis. /pesanan/123 → /pesanan/124)."
    ),
    "auth_bypass": (
        "Halaman admin atau akun penting bisa dimasuki tanpa password yang benar "
        "(mis. password default seperti 'admin/admin')."
    ),
    "file_upload": (
        "Form upload (foto profil, KTP, dll.) menerima file berbahaya yang "
        "bisa membuat penyerang menguasai server."
    ),
    "db_pii_leak": (
        "Data pribadi pelanggan (NIK, KK, nomor rekening, HP, email) bocor "
        "lewat URL/API publik dalam jumlah banyak — pelanggaran serius UU PDP."
    ),
    "pii_leak": (
        "Pola data pribadi (NIK, NPWP, HP, kartu kredit) muncul di halaman "
        "publik — risiko pelanggaran UU PDP."
    ),
    "ssrf": (
        "Server Anda dapat 'disuruh' membuka alamat internal yang seharusnya "
        "tertutup dari luar — seperti memerintah penjaga toko membuka brankas."
    ),
    "ssrf_metadata": (
        "Server Anda dapat dipaksa mengambil kunci cloud (AWS/GCP) — sama saja "
        "memberikan kunci server pusat ke penyerang."
    ),
    "ssti": (
        "Penyerang dapat menjalankan kode Python/PHP di server Anda lewat "
        "formulir biasa — seperti memberi remote-control ke server."
    ),
    "xxe": (
        "File XML yang di-upload bisa membuka file rahasia di server."
    ),
    "deserialization": (
        "Data yang dikirim ke server bisa diubah jadi 'paket berbahaya' yang "
        "membuat penyerang mengambil alih server."
    ),
    "redirect": (
        "Link yang awalnya menuju domain Anda bisa dibelokkan ke situs phishing — "
        "pelanggan tertipu karena alamat awal terlihat resmi."
    ),
    "xss": (
        "Penyerang menyisipkan script JavaScript ke halaman Anda yang akan "
        "dijalankan di komputer pengunjung — bisa mencuri cookie / login mereka."
    ),
    "stored_xss": (
        "Script jahat yang disimpan di profil/komentar akan otomatis dijalankan "
        "di browser SETIAP pengunjung profil itu (efek viral)."
    ),
    "dom_xss": (
        "Sama dengan XSS, tapi 'pintu masuk'-nya ada di kode JavaScript yang "
        "dijalankan di browser pengunjung."
    ),
    "csrf": (
        "Pengunjung yang sedang login bisa 'ditipu' melakukan transfer/post/"
        "update tanpa sadar saat membuka halaman jahat di tab lain."
    ),
    "logout_csrf": (
        "Pengunjung bisa di-logout paksa hanya dengan membuka gambar/halaman "
        "jahat di tab lain."
    ),
    "social_csrf": (
        "Tombol follow/like/post bisa di-trigger tanpa sadar dari halaman lain."
    ),
    "host_header": (
        "Link reset password yang dikirim ke email pelanggan bisa diarahkan ke "
        "domain penyerang — pelanggan klik, password baru jatuh ke penyerang."
    ),
    "cache_poison": (
        "Halaman utama bisa 'diracun' — semua pengunjung berikutnya akan "
        "melihat versi yang sudah dimodifikasi penyerang."
    ),
    "jwt": (
        "Token login (JWT) lemah — penyerang bisa membuat token sendiri yang "
        "diterima sebagai admin."
    ),
    "jwt_confusion": (
        "Konfigurasi JWT salah — penyerang dapat memalsukan token admin."
    ),
    "otp_check": (
        "Kode OTP (verifikasi SMS/email) dapat ditebak/brute-force karena "
        "tidak ada batas percobaan."
    ),
    "password_reset": (
        "Mekanisme 'lupa password' rentan — link reset bisa dipakai berulang, "
        "bocor lewat Referer, atau bisa diarahkan ke domain penyerang."
    ),
    "voucher": (
        "Kode voucher / kupon bisa dipakai berkali-kali atau ditebak — "
        "kerugian finansial langsung."
    ),
    "payment": (
        "Harga produk / status pembayaran bisa dimanipulasi sebelum sampai ke "
        "server — pelanggan bayar Rp 1 untuk barang Rp 1 juta."
    ),
    "balance": (
        "Saldo / e-wallet bisa dimanipulasi (withdraw negatif, top-up palsu)."
    ),
    "race_condition": (
        "Aksi penting (klaim voucher / withdraw) bisa dipanggil banyak kali "
        "secara simultan untuk dapat berkali-kali."
    ),
    "api_auth": (
        "Endpoint API balas data pelanggan tanpa perlu login."
    ),
    "mass_assignment": (
        "Form registrasi/profil menerima field tambahan seperti `is_admin=true` — "
        "akun biasa bisa naik jadi admin."
    ),
    "cors": (
        "API Anda mengizinkan website lain membaca data pelanggan dari browser "
        "pelanggan tersebut."
    ),
    "subdomain_takeover": (
        "Sub-domain Anda mengarah ke layanan cloud yang sudah dihapus — siapa "
        "pun bisa klaim dan membuat halaman atas nama brand Anda."
    ),
    "cloud_buckets": (
        "Bucket cloud (S3/GCS) Anda terbuka publik — siapa pun bisa men-download "
        "seluruh isinya."
    ),
}


# ---------------------------------------------------------------------------
# Step-by-step (max 6 langkah) — tampil sebagai numbered list di laporan
# ---------------------------------------------------------------------------
AWAM_STEPS: dict[str, list[str]] = {
    "lfi": [
        "Penyerang membuka URL aplikasi yang punya parameter file/page (mis. ?file=).",
        "Penyerang mengganti nilai parameter dengan path khusus seperti ../../etc/passwd.",
        "Browser menampilkan isi file sistem operasi yang berisi daftar pengguna server.",
        "Dari sana penyerang lanjut membaca file konfigurasi (database password, kunci API).",
        "Dengan kunci tersebut, penyerang bisa login ke layanan internal Anda.",
    ],
    "cmdi": [
        "Penyerang menemukan field/parameter yang nilainya ikut dijalankan oleh server.",
        "Penyerang menyisipkan tanda khusus (mis. ;sleep 5) di nilai tersebut.",
        "Server menjalankan perintah sleep — terlihat dari respons yang lambat 5 detik.",
        "Penyerang lanjut menjalankan perintah lain (cat /etc/passwd, curl, wget).",
        "Akhirnya penyerang bisa pasang backdoor agar tetap punya akses.",
    ],
    "sqli": [
        "Penyerang mengetik tanda kutip ' di kolom login/search.",
        "Database error muncul — tanda input langsung diadu ke perintah SQL.",
        "Penyerang menyisipkan perintah ' OR 1=1-- untuk login tanpa password.",
        "Setelah masuk, penyerang menjalankan perintah SELECT untuk membaca tabel pelanggan.",
        "Seluruh database (NIK, password, transaksi) dapat di-download.",
    ],
    "dirlist": [
        "Penyerang membuka URL folder mis. https://situs.com/uploads/.",
        "Browser menampilkan daftar file lengkap di folder itu seperti file explorer.",
        "Penyerang membuka file demi file untuk mencari backup, foto KTP, atau database.",
        "File-file pribadi pelanggan diunduh tanpa login.",
    ],
    "source_leak": [
        "Penyerang mencoba alamat khusus seperti /.git/config atau /.env.",
        "Server membalas dengan isi file mentah (tidak ada login wall).",
        "File berisi password database, kunci AWS, dan token API.",
        "Penyerang langsung pakai kunci itu untuk login ke layanan Anda.",
    ],
    "sensitive_files": [
        "Penyerang menebak nama file backup (backup.sql, dump.zip, config.bak).",
        "Server mengirim file tersebut sebagai download.",
        "Penyerang membuka file di komputernya — di dalamnya ada data pelanggan & password.",
    ],
    "env_leak": [
        "Penyerang membuka halaman aplikasi atau halaman error.",
        "Di dalamnya muncul teks seperti AWS_ACCESS_KEY=AKIA... atau DATABASE_URL=postgres://...",
        "Kunci tersebut diuji dan masih aktif.",
        "Penyerang masuk ke akun cloud / database Anda dengan kunci yang bocor.",
    ],
    "idor_generic": [
        "Pelanggan biasa (atau penyerang dengan akun palsu) login ke aplikasi.",
        "Penyerang membuka URL pesanannya, mis. /order/100.",
        "Penyerang mengganti angka 100 menjadi 99, 101, 102, dst.",
        "Setiap kali, server menampilkan data pesanan milik pelanggan lain.",
        "Penyerang menulis script kecil untuk mengambil ribuan pesanan sekaligus.",
    ],
    "auth_bypass": [
        "Penyerang menebak path admin (mis. /admin atau /administrator).",
        "Halaman login admin terbuka dan tidak dibatasi IP.",
        "Penyerang mencoba kombinasi default (admin/admin, root/123456, dst).",
        "Salah satu kombinasi diterima dan penyerang masuk ke dashboard admin.",
        "Dari dashboard, seluruh data pelanggan & konfigurasi terbuka.",
    ],
    "file_upload": [
        "Penyerang membuat file berbahaya berbungkus ekstensi gambar (mis. shell.php.jpg).",
        "Penyerang upload file tersebut lewat form unggah foto profil.",
        "Server menerima file dan menyimpan di folder yang bisa diakses publik.",
        "Penyerang membuka URL file — server menjalankannya sebagai script.",
        "Penyerang sekarang dapat menjalankan perintah apa pun di server.",
    ],
    "db_pii_leak": [
        "Penyerang membuka URL listing/dump (mis. /api/users atau /backup/data.json).",
        "Server membalas dengan respons besar berisi banyak baris data pelanggan.",
        "Di dalamnya ada NIK, nomor KK, nomor rekening, HP, dan email pelanggan.",
        "Penyerang men-download semua data tersebut dalam beberapa detik.",
        "Data dijual di forum dark-web atau dipakai untuk penipuan, pinjol ilegal, "
        "phishing terarah.",
    ],
    "pii_leak": [
        "Penyerang membuka halaman publik aplikasi.",
        "Di dalam HTML / response API muncul nomor NIK / HP / kartu kredit pelanggan.",
        "Penyerang men-scrape massal halaman tersebut untuk kumpulkan database PII.",
    ],
    "ssrf": [
        "Penyerang menemukan fitur yang menerima URL (mis. preview link, fetch image).",
        "Penyerang mengganti URL dengan alamat internal mis. http://127.0.0.1/admin.",
        "Server membuka alamat internal itu dan mengirim isinya ke penyerang.",
        "Penyerang melihat halaman admin internal yang seharusnya hanya bisa diakses dari kantor.",
    ],
    "ssrf_metadata": [
        "Penyerang menemukan parameter yang menerima URL.",
        "Penyerang isi dengan http://169.254.169.254/latest/meta-data/ (alamat khusus AWS).",
        "Server membalas dengan kunci cloud (IAM token) milik server itu sendiri.",
        "Penyerang pakai kunci tersebut untuk masuk ke akun cloud Anda — semua data hilang.",
    ],
    "ssti": [
        "Penyerang menemukan field yang nilainya muncul lagi di halaman (mis. nama).",
        "Penyerang isi nama dengan {{7*7}}.",
        "Halaman menampilkan 49 — server benar-benar 'menghitung' input penyerang.",
        "Penyerang ganti dengan kode untuk membuka shell / membaca file.",
        "Penyerang mengambil alih server.",
    ],
    "xxe": [
        "Penyerang menemukan endpoint yang menerima data XML (mis. import data).",
        "Penyerang upload XML berisi referensi ke file lokal seperti file:///etc/passwd.",
        "Server membaca file tersebut dan menyertakan isinya di respons.",
        "Penyerang membaca file rahasia di server.",
    ],
    "deserialization": [
        "Penyerang menemukan cookie atau parameter yang berisi data terserialisasi.",
        "Penyerang membuat 'paket berbahaya' (gadget chain) menggunakan tool publik.",
        "Penyerang mengirim paket tersebut ke server.",
        "Server membongkar paket dan menjalankan kode di dalamnya.",
        "Penyerang sekarang menjalankan kode di server Anda.",
    ],
    "redirect": [
        "Penyerang membuat link panjang yang awalnya https://situsanda.com/...",
        "Di dalam parameter ada redirect=https://phishing.com.",
        "Pelanggan klik link itu (terlihat resmi karena diawali domain Anda).",
        "Browser otomatis pindah ke situs phishing yang menyamar identik.",
        "Pelanggan masukkan email & password — penyerang menerimanya.",
    ],
    "xss": [
        "Penyerang membuat URL khusus yang isinya kode JavaScript jahat.",
        "Penyerang mengirim URL itu ke korban (chat / email).",
        "Korban klik URL — kode dijalankan di browser korban.",
        "Kode mencuri cookie login korban dan kirim ke server penyerang.",
        "Penyerang pakai cookie itu untuk login sebagai korban.",
    ],
    "stored_xss": [
        "Penyerang menulis kode jahat di kolom bio / komentar / nama profil.",
        "Aplikasi menyimpannya apa adanya ke database.",
        "Setiap pelanggan yang membuka profil itu, kode dijalankan di browser mereka.",
        "Penyerang mencuri cookie / login massal seluruh pengunjung.",
    ],
    "dom_xss": [
        "Penyerang membuat URL khusus dengan parameter berisi kode JavaScript.",
        "Halaman membaca parameter dan menampilkannya tanpa disaring.",
        "Browser pengunjung menjalankan kode jahat tersebut.",
    ],
    "csrf": [
        "Penyerang membuat halaman jahat dengan tombol/form tersembunyi.",
        "Form menargetkan endpoint penting di situs Anda (transfer, ubah email).",
        "Penyerang mengundang korban yang sedang login membuka halaman jahat.",
        "Browser korban otomatis kirim form ke situs Anda dengan cookie login korban.",
        "Aksi (transfer / ganti email) berhasil tanpa korban sadar.",
    ],
    "logout_csrf": [
        "Penyerang membuat tag <img src='https://situsanda.com/logout'> di halaman jahat.",
        "Korban yang sedang login membuka halaman jahat — browser otomatis logout.",
        "Korban kebingungan dan rentan trik phishing lanjutan.",
    ],
    "social_csrf": [
        "Penyerang buat halaman jahat dengan form auto-submit ke endpoint follow/like.",
        "Korban yang login klik halaman jahat.",
        "Akun korban otomatis follow/like akun penyerang tanpa sadar.",
    ],
    "host_header": [
        "Penyerang trigger 'lupa password' atas email korban.",
        "Saat trigger, penyerang ubah header Host ke domain penyerang.",
        "Sistem mengirim email reset dengan link mengarah ke domain penyerang.",
        "Korban klik link, ketik password baru — password jatuh ke penyerang.",
    ],
    "cache_poison": [
        "Penyerang kirim request ke halaman utama dengan header non-standar.",
        "Server pantulkan header itu di response, lalu CDN cache versi tercemar.",
        "Pengunjung berikutnya yang request halaman sama dapat versi cemar dari CDN.",
    ],
    "jwt": [
        "Penyerang ambil token JWT dari response login.",
        "Penyerang decode token dan lihat algoritmanya (alg=none / HS256 lemah).",
        "Penyerang buat token baru atas nama admin tanpa tahu kunci.",
        "Penyerang pakai token palsu — server menerima sebagai admin.",
    ],
    "jwt_confusion": [
        "Penyerang ambil JWT dan ubah algoritma dari RS256 ke HS256.",
        "Penyerang sign ulang token dengan public key sebagai secret.",
        "Server salah memverifikasi dan menerima token palsu sebagai valid.",
    ],
    "otp_check": [
        "Penyerang trigger pengiriman OTP atas nomor korban.",
        "Penyerang menebak OTP 4-digit (10.000 kemungkinan).",
        "Tidak ada batas percobaan — OTP berhasil ditebak dalam beberapa menit.",
        "Penyerang lanjut login sebagai korban.",
    ],
    "password_reset": [
        "Penyerang trigger reset password atas email korban.",
        "Penyerang manipulasi alur (host header / token tebak / link reusable).",
        "Penyerang tetapkan password baru atas akun korban.",
        "Penyerang login dan menguasai akun.",
    ],
    "voucher": [
        "Penyerang dapatkan satu kode voucher (mis. dari email promo).",
        "Penyerang apply kode tersebut berkali-kali secara bersamaan.",
        "Server tidak punya lock — kode dipakai berulang.",
        "Penyerang mendapat banyak diskon / cashback.",
    ],
    "payment": [
        "Penyerang isi keranjang belanja dengan barang mahal.",
        "Saat checkout, penyerang intercept request dan ubah field amount jadi Rp 1.",
        "Server menerima nilai baru dan generate invoice Rp 1.",
        "Penyerang bayar Rp 1 untuk barang mahal — kerugian penjual.",
    ],
    "balance": [
        "Penyerang panggil endpoint withdraw dengan nilai negatif (-1.000.000).",
        "Server tanpa validasi memproses sebagai 'tambah saldo' 1.000.000.",
        "Saldo penyerang membengkak tanpa transaksi nyata.",
    ],
    "race_condition": [
        "Penyerang siapkan 20 request klaim cashback identik.",
        "Penyerang kirim semuanya nyaris bersamaan (paralel).",
        "Server tidak punya lock — semuanya diproses sukses.",
        "Penyerang dapat 20x cashback dari satu kode.",
    ],
    "api_auth": [
        "Penyerang jalankan curl https://api.situsanda.com/users tanpa header Authorization.",
        "Server tetap balas dengan daftar pelanggan lengkap.",
        "Penyerang scrape semua data dalam menit.",
    ],
    "mass_assignment": [
        "Penyerang daftar akun baru dan intercept request registrasi.",
        "Penyerang tambah field 'role':'admin' di body JSON.",
        "Server simpan field tersebut ke database tanpa filter.",
        "Akun penyerang langsung jadi admin.",
    ],
    "cors": [
        "Penyerang buat halaman jahat di domain miliknya.",
        "Halaman jalankan fetch ke API Anda dengan credentials.",
        "Server Anda balas dengan header Access-Control-Allow-Origin: <domain penyerang>.",
        "Browser korban memberikan data ke domain penyerang — data exfil sukses.",
    ],
    "subdomain_takeover": [
        "Penyerang scan DNS sub-domain Anda dan menemukan CNAME ke layanan cloud terlantar.",
        "Penyerang mendaftar di layanan cloud tersebut dan klaim nama yang sama.",
        "Sub-domain Anda kini milik penyerang — bisa dipakai untuk phishing.",
    ],
    "cloud_buckets": [
        "Penyerang menebak nama bucket berdasarkan nama brand (mis. brand-backup).",
        "Bucket dapat diakses publik dengan list permission.",
        "Penyerang men-download seluruh isi bucket (foto KTP, dokumen, backup).",
    ],
}


def get_awam(module: str) -> tuple[str, list[str]]:
    """Return (summary, steps) untuk modul tertentu. Kosong kalau belum dipetakan."""
    m = (module or "").lower()
    return AWAM_SUMMARY.get(m, ""), list(AWAM_STEPS.get(m, []))


def render_steps(steps: Iterable[str]) -> str:
    """Format list langkah jadi numbered text — dipakai console reporter."""
    return "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
