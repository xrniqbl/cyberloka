"""Business logic abuse — checklist tester (info-only).

Modul ini tidak melakukan probe aktif. Banyak business logic flaw butuh
domain knowledge dan akun test dengan hak yang spesifik. Tool memberi
checklist yang lengkap berdasarkan pola URL yang terdeteksi crawler:

- Bila ada endpoint referral → checklist referral abuse
- Bila ada endpoint cart/checkout → checklist quantity manipulation
- Bila ada endpoint order → checklist order status tampering
- Bila ada endpoint trial/free → checklist multi-account abuse
- Bila ada endpoint upload → checklist file upload abuse
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CATEGORIES = {
    "referral": {
        "hints": ("referral", "refer", "invite", "ajak", "referral-code", "kode-referral"),
        "tests": [
            "Self-referral: register akun A, dapat referral code, register akun B "
            "dengan code itu memakai email/IP yang sama. Server harus reject.",
            "Loop referral: A invite B invite A — apakah benefit double?",
            "Referral abuse via fake email: register dengan +1, +2 (gmail tricks) "
            "atau email throwaway. Apakah server detect?",
            "Referral expired: pakai code yang sudah lewat masa berlaku — harus reject.",
            "Referral dari akun blocked/banned: apakah masih dapat reward?",
            "Referral untuk produk premium yang dipakai di akun gratis.",
            "Concurrent claim: 2 user pakai code yang same-once dalam waktu bersamaan.",
        ],
    },
    "cart_quantity": {
        "hints": ("cart", "checkout", "keranjang", "add-to-cart", "addtocart", "/order"),
        "tests": [
            "Quantity = 0: tambah ke cart dengan qty=0, apakah bisa proses bayar Rp 0?",
            "Quantity negatif: qty=-1 di intercept request — apakah saldo bertambah?",
            "Quantity overflow: qty=999999999 (int overflow). Server handle?",
            "Decimal quantity untuk barang non-pecahan: qty=0.5, qty=1.999",
            "Add-to-cart bypass stock: tambah barang yang stock=0 lewat API langsung.",
            "Concurrent add-to-cart: 100 paralel request — apakah server consistent?",
            "Cart untuk user lain: tambah/hapus item di cart user lain (IDOR cart).",
            "Price manipulation di cart: ubah price di body request — server harus refetch.",
            "Pre-order date manipulation: ubah expectedDelivery jadi tanggal lampau.",
        ],
    },
    "order_status": {
        "hints": ("order", "transaction", "transaksi", "tagihan", "invoice"),
        "tests": [
            "Order status tampering: PATCH /api/order/{id} body {status:'paid'} dari user.",
            "Order milik user lain: GET / PATCH order user lain (IDOR).",
            "Order zero amount: bayar order yang amount=0.",
            "Order setelah expired: bayar order yang sudah expired (>24 jam).",
            "Order cancel-then-pay: cancel order, lalu pay manual via webhook.",
            "Order dengan voucher dipakai 2x.",
            "Refund untuk order yang belum di-bayar (free refund).",
            "Refund partial diulang: refund 30% × 4 = lebih dari total order.",
        ],
    },
    "trial_abuse": {
        "hints": ("trial", "free", "gratis", "subscribe", "subscription", "premium"),
        "tests": [
            "Multi-account abuse: register 100 email berbeda, dapat 100x trial gratis.",
            "Email tricks: gmail+1, +2, dst. - apakah dianggap account berbeda?",
            "Trial extension: setelah trial habis, claim trial lagi (apakah server check?).",
            "Card same: 100 akun trial pakai kartu kredit yang sama → harus block.",
            "IP/Device fingerprint: 100 akun dari device yang sama.",
            "Trial untuk fitur premium: cek apakah ada feature yang seharusnya hanya "
            "berbayar tapi accessible saat trial.",
        ],
    },
    "file_upload": {
        "hints": ("upload", "file", "image", "avatar", "attachment", "/files/"),
        "tests": [
            "Upload file dengan extension berbahaya: .php, .jsp, .aspx, .exe — server reject?",
            "Bypass extension: shell.php.png, shell.php%00.jpg, shell.PHp.",
            "Bypass MIME type: kirim PHP shell dengan Content-Type: image/png.",
            "Magic byte bypass: tempel header GIF89a; di awal PHP shell.",
            "Path traversal di filename: ../../etc/passwd, atau ..\\..\\Windows\\.",
            "File size: upload file 10 GB — apakah ada limit?",
            "Polyglot file: gambar yang juga valid sebagai PHP (GIFAR-style).",
            "SVG dengan JS embedded — apakah di-render? Bisa stored XSS.",
            "Zip slip: upload zip yang berisi ../../path.txt — apakah extract ke luar dir?",
            "Filename collision: upload nama yang sama 100x → apakah pertama overwrite?",
            "Cek di mana file di-serve: kalau /uploads/ executable as PHP, RCE.",
        ],
    },
    "negotiation": {
        "hints": ("bid", "auction", "negosiasi", "tawar", "lelang"),
        "tests": [
            "Bid setelah auction tutup: kirim bid 1 detik setelah end-time.",
            "Bid dari user yang sama 2x dalam waktu bersamaan (race).",
            "Bid amount manipulation: amount=highestBid+1 vs server hitung sendiri.",
            "Cancel bid yang sudah jadi pemenang.",
        ],
    },
}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return findings

    detected: dict[str, list[str]] = {}  # category -> list URL
    for ep in getattr(discovered, "endpoints", []):
        low = ep.url.lower()
        for cat, meta in CATEGORIES.items():
            if any(h in low for h in meta["hints"]):
                detected.setdefault(cat, []).append(ep.url)

    if not detected:
        return findings

    for cat, urls in detected.items():
        meta = CATEGORIES[cat]
        urls_unique = list(dict.fromkeys(urls))[:5]
        findings.append(
            Finding(
                module="business_logic",
                title=f"Business logic flow `{cat}` terdeteksi - perlu test manual",
                severity=Severity.INFO,
                description=(
                    f"Cyberloka mendeteksi adanya alur `{cat}` di website. Banyak "
                    "business-logic flaw di area ini hanya bisa di-konfirmasi lewat "
                    "test manual oleh tester yang paham bisnis."
                ),
                target=target.base_url,
                evidence=(
                    f"endpoint terdeteksi:\n"
                    + "\n".join(f"  - {u}" for u in urls_unique)
                    + "\n\nTest manual yang harus dilakukan:\n"
                    + "\n".join(f"  - {t}" for t in meta["tests"])
                ),
                remediation=(
                    "Lakukan dedicated business-logic pentest di environment sandbox "
                    "dengan 2-3 akun test (free tier, premium, admin). Audit log "
                    "transaksi di production untuk pola anomali."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                ],
            )
        )
    return findings
