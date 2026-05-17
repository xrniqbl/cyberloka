"""Reporter naratif bahasa Indonesia.

Mengubah daftar Finding menjadi paragraf yang mudah dibaca, mis.:

    Website https://example.com TERINDIKASI RENTAN.
    Ditemukan 4 celah serius dan 7 masalah konfigurasi:

      - [CRITICAL] SQL Injection pada parameter `id` di /products
        Penyebab: query database dibangun dari input user tanpa parameterisasi.
        Solusi  : pakai prepared statement / ORM parameterized.

      - [HIGH] Reflected XSS pada parameter `q` di /search
        ...

Tujuannya: pengguna non-teknis dapat langsung tahu "rentan / aman" dan
"celahnya apa", tanpa perlu membaca tabel JSON.
"""
from __future__ import annotations

from cyberloka.core import Finding, Severity

SEVERITY_LABEL = {
    Severity.CRITICAL: "KRITIS",
    Severity.HIGH: "TINGGI",
    Severity.MEDIUM: "SEDANG",
    Severity.LOW: "RENDAH",
    Severity.INFO: "INFO",
}

# Penjelasan singkat per modul -> kalimat manusia.
MODULE_HUMAN: dict[str, str] = {
    "sqli": "SQL Injection (database dapat dibaca/diubah lewat input)",
    "xss": "Cross-Site Scripting (script jahat dapat dijalankan di browser pengunjung)",
    "lfi": "Local File Inclusion / Path Traversal (file server dapat dibaca attacker)",
    "cmdi": "Command Injection (perintah shell dapat dijalankan di server)",
    "ssrf": "Server-Side Request Forgery (server bisa disuruh akses URL internal)",
    "ssti": "Server-Side Template Injection (template dieksekusi dari input user)",
    "xxe": "XML External Entity (parser XML membaca file lokal lewat entity)",
    "nosqli": "NoSQL Injection (operator MongoDB diterima dari input user)",
    "redirect": "Open Redirect (URL redirect dapat diarahkan ke domain attacker)",
    "dirlist": "Directory Listing aktif (isi folder dapat ditelusuri publik)",
    "sensitive_files": "File sensitif ter-ekspos (mis. .env, .git, backup)",
    "graphql": "GraphQL bermasalah (introspection / batching / alias overload)",
    "websocket": "WebSocket tidak aman (cross-origin / cleartext / token bocor)",
    "jwt": "JWT bermasalah (alg=none / secret lemah / lifetime panjang)",
    "headers": "Security header HTTP kurang lengkap",
    "tls": "Konfigurasi TLS/SSL bermasalah",
    "cookies": "Cookie session tanpa atribut Secure/HttpOnly/SameSite",
    "cors": "CORS salah konfigurasi (origin attacker dapat membaca data)",
    "clickjacking": "Halaman dapat di-iframe (clickjacking)",
    "methods": "HTTP method berisiko diizinkan (TRACE/PUT/DELETE)",
    "csrf": "Form tanpa anti-CSRF token",
    "robots": "robots.txt / sitemap.xml memberi info path internal",
    "fingerprint": "Versi teknologi / framework bocor di header / body",
    "dns": "Konfigurasi DNS / SPF / DMARC kurang lengkap",
    "whois": "Informasi WHOIS publik",
    "ports": "Port jaringan terbuka",
    "subdomains": "Subdomain ditemukan (perluas attack surface)",
    "crawler": "Endpoint dan form ter-discover oleh crawler",
    "openapi": "Spesifikasi OpenAPI/Swagger ter-ekspos",
    "rate_limit": "Endpoint login tanpa rate-limit (rentan brute-force)",
    "burst": "Tidak ada rate-limit/WAF saat burst request",
}


def _verdict(findings: list[Finding]) -> tuple[str, str]:
    """Return (status_label, summary_sentence)."""
    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)

    if crit > 0:
        return (
            "TERINDIKASI SANGAT RENTAN",
            f"Ditemukan {crit} celah KRITIS yang dapat dieksploitasi attacker untuk mengambil-alih sistem / mencuri data.",
        )
    if high > 0:
        return (
            "TERINDIKASI RENTAN",
            f"Ditemukan {high} celah berisiko TINGGI yang sebaiknya segera diperbaiki.",
        )
    if med > 0:
        return (
            "PERLU PERBAIKAN",
            f"Tidak ada celah kritis terdeteksi, tapi ada {med} masalah keamanan tingkat sedang.",
        )
    if low > 0:
        return (
            "RELATIF AMAN (perlu hardening)",
            f"Tidak ada kerentanan signifikan terdeteksi. Ada {low} item best-practice yang bisa diperbaiki.",
        )
    return (
        "AMAN (sejauh yang dapat dideteksi tool ini)",
        "Tidak ada finding pada modul yang dijalankan. Tetap lakukan review berkala.",
    )


def build_narrative(target_url: str, findings: list[Finding]) -> str:
    """Hasilkan teks naratif lengkap."""
    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module))
    status, summary = _verdict(findings_sorted)

    n_crit = sum(1 for f in findings_sorted if f.severity == Severity.CRITICAL)
    n_high = sum(1 for f in findings_sorted if f.severity == Severity.HIGH)
    n_med = sum(1 for f in findings_sorted if f.severity == Severity.MEDIUM)
    n_low = sum(1 for f in findings_sorted if f.severity == Severity.LOW)

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(f" HASIL PEMERIKSAAN: {target_url}")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Status website : {status}")
    lines.append(f"Ringkasan      : {summary}")
    lines.append("")
    lines.append(
        f"Total finding  : {len(findings_sorted)}  "
        f"(KRITIS={n_crit}, TINGGI={n_high}, SEDANG={n_med}, RENDAH={n_low})"
    )
    lines.append("")

    # Daftar celah berdasarkan modul (dedup judul)
    if findings_sorted:
        # Kelompokkan modul yang menemukan celah serius
        serious_modules: dict[str, list[Finding]] = {}
        for f in findings_sorted:
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                serious_modules.setdefault(f.module, []).append(f)

        if serious_modules:
            lines.append("Website ini rentan dan ada celah dari:")
            for mod, group in serious_modules.items():
                human = MODULE_HUMAN.get(mod, mod)
                lines.append(f"  - {human}  ({len(group)} temuan)")
            lines.append("")

        lines.append("Detail celah yang ditemukan:")
        lines.append("-" * 70)
        for i, f in enumerate(findings_sorted, 1):
            sev = SEVERITY_LABEL[f.severity]
            human_mod = MODULE_HUMAN.get(f.module, f.module)
            lines.append(f"")
            lines.append(f"[{i}] [{sev}] {f.title}")
            lines.append(f"    Kategori   : {human_mod}")
            lines.append(f"    Lokasi     : {f.target}")
            if f.cwe:
                lines.append(f"    Referensi  : {f.cwe}")
            if f.description:
                # Pecah deskripsi jadi baris ~80 karakter
                lines.append(f"    Penjelasan : {_wrap(f.description, 80, indent=17)}")
            if f.remediation:
                lines.append(f"    Cara fix   : {_wrap(f.remediation, 80, indent=17)}")
            if f.evidence:
                ev_short = f.evidence.replace("\n", " | ")
                if len(ev_short) > 200:
                    ev_short = ev_short[:200] + "..."
                lines.append(f"    Bukti      : {ev_short}")
        lines.append("")
        lines.append("-" * 70)
    else:
        lines.append("Tidak ada celah ditemukan oleh tool. Disarankan tetap melakukan")
        lines.append("review manual dan pentest oleh profesional secara berkala.")
        lines.append("")

    # Disclaimer
    lines.append("")
    lines.append("CATATAN:")
    lines.append("- Hasil otomatis ini tidak menggantikan pentest manual oleh profesional.")
    lines.append("- Beberapa finding bertanda 'tentative' perlu diverifikasi manual.")
    lines.append("- Tool ini hanya boleh dipakai pada target yang Anda miliki / yang")
    lines.append("  memberi izin tertulis.")
    lines.append("")
    return "\n".join(lines)


def _wrap(text: str, width: int, indent: int) -> str:
    """Bungkus paragraf sederhana dengan indent untuk baris ke-2 dst."""
    text = " ".join(text.split())  # normalise whitespace
    if len(text) <= width:
        return text
    out = []
    line = ""
    for word in text.split(" "):
        if len(line) + len(word) + 1 > width and line:
            out.append(line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        out.append(line)
    pad = " " * indent
    return out[0] + "\n" + "\n".join(pad + l for l in out[1:])
