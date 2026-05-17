"""Reporter naratif bahasa Indonesia.

Ubah daftar Finding jadi laporan terstruktur:

    1. RINGKASAN STATUS
    2. INFORMASI WEBSITE (DNS, WHOIS, teknologi)
    3. PORT TERBUKA
    4. SUBDOMAIN
    5. ENDPOINT & FILE TEREKSPOS
    6. CELAH KEAMANAN (urut severity)

Tujuannya: pengguna non-teknis dapat langsung tahu "rentan / aman" dan
"celahnya apa", PLUS info hasil recon (port/subdomain/dll.) yang biasanya
di-bury di dalam evidence finding.
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


# ---------------------------------------------------------------------------
# verdict & helpers
# ---------------------------------------------------------------------------

def _verdict(vuln_findings: list[Finding]) -> tuple[str, str]:
    """Tentukan status & ringkasan dari finding bermuatan keamanan saja
    (CRITICAL/HIGH/MEDIUM/LOW; INFO tidak menentukan rentan-tidak-nya)."""
    crit = sum(1 for f in vuln_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in vuln_findings if f.severity == Severity.HIGH)
    med = sum(1 for f in vuln_findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in vuln_findings if f.severity == Severity.LOW)

    if crit > 0:
        return (
            "TERINDIKASI SANGAT RENTAN",
            f"Ditemukan {crit} celah KRITIS yang dapat dieksploitasi attacker "
            "untuk mengambil-alih sistem / mencuri data.",
        )
    if high > 0:
        return (
            "TERINDIKASI RENTAN",
            f"Ditemukan {high} celah berisiko TINGGI yang sebaiknya segera diperbaiki.",
        )
    if med > 0:
        return (
            "PERLU PERBAIKAN",
            f"Tidak ada celah kritis terdeteksi, tapi ada {med} masalah keamanan "
            "tingkat sedang.",
        )
    if low > 0:
        return (
            "RELATIF AMAN (perlu hardening)",
            f"Tidak ada kerentanan signifikan terdeteksi. Ada {low} item "
            "best-practice yang bisa diperbaiki.",
        )
    return (
        "AMAN (sejauh yang dapat dideteksi tool ini)",
        "Tidak ada celah keamanan terdeteksi pada modul yang dijalankan. "
        "Tetap lakukan review berkala.",
    )


def _wrap(text: str, width: int, indent: int) -> str:
    """Bungkus paragraf sederhana dengan indent untuk baris ke-2 dst."""
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    out: list[str] = []
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


# ---------------------------------------------------------------------------
# section builders
# ---------------------------------------------------------------------------

def _section_ports(findings: list[Finding]) -> list[str]:
    """Bangun section daftar port terbuka."""
    out: list[str] = []
    open_ports: dict[int, str] = {}
    insecure: list[tuple[str, str]] = []  # (location, title)
    for f in findings:
        if f.module != "ports":
            continue
        # finding ringkasan punya extra.open_ports
        ports = f.extra.get("open_ports") if f.extra else None
        if isinstance(ports, dict):
            for k, v in ports.items():
                try:
                    open_ports[int(k)] = str(v)
                except (TypeError, ValueError):
                    continue
        # finding "Port tidak aman terbuka" -> severity HIGH
        if f.severity == Severity.HIGH and "Port tidak aman" in f.title:
            insecure.append((f.target, f.title))

    if not open_ports and not insecure:
        return out

    out.append("[2] PORT TERBUKA")
    out.append("-" * 70)
    if open_ports:
        out.append(f"Total port terbuka: {len(open_ports)}")
        out.append("")
        for p in sorted(open_ports):
            out.append(f"   {p:>5}/tcp   {open_ports[p]}")
        out.append("")
    if insecure:
        out.append("Port tidak aman yang harus segera ditutup / dibatasi:")
        for loc, t in insecure:
            out.append(f"   - {t}")
            out.append(f"     ({loc})")
        out.append("")
    out.append("Rekomendasi:")
    out.append("   - Tutup port yang tidak diperlukan via firewall / security group.")
    out.append("   - Batasi akses port admin (SSH/RDP) hanya dari IP terpercaya.")
    out.append("")
    return out


def _section_subdomains(findings: list[Finding]) -> list[str]:
    """Bangun section daftar subdomain."""
    subs: dict[str, str] = {}
    for f in findings:
        if f.module != "subdomains":
            continue
        s = f.extra.get("subdomains") if f.extra else None
        if isinstance(s, dict):
            for k, v in s.items():
                subs[str(k)] = str(v)

    if not subs:
        return []

    out: list[str] = []
    out.append("[3] SUBDOMAIN YANG DITEMUKAN")
    out.append("-" * 70)
    out.append(f"Total subdomain teridentifikasi: {len(subs)}")
    out.append("")
    for host in sorted(subs):
        out.append(f"   {host}  ->  {subs[host]}")
    out.append("")
    out.append("Rekomendasi:")
    out.append("   - Inventarisasi semua subdomain. Pastikan setiap aktif & di-monitor.")
    out.append("   - Hapus DNS record service yang sudah tidak dipakai untuk mencegah")
    out.append("     subdomain takeover.")
    out.append("")
    return out


def _section_dns(findings: list[Finding]) -> list[str]:
    """Section DNS records + status SPF/DMARC."""
    out: list[str] = []
    records: dict[str, list[str]] = {}
    notes: list[str] = []
    for f in findings:
        if f.module != "dns":
            continue
        if f.extra and "records" in f.extra:
            r = f.extra["records"]
            if isinstance(r, dict):
                for k, v in r.items():
                    records[str(k)] = list(v) if isinstance(v, list) else [str(v)]
        if "SPF" in f.title or "DMARC" in f.title:
            notes.append(f"   - {f.title} (severity {SEVERITY_LABEL[f.severity]})")

    if not records and not notes:
        return out

    out.append("[1b] DNS RECORDS")
    out.append("-" * 70)
    if records:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            if rtype in records:
                vals = ", ".join(records[rtype])
                out.append(f"   {rtype:6s}: {vals}")
    if notes:
        out.append("")
        out.append("Catatan keamanan email:")
        out.extend(notes)
    out.append("")
    return out


def _section_tech(findings: list[Finding]) -> list[str]:
    """Teknologi yang terdeteksi via fingerprint."""
    techs: dict[str, str] = {}
    for f in findings:
        if f.module != "fingerprint":
            continue
        t = f.extra.get("tech") if f.extra else None
        if isinstance(t, dict):
            for k, v in t.items():
                techs[str(k)] = str(v)

    if not techs:
        return []

    out: list[str] = []
    out.append("[1c] TEKNOLOGI YANG TERDETEKSI")
    out.append("-" * 70)
    for k, v in techs.items():
        out.append(f"   {k:18s}: {v}")
    out.append("")
    return out


def _section_whois(findings: list[Finding]) -> list[str]:
    """Info WHOIS singkat."""
    info: dict[str, str] = {}
    for f in findings:
        if f.module != "whois":
            continue
        w = f.extra.get("whois") if f.extra else None
        if isinstance(w, dict):
            for k, v in w.items():
                info[str(k)] = str(v)

    if not info:
        return []

    out: list[str] = []
    out.append("[1d] WHOIS")
    out.append("-" * 70)
    for k in ("domain_name", "registrar", "creation_date", "expiration_date",
              "name_servers", "country", "org", "emails"):
        if k in info:
            out.append(f"   {k:18s}: {info[k]}")
    out.append("")
    return out


def _section_endpoints(findings: list[Finding]) -> list[str]:
    """Endpoint hasil crawler/openapi + file sensitif."""
    out: list[str] = []
    crawler_count = 0
    crawler_visited: list[str] = []
    crawler_endpoints: list[dict] = []
    openapi_count = 0
    sensitive: list[tuple[str, str]] = []  # (severity, target)

    for f in findings:
        if f.module == "crawler" and f.extra:
            crawler_visited = list(f.extra.get("visited", []))[:20]
            crawler_endpoints = list(f.extra.get("endpoints", []))[:25]
            crawler_count = len(f.extra.get("endpoints", []))
        elif f.module == "openapi":
            openapi_count += 1
        elif f.module == "sensitive_files":
            sensitive.append((SEVERITY_LABEL[f.severity], f.target))

    if not (crawler_count or openapi_count or sensitive):
        return out

    out.append("[4] ENDPOINT & FILE")
    out.append("-" * 70)
    if crawler_count:
        out.append(f"Crawler menemukan {crawler_count} endpoint, {len(crawler_visited)} halaman dikunjungi.")
        if crawler_visited:
            out.append("Halaman yang dikunjungi (sampel):")
            for u in crawler_visited[:10]:
                out.append(f"   - {u}")
        if crawler_endpoints:
            with_params = [e for e in crawler_endpoints if e.get("params")]
            if with_params:
                out.append("")
                out.append("Endpoint dengan parameter (kandidat injeksi):")
                for e in with_params[:10]:
                    params = ",".join(e.get("params") or [])
                    out.append(f"   - [{e.get('method', 'GET')}] {e.get('url')}  ({params})")
        out.append("")

    if openapi_count:
        out.append(f"Spesifikasi OpenAPI/Swagger ditemukan ({openapi_count} entri).")
        out.append("   Pastikan ini memang ditujukan untuk publik.")
        out.append("")

    if sensitive:
        out.append("File / path SENSITIF yang ter-ekspos:")
        for sev, tgt in sensitive[:15]:
            out.append(f"   [{sev}] {tgt}")
        out.append("")
        out.append("   ⚠ Segera hapus / blokir akses ke file-file ini.")
        out.append("")
    return out


def _section_vulns(findings_sorted: list[Finding]) -> list[str]:
    """Daftar celah keamanan, urut severity. INFO disembunyikan di sini."""
    vulns = [f for f in findings_sorted if f.severity != Severity.INFO]
    if not vulns:
        return []

    out: list[str] = []
    out.append("[5] CELAH KEAMANAN")
    out.append("-" * 70)

    # Kelompokkan by module untuk header singkat
    by_mod: dict[str, list[Finding]] = {}
    for f in vulns:
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            by_mod.setdefault(f.module, []).append(f)

    if by_mod:
        out.append("Website ini rentan dan ada celah dari:")
        for mod, group in by_mod.items():
            out.append(f"   - {MODULE_HUMAN.get(mod, mod)}  ({len(group)} temuan)")
        out.append("")

    out.append("Detail:")
    for i, f in enumerate(vulns, 1):
        sev = SEVERITY_LABEL[f.severity]
        human_mod = MODULE_HUMAN.get(f.module, f.module)
        out.append("")
        out.append(f"[{i}] [{sev}] {f.title}")
        out.append(f"    Kategori   : {human_mod}")
        out.append(f"    Lokasi     : {f.target}")
        if f.cwe:
            out.append(f"    Referensi  : {f.cwe}")
        if f.description:
            out.append(f"    Penjelasan : {_wrap(f.description, 80, indent=17)}")
        if f.remediation:
            out.append(f"    Cara fix   : {_wrap(f.remediation, 80, indent=17)}")
        if f.evidence:
            ev = f.evidence.replace("\n", " | ")
            if len(ev) > 200:
                ev = ev[:200] + "..."
            out.append(f"    Bukti      : {ev}")
    out.append("")
    return out


# ---------------------------------------------------------------------------
# main entry
# ---------------------------------------------------------------------------

def build_narrative(target_url: str, findings: list[Finding]) -> str:
    """Hasilkan teks naratif lengkap (info recon + celah keamanan)."""
    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module))

    vulns = [f for f in findings_sorted if f.severity != Severity.INFO]
    status, summary = _verdict(vulns)

    n_crit = sum(1 for f in vulns if f.severity == Severity.CRITICAL)
    n_high = sum(1 for f in vulns if f.severity == Severity.HIGH)
    n_med = sum(1 for f in vulns if f.severity == Severity.MEDIUM)
    n_low = sum(1 for f in vulns if f.severity == Severity.LOW)

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(f" HASIL PEMERIKSAAN: {target_url}")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Status website : {status}")
    lines.append(f"Ringkasan      : {_wrap(summary, 80, indent=17)}")
    lines.append("")
    lines.append(
        f"Total celah    : {len(vulns)}  "
        f"(KRITIS={n_crit}, TINGGI={n_high}, SEDANG={n_med}, RENDAH={n_low})"
    )
    lines.append(f"Total info     : {sum(1 for f in findings_sorted if f.severity == Severity.INFO)}")
    lines.append("")

    # Section 1: info recon (DNS, teknologi, WHOIS)
    has_recon = False
    dns_lines = _section_dns(findings_sorted)
    tech_lines = _section_tech(findings_sorted)
    whois_lines = _section_whois(findings_sorted)
    if dns_lines or tech_lines or whois_lines:
        lines.append("[1] INFORMASI WEBSITE")
        lines.append("-" * 70)
        lines.append("")
        has_recon = True

    if dns_lines:
        lines.extend(dns_lines)
    if tech_lines:
        lines.extend(tech_lines)
    if whois_lines:
        lines.extend(whois_lines)

    # Section 2: ports
    port_lines = _section_ports(findings_sorted)
    if port_lines:
        lines.extend(port_lines)

    # Section 3: subdomains
    sub_lines = _section_subdomains(findings_sorted)
    if sub_lines:
        lines.extend(sub_lines)

    # Section 4: endpoints + file sensitif
    ep_lines = _section_endpoints(findings_sorted)
    if ep_lines:
        lines.extend(ep_lines)

    # Section 5: vuln details
    vuln_lines = _section_vulns(findings_sorted)
    if vuln_lines:
        lines.extend(vuln_lines)
    else:
        lines.append("Tidak ada celah keamanan ditemukan oleh tool. Disarankan tetap")
        lines.append("melakukan review manual dan pentest oleh profesional.")
        lines.append("")

    # Disclaimer
    lines.append("-" * 70)
    lines.append("CATATAN:")
    lines.append("- Hasil otomatis ini tidak menggantikan pentest manual oleh profesional.")
    lines.append("- Beberapa finding bertanda 'tentative' perlu diverifikasi manual.")
    lines.append("- Tool ini hanya boleh dipakai pada target yang Anda miliki / yang")
    lines.append("  memberi izin tertulis.")
    lines.append("")
    return "\n".join(lines)
