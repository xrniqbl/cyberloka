"""TCP port scan + banner grab + intrusion probes for high-risk services.

Bukan hanya mendeteksi port terbuka — modul ini juga melakukan probe ringan
yang aman untuk mengevaluasi apakah service di port tersebut dapat
disusupi/diakses tanpa otentikasi:

- FTP (21): coba login `anonymous`.
- SMTP (25/587): cek apakah server menjadi open relay.
- Redis (6379): kirim `PING` — Redis tanpa auth akan balas `+PONG`.
- MongoDB (27017): cek banner ismaster.
- Elasticsearch (9200): GET / berisi cluster info tanpa auth.
- Docker (2375): GET /version — Docker daemon terbuka.
- Memcached (11211): kirim `stats` — keluar daftar info.
- etcd (2379): GET /version.
- Kibana (5601): GET /api/status.
- SSH (22): grab banner versi.
- RDP (3389): port terbuka publik = vektor brute-force.
- Generic banner grab pada port lain.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig

COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 512: "rexec", 513: "rlogin", 514: "rsh/syslog",
    587: "SMTP-Submission", 636: "LDAPS", 873: "rsync", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 2379: "etcd", 2380: "etcd-peer", 3000: "Node/Dev",
    3306: "MySQL", 3389: "RDP", 4369: "Erlang-EPMD", 5000: "Flask/Dev",
    5432: "Postgres", 5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 7001: "WebLogic", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8086: "InfluxDB", 8161: "ActiveMQ", 8443: "HTTPS-Alt",
    8500: "Consul", 8888: "HTTP-Alt", 9000: "PHP-FPM/SonarQube",
    9042: "Cassandra", 9092: "Kafka", 9200: "Elasticsearch",
    9300: "Elasticsearch-cluster", 11211: "Memcached", 27017: "MongoDB",
    27018: "MongoDB-shard", 50070: "Hadoop",
}

INSECURE_PLAINTEXT = {
    21: "FTP", 23: "Telnet", 25: "SMTP (plaintext)", 69: "TFTP",
    110: "POP3 (plaintext)", 143: "IMAP (plaintext)", 161: "SNMP",
    512: "rexec", 513: "rlogin", 514: "rsh", 873: "rsync",
}

# Tanda-tangan banner untuk MENGKONFIRMASI layanan plaintext (bukan asumsi
# dari nomor port). Hanya yang cocok yang dilaporkan HIGH+confirmed.
_PLAINTEXT_BANNER_SIG: dict[int, tuple[str, ...]] = {
    21: ("220 ", "220-", "ftp"),
    23: ("\xff\xfb", "\xff\xfd", "\xff\xfe", "login:"),  # Telnet IAC / prompt
    25: ("220 ", "esmtp", "smtp"),
    110: ("+OK",),
    143: ("* OK", "* PREAUTH"),
    873: ("@RSYNCD",),
}


def _plaintext_confirmed(port: int, banner: str) -> bool:
    sigs = _PLAINTEXT_BANNER_SIG.get(port)
    if not sigs or not banner:
        return False
    low = banner.lower()
    return any(s.lower() in low for s in sigs)


def _check_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _grab_banner(host: str, port: int, timeout: float = 3.0,
                 send: bytes | None = None) -> str:
    """Open a TCP connection, optionally send `send`, return up to 512 bytes."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if send is not None:
                try:
                    s.sendall(send)
                except OSError:
                    return ""
            try:
                data = s.recv(512)
            except socket.timeout:
                return ""
            return data.decode("latin-1", errors="replace").strip()
    except OSError:
        return ""


# ------------------- Service-specific intrusion probes -------------------


def _probe_ftp(host: str, port: int) -> tuple[str, Finding | None]:
    banner = _grab_banner(host, port, timeout=4.0)
    finding = None
    try:
        with socket.create_connection((host, port), timeout=4.0) as s:
            s.settimeout(4.0)
            s.recv(512)
            s.sendall(b"USER anonymous\r\n")
            resp1 = s.recv(512).decode("latin-1", errors="replace")
            s.sendall(b"PASS anonymous@cyberloka.invalid\r\n")
            resp2 = s.recv(512).decode("latin-1", errors="replace")
            if "230" in resp2 or "logged" in resp2.lower():
                finding = Finding(
                    module="ports", target=f"{host}:{port}",
                    title="FTP anonymous login berhasil",
                    severity=Severity.HIGH,
                    description=(
                        "Server FTP mengizinkan login anonymous. Penyerang dapat "
                        "membaca file public folder, dan jika tidak read-only "
                        "dapat upload payload."
                    ),
                    evidence=(banner + "\n" + resp1 + resp2)[:300],
                    cwe="CWE-287",
                    remediation=(
                        "Matikan anonymous login di konfigurasi FTP. Pakai SFTP "
                        "(SSH-22) untuk transfer terenkripsi."
                    ),
                )
    except OSError:
        pass
    return banner, finding


def _probe_ssh(host: str, port: int) -> tuple[str, Finding | None]:
    banner = _grab_banner(host, port, timeout=4.0)
    finding = None
    if banner and "ssh" in banner.lower():
        for old in ("openssh_5.", "openssh_6.", "openssh_7."):
            if old in banner.lower():
                finding = Finding(
                    module="ports", target=f"{host}:{port}",
                    title="OpenSSH versi lama terdeteksi",
                    severity=Severity.MEDIUM,
                    description=(
                        "Banner SSH menunjukkan versi OpenSSH lama yang punya beberapa "
                        "CVE diketahui (mis. CVE-2018-15473 user enumeration)."
                    ),
                    evidence=banner[:200], cwe="CWE-1395",
                    remediation="Upgrade OpenSSH ke versi terbaru (>= 9.x).",
                )
                break
    return banner, finding


def _probe_smtp_relay(host: str, port: int) -> tuple[str, Finding | None]:
    banner = _grab_banner(host, port, timeout=4.0)
    finding = None
    try:
        with socket.create_connection((host, port), timeout=4.0) as s:
            s.settimeout(4.0)
            s.recv(512)
            s.sendall(b"EHLO cyberloka.invalid\r\n")
            ehlo = s.recv(2048).decode("latin-1", errors="replace")
            s.sendall(b"MAIL FROM:<test@cyberloka.invalid>\r\n")
            mf = s.recv(512).decode("latin-1", errors="replace")
            s.sendall(b"RCPT TO:<external@example.com>\r\n")
            rt = s.recv(512).decode("latin-1", errors="replace")
            try:
                s.sendall(b"QUIT\r\n")
            except OSError:
                pass
            if mf.strip().startswith("250") and rt.strip().startswith("250"):
                finding = Finding(
                    module="ports", target=f"{host}:{port}",
                    title="SMTP server tampak menerima relay ke domain eksternal",
                    severity=Severity.HIGH,
                    confidence="firm",
                    description=(
                        "Server SMTP menerima `MAIL FROM` eksternal DAN `RCPT TO` ke "
                        "domain di luar tanpa autentikasi (keduanya balas 250). "
                        "Indikasi kuat open-relay. Konfirmasi final (kirim DATA) "
                        "TIDAK dilakukan agar tidak mengirim email nyata — verifikasi "
                        "manual disarankan sebelum eskalasi."
                    ),
                    evidence=f"EHLO: {ehlo[:80]}\nMAIL(250): {mf[:80]}\nRCPT(250): {rt[:80]}",
                    cwe="CWE-942",
                    remediation=(
                        "Konfigurasi MTA agar hanya menerima relay untuk domain yang "
                        "dimiliki dan IP terpercaya."
                    ),
                )
    except OSError:
        pass
    return banner, finding


def _probe_redis(host: str, port: int) -> tuple[str, Finding | None]:
    banner = ""
    finding = None
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(3.0)
            s.sendall(b"*1\r\n$4\r\nPING\r\n")
            resp = s.recv(64).decode("latin-1", errors="replace")
            banner = resp.strip()
            if "+PONG" in resp:
                finding = Finding(
                    module="ports", target=f"{host}:{port}",
                    title="Redis terbuka tanpa autentikasi",
                    severity=Severity.CRITICAL,
                    description=(
                        "Server Redis merespons PING tanpa AUTH. Attacker dapat "
                        "membaca/menghapus seluruh data, atau eksekusi perintah "
                        "`CONFIG SET dir` untuk RCE klasik."
                    ),
                    evidence=f"PING -> {banner}", cwe="CWE-306",
                    remediation=(
                        "Set `requirepass` di redis.conf, bind ke 127.0.0.1 saja, "
                        "atau pakai TLS + ACL. Jangan publikasikan port 6379."
                    ),
                    references=["https://redis.io/docs/management/security/"],
                )
    except OSError:
        pass
    return banner, finding


def _probe_mongodb(host: str, port: int) -> tuple[str, Finding | None]:
    banner = ""
    finding = None
    msg = (
        b"\x39\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\xd4\x07\x00\x00"
        b"\x00\x00\x00\x00"
        b"admin.$cmd\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
    )
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(3.0)
            s.sendall(msg)
            data = s.recv(2048)
            banner = data[:200].decode("latin-1", errors="replace")
            if b"ismaster" in data or b"maxBsonObjectSize" in data or b"version" in data:
                finding = Finding(
                    module="ports", target=f"{host}:{port}",
                    title="MongoDB merespons ismaster tanpa autentikasi",
                    severity=Severity.CRITICAL,
                    description=(
                        "MongoDB menjawab perintah cluster tanpa otentikasi — biasanya "
                        "berarti seluruh database dapat dibaca/dimodifikasi."
                    ),
                    evidence=banner[:200], cwe="CWE-306",
                    remediation=(
                        "Aktifkan auth (`security.authorization: enabled`), pakai TLS, "
                        "bind ke localhost / VPN saja."
                    ),
                )
    except OSError:
        pass
    return banner, finding


def _http_probe(host: str, port: int, path: str = "/") -> str:
    req = (
        f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
        f"User-Agent: Cyberloka\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(3.0)
            s.sendall(req)
            chunks: list[bytes] = []
            while True:
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 4096:
                    break
            return b"".join(chunks).decode("latin-1", errors="replace")
    except OSError:
        return ""


def _probe_elasticsearch(host: str, port: int) -> tuple[str, Finding | None]:
    body = _http_probe(host, port, "/")
    banner = body[:300]
    finding = None
    if "cluster_name" in body and "elasticsearch" in body.lower():
        finding = Finding(
            module="ports", target=f"{host}:{port}",
            title="Elasticsearch terbuka tanpa autentikasi",
            severity=Severity.CRITICAL,
            description=(
                "Cluster Elasticsearch dapat di-query tanpa auth. Attacker dapat "
                "mengekspor seluruh index data — sering jadi sumber kebocoran "
                "data massal."
            ),
            evidence=banner[:200], cwe="CWE-306",
            remediation=(
                "Aktifkan X-Pack security / Open Distro Security, set "
                "`xpack.security.enabled: true`, pakai HTTPS dan auth basic."
            ),
        )
    return banner, finding


def _probe_docker(host: str, port: int) -> tuple[str, Finding | None]:
    body = _http_probe(host, port, "/version")
    banner = body[:200]
    finding = None
    if "ApiVersion" in body or '"Version"' in body:
        finding = Finding(
            module="ports", target=f"{host}:{port}",
            title="Docker daemon API terbuka tanpa TLS",
            severity=Severity.CRITICAL,
            description=(
                "Docker daemon menerima request HTTP tanpa otentikasi. Attacker "
                "dapat membuat container yang me-mount root filesystem host = "
                "RCE setara root."
            ),
            evidence=banner[:200], cwe="CWE-306",
            remediation=(
                "Jangan ekspos Docker daemon ke jaringan publik. Pakai socket "
                "Unix (default) atau TLS mutual auth + IP allowlist."
            ),
        )
    return banner, finding


def _probe_memcached(host: str, port: int) -> tuple[str, Finding | None]:
    banner = ""
    finding = None
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(3.0)
            s.sendall(b"stats\r\n")
            data = s.recv(2048).decode("latin-1", errors="replace")
            banner = data[:200]
            if "STAT version" in data or "STAT pid" in data:
                finding = Finding(
                    module="ports", target=f"{host}:{port}",
                    title="Memcached terbuka tanpa autentikasi",
                    severity=Severity.CRITICAL,
                    description=(
                        "Memcached merespons `stats` tanpa auth. Service ini juga sering "
                        "jadi vector amplifikasi DDoS dan dapat membongkar data cache "
                        "(termasuk session)."
                    ),
                    evidence=banner[:200], cwe="CWE-306",
                    remediation=(
                        "Bind memcached ke 127.0.0.1, atau gunakan SASL auth + firewall."
                    ),
                )
    except OSError:
        pass
    return banner, finding


def _probe_etcd(host: str, port: int) -> tuple[str, Finding | None]:
    body = _http_probe(host, port, "/version")
    banner = body[:200]
    finding = None
    if "etcdserver" in body:
        finding = Finding(
            module="ports", target=f"{host}:{port}",
            title="etcd API terbuka tanpa autentikasi",
            severity=Severity.HIGH,
            description=(
                "etcd biasanya memuat secret Kubernetes & service mesh. "
                "Akses tanpa auth dapat membongkar konfigurasi cluster."
            ),
            evidence=banner[:200], cwe="CWE-306",
            remediation="Aktifkan client certificate auth + RBAC di etcd.",
        )
    return banner, finding


def _probe_kibana(host: str, port: int) -> tuple[str, Finding | None]:
    body = _http_probe(host, port, "/api/status")
    banner = body[:200]
    finding = None
    if "kibana" in body.lower():
        finding = Finding(
            module="ports", target=f"{host}:{port}",
            title="Kibana dashboard dapat diakses publik",
            severity=Severity.HIGH,
            description=(
                "Kibana terbuka biasanya = jendela ke seluruh log/metrics "
                "internal. Wajib di-protect dengan auth."
            ),
            evidence=banner[:200], cwe="CWE-284",
            remediation="Letakkan di balik VPN atau aktifkan X-Pack security.",
        )
    return banner, finding


def _probe_rdp(host: str, port: int) -> tuple[str, Finding | None]:
    """Buktikan port 3389 benar-benar RDP via X.224 Connection Request.

    Dulu: HIGH hanya dari port terbuka (asumsi dari nomor port). Sekarang kirim
    X.224 CR standar (non-destruktif) dan wajib server membalas TPKT (0x03 0x00)
    sebelum melaporkan. Bila tidak membalas seperti RDP → tidak ada finding.
    """
    # Cookie + RDP Negotiation Request (RFC 2126 / MS-RDPBCGR), aman/non-destruktif.
    x224_cr = bytes.fromhex("030000130ee000000000000100080003000000")
    data = b""
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(3.0)
            s.sendall(x224_cr)
            data = s.recv(64)
    except OSError:
        return "", None
    # TPKT header 0x03 0x00 = respons protokol RDP/X.224 yang sah.
    if data[:2] != b"\x03\x00":
        return "", None
    return "RDP X.224 response (TPKT)", Finding(
        module="ports", target=f"{host}:{port}",
        title="RDP (Remote Desktop) terbuka di internet",
        severity=Severity.HIGH,
        confidence="confirmed",
        description=(
            "Port 3389 membalas handshake X.224 RDP (terkonfirmasi sebagai RDP, "
            "bukan sekadar port terbuka). RDP publik adalah salah satu vektor "
            "brute-force paling umum (cth. BlueKeep / ransomware Dharma)."
        ),
        evidence="X.224 Connection Confirm (TPKT 0x0300) diterima",
        cwe="CWE-284",
        remediation=(
            "Jangan publikasikan RDP. Pakai VPN, RDP Gateway, atau Network Level "
            "Authentication + 2FA. Batasi IP source via firewall."
        ),
    )


PROBES: dict[int, Any] = {
    21: _probe_ftp,
    22: _probe_ssh,
    25: _probe_smtp_relay,
    587: _probe_smtp_relay,
    2375: _probe_docker,
    2379: _probe_etcd,
    3389: _probe_rdp,
    5601: _probe_kibana,
    6379: _probe_redis,
    9200: _probe_elasticsearch,
    11211: _probe_memcached,
    27017: _probe_mongodb,
    27018: _probe_mongodb,
}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    host = target.resolve_ip() or target.host

    open_ports: dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=min(50, config.threads * 5)) as ex:
        future_map = {
            ex.submit(_check_port, host, p, min(config.timeout, 2.0)): p
            for p in COMMON_PORTS
        }
        for fut in as_completed(future_map):
            port = future_map[fut]
            try:
                if fut.result():
                    open_ports[port] = COMMON_PORTS[port]
            except Exception:  # noqa: BLE001
                continue

    if not open_ports:
        return findings

    findings.append(
        Finding(
            module="ports",
            title=f"{len(open_ports)} port terbuka terdeteksi",
            severity=Severity.INFO,
            description=(
                "Daftar port TCP umum yang terbuka. Lihat finding terpisah untuk "
                "hasil intrusion test."
            ),
            target=host,
            evidence="\n".join(f"{p}/tcp - {s}" for p, s in sorted(open_ports.items())),
            remediation=(
                "Tutup port yang tidak diperlukan via firewall/security group. "
                "Batasi akses port admin (SSH/RDP) hanya dari IP terpercaya."
            ),
            extra={"open_ports": open_ports},
        )
    )

    banners: dict[int, str] = {}
    for port in open_ports:
        if port not in PROBES:
            continue
        try:
            banner, finding = PROBES[port](host, port)
            if banner:
                banners[port] = banner
            if finding:
                findings.append(finding)
        except Exception:  # noqa: BLE001
            continue

    for port, name in open_ports.items():
        if port in PROBES or port in (80, 443, 8080, 8443):
            continue
        try:
            banner = _grab_banner(host, port, timeout=2.0)
        except Exception:  # noqa: BLE001
            banner = ""
        if banner:
            banners[port] = banner

    if banners:
        findings.append(
            Finding(
                module="ports",
                title="Banner service yang dikumpulkan",
                severity=Severity.INFO,
                description=(
                    "Banner yang dikumpulkan dari port terbuka. Membantu memastikan "
                    "versi software yang dipakai (untuk audit CVE)."
                ),
                target=host,
                evidence="\n".join(
                    f"[{p}/{COMMON_PORTS.get(p, '?')}] {b[:120]}"
                    for p, b in sorted(banners.items())
                ),
                extra={"banners": banners},
            )
        )

    for p, name in open_ports.items():
        if p in INSECURE_PLAINTEXT and not any(
            f.target == f"{host}:{p}" for f in findings
        ):
            banner = banners.get(p, "")
            confirmed = _plaintext_confirmed(p, banner)
            if confirmed:
                # Layanan terkonfirmasi via banner → klaim plaintext sah.
                sev, conf = Severity.HIGH, "confirmed"
                desc = (
                    f"Service {INSECURE_PLAINTEXT[p]} pada port {p} TERKONFIRMASI "
                    "via banner dan mengirim data tanpa enkripsi. Kredensial dan "
                    "konten dapat disadap di jaringan."
                )
                ev = f"banner terkonfirmasi: {banner[:120]!r}"
            else:
                # Port terbuka tetapi layanan HANYA diasumsikan dari nomor port —
                # belum terverifikasi. Turunkan ke INFO/tentative, bukan HIGH.
                sev, conf = Severity.INFO, "tentative"
                desc = (
                    f"Port {p} terbuka. Layanan DIASUMSIKAN '{INSECURE_PLAINTEXT[p]}' "
                    "dari nomor port standar, tetapi BELUM terkonfirmasi via banner. "
                    "Verifikasi manual sebelum menyimpulkan layanan plaintext."
                )
                ev = f"port terbuka; banner tidak konklusif: {banner[:120]!r}"
            findings.append(
                Finding(
                    module="ports",
                    title=(
                        f"Service plaintext / tidak terenkripsi: {p}/{INSECURE_PLAINTEXT[p]}"
                        if confirmed else
                        f"Port terbuka (layanan belum terverifikasi): {p}/{INSECURE_PLAINTEXT[p]}?"
                    ),
                    severity=sev,
                    confidence=conf,
                    description=desc,
                    target=f"{host}:{p}",
                    evidence=ev,
                    cwe="CWE-319",
                    remediation=(
                        "Migrasi ke alternatif terenkripsi: SFTP (SSH-22) untuk file, "
                        "IMAPS/POP3S untuk email, SMTP+STARTTLS, atau letakkan di "
                        "belakang VPN."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                    ],
                )
            )
    return findings
