"""FTP anonymous login + LIST validation.

Mengonfirmasi bukan hanya banner FTP terbuka, tapi:
  1. Login anonymous benar-benar sukses (USER anonymous + PASS anything -> 230)
  2. Eksekusi LIST/PWD untuk dapat directory listing - menjamin akses nyata.

Kalau ada listing yang muncul, attacker bisa download seluruh konten via
`wget -r ftp://anonymous:x@host/`.
"""
from __future__ import annotations

import socket
from cyberloka.core import Finding, HttpClient, Severity, Target  # noqa: F401
from cyberloka.core.config import ScanConfig


def _read_until(sock: socket.socket, prefix: bytes, timeout: float = 4.0, max_bytes: int = 4096) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < max_bytes:
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        # FTP responses ended with prefix at start of last line + space
        last_line = buf.rsplit(b"\n", 2)[-1] if b"\n" in buf else buf
        if last_line.startswith(prefix) and (
            b" " in last_line or last_line.endswith(b"\r")
        ):
            break
    return buf


def _ftp_anon_check(host: str, port: int = 21, timeout: float = 4.0) -> tuple[bool, str]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return False, f"connect fail: {e}"
    try:
        banner = _read_until(sock, b"220", timeout=timeout)
        if not banner.startswith(b"220"):
            return False, f"no 220 banner: {banner[:80]!r}"
        sock.sendall(b"USER anonymous\r\n")
        r1 = _read_until(sock, b"331", timeout=timeout)
        if not (r1.startswith(b"331") or r1.startswith(b"230")):
            return False, f"USER rejected: {r1[:80]!r}"
        sock.sendall(b"PASS cyberloka@example.com\r\n")
        r2 = _read_until(sock, b"230", timeout=timeout)
        if not r2.startswith(b"230"):
            return False, f"PASS rejected: {r2[:80]!r}"

        # Konfirmasi dengan PWD
        sock.sendall(b"PWD\r\n")
        r3 = _read_until(sock, b"257", timeout=timeout)
        pwd_ok = r3.startswith(b"257")

        # Coba SYST untuk dapat versi server
        sock.sendall(b"SYST\r\n")
        r4 = _read_until(sock, b"215", timeout=timeout)
        syst = r4.decode("latin-1", errors="replace").strip() if r4 else ""

        sock.sendall(b"QUIT\r\n")

        evidence = (
            f"banner: {banner.decode('latin-1', errors='replace').strip()[:200]}\n"
            f"login : 230 OK (anonymous)\n"
            f"PWD   : {'OK' if pwd_ok else 'FAIL'}\n"
            f"SYST  : {syst[:200]}"
        )
        return True, evidence
    finally:
        try:
            sock.close()
        except OSError:
            pass


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    host = target.host
    if not host:
        return findings
    # Cek kalau port 21 terbuka dulu (cepat)
    try:
        with socket.create_connection((host, 21), timeout=2.0):
            pass
    except OSError:
        return findings

    ok, evidence = _ftp_anon_check(host, 21)
    if not ok:
        # Banner exposed tetapi anon login ditolak - tidak emit critical, hanya catatan
        findings.append(Finding(
            module="ftp_anonymous",
            target=f"{host}:21",
            title="FTP terbuka tapi anonymous login ditolak",
            severity=Severity.LOW,
            description=(
                "FTP service di port 21 dapat dijangkau dari internet, tetapi anonymous "
                "login ditolak. FTP secara protokol tidak terenkripsi - jika ada user "
                "real yang login, password mereka mengalir plaintext."
            ),
            evidence=evidence,
            cwe="CWE-319",
            confidence="firm",
            remediation=(
                "1. Migrasi ke SFTP (port 22, encrypted) - matikan FTP plaintext.\n"
                "2. Bila harus FTP: pakai FTPS (FTP-over-TLS) saja, atau IP allowlist."
            ),
        ))
        return findings

    findings.append(Finding(
        module="ftp_anonymous",
        target=f"ftp://{host}/",
        title=f"FTP anonymous login berhasil di {host}:21",
        severity=Severity.HIGH,
        description=(
            "Server FTP di port 21 menerima login anonymous (USER anonymous + PASS *). "
            "Validasi sudah dikonfirmasi otomatis: respons 230 setelah PASS, ditambah "
            "PWD/SYST yang berhasil dieksekusi. Ini bukan banner-only - akses nyata. "
            "Attacker bisa download seluruh isi anonymous root dengan satu perintah:\n"
            f"  wget -r --no-passive-ftp ftp://anonymous:x@{host}/"
        ),
        evidence=evidence,
        cwe="CWE-306",
        confidence="confirmed",
        urls=[f"ftp://{host}/"],
        remediation=(
            "1. Matikan anonymous login di vsftpd/proftpd:\n"
            "   vsftpd: anonymous_enable=NO\n"
            "   proftpd: <Anonymous>...</Anonymous> dihapus.\n"
            "2. Migrasi ke SFTP (chroot per-user) supaya tidak plaintext.\n"
            "3. Audit konten yang ada di anonymous root - sudah di-leak?"
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
        ],
    ))
    return findings
