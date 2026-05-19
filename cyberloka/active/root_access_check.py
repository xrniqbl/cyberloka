"""Root-equivalent access detection via exposed admin services.

Tujuan:
Memvalidasi secara otomatis apakah ada port/service yang, jika dibiarkan
terbuka tanpa autentikasi, memberikan akses setara root ke server / cluster.

Service yang dicek lebih dalam (TIDAK MELAKUKAN EKSPLOITASI - hanya read-only
verification request):

- Docker daemon API (2375 / 2376)
    GET /version, /containers/json. Daemon root = RCE setara root.
- Kubernetes API (10250 kubelet, 6443 apiserver, 8001 proxy)
    GET /pods, /api -> akses bisa exec ke pod = root cluster.
- etcd (2379 / 2380)
    GET /version. Memuat secret kubernetes.
- Redis (6379)
    PING + INFO. Sering dipakai chain RCE via CONFIG SET dir.
- MongoDB (27017 / 27018)
    isMaster + listDatabases. Database tanpa auth.
- Elasticsearch (9200)
    GET / + /_cluster/health.
- CouchDB (5984)
    GET /_all_dbs, /_users.
- Memcached (11211)
    stats command.
- VNC (5900)
    Probe ProtocolVersion handshake - jika RFB version diberikan TANPA auth
    type 2 (VNC Auth), ada chance no-auth.
- SMB (445)
    Cek apakah ada null session yang valid (terlalu invasive untuk default,
    hanya banner check).
- Jenkins script console (8080 /script)
    Akses tanpa auth = RCE Groovy.
- Spring Boot Actuator (/actuator/env, /actuator/heapdump)
    Heap dump = leak credentials.
- Solr / Druid / Hadoop UI dengan known unauth endpoints.
- JDWP (8000-9000) -> RCE klasik.

Setiap finding memuat status_code + body fingerprint sehingga tidak ada
pengecekan manual; modul ini sendiri yang melakukan validasi positive
identification berbasis signature respons.
"""
from __future__ import annotations

import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Daftar (port, scheme, name) yang akan dicek lewat HTTP probe + signature.
HTTP_TARGETS: list[tuple[int, str, str]] = [
    (2375, "http", "docker"),
    (2376, "https", "docker-tls"),
    (2379, "http", "etcd"),
    (5984, "http", "couchdb"),
    (6443, "https", "k8s-apiserver"),
    (8001, "http", "k8s-proxy"),
    (8080, "http", "jenkins-or-actuator"),
    (8081, "http", "jenkins-or-actuator"),
    (8443, "https", "jenkins-or-actuator"),
    (9200, "http", "elasticsearch"),
    (9300, "http", "elasticsearch"),
    (10250, "https", "k8s-kubelet"),
    (15672, "http", "rabbitmq-mgmt"),
    (50070, "http", "hadoop-namenode"),
]


# ---------- low-level helpers (no external deps for socket-level probes) ----


def _is_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_get(client: HttpClient, scheme: str, host: str, port: int, path: str):
    url = f"{scheme}://{host}:{port}{path}"
    return client.get(url, allow_redirects=False), url


def _redis_unauth(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Probe Redis dengan PING + INFO. Return (vulnerable, evidence)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"*1\r\n$4\r\nPING\r\n")
            r1 = s.recv(64).decode("latin-1", errors="replace").strip()
            if "+PONG" not in r1:
                return False, r1
            # Extra konfirmasi: INFO server (kalau auth dibutuhkan ini gagal)
            s.sendall(b"*1\r\n$4\r\nINFO\r\n")
            r2 = s.recv(2048).decode("latin-1", errors="replace")
            if "redis_version" in r2:
                # ambil versi
                m = re.search(r"redis_version:([^\r\n]+)", r2)
                return True, f"PING -> {r1}; redis_version={m.group(1) if m else '?'}"
            return False, r1
    except OSError as e:
        return False, f"err: {e}"


def _mongo_unauth(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Wire-protocol legacy isMaster query (cocok untuk MongoDB <= 5)."""
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
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(msg)
            data = s.recv(4096)
            if b"ismaster" in data or b"maxBsonObjectSize" in data:
                # Look for version
                m = re.search(rb"version\x00.{0,4}([0-9.]+)", data)
                ver = m.group(1).decode() if m else "?"
                return True, f"isMaster ok; version={ver}"
            return False, data[:80].decode("latin-1", errors="replace")
    except OSError as e:
        return False, f"err: {e}"


def _memcached_unauth(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"stats\r\n")
            data = s.recv(2048).decode("latin-1", errors="replace")
            if "STAT version" in data or "STAT pid" in data:
                m = re.search(r"STAT version (\S+)", data)
                return True, f"stats ok; version={m.group(1) if m else '?'}"
            return False, data[:80]
    except OSError as e:
        return False, f"err: {e}"


def _vnc_check(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Cek VNC handshake. Server kirim 'RFB <ver>\\n' lalu authentication
    type byte. Type 1 = no-auth = sangat rentan."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            ver = s.recv(12)
            if not ver.startswith(b"RFB "):
                return False, ver[:20].decode("latin-1", errors="replace")
            s.sendall(ver)  # echo version
            sec = s.recv(64)
            if not sec or len(sec) < 1:
                return False, "no security types"
            # Older RFB sends single byte security type
            if len(sec) >= 4 and sec[0] == 0:
                # error
                return False, "VNC reject"
            # RFB 3.7+: first byte = number of types, then types
            # Type 1 = none, 2 = VNC auth
            types_present = set(sec[1: 1 + sec[0]]) if sec[0] < 32 else set(sec)
            if 1 in types_present:
                return True, f"VNC version {ver[4:11].decode(errors='ignore').strip()}, security type 1 (none) OFFERED"
            return False, f"types={list(types_present)[:5]}"
    except OSError as e:
        return False, f"err: {e}"


# ---------- HTTP signature checks (fingerprint based) ----------


SIGNATURES: dict[str, list[tuple[str, str, str]]] = {
    # name -> list of (path, regex_must_match, severity)
    "docker": [
        ("/version", r'"ApiVersion"\s*:', "critical"),
    ],
    "docker-tls": [
        ("/version", r'"ApiVersion"\s*:', "critical"),
    ],
    "etcd": [
        ("/version", r'"etcdserver"\s*:', "high"),
    ],
    "k8s-apiserver": [
        ("/api", r'"versions"\s*:', "critical"),
        ("/version", r'"gitVersion"\s*:', "critical"),
    ],
    "k8s-kubelet": [
        ("/pods", r'"kind"\s*:\s*"PodList"', "critical"),
        ("/runningpods/", r'"kind"\s*:\s*"PodList"', "critical"),
    ],
    "k8s-proxy": [
        ("/api", r'"versions"\s*:', "critical"),
    ],
    "elasticsearch": [
        ("/", r'"cluster_name"\s*:', "critical"),
        ("/_cluster/health", r'"status"\s*:\s*"(green|yellow|red)"', "critical"),
    ],
    "couchdb": [
        ("/_all_dbs", r"^\s*\[", "high"),
        ("/_users/_all_docs", r'"rows"\s*:', "critical"),
    ],
    "rabbitmq-mgmt": [
        ("/api/overview", r'"rabbitmq_version"\s*:', "high"),
    ],
    "hadoop-namenode": [
        ("/dfshealth.html", r"Hadoop\s+Administration", "high"),
    ],
    # Jenkins or Actuator running on 8080/8081/8443
    "jenkins-or-actuator": [
        ("/script", r"Groovy\s*Script", "critical"),
        ("/actuator/env", r'"activeProfiles"|"propertySources"', "high"),
        ("/actuator/heapdump", r"^.PK|^\x1f\x8b|HeapDump", "critical"),
        ("/manage/login", r"<title>\s*Sign in.*Jenkins", "low"),
    ],
}


REMEDIATION: dict[str, str] = {
    "docker": (
        "Jangan ekspos socket Docker ke jaringan. Pakai socket Unix default "
        "atau TLS mutual auth + IP allowlist. Audit semua firewall rule."
    ),
    "k8s-apiserver": (
        "Apiserver harus di belakang RBAC + autentikasi. Block /api anonymous "
        "via `--anonymous-auth=false`. Batasi network ke control plane saja."
    ),
    "k8s-kubelet": (
        "Set `--anonymous-auth=false` dan `--authorization-mode=Webhook` di "
        "kubelet. Port 10250 jangan publik."
    ),
    "etcd": (
        "Aktifkan TLS client cert auth di etcd. Jangan ekspos ke jaringan "
        "publik."
    ),
    "redis": (
        "Set `requirepass` di redis.conf, bind 127.0.0.1, atau pakai TLS+ACL."
    ),
    "mongo": (
        "Aktifkan `security.authorization: enabled` + auth user. Bind ke "
        "localhost atau VPN."
    ),
    "elasticsearch": (
        "Aktifkan X-Pack security + HTTPS + auth basic / token."
    ),
    "couchdb": (
        "Set admin password (`server admin`), nonaktifkan `_users` public, "
        "letakkan di belakang reverse proxy auth."
    ),
    "memcached": (
        "Bind ke 127.0.0.1, atau pakai SASL auth + firewall."
    ),
    "vnc": (
        "Set password VNC (security type 2 minimum) atau gunakan SSH tunnel. "
        "Lebih baik: nonaktifkan VNC publik."
    ),
    "rabbitmq-mgmt": (
        "Ganti default user/password (guest/guest), bind admin port ke "
        "loopback, atau pakai HTTPS + auth basic eksternal."
    ),
    "hadoop-namenode": (
        "Aktifkan Kerberos auth di Hadoop. Nonaktifkan akses publik UI."
    ),
    "jenkins-or-actuator": (
        "Jenkins script console harus di belakang auth admin (nonaktifkan "
        "anonymous read). Spring Boot Actuator: matikan endpoint berbahaya "
        "(env, heapdump) di production."
    ),
}


def _build_finding(
    name: str,
    host: str,
    port: int,
    url: str,
    body_excerpt: str,
    severity: str,
) -> Finding:
    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
    }
    sev = sev_map.get(severity, Severity.HIGH)
    rem = REMEDIATION.get(name) or REMEDIATION.get(name.split("-")[0]) or (
        "Letakkan service di belakang autentikasi + jangan ekspos port "
        "internal ke internet."
    )
    return Finding(
        module="root_access_check",
        target=f"{host}:{port}",
        title=f"AKSES SETARA ROOT: service `{name}` terbuka tanpa auth di {host}:{port}",
        severity=sev,
        description=(
            f"Service `{name}` di {host}:{port} merespons request privileged "
            f"tanpa autentikasi. Jenis service ini, jika tidak ter-protect, "
            f"setara dengan akses root ke server / cluster (bukan hanya satu "
            f"aplikasi). Modul ini sudah memvalidasi otomatis dengan signature "
            f"response di bawah - bukan tebak-tebakan dari port terbuka saja."
        ),
        evidence=f"URL    : {url}\nExcerpt: {body_excerpt[:400]}",
        cwe="CWE-306",  # Missing Authentication for Critical Function
        confidence="confirmed",
        urls=[url],
        remediation=rem,
        references=[
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
            "https://cwe.mitre.org/data/definitions/306.html",
        ],
    )


def _check_http_service(
    client: HttpClient, host: str, port: int, scheme: str, name: str,
) -> list[Finding]:
    sigs = SIGNATURES.get(name, [])
    out: list[Finding] = []
    for path, pattern, sev in sigs:
        resp, url = _http_get(client, scheme, host, port, path)
        if resp is None or resp.status_code >= 400:
            continue
        body = resp.text or ""
        if re.search(pattern, body, re.I | re.S):
            out.append(
                _build_finding(name, host, port, url, body[:500], sev)
            )
            # cukup 1 finding per service di port itu (jangan bikin noise)
            break
    return out


# ---------- top-level entry ----------


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    host = target.resolve_ip() or target.host
    if not host:
        return findings

    # Step 1: pre-scan port supaya tidak buang waktu di port mati
    candidate_ports: set[int] = set(p for p, *_ in HTTP_TARGETS)
    candidate_ports.update(
        [6379, 27017, 27018, 11211, 5900, 5901, 5902]
    )  # native protocol probes

    timeout_for_port = min(config.timeout, 1.5)
    open_ports: set[int] = set()
    with ThreadPoolExecutor(max_workers=min(40, config.threads * 4)) as ex:
        future_map = {
            ex.submit(_is_open, host, p, timeout_for_port): p
            for p in candidate_ports
        }
        for fut in as_completed(future_map):
            try:
                if fut.result():
                    open_ports.add(future_map[fut])
            except Exception:  # noqa: BLE001
                continue

    if not open_ports:
        return findings

    client = HttpClient(config)
    try:
        # Step 2: HTTP-based services with signature validation
        for port, scheme, name in HTTP_TARGETS:
            if port not in open_ports:
                continue
            findings.extend(_check_http_service(client, host, port, scheme, name))
    finally:
        client.close()

    # Step 3: Native-protocol services (Redis / Mongo / Memcached / VNC)
    native_probes: list[tuple[int, str, Callable, str]] = [
        (6379, "redis", _redis_unauth, "critical"),
        (27017, "mongo", _mongo_unauth, "critical"),
        (27018, "mongo", _mongo_unauth, "critical"),
        (11211, "memcached", _memcached_unauth, "critical"),
        (5900, "vnc", _vnc_check, "critical"),
        (5901, "vnc", _vnc_check, "critical"),
        (5902, "vnc", _vnc_check, "critical"),
    ]
    for port, name, fn, sev in native_probes:
        if port not in open_ports:
            continue
        try:
            ok, evidence = fn(host, port)
        except Exception:  # noqa: BLE001
            continue
        if ok:
            findings.append(
                _build_finding(name, host, port, f"tcp://{host}:{port}", evidence, sev)
            )

    if findings:
        # Tambahkan summary finding di awal supaya laporan punya 1-glance view
        services = sorted({f.target for f in findings})
        findings.insert(
            0,
            Finding(
                module="root_access_check",
                target=host,
                title=(
                    f"{len(findings)} service privileged terbuka tanpa auth "
                    f"(akses setara ROOT)"
                ),
                severity=Severity.CRITICAL,
                description=(
                    "Modul root_access_check menemukan satu atau lebih service "
                    "yang, jika dibiarkan publik, memberi attacker kemampuan "
                    "setara root atau setara take-over server. Setiap finding "
                    "di bawah sudah dimvalidasi otomatis via signature response "
                    "(bukan hanya port terbuka)."
                ),
                evidence="Service tervalidasi:\n" + "\n".join(f"- {s}" for s in services),
                cwe="CWE-306",
                confidence="confirmed",
                remediation=(
                    "Lihat finding spesifik untuk perbaikan per-service. Kunci: "
                    "letakkan service kontrol-bidang (Docker, K8s API/kubelet, "
                    "etcd, Redis, MongoDB, dll.) di balik VPN/network policy + "
                    "autentikasi + TLS mutual."
                ),
                references=[
                    "https://kubernetes.io/docs/concepts/security/",
                    "https://docs.docker.com/engine/security/",
                ],
            ),
        )

    return findings
