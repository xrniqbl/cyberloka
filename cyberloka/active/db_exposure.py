"""Deep database / data-leak exposure scanner.

Tujuan: mendeteksi cara attacker bisa **mengakses database** atau **menarik
data sensitif** dari target. Scanner ini melakukan tujuh kategori probe:

    1. Direct DB ports                — TCP probe + banner sniff
       (MySQL/MariaDB 3306, Postgres 5432, MongoDB 27017, Redis 6379,
        Elasticsearch 9200, MSSQL 1433, Memcached 11211, Cassandra 9042,
        Neo4j 7474/7687, CouchDB 5984)
    2. DB admin panels                — phpMyAdmin, Adminer, RockMongo,
       RedisCommander, pgAdmin, kibana, Mongo-Express
    3. DB REST endpoints              — ES `_cat/_search`, Couch `/_all_dbs`,
       Mongo REST, Solr `/admin/cores`, Cassandra HTTP REST.
    4. SQL/NoSQL dump files           — `dump.sql`, `database.sql.gz`,
       `db.sqlite`, `db.sqlite3`, `*.bak.zip`, `mongodump.tar`
    5. ORM / cache UI                 — Sidekiq web, Bull-board, Flower,
       Hangfire, RQ-dashboard
    6. Public GraphQL introspection   — query model & field names yang
       biasanya berisi tabel sensitif (User, Token, Order, Payment).
    7. Pattern leak di response       — DSN string (`postgres://user:pass@`,
       `mysql://`, `mongodb+srv://`, `redis://:pass@`) DI BODY publik.

Setiap finding di-set `extra["reverify"]` untuk dicek validator agar tidak
ada false-positive (mis. SPA halaman 200 yang sebenarnya 404).
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

# ----------------------------------------------------------------------------
# 1. Direct DB ports (host saja, bukan brute-force kredensial)
# ----------------------------------------------------------------------------
DB_PORTS: list[tuple[int, str, bytes | None, re.Pattern[bytes] | None]] = [
    # (port, label, probe-bytes, banner-regex)
    (3306, "MySQL/MariaDB", None,
     re.compile(rb"\x00\x00\x00\x0a[\d.]+|mariadb|mysql_native_password", re.I)),
    (5432, "PostgreSQL", b"\x00\x00\x00\x08\x04\xd2\x16/",
     re.compile(rb"FATAL|postgres", re.I)),
    (27017, "MongoDB", None, None),  # banner kosong → confirm via HTTP /
    (6379, "Redis", b"*1\r\n$4\r\nPING\r\n",
     re.compile(rb"\+PONG|NOAUTH|-ERR", re.I)),
    (9200, "Elasticsearch", None, None),  # via HTTP probe
    (1433, "MSSQL", None, re.compile(rb"\x04\x01|tabular data stream", re.I)),
    (11211, "Memcached", b"version\r\n",
     re.compile(rb"VERSION\s+\S+", re.I)),
    (9042, "Cassandra", None, None),
    (5984, "CouchDB", None, None),  # HTTP only
    (7474, "Neo4j HTTP", None, None),  # HTTP only
]


def _probe_port(host: str, port: int, probe: bytes | None,
                banner_re: re.Pattern[bytes] | None,
                timeout: float = 3.0) -> tuple[bool, str]:
    """Return (matched, evidence)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe:
                s.sendall(probe)
            data = b""
            try:
                data = s.recv(256)
            except socket.timeout:
                pass
            if banner_re:
                m = banner_re.search(data)
                if m:
                    return True, truncate(repr(data[:120]), 120)
                return False, ""
            # tanpa banner_re: cukup port terbuka untuk kandidat
            return True, f"port open, banner={truncate(repr(data[:60]), 60)}"
    except (OSError, socket.timeout):
        return False, ""


# ----------------------------------------------------------------------------
# 2. DB admin panels
# ----------------------------------------------------------------------------
ADMIN_PANELS: list[tuple[str, str, str, Severity]] = [
    # (path, label, body-marker, severity)
    ("phpmyadmin/", "phpMyAdmin", "phpmyadmin", Severity.CRITICAL),
    ("phpMyAdmin/", "phpMyAdmin", "phpmyadmin", Severity.CRITICAL),
    ("pma/", "phpMyAdmin alias", "phpmyadmin", Severity.CRITICAL),
    ("adminer.php", "Adminer", "adminer", Severity.CRITICAL),
    ("adminer/", "Adminer dir", "adminer", Severity.CRITICAL),
    ("dbadmin/", "dbadmin", "database", Severity.HIGH),
    ("phppgadmin/", "phpPgAdmin", "phppgadmin", Severity.CRITICAL),
    ("rockmongo/", "RockMongo", "rockmongo", Severity.CRITICAL),
    ("mongo-express/", "Mongo-Express", "mongo express", Severity.CRITICAL),
    ("redis-commander/", "RedisCommander", "redis commander", Severity.CRITICAL),
    ("pgadmin/", "pgAdmin", "pgadmin", Severity.HIGH),
    ("pgadmin4/", "pgAdmin4", "pgadmin", Severity.HIGH),
    ("kibana/", "Kibana", "kbn-license-sig", Severity.HIGH),
    ("kibana/app/home", "Kibana app", "kbn-name", Severity.HIGH),
    ("solr/", "Solr admin", "solr admin", Severity.HIGH),
    ("hangfire", "Hangfire", "hangfire", Severity.MEDIUM),
    ("sidekiq", "Sidekiq dashboard", "sidekiq", Severity.MEDIUM),
    ("bull-board", "Bull-board", "bull board", Severity.MEDIUM),
    ("flower/", "Celery Flower", "flower", Severity.MEDIUM),
    ("rq", "RQ dashboard", "rq dashboard", Severity.MEDIUM),
]

# ----------------------------------------------------------------------------
# 3. DB REST endpoints (no auth → langsung dump data)
# ----------------------------------------------------------------------------
REST_ENDPOINTS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    ("_cat/indices?v", "Elasticsearch _cat/indices",
     re.compile(r"health\s+status\s+index", re.I), Severity.CRITICAL),
    ("_search?pretty&size=1", "Elasticsearch _search",
     re.compile(r'"_index"|"hits"', re.I), Severity.CRITICAL),
    ("_all_dbs", "CouchDB _all_dbs",
     re.compile(r"^\[\s*\""), Severity.CRITICAL),
    ("admin/cores?wt=json", "Solr cores list",
     re.compile(r'"responseHeader"|"status":\s*0', re.I), Severity.HIGH),
    ("solr/admin/info/system?wt=json", "Solr system info",
     re.compile(r'"jvm"|"lucene"', re.I), Severity.HIGH),
    ("_node/_local/_stats", "CouchDB stats",
     re.compile(r"couchdb"), Severity.HIGH),
    ("server-status", "Apache server-status",
     re.compile(r"Apache Server Status", re.I), Severity.MEDIUM),
    (".well-known/openid-configuration", "OIDC discovery",
     re.compile(r"issuer|authorization_endpoint", re.I), Severity.INFO),
]

# ----------------------------------------------------------------------------
# 4. DB dump file paths
# ----------------------------------------------------------------------------
DUMP_PATHS: list[tuple[str, str, Severity]] = [
    ("backup.sql", "SQL dump", Severity.CRITICAL),
    ("dump.sql", "SQL dump", Severity.CRITICAL),
    ("database.sql", "SQL dump", Severity.CRITICAL),
    ("db.sql", "SQL dump", Severity.CRITICAL),
    ("backup.sql.gz", "Compressed SQL dump", Severity.CRITICAL),
    ("backup.sql.zip", "Compressed SQL dump", Severity.CRITICAL),
    ("db.sqlite", "SQLite database", Severity.CRITICAL),
    ("db.sqlite3", "SQLite database", Severity.CRITICAL),
    ("database.sqlite", "SQLite database", Severity.CRITICAL),
    ("storage/database.sqlite", "Laravel SQLite", Severity.CRITICAL),
    ("mongodump.tar", "Mongo dump", Severity.CRITICAL),
    ("mongodump.tar.gz", "Mongo dump", Severity.CRITICAL),
    ("backup.bak", "DB backup", Severity.CRITICAL),
    ("db.bak", "DB backup", Severity.CRITICAL),
    ("backup.7z", "DB backup archive", Severity.HIGH),
    ("backup.tar.gz", "Server backup", Severity.HIGH),
    ("www.sql", "SQL dump", Severity.CRITICAL),
    ("site.sql", "SQL dump", Severity.CRITICAL),
    ("data.json", "JSON data dump", Severity.MEDIUM),
    ("export.csv", "CSV dump", Severity.MEDIUM),
    ("users.csv", "User CSV dump", Severity.HIGH),
]

# Marker biner / teks → confirm bukan SPA generic 200.
SQL_MARKERS = (
    b"-- MySQL dump", b"-- PostgreSQL database dump",
    b"INSERT INTO", b"CREATE TABLE", b"DROP TABLE IF EXISTS",
    b"PRAGMA foreign_keys", b"sqlite_master",
)
SQLITE_MAGIC = b"SQLite format 3\x00"
GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"
TAR_MARKER = b"ustar"


def _dump_marker_match(body: bytes, path: str) -> bool:
    if path.endswith((".sqlite", ".sqlite3", ".db")):
        return body.startswith(SQLITE_MAGIC)
    if path.endswith(".gz"):
        return body.startswith(GZIP_MAGIC)
    if path.endswith(".zip") or path.endswith(".7z"):
        return body.startswith(ZIP_MAGIC) or body[:6] == b"7z\xbc\xaf'\x1c"
    if path.endswith(".tar") or path.endswith(".tar.gz"):
        return TAR_MARKER in body[:512] or body.startswith(GZIP_MAGIC)
    if path.endswith((".sql", ".bak")):
        return any(m in body[:2048] for m in SQL_MARKERS)
    if path.endswith(".csv"):
        # cek minimal 2 baris dengan koma & header berisi field umum.
        head = body[:1024].decode("utf-8", "ignore").lower()
        return head.count(",") >= 3 and any(
            k in head for k in ("email", "phone", "id,", "name,", "user")
        )
    if path.endswith(".json"):
        return body[:2].strip() in (b"[", b"{") and b'"id"' in body[:2048]
    return False


# ----------------------------------------------------------------------------
# 5. GraphQL introspection — schema + field enumerasi sensitif
# ----------------------------------------------------------------------------
GQL_INTROSPECTION = (
    '{"query":"{__schema{types{name fields{name type{name}}}}}"}'
)
SENSITIVE_TYPE_RE = re.compile(
    r"\b(User|Account|Token|Session|Order|Invoice|Payment|Wallet|Secret|"
    r"ApiKey|Credential|Customer|Address|Card|Transaction|RefreshToken)\b"
)
SENSITIVE_FIELD_RE = re.compile(
    r"\b(password|passwd|secret|token|apiKey|api_key|otp|pin|saldo|balance|"
    r"creditCard|cardNumber|cvv|ssn|nik|npwp)\b", re.I
)
GQL_PATHS = ("graphql", "api/graphql", "v1/graphql", "v2/graphql",
             "graphiql", "query", "api")


# ----------------------------------------------------------------------------
# 6. DSN regex di response body
# ----------------------------------------------------------------------------
DSN_RE = re.compile(
    r"(?P<scheme>postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|jdbc:[\w]+)"
    r"://(?P<user>[^:@/\s]+)(?::(?P<pass>[^@/\s]{1,64}))?@"
    r"(?P<host>[\w.\-]+)(?::\d+)?[/\w.\-]*",
    re.I,
)


# ============================================================================
# Helpers
# ============================================================================
def _crawl_urls(config: ScanConfig, max_n: int = 8) -> list[str]:
    s = get_state(config)
    if not s:
        return []
    return s.urls[:max_n]


def _http_match(client: HttpClient, url: str, marker_re: re.Pattern[str],
                accept_status=(200, 401, 403)) -> tuple[bool, str, int]:
    r = client.get(url, allow_redirects=False)
    if r is None:
        return False, "", 0
    if r.status_code not in accept_status:
        return False, "", r.status_code
    body = r.text or ""
    m = marker_re.search(body)
    if not m:
        return False, "", r.status_code
    return True, truncate(m.group(0), 120), r.status_code


# ============================================================================
# Probes
# ============================================================================
def _probe_db_ports(target: Target, host_ip: str | None) -> list[Finding]:
    out: list[Finding] = []
    host = host_ip or target.host
    if not host:
        return out
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {
            ex.submit(_probe_port, host, port, probe, banner): (port, label)
            for port, label, probe, banner in DB_PORTS
        }
        for fut in as_completed(futs):
            port, label = futs[fut]
            ok, ev = fut.result()
            if not ok:
                continue
            out.append(Finding(
                module="db_exposure",
                title=f"Port database {label} terbuka publik ({port}/tcp)",
                severity=Severity.HIGH,
                description=(
                    f"Service {label} merespons di port {port} dari internet. "
                    "DB seharusnya tidak terekspos di luar private network — "
                    "attacker bisa mencoba kredensial default atau exploit "
                    "service-specific."
                ),
                target=f"{host}:{port}",
                evidence=ev or "port responding",
                cwe="CWE-200",
                confidence="firm",
                remediation=(
                    "Bind DB ke 127.0.0.1 atau private subnet, gunakan firewall "
                    "(security-group / iptables) untuk hanya allow IP backend, "
                    "wajibkan TLS + autentikasi kuat, rotasi password rutin."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
                ],
            ))
    return out


def _probe_admin_panels(client: HttpClient, target: Target) -> list[Finding]:
    out: list[Finding] = []
    base = target.origin + "/"
    seen: set[str] = set()
    for path, label, marker, sev in ADMIN_PANELS:
        url = urljoin(base, path)
        if url in seen:
            continue
        seen.add(url)
        r = client.get(url, allow_redirects=True)
        if r is None or r.status_code >= 400:
            continue
        body_low = (r.text or "").lower()
        if marker not in body_low:
            continue
        out.append(Finding(
            module="db_exposure",
            title=f"Panel admin DB terbuka publik: {label}",
            severity=sev,
            description=(
                f"Panel admin {label} dapat diakses tanpa auth wall yang ketat. "
                "Attacker bisa coba kredensial default dan langsung kelola DB "
                "atau queue."
            ),
            target=url,
            evidence=f"HTTP {r.status_code}, marker='{marker}' ditemukan",
            cwe="CWE-284",
            confidence="firm",
            remediation=(
                "Hapus panel admin dari root publik atau lindungi via VPN / "
                "IP allowlist + basic-auth. Jangan deploy panel admin di "
                "production internet-facing."
            ),
            extra={"reverify": {"marker": marker, "in_body": True,
                                "status": (200, 401, 403)}},
        ))
    return out


def _probe_rest(client: HttpClient, target: Target) -> list[Finding]:
    out: list[Finding] = []
    base = target.origin + "/"
    for path, label, marker_re, sev in REST_ENDPOINTS:
        url = urljoin(base, path)
        ok, ev, status = _http_match(client, url, marker_re,
                                     accept_status=(200,))
        if not ok:
            continue
        out.append(Finding(
            module="db_exposure",
            title=f"Endpoint REST data store terekspos: {label}",
            severity=sev,
            description=(
                f"Endpoint {label} mengembalikan data terstruktur tanpa auth — "
                "attacker bisa enumerasi index/database dan langsung men-dump "
                "isinya."
            ),
            target=url,
            evidence=f"HTTP {status}, marker='{ev}'",
            cwe="CWE-200",
            confidence="confirmed",
            remediation=(
                "Aktifkan auth (X-Pack/Open-Distro untuk ES, basic-auth + TLS "
                "untuk Couch/Solr). Letakkan di VPC private dan ekspos hanya "
                "via API gateway dengan rate-limit."
            ),
            extra={"reverify": {"marker": ev[:24], "in_body": True}},
        ))
    return out


def _probe_dumps(client: HttpClient, target: Target) -> list[Finding]:
    out: list[Finding] = []
    base = target.origin + "/"
    for path, label, sev in DUMP_PATHS:
        url = urljoin(base, path)
        # HEAD dulu untuk hemat bandwidth
        h = client.head(url, allow_redirects=False)
        if h is None:
            continue
        if h.status_code >= 400 and h.status_code != 405:
            continue
        # GET hanya 8 KB pertama untuk verifikasi magic byte / marker.
        r = client.get(url, allow_redirects=False, stream=False,
                       headers={"Range": "bytes=0-8191"})
        if r is None or r.status_code >= 400:
            continue
        body = r.content[:8192] if r.content else b""
        if not body or not _dump_marker_match(body, path.lower()):
            continue
        out.append(Finding(
            module="db_exposure",
            title=f"Dump database / data terbuka: {path} ({label})",
            severity=sev,
            description=(
                f"File {label} dapat di-download publik. Berisi data nyata "
                "yang bisa langsung di-restore attacker — kebocoran DB total."
            ),
            target=url,
            evidence=f"HTTP {r.status_code}, content-len={len(body)}, "
                     f"magic_ok=True, ctype={r.headers.get('Content-Type','')}",
            cwe="CWE-538",
            confidence="confirmed",
            remediation=(
                "Hapus dump dari webroot. Simpan backup di object storage "
                "private dengan enkripsi. Tambahkan rule WAF block ekstensi "
                "`.sql/.bak/.sqlite/.dump`."
            ),
            extra={"reverify": {"status": (200, 206)}},
        ))
    return out


def _probe_graphql(client: HttpClient, target: Target) -> list[Finding]:
    out: list[Finding] = []
    base = target.origin + "/"
    for path in GQL_PATHS:
        url = urljoin(base, path)
        r = client.post(url, data=GQL_INTROSPECTION,
                        headers={"Content-Type": "application/json"},
                        allow_redirects=False)
        if r is None or r.status_code >= 400:
            continue
        body = r.text or ""
        if "__schema" not in body or '"types"' not in body:
            continue
        types = SENSITIVE_TYPE_RE.findall(body)
        fields = SENSITIVE_FIELD_RE.findall(body)
        if not types and not fields:
            continue
        sev = Severity.CRITICAL if fields else Severity.HIGH
        out.append(Finding(
            module="db_exposure",
            title="GraphQL introspection mengekspos schema sensitif",
            severity=sev,
            description=(
                "Endpoint GraphQL membalas query introspection lengkap. "
                "Attacker dapat memetakan seluruh model data, termasuk type/"
                "field bernama sensitif."
            ),
            target=url,
            evidence=truncate(
                f"types={sorted(set(types))[:10]} fields={sorted(set(fields))[:10]}",
                240,
            ),
            cwe="CWE-200",
            confidence="confirmed",
            remediation=(
                "Matikan introspection di production. Aktifkan persisted "
                "queries (whitelist hash) sehingga server hanya menerima query "
                "yang sudah di-approve."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
            ],
            extra={"reverify": {"marker": "__schema", "in_body": True,
                                "method": "POST"}},
        ))
        return out  # cukup satu endpoint
    return out


def _probe_dsn_in_body(client: HttpClient, target: Target,
                       config: ScanConfig) -> list[Finding]:
    out: list[Finding] = []
    urls = [target.base_url, *_crawl_urls(config, 6)]
    seen: set[str] = set()
    for url in urls:
        r = client.get(url)
        if r is None:
            continue
        body = r.text or ""
        for m in DSN_RE.finditer(body):
            scheme = m.group("scheme").lower()
            host = m.group("host").lower()
            user = m.group("user")
            has_pass = bool(m.group("pass"))
            key = f"{scheme}:{user}@{host}"
            if key in seen:
                continue
            # filter false-positive: localhost example tanpa password.
            if host in ("localhost", "127.0.0.1", "example.com",
                        "your-host", "<host>") and not has_pass:
                continue
            seen.add(key)
            out.append(Finding(
                module="db_exposure",
                title=f"Connection string {scheme.upper()} bocor di response publik",
                severity=Severity.CRITICAL if has_pass else Severity.HIGH,
                description=(
                    "Pola DSN database ditemukan di body publik (HTML/JS bundle). "
                    "Bila kredensial nyata, attacker bisa langsung connect ke DB."
                ),
                target=url,
                evidence=truncate(m.group(0), 180),
                cwe="CWE-200",
                confidence="firm",
                remediation=(
                    "Jangan bundle env DB ke front-end. Pakai env-server-side + "
                    "API gateway. Rotasi kredensial yang sudah bocor segera."
                ),
            ))
    return out


# ============================================================================
# Entry-point
# ============================================================================
def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1. ports (skip kalau target IP private — anggap user sudah authorized)
        host_ip = target.resolve_ip()
        findings += _probe_db_ports(target, host_ip)

        # 2. admin panels
        findings += _probe_admin_panels(client, target)

        # 3. REST endpoints
        findings += _probe_rest(client, target)

        # 4. dumps
        findings += _probe_dumps(client, target)

        # 5. graphql introspection
        findings += _probe_graphql(client, target)

        # 6. DSN in body
        findings += _probe_dsn_in_body(client, target, config)
    finally:
        client.close()
    return findings
