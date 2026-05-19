"""Apache Tomcat / JBoss / WildFly Manager dengan kredensial default.

Lebih dalam dari sekadar 'manager terbuka':
  1. Cek /manager/html, /host-manager/html, /jboss-app/, /admin-console/
  2. Coba kredensial paling umum (tomcat/tomcat, admin/admin, jboss/jboss).
  3. Validasi via (a) status 200 + body memuat 'Tomcat Web Application Manager'
     atau 'JBoss Management Console', dan (b) endpoint /manager/text/list
     mengembalikan daftar app yang terdeploy.

Tomcat manager = upload .war = RCE root. Mendeteksi ini = kritikal absolut.
"""
from __future__ import annotations

from base64 import b64encode
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

ENDPOINTS = (
    ("/manager/html", "Tomcat Manager HTML", b"Tomcat Web Application Manager"),
    ("/host-manager/html", "Tomcat Host Manager", b"Tomcat Virtual Host Manager"),
    ("/manager/text/list", "Tomcat Manager API", b"OK"),
    ("/admin-console/", "JBoss Admin Console", b"JBoss"),
    ("/jmx-console/", "JBoss JMX Console", b"JMX Agent View"),
    ("/console/", "WildFly Console", b"WildFly"),
)

CREDS: list[tuple[str, str]] = [
    ("tomcat", "tomcat"),
    ("tomcat", "s3cret"),
    ("admin", "admin"),
    ("admin", "tomcat"),
    ("admin", "password"),
    ("manager", "manager"),
    ("manager", "s3cret"),
    ("jboss", "jboss"),
    ("admin", "admin123"),
    ("root", "root"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        for path, label, marker in ENDPOINTS:
            url = urljoin(base, path.lstrip("/"))
            head = client.get(url, allow_redirects=False)
            if head is None:
                continue
            if head.status_code not in (401, 403):
                # Tidak Basic-Auth-protected - lewati (atau target bukan Tomcat)
                continue
            for u, p in CREDS[:6]:
                token = b64encode(f"{u}:{p}".encode("latin-1")).decode("ascii")
                r = client.get(url, headers={"Authorization": f"Basic {token}"}, allow_redirects=False)
                if r is None or r.status_code != 200:
                    continue
                body_bytes = r.content or b""
                if marker in body_bytes:
                    # Konfirmasi tambahan untuk Tomcat: hit /manager/text/list
                    extra_evidence = ""
                    list_url = urljoin(base, "manager/text/list")
                    r2 = client.get(list_url, headers={"Authorization": f"Basic {token}"})
                    if r2 is not None and r2.status_code == 200 and "OK" in (r2.text or ""):
                        apps = [
                            line for line in (r2.text or "").splitlines()
                            if ":" in line and not line.startswith("OK")
                        ]
                        extra_evidence = (
                            f"\nDeployed apps via /manager/text/list:\n"
                            + "\n".join(apps[:10])
                        )

                    findings.append(Finding(
                        module="tomcat_manager_default",
                        target=url,
                        title=f"{label} tertembus dengan default {u}/{p} (RCE setara root)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"{label} di {url} menerima kredensial default '{u}/{p}'. "
                            f"Modul memvalidasi otomatis dengan body marker '{marker.decode()}'."
                            + (
                                " Ditambah konfirmasi via /manager/text/list yang mengembalikan "
                                "daftar app terdeploy."
                                if extra_evidence else ""
                            )
                            + " Tomcat manager = attacker dapat upload file .war (web "
                            "application archive) yang berisi webshell, lalu eksekusi "
                            "perintah sebagai user Tomcat (sering = root). Ini setara "
                            "ROOT-equivalent access."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Credentials: {u}:{p}\n"
                            f"Marker found: '{marker.decode()}'\n"
                            f"Status: {r.status_code}"
                            + extra_evidence
                        ),
                        cwe="CWE-798",
                        confidence="confirmed",
                        urls=[url, list_url],
                        remediation=(
                            "1. SEGERA edit conf/tomcat-users.xml: ganti password atau hapus user.\n"
                            "2. Restrict akses /manager/* ke localhost saja (RemoteAddrValve).\n"
                            "3. Pertimbangkan hapus webapp manager total di production:\n"
                            "   `rm -rf $CATALINA_HOME/webapps/manager $CATALINA_HOME/webapps/host-manager`\n"
                            "4. Audit log akses untuk lihat apakah sudah ter-eksploitasi\n"
                            "   (cari .war upload yang mencurigakan di /webapps/)."
                        ),
                        references=[
                            "https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html",
                            "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
                        ],
                    ))
                    break  # cukup 1 finding per endpoint
    finally:
        client.close()
    return findings
