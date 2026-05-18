"""Admin panel finder — bruteforce ~80 path admin tipikal.

Berbeda dari ``framework_default`` yang fokus di halaman default framework,
modul ini fokus pada path admin / management console yang sering dilewatkan:

- WordPress, Joomla, Drupal admin login.
- Spring Boot Actuator, JMX console, Tomcat manager, JBoss, WebLogic.
- DB admin tools: phpMyAdmin, Adminer, RockMongo, Mongo-Express,
  pgAdmin, Redis Commander.
- Container / Cluster: Portainer, Rancher, Kubernetes Dashboard, Consul UI.
- CI / monitoring: Jenkins, Grafana, Prometheus, Kibana, Elasticsearch HQ.
- Email / API: SwaggerUI, RabbitMQ management, Mailcatcher, MailHog.

Selain detect, modul juga menambahkan **soft-404 baseline** supaya situs
yang return 200 untuk semua path (catch-all) tidak menghasilkan false positive.

Output dilabeli per kategori:
  HIGH    -> panel kontrol penuh (Tomcat manager, Jenkins, K8s dashboard)
  MEDIUM  -> management UI lain (Adminer, Grafana, Mailhog)
  LOW     -> halaman login standar (login, ekspos minimum tapi target spam)
  INFO    -> 401/403 -> ada tapi terlindungi (recon catatan)
"""
from __future__ import annotations

import hashlib
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# (path, label, severity_when_found, description)
PATHS: list[tuple[str, str, Severity, str]] = [
    # WordPress
    ("/wp-admin/", "WordPress admin", Severity.LOW,
     "WordPress admin login terbuka. Kombinasi dengan brute-force user "
     "(/wp-json/wp/v2/users) sering jadi pintu masuk."),
    ("/wp-login.php", "WordPress login", Severity.LOW,
     "Halaman login WP klasik."),
    # Joomla / Drupal
    ("/administrator/", "Joomla admin", Severity.LOW,
     "Joomla admin login terbuka."),
    ("/user/login", "Drupal login", Severity.LOW, "Drupal user login."),

    # PHP DB tools (high impact)
    ("/phpmyadmin/", "phpMyAdmin", Severity.HIGH,
     "phpMyAdmin terbuka. Bila kredensial default / lemah = full DB access."),
    ("/pma/", "phpMyAdmin (alt)", Severity.HIGH,
     "phpMyAdmin di path alternatif."),
    ("/adminer.php", "Adminer", Severity.HIGH,
     "Adminer (alternatif phpMyAdmin) — siapa pun bisa coba kredensial DB."),
    ("/rockmongo/", "RockMongo", Severity.HIGH,
     "RockMongo MongoDB UI — sering dengan kredensial default admin/admin."),
    ("/mongo-express/", "Mongo Express", Severity.HIGH,
     "Mongo Express UI — basic auth admin/pass default."),
    ("/pgadmin/", "pgAdmin", Severity.HIGH,
     "pgAdmin Web UI."),

    # App server management
    ("/manager/html", "Tomcat Manager", Severity.HIGH,
     "Tomcat Manager UI — credential default tomcat/tomcat masih banyak. "
     "Kombinasi dengan WAR upload = RCE root."),
    ("/host-manager/html", "Tomcat Host Manager", Severity.HIGH,
     "Tomcat Host Manager."),
    ("/jmx-console/", "JBoss JMX Console", Severity.HIGH,
     "JBoss JMX console — RCE klasik via DeploymentScanner."),
    ("/web-console/", "JBoss Web Console", Severity.HIGH, "JBoss web console."),
    ("/wls-wsat/CoordinatorPortType", "WebLogic WSAT", Severity.HIGH,
     "WebLogic WSAT — CVE-2017-10271 deserialization."),
    ("/console/login/LoginForm.jsp", "WebLogic Console", Severity.HIGH,
     "WebLogic Admin Console."),

    # Spring Boot
    ("/actuator", "Spring Actuator", Severity.HIGH,
     "Spring Boot Actuator. /env, /heapdump, /trace = info disclosure besar; "
     "/jolokia = potensi RCE (Apache Camel)."),
    ("/actuator/env", "Spring Actuator /env", Severity.CRITICAL,
     "Spring /actuator/env membocorkan environment variables — termasuk DB "
     "credential, API key."),
    ("/actuator/heapdump", "Spring Actuator /heapdump", Severity.CRITICAL,
     "Spring /actuator/heapdump unduh heap memory — credential & token "
     "dapat di-extract dari heap."),

    # CI / monitoring
    ("/jenkins/", "Jenkins", Severity.HIGH,
     "Jenkins UI — anonymous read access masih banyak. Bila /script ada = RCE."),
    ("/jenkins/script", "Jenkins Script Console", Severity.CRITICAL,
     "Jenkins script console — Groovy execution = RCE root."),
    ("/grafana/", "Grafana", Severity.MEDIUM,
     "Grafana UI. Default login admin/admin sering belum diganti."),
    ("/prometheus/", "Prometheus", Severity.MEDIUM,
     "Prometheus UI — ekspos query tanpa auth, baca metric internal."),
    ("/kibana", "Kibana", Severity.MEDIUM,
     "Kibana UI. Tanpa auth = baca seluruh log Elasticsearch."),
    ("/_plugin/kibana", "Kibana (AWS ES)", Severity.MEDIUM,
     "Kibana di Amazon ES."),
    ("/elasticsearch/", "Elasticsearch HQ / head", Severity.HIGH,
     "Elasticsearch UI/proxy — query data tanpa auth."),
    ("/_cat/indices", "Elasticsearch direct", Severity.HIGH,
     "Endpoint Elasticsearch publik tanpa auth."),

    # Container / Cluster
    ("/portainer/", "Portainer", Severity.HIGH,
     "Portainer Docker UI. Default admin password bisa attacker set sendiri "
     "kalau install pertama belum diakses."),
    ("/rancher/", "Rancher", Severity.HIGH, "Rancher k8s UI."),
    ("/kubernetes-dashboard/", "K8s Dashboard", Severity.CRITICAL,
     "Kubernetes Dashboard — exec ke pod, baca semua secret."),
    ("/consul/ui/", "Consul UI", Severity.MEDIUM,
     "Consul service mesh UI. Tanpa auth = baca service catalog."),
    ("/etcd/", "etcd", Severity.HIGH, "etcd HTTP UI/proxy."),

    # API / Mail / Misc
    ("/swagger-ui.html", "Swagger UI (Spring)", Severity.MEDIUM,
     "Swagger UI public — peta lengkap API. Bukan vuln, tapi memudahkan "
     "attacker. Bila ada /actuator -> kombinasi berbahaya."),
    ("/swagger-ui/index.html", "Swagger UI", Severity.MEDIUM, "Swagger UI."),
    ("/api/swagger-ui/", "API Swagger UI", Severity.MEDIUM, "API Swagger UI."),
    ("/v3/api-docs", "OpenAPI v3 docs", Severity.MEDIUM,
     "OpenAPI/Swagger spec terbuka."),
    ("/api-docs", "OpenAPI docs", Severity.MEDIUM, "OpenAPI docs."),
    ("/rabbitmq/", "RabbitMQ Management", Severity.HIGH,
     "RabbitMQ Management UI — guest/guest default."),
    ("/mailhog/", "MailHog", Severity.LOW,
     "MailHog dev mailbox — kalau ekspos di prod, baca email transaksional."),
    ("/mailcatcher/", "MailCatcher", Severity.LOW, "MailCatcher dev mailbox."),

    # Generic admin paths
    ("/admin", "Generic /admin", Severity.LOW, "Path /admin generik."),
    ("/admin/", "Generic /admin/", Severity.LOW, "Path /admin/ generik."),
    ("/admin/login", "Generic /admin/login", Severity.LOW, "Halaman login admin."),
    ("/administrator/index.php", "Generic admin index", Severity.LOW, "Admin index generik."),
    ("/cms", "CMS path", Severity.LOW, "Path /cms."),
    ("/dashboard", "Generic /dashboard", Severity.LOW, "Path dashboard."),
    ("/controlpanel", "Control panel", Severity.LOW, "Halaman control panel."),
    ("/cpanel", "cPanel", Severity.LOW, "cPanel WHM."),
    ("/webmail", "Webmail", Severity.LOW, "Webmail interface."),
    ("/horde/", "Horde Webmail", Severity.LOW, "Horde webmail."),
    ("/roundcube/", "Roundcube", Severity.LOW, "Roundcube webmail."),

    # CI/CD lain
    ("/teamcity/", "TeamCity", Severity.MEDIUM, "TeamCity UI."),
    ("/bamboo/", "Bamboo", Severity.MEDIUM, "Atlassian Bamboo."),
    ("/sonar/", "SonarQube", Severity.MEDIUM, "SonarQube — kode review."),
    ("/nexus/", "Nexus Repo", Severity.MEDIUM, "Sonatype Nexus."),
    ("/gitlab/", "GitLab", Severity.LOW, "GitLab self-hosted UI."),

    # Storage / NAS
    ("/owncloud/", "ownCloud", Severity.LOW, "ownCloud login."),
    ("/nextcloud/", "Nextcloud", Severity.LOW, "Nextcloud login."),
    ("/seafile/", "Seafile", Severity.LOW, "Seafile login."),

    # Network device / IoT
    ("/login.cgi", "Generic login.cgi", Severity.LOW,
     "Path login.cgi tipikal IoT device."),
    ("/cgi-bin/luci", "OpenWRT LuCI", Severity.LOW, "OpenWRT LuCI router admin."),
]


def _baseline_404_hash(client: HttpClient, origin: str) -> str:
    """Probe path acak untuk dapat sidik jari soft-404."""
    probe = "/" + os.urandom(8).hex() + "-cyberloka-doesnotexist.html"
    r = client.get(urljoin(origin + "/", probe.lstrip("/")), allow_redirects=False)
    if r is None:
        return ""
    return hashlib.sha1((r.text or "").encode("utf-8", errors="ignore")).hexdigest()


def _check(client: HttpClient, origin: str, baseline_hash: str, path: str, label: str, sev: Severity, desc: str):
    url = urljoin(origin + "/", path.lstrip("/"))
    r = client.get(url, allow_redirects=False)
    if r is None:
        return None
    status = r.status_code
    if status in (401, 403):
        return ("protected", url, label, status, "")
    if status not in (200, 301, 302):
        return None
    body = r.text or ""
    body_hash = hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest()
    if baseline_hash and body_hash == baseline_hash:
        return None  # SPA catch-all, skip
    # Fingerprint sederhana per label supaya 200=OK generic tidak dianggap
    # panel yang bukan sebenarnya. Kita require salah satu kata kunci.
    keyword_hint = label.lower().split()[0]
    if keyword_hint in body.lower() or keyword_hint in (r.headers.get("Server", "") or "").lower():
        kind = "found"
    elif status in (301, 302):
        kind = "redirect"
    else:
        kind = "exists"
    return (kind, url, label, status, truncate(body, 240), sev, desc)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.authorized:
        return findings
    client = HttpClient(config)
    try:
        baseline_hash = _baseline_404_hash(client, target.origin)
        with ThreadPoolExecutor(max_workers=min(20, max(1, config.threads * 2))) as ex:
            futures = [
                ex.submit(_check, client, target.origin, baseline_hash, p, l, s, d)
                for p, l, s, d in PATHS
            ]
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                kind = res[0]
                if kind == "protected":
                    _, url, label, status, _ = res
                    findings.append(
                        Finding(
                            module="admin_panel_finder",
                            title=f"Admin panel TERLINDUNGI: {label}",
                            severity=Severity.INFO,
                            description=(
                                f"Path {label} ada di server tapi server merespons "
                                f"HTTP {status} (auth wall). Bukan kerentanan langsung, "
                                "tapi catatan recon — attacker yang tahu kredensial / "
                                "vendor default credential bisa coba."
                            ),
                            target=url,
                            evidence=f"HTTP {status}",
                            confidence="firm",
                            urls=[url],
                            remediation=(
                                "Bila tidak diperlukan publik, batasi akses lewat IP "
                                "allow-list / VPN."
                            ),
                        )
                    )
                    continue
                _, url, label, status, body_snippet, sev, desc = res
                findings.append(
                    Finding(
                        module="admin_panel_finder",
                        title=f"Admin panel terbuka: {label} ({url})",
                        severity=sev,
                        description=desc,
                        target=url,
                        evidence=f"HTTP {status}\n\nbody snippet:\n{body_snippet}",
                        cwe="CWE-284",
                        confidence="firm",
                        urls=[url],
                        remediation=(
                            "Restriksi akses panel admin: IP allow-list (firewall/WAF), "
                            "VPN-only, atau hapus dari akses publik kalau tidak dipakai. "
                            "Wajib non-default credential, MFA, dan rate-limit login. "
                            "Subscribe ke advisory vendor untuk patch CVE management UI."
                        ),
                        references=[
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                            "https://cwe.mitre.org/data/definitions/284.html",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
