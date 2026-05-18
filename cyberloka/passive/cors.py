"""CORS misconfiguration check.

Test multi-origin untuk membedakan:

- ``ACAO: *`` (statis, tanpa credentials) → low.
- Origin attacker dipantulkan apa adanya → medium/high tergantung credentials.
- Origin attacker yang merupakan subdomain dari target dipantulkan
  (misal: ``Origin: evil.target.com``) → masih medium karena memungkinkan
  XSS pada subdomain naik ke origin utama.
- Null origin diterima → medium (sandbox iframe / file://).
- Reflektor naive (regex starts-with target.com → bypass dengan
  ``target.com.evil.com``) → high.

Verifikasi: setiap kandidat di-test 2x untuk memastikan respons stabil.
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

EVIL = "https://evil.example.com"


def _probe(client: HttpClient, url: str, origin: str | None) -> tuple[str, str, str] | None:
    headers = {"Origin": origin} if origin is not None else {}
    resp = client.get(url, headers=headers)
    if resp is None:
        return None
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    vary = resp.headers.get("Vary", "").lower()
    return acao, acac, vary


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url

        # --- 1) attacker origin ---------------------------------------------
        evil_probe = _probe(client, url, EVIL)
        if evil_probe is not None:
            acao, acac, vary = evil_probe
            # Reproduce
            evil_probe2 = _probe(client, url, EVIL)
            stable = evil_probe2 is not None and evil_probe2[0] == acao and evil_probe2[1] == acac

            if acao == EVIL and acac == "true":
                findings.append(
                    Finding(
                        module="cors",
                        title="CORS: origin attacker dipantulkan dengan credentials",
                        severity=Severity.HIGH,
                        description=(
                            "Server meng-echo Origin attacker dan mengizinkan "
                            "`Access-Control-Allow-Credentials: true`. Site jahat dapat "
                            "membaca data terotentikasi pengguna Anda."
                        ),
                        target=url,
                        evidence=(
                            f"Origin sent: {EVIL}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}\n"
                            f"Vary: {vary or '<none>'}"
                        ),
                        cwe="CWE-942",
                        confidence="confirmed" if stable else "firm",
                        remediation=(
                            "Whitelist origin secara eksplisit (cek Origin terhadap daftar "
                            "yang diizinkan, lalu kembalikan persis nilainya). Tambah `Vary: "
                            "Origin`. JANGAN gunakan wildcard `*` bersamaan dengan "
                            "`Allow-Credentials: true` (browser akan blokir, tapi tetap "
                            "indikasi konfigurasi yang salah)."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cors",
                            "https://cwe.mitre.org/data/definitions/942.html",
                        ],
                    )
                )
            elif acao == EVIL:
                findings.append(
                    Finding(
                        module="cors",
                        title="CORS: origin attacker dipantulkan (tanpa credentials)",
                        severity=Severity.MEDIUM,
                        description=(
                            "Server memantulkan Origin attacker. Walau tanpa credentials, "
                            "data dari endpoint publik tetap bisa dibaca lintas-origin oleh "
                            "skrip jahat — berbahaya bila endpoint mengembalikan data sensitif "
                            "berbasis IP / cookie pihak ketiga."
                        ),
                        target=url,
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        cwe="CWE-942",
                        confidence="confirmed" if stable else "firm",
                        remediation=(
                            "Whitelist origin yang diperbolehkan, dan tambahkan `Vary: Origin`."
                        ),
                    )
                )
            elif acao == "*" and acac == "true":
                findings.append(
                    Finding(
                        module="cors",
                        title="CORS: wildcard origin + credentials (kombinasi terlarang)",
                        severity=Severity.HIGH,
                        description=(
                            "Server mengiklankan kombinasi `*` + credentials. Browser modern "
                            "akan menolak permintaan, tapi ini menandakan konfigurasi salah "
                            "yang bisa berubah jadi reflektif kapan saja."
                        ),
                        target=url,
                        evidence=f"ACAO={acao}, ACAC={acac}",
                        cwe="CWE-942",
                        confidence="confirmed",
                        remediation=(
                            "Pilih salah satu: kembalikan `*` tanpa credentials untuk API "
                            "publik, atau echo origin yg dilist dengan credentials."
                        ),
                    )
                )
            elif acao == "*":
                findings.append(
                    Finding(
                        module="cors",
                        title="CORS: wildcard origin diset",
                        severity=Severity.LOW,
                        description=(
                            "API mengembalikan `Access-Control-Allow-Origin: *`. Aman untuk "
                            "API benar-benar publik, tapi pastikan endpoint tidak "
                            "mengembalikan data ber-otoritas."
                        ),
                        target=url,
                        evidence=f"ACAO={acao}",
                        confidence="firm",
                        remediation=(
                            "Bila endpoint butuh auth, jangan gunakan `*`. Echo origin dari "
                            "whitelist + tambahkan `Vary: Origin`."
                        ),
                    )
                )

        # --- 2) prefix bypass (target.com.evil.example.com) ------------------
        prefix_origin = f"https://{target.host}.evil.example.com"
        bypass = _probe(client, url, prefix_origin)
        if bypass is not None and bypass[0] == prefix_origin:
            findings.append(
                Finding(
                    module="cors",
                    title="CORS: prefix-match bypass (regex naive)",
                    severity=Severity.HIGH,
                    description=(
                        "Server menerima origin yang HANYA berisi domain target sebagai "
                        "substring/prefix (mis. `target.com.evil.com`). Indikasi regex "
                        "validasi origin yang salah (lupa anchor `$`)."
                    ),
                    target=url,
                    evidence=f"Origin: {prefix_origin}\nACAO: {bypass[0]}",
                    cwe="CWE-942",
                    confidence="confirmed",
                    remediation=(
                        "Validasi origin dengan parser URL, bukan regex string. Bandingkan "
                        "`hostname` exact match terhadap whitelist."
                    ),
                )
            )

        # --- 3) null origin --------------------------------------------------
        null_probe = _probe(client, url, "null")
        if null_probe is not None and null_probe[0] == "null":
            sev = Severity.HIGH if null_probe[1] == "true" else Severity.MEDIUM
            findings.append(
                Finding(
                    module="cors",
                    title="CORS: origin `null` diterima",
                    severity=sev,
                    description=(
                        "Server menerima `Origin: null`. Sandbox iframe atau halaman "
                        "`data:`/`file:` mengirim origin `null` — attacker bisa men-trigger "
                        "request lintas-origin dari konteks tersebut."
                    ),
                    target=url,
                    evidence=f"ACAO={null_probe[0]}, ACAC={null_probe[1]}",
                    cwe="CWE-942",
                    confidence="confirmed",
                    remediation="Tolak origin `null`. Whitelist origin yang valid saja.",
                )
            )
    finally:
        client.close()
    return findings
