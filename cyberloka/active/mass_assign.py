"""Mass Assignment heuristic.

Strategi non-destruktif:
- Untuk endpoint POST/PATCH/PUT yang menerima JSON, kirim payload dengan
  field tambahan yang umum berbahaya (`isAdmin`, `role`, `is_staff`, `verified`,
  `balance`, `creditLimit`).
- Bandingkan response dengan request normal: bila status 200 dan tidak ada
  validasi error, ada indikasi server menerima field tambahan.

Tidak melakukan login auto & tidak menulis ke database production -- hanya
mengirim JSON probe yang sama dengan field "ekstra" untuk lihat apakah
server reject atau silently accept.

Catatan: ini benar-benar TENTATIVE. Hasil harus diverifikasi manual dengan
akun test.
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

DANGEROUS_FIELDS = {
    "isAdmin": True,
    "is_admin": True,
    "admin": True,
    "role": "admin",
    "roles": ["admin"],
    "is_staff": True,
    "verified": True,
    "isVerified": True,
    "approved": True,
    "balance": 999999,
    "saldo": 999999,
    "creditLimit": 999999,
    "is_premium": True,
    "isPremium": True,
}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return findings

    state_changing = [
        ep for ep in getattr(discovered, "endpoints", [])
        if ep.method.upper() in ("POST", "PATCH", "PUT") and ep.params
    ]
    if not state_changing:
        return findings

    client = HttpClient(config)
    try:
        for ep in state_changing[:8]:
            # request normal: kirim JSON dengan nilai dummy untuk field yang dideklarasi form
            normal_body = {f: "x" for f in ep.params}
            normal_resp = client.post(
                ep.url,
                json=normal_body,
                headers={"Content-Type": "application/json"},
            )
            if normal_resp is None:
                continue
            normal_status = normal_resp.status_code

            # request "polluted": tambahkan field berbahaya
            poll_body = dict(normal_body)
            poll_body.update(DANGEROUS_FIELDS)
            poll_resp = client.post(
                ep.url,
                json=poll_body,
                headers={"Content-Type": "application/json"},
            )
            if poll_resp is None:
                continue

            # heuristik: kalau normal & polluted sama-sama 2xx, dan response polluted
            # sama atau lebih besar (echoed back) -> kandidat mass assignment.
            if normal_status < 400 and poll_resp.status_code < 400:
                normal_len = len(normal_resp.text or "")
                poll_len = len(poll_resp.text or "")
                if poll_len >= normal_len:
                    findings.append(
                        Finding(
                            module="mass_assign",
                            title=f"Indikasi Mass Assignment pada {ep.url}",
                            severity=Severity.MEDIUM,
                            confidence="tentative",
                            description=(
                                "Server menerima request JSON dengan field privileged "
                                "tambahan (mis. isAdmin, role, balance) tanpa error. "
                                "Bila server bind langsung body ke model DB tanpa "
                                "filter, attacker bisa menaikkan privilege/saldo."
                            ),
                            target=ep.url,
                            evidence=(
                                f"normal_status={normal_status} normal_len={normal_len}\n"
                                f"polluted_status={poll_resp.status_code} polluted_len={poll_len}\n"
                                f"injected_fields={list(DANGEROUS_FIELDS)}"
                            ),
                            cwe="CWE-915",
                            remediation=(
                                "Pakai allow-list / DTO / strong parameters. Jangan bind "
                                "request body langsung ke model. Field seperti role, isAdmin, "
                                "balance harus ditolak oleh validator."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                            ],
                        )
                    )
    finally:
        client.close()
    return findings
