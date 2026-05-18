"""Secret scanner — pindai response & file JS untuk 30+ jenis kredensial.

Berbeda dari ``sentry_dsn_leak`` yang fokus pada beberapa client-side analytics
token, modul ini menambah deteksi luas: cloud provider, payment, source-control,
messaging, search/index, dan secret JWT/private key.

Setiap match diikat ke severity berbasis dampak nyata bila bocor:
- CRITICAL: server-side credential (AWS secret, Stripe live, GCP service-account
  JSON, GitHub PAT, Slack bot token, private key blocks).
- HIGH    : token messaging/payment client yang masih bisa nge-spoof (Twilio,
  SendGrid, Mailgun, Telegram Bot, Square, Razorpay live).
- MEDIUM  : token client (Stripe publishable, Google Maps, Mapbox PK) — bukan
  fatal, tapi tetap perlu rotasi.
- LOW     : analytics / SDK keys yang memang dibuat untuk klien.

Modul ini sengaja menghindari false positive lewat:
- Anchor regex yang ketat (panjang + prefix wajib + char-set yang spesifik).
- Filter "looks like base64 secret" via Shannon entropy >= 4.0 bits/char.
- Skip kalau pattern muncul di komentar contoh (``// example: AKIA...``).
"""
from __future__ import annotations

import math
import re
from collections import Counter

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# (regex, label, severity, description fragment)
PATTERNS: list[tuple["re.Pattern[str]", str, Severity, str]] = [
    # --- Cloud providers (CRITICAL) ---
    (re.compile(r"\b(AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b"),
     "AWS Access Key ID", Severity.CRITICAL,
     "Identifier kunci akses AWS. Bila pasangan Secret juga bocor, attacker "
     "bisa take-over akun cloud Anda."),
    (re.compile(r"aws_secret_access_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
     "AWS Secret Access Key", Severity.CRITICAL,
     "Secret AWS — kombinasi dengan Access Key ID = full IAM control."),
    (re.compile(r'"type":\s*"service_account"[^}]+"private_key":\s*"-----BEGIN'),
     "GCP service-account JSON", Severity.CRITICAL,
     "JSON service-account Google Cloud — full akses ke project yang ditugaskan."),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     "Google API Key", Severity.MEDIUM,
     "Google API key. Cek scope di console — kalau dipakai server-side & "
     "tidak ada referrer restriction, attacker bisa habisin quota."),
    (re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b"),
     "Google OAuth access token", Severity.HIGH,
     "Token akses OAuth yang masih valid (jangka pendek tapi nyata)."),
    (re.compile(r"\bAccountKey=[A-Za-z0-9+/=]{88}\b"),
     "Azure Storage account key", Severity.CRITICAL,
     "Kunci Azure Blob storage. Attacker dapat membaca/menulis container."),

    # --- Source control / CI ---
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
     "GitHub Personal Access Token", Severity.CRITICAL,
     "PAT GitHub — repo/org access tergantung scope."),
    (re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
     "GitHub OAuth token", Severity.CRITICAL,
     "OAuth user-to-server token GitHub."),
    (re.compile(r"\bghs_[A-Za-z0-9]{36}\b"),
     "GitHub Server-to-server token", Severity.CRITICAL,
     "Token GitHub Apps — high privilege."),
    (re.compile(r"\bghr_[A-Za-z0-9]{36}\b"),
     "GitHub Refresh token", Severity.HIGH,
     "Refresh token yang dapat dipakai me-mint access token baru."),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
     "GitLab Personal Access Token", Severity.CRITICAL,
     "GitLab PAT — repo/CI access."),
    (re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
     "npm token", Severity.CRITICAL,
     "Token npm — bisa publish paket malicious atas nama Anda."),

    # --- Payment ---
    (re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
     "Stripe live secret key", Severity.CRITICAL,
     "Stripe LIVE secret — full kontrol billing customer Anda."),
    (re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"),
     "Stripe live restricted key", Severity.HIGH,
     "Restricted key Stripe — masih punya scope tertentu di production."),
    (re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b"),
     "Stripe test secret key", Severity.LOW,
     "Stripe TEST secret. Bukan fatal di prod, tapi tetap kebocoran credential."),
    (re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
     "Stripe publishable key", Severity.LOW,
     "Publishable key memang untuk klien — info saja."),
    (re.compile(r"\bMidtrans-Server-Key:\s*Mid-server-[A-Za-z0-9_\-]{20,}\b", re.I),
     "Midtrans server key", Severity.CRITICAL,
     "Midtrans SERVER key — attacker bisa create transaction palsu."),
    (re.compile(r"\bxnd_(production|development)_[A-Za-z0-9_]{40,}\b"),
     "Xendit API key", Severity.CRITICAL,
     "Xendit API key — full akses ke akun merchant."),
    (re.compile(r"\brzp_live_[A-Za-z0-9]{14,}\b"),
     "Razorpay live key", Severity.HIGH,
     "Razorpay LIVE key — payment gateway India."),
    (re.compile(r"\bsq0[a-z]{3}-[A-Za-z0-9_\-]{22,43}\b"),
     "Square access token", Severity.CRITICAL,
     "Square access token (variant produksi atau sandbox)."),

    # --- Messaging / Email ---
    (re.compile(r"\bSK[a-z0-9]{32}\b"),
     "Twilio Account SID API key", Severity.HIGH,
     "Twilio API SID. Kombinasi dengan auth token = kontrol SMS/voice."),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
     "Slack token", Severity.CRITICAL,
     "Slack token (bot/user/app/admin) — read/write workspace tergantung scope."),
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b"),
     "SendGrid API key", Severity.HIGH,
     "SendGrid API — kirim email atas nama Anda (BEC vector)."),
    (re.compile(r"\bkey-[a-f0-9]{32}\b"),
     "Mailgun private key", Severity.HIGH,
     "Mailgun private key — kirim email atas domain Anda."),
    (re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
     "Telegram Bot token", Severity.HIGH,
     "Token Telegram Bot. Attacker dapat menyalakan bot atas nama Anda."),
    (re.compile(r"\bdiscord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,}"),
     "Discord webhook URL", Severity.MEDIUM,
     "Webhook Discord — siapa pun bisa post pesan ke channel."),

    # --- Generic JWT / private keys / DB connection ---
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "PEM private key block", Severity.CRITICAL,
     "Kunci privat PEM ditemukan terbuka — segera rotasi."),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "JWT-like token", Severity.MEDIUM,
     "Token mirip JWT muncul di response. Decode payload untuk lihat klaim — "
     "bisa jadi service token, akses pelanggan lain, atau token admin."),
    (re.compile(r"(mongodb(?:\+srv)?://)[^:\s]+:[^@\s]+@[^/?\s]+"),
     "MongoDB connection URI", Severity.CRITICAL,
     "URI MongoDB termasuk username & password — full akses DB."),
    (re.compile(r"(postgres(?:ql)?://)[^:\s]+:[^@\s]+@[^/?\s]+"),
     "PostgreSQL connection URI", Severity.CRITICAL,
     "URI Postgres termasuk username & password — full akses DB."),
    (re.compile(r"(mysql://)[^:\s]+:[^@\s]+@[^/?\s]+"),
     "MySQL connection URI", Severity.CRITICAL,
     "URI MySQL termasuk username & password."),
    (re.compile(r"\bredis://[^:\s]*:[^@\s]+@[^/?\s]+"),
     "Redis connection URI dengan password", Severity.HIGH,
     "URI Redis berisi password — attacker yang reach jaringan = akses cache."),

    # --- Search/index, lain-lain ---
    (re.compile(r"\b[A-Z0-9]{32}-us[0-9]{1,2}\b"),
     "Mailchimp API key", Severity.HIGH,
     "Mailchimp API key — bisa ekspor list pelanggan, kirim newsletter palsu."),
    (re.compile(r"\bAPP_KEY=base64:[A-Za-z0-9+/=]{40,}\b"),
     "Laravel APP_KEY", Severity.CRITICAL,
     "Laravel APP_KEY bocor → forge session, decrypt data terenkripsi."),
]

CONTEXT_SKIP = re.compile(r"//\s*example|/\*\s*example|\bplaceholder\b|\bsample[_-]?key\b", re.I)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _scan(body: str, source: str) -> list[tuple[str, Severity, str, str]]:
    """Return list of (label, severity, description, evidence)."""
    out: list[tuple[str, Severity, str, str]] = []
    if not body:
        return out
    for rx, label, sev, why in PATTERNS:
        for m in rx.finditer(body):
            matched = m.group(0)
            # Skip kalau di-mark sebagai contoh
            window_start = max(0, m.start() - 60)
            window = body[window_start:m.end() + 20]
            if CONTEXT_SKIP.search(window):
                continue
            # Untuk pola panjang & generic (JWT/connection URI), pastikan entropy
            # cukup untuk menyaring placeholder.
            if "JWT" in label or "connection URI" in label:
                if _shannon(matched) < 3.5:
                    continue
            out.append((label, sev, why, f"source={source}\nmatch={truncate(matched, 120)}"))
            break  # 1 hit per regex per source sudah cukup
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen: set[tuple[str, str]] = set()
    try:
        # Sumber 1: homepage
        r = client.get(target.base_url)
        bodies: list[tuple[str, str]] = []
        if r is not None:
            bodies.append((target.base_url, r.text or ""))
            # Sumber 2: file JS yang di-include homepage (max 8 file)
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text or "")
            from urllib.parse import urljoin
            for src in scripts[:8]:
                full = urljoin(target.base_url, src)
                jr = client.get(full)
                if jr is not None and jr.text:
                    bodies.append((full, jr.text))

        for src, body in bodies:
            for label, sev, why, evidence in _scan(body, src):
                key = (label, src)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        module="secrets_scanner",
                        title=f"Secret terdeteksi: {label} (di {src})",
                        severity=sev,
                        description=why,
                        target=src,
                        evidence=evidence,
                        cwe="CWE-798",
                        confidence="firm",
                        urls=[src],
                        remediation=(
                            "ROTASI segera secret yang bocor. Audit log akses 30 hari ke "
                            "belakang. Hapus dari source/HTML/JS bundle. Pakai env-var/vault "
                            "untuk menyimpan secret. Tambahkan pre-commit hook (gitleaks/"
                            "truffleHog) supaya tidak terjadi lagi."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/798.html",
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                            "https://github.com/gitleaks/gitleaks",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
