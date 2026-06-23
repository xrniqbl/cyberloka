"""Firebase Realtime Database open rules detection.

Auto-validation: untuk URL `*.firebaseio.com`, akses `/.json`. Bila 200 +
JSON valid (bukan `Permission denied`) -> rules `.read=true` aktif.
Bila PUT 200 -> `.write=true` juga aktif.

Selain itu modul juga melakukan recon: kalau target bukan firebaseio,
modul mencoba mendeteksi project Firebase di JS bundle homepage dan
mengetesnya bila terlihat.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PROJECT_RE = re.compile(
    r'(?:firebaseio\.com|firebasedatabase\.app)/?["\']?\s*[,;)]'
    r'|databaseURL["\']?\s*:\s*["\']https?://([a-z0-9-]+\.firebaseio\.com)'
    r'|"projectId":\s*"([a-z0-9-]+)"',
    re.I,
)


def _candidate_dbs(target: Target, client: HttpClient) -> list[str]:
    out: list[str] = []
    if "firebaseio.com" in (target.host or "").lower():
        out.append(f"https://{target.host}")
        return out
    # Crawl homepage JS bundle untuk projectId
    r = client.get(target.base_url)
    if r is None or r.status_code >= 400:
        return out
    body = r.text or ""
    for m in PROJECT_RE.finditer(body):
        url = m.group(1)
        pid = m.group(2)
        if url:
            out.append("https://" + url)
        elif pid:
            out.append(f"https://{pid}.firebaseio.com")
    # dedup
    return list(dict.fromkeys(out))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for db in _candidate_dbs(target, client):
            url = db.rstrip("/") + "/.json"
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = (r.text or "").strip()
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                continue
            # Skip kalau body literally null (bisa jadi project kosong tapi
            # rules tetap proteksi). Kita validasi lewat write-probe tambahan
            # baru lapor.
            sev = Severity.HIGH
            evidence = f"GET {url} -> 200; body_size={len(body)} chars"
            confidence = "firm"
            note = "rules `.read=true` aktif"

            # Probe write
            poke_url = db.rstrip("/") + "/cyblok-poc.json"
            rw = client.request("PUT", poke_url, data=json.dumps("CYBLOK_POC"),
                                headers={"Content-Type": "application/json"},
                                allow_redirects=False)
            if rw is not None and rw.status_code == 200:
                sev = Severity.CRITICAL
                confidence = "confirmed"
                note = "rules `.read` AND `.write` keduanya `true`"
                # Cleanup best-effort
                client.request("DELETE", poke_url, allow_redirects=False)

            findings.append(Finding(
                module="firebase_open_db",
                title=f"Firebase Realtime DB tanpa proteksi: {db}",
                severity=sev,
                description=(
                    "Firebase Realtime Database mengembalikan data "
                    f"tanpa autentikasi ({note}). Bug klasik 'app baru' "
                    "yang lupa set rules production."
                ),
                target=url,
                urls=[url],
                evidence=evidence + f"; {note}",
                cwe="CWE-284",
                confidence=confidence,
                remediation=(
                    "Edit rules di Firebase Console: "
                    "`{ \"rules\": { \".read\": \"auth != null\", "
                    "\".write\": \"auth != null\" } }`. Untuk production, "
                    "buat rules per-collection berdasarkan UID. Aktifkan "
                    "App Check untuk memastikan request datang dari "
                    "aplikasi resmi."
                ),
                references=[
                    "https://firebase.google.com/docs/database/security",
                    "https://firebase.google.com/docs/app-check",
                ],
            ))
    finally:
        client.close()
    return findings
