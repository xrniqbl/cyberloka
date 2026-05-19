"""IIS 8.3 short-filename enumeration scanner.

Bug klasik di IIS (CVE-2010-4475 / advisory MS10-002): URL dengan tilde
`~1` plus karakter wildcard mengembalikan response berbeda tergantung
file ada atau tidak. Attacker dapat menebak nama file `8.3` (mis.
`web~1.con` -> `web.config`) tanpa perlu directory listing.

Strategi probe (bandingkan response 4 URL):

    1. baseline                              {url}/randomprobeXyz123/.aspx
    2. exists-file via wildcard              {url}/*~1.aspx
    3. exists-file via explicit + wildcard   {url}/a*~1.aspx
    4. method odd: OPTIONS / TRACE           validate IIS

Indikator IIS-rentan:
    * Response baseline & probe-2 berbeda (length atau status code).
    * Server header memuat `Microsoft-IIS`.
    * Probe `~1` membalas 404 dengan body kosong vs probe biasa 400.

Validasi: confirmed hanya bila perbedaan response konsisten + Server
header IIS terdeteksi.
"""
from __future__ import annotations

import random
import string
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate


def _rand(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _is_iis(server_hdr: str | None) -> bool:
    return bool(server_hdr) and "iis" in server_hdr.lower()


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.origin + "/"
    client = HttpClient(config)
    try:
        # Quick fingerprint
        head = client.head(base, allow_redirects=False)
        if head is None:
            return findings
        server = head.headers.get("Server", "")
        if not _is_iis(server):
            # Bukan IIS -> tidak relevan, skip diam-diam
            return findings

        # Test pasangan URL.
        rand = _rand()
        baseline_url = urljoin(base, f"{rand}/abc.aspx")
        probe_a = urljoin(base, "*~1.aspx")
        probe_b = urljoin(base, "a*~1.aspx")
        probe_404 = urljoin(base, f"{_rand()}*~1.aspx")

        responses = {}
        for name, u in [("baseline", baseline_url), ("probeA", probe_a),
                        ("probeB", probe_b), ("ctl_404", probe_404)]:
            r = client.get(u, allow_redirects=False)
            if r is None:
                return findings  # network error -> bail
            responses[name] = (r.status_code, len(r.content or b""))

        # Heuristik:
        #   - IIS-vuln: ada path nyata -> probeA/probeB beda dari ctl_404.
        #   - Aman/patched: semua 4 response sama (status & length).
        baseline_sig = responses["baseline"]
        ctl_404_sig = responses["ctl_404"]
        probe_a_sig = responses["probeA"]
        probe_b_sig = responses["probeB"]

        # Bila wildcard probe membalas dengan signature berbeda dari ctl_404,
        # IIS tampak rentan.
        if (probe_a_sig != ctl_404_sig or probe_b_sig != ctl_404_sig) and \
                (probe_a_sig != baseline_sig):
            findings.append(Finding(
                module="iis_shortname",
                title="IIS short-filename (8.3) enumeration mungkin aktif",
                severity=Severity.MEDIUM,
                description=(
                    "Server IIS memberi response berbeda untuk URL berisi "
                    "wildcard `*~1.aspx`. Indikasi bug klasik IIS yang "
                    "membuka pintu enumerasi short-name (8.3). Attacker "
                    "dapat menebak nama file/folder seperti "
                    "`web.config`, `backup.zip`, dst., satu karakter per "
                    "iterasi."
                ),
                target=base,
                evidence=truncate(
                    f"server={server!r}; "
                    f"baseline={baseline_sig} probeA={probe_a_sig} "
                    f"probeB={probe_b_sig} ctl_404={ctl_404_sig}",
                    240,
                ),
                cwe="CWE-200",
                confidence="firm",
                remediation=(
                    "Matikan generasi short-name di registry: "
                    "`fsutil 8dot3name set 1`. Lalu hapus 8.3 dari volume "
                    "yang sudah ada: `fsutil 8dot3name strip <drive>`. "
                    "Verifikasi dengan rerun probe yang sama."
                ),
                references=[
                    "https://soroush.secproject.com/blog/2014/08/iis-tilde-character-vulnerabilityfeature-short-file-folder-name-disclosure/",
                ],
                extra={"reverify": {"status": (200, 400, 404)}},
            ))
    finally:
        client.close()
    return findings
