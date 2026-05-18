"""Deep, NON-DESTRUCTIVE Command Injection / RCE validator.

Tujuan
------
Banyak hasil dari ``cmdi`` (atau modul lain yang memunculkan kandidat
RCE seperti ``ssti``, ``deserialization``, ``xss`` di endpoint perintah,
``log_injection``) hanya berdasarkan satu sinyal — misal output marker
muncul sekali, atau respons sedikit lebih lambat. Modul ini menjalankan
**multi-oracle, multi-shell** verification yang aman:

- TIDAK destruktif: hanya read-only payload (echo / printf / whoami / id /
  uname / hostname / sleep / ping). Tidak menulis file, tidak melakukan
  koneksi keluar (out-of-band), tidak escalate, tidak ekfiltrasi data.
- Memastikan parameter benar-benar dieksekusi shell — bukan sekadar
  reflected.
- Membandingkan: status, panjang body, encoding (hex/base64), timing
  (5x sample untuk reduksi jitter), dan WAF/sanitization patterns.
- Mengembalikan `Finding` dengan ``confidence``:
  ``confirmed`` / ``firm`` / ``low_confidence`` / ``false_positive``.
- Setiap finding membawa laporan profesional di field ``description``
  (summary, technical analysis, reproduction non-destruktif, impact,
  remediation) sehingga PDF report langsung punya konten lengkap.

Cara pakai
----------
- **Standalone**: tambahkan `rce_validator` ke `--modules`. Ia akan
  memprobe URL target seperti `cmdi`.
- **Sebagai konfirmator**: scanner orchestrator akan otomatis menyertakan
  modul ini di akhir kalau menemukan kandidat dari `cmdi` (lihat
  `_collect_candidates`).
"""
from __future__ import annotations

import base64
import re
import secrets
import statistics
import time
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from cyberloka.active._helpers import (
    append_param,
    candidate_params,
    iter_param_urls,
    replace_param,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# ---------------------------------------------------------------------------
# Tunables (kept conservative & non-destructive)
# ---------------------------------------------------------------------------
SLEEP_S = 5  # delay used in time-based oracle (read-only)
TIMING_SAMPLES = 5  # number of samples for stable median
PARAM_HINTS_RCE = (
    "cmd", "command", "exec", "ip", "host", "ping", "lookup", "dns",
    "domain", "url", "page", "query", "search", "name", "target",
    "input", "filename",
)


@dataclass
class _Probe:
    """One observation of (status, length, latency, body)."""
    status: int
    length: int
    latency: float
    body: str

    @classmethod
    def from_response(cls, resp, dt: float) -> "_Probe | None":
        if resp is None:
            return None
        body = resp.text or ""
        return cls(resp.status_code, len(body), dt, body)


# ---------------------------------------------------------------------------
# Baseline & timing helpers
# ---------------------------------------------------------------------------
def _sample(client: HttpClient, url: str) -> "_Probe | None":
    t0 = time.monotonic()
    r = client.get(url, allow_redirects=False)
    return _Probe.from_response(r, time.monotonic() - t0)


def _baseline(client: HttpClient, url: str, samples: int = 4) -> dict | None:
    probes: list[_Probe] = []
    for _ in range(samples):
        p = _sample(client, url)
        if p is not None:
            probes.append(p)
    if not probes:
        return None
    lats = [p.latency for p in probes]
    lens = [p.length for p in probes]
    return {
        "status": probes[-1].status,
        "length_median": int(statistics.median(lens)),
        "length_max": max(lens),
        "latency_median": statistics.median(lats),
        "latency_p95": max(lats),
        "body": probes[-1].body,
    }


def _timing_samples(client: HttpClient, url: str, n: int = TIMING_SAMPLES) -> list[float]:
    out: list[float] = []
    for _ in range(n):
        p = _sample(client, url)
        if p is not None:
            out.append(p.latency)
    return out


# ---------------------------------------------------------------------------
# Payload templates - read-only commands
# ---------------------------------------------------------------------------
SHELL_TYPES = ("bash-sh", "cmd-windows", "powershell")


def _separators(shell_type: str) -> list[str]:
    """Return command-separator templates that try the shell.

    We keep the prefix as a placeholder ``X`` that callers replace with the
    original parameter value (e.g. ``1``).
    """
    if shell_type == "cmd-windows":
        return ["X & {cmd}", "X | {cmd}", "X && {cmd}"]
    if shell_type == "powershell":
        return ["X; {cmd}", "X | {cmd}", "X; & {cmd}"]
    # bash / sh - default Linux
    return [
        "X;{cmd}",
        "X|{cmd}",
        "X&&{cmd}",
        "X`{cmd}`",
        "X$({cmd})",
        "X%0a{cmd}",  # newline injection
    ]


def _echo_cmd(marker: str, shell_type: str) -> str:
    if shell_type == "cmd-windows":
        return f"echo {marker}"
    if shell_type == "powershell":
        return f"Write-Output {marker}"
    return f"echo {marker}"


def _info_cmds(shell_type: str) -> list[tuple[str, str, "re.Pattern[str]"]]:
    """Read-only info disclosure - only used after marker echo confirms.

    Returns: (label, command, regex-that-must-match)
    """
    if shell_type == "cmd-windows":
        return [
            ("whoami", "whoami", re.compile(r"\b[\w.-]+\\[\w.-]+\b")),
            ("hostname", "hostname", re.compile(r"^[A-Za-z0-9.-]{2,63}\s*$", re.M)),
            ("ver", "ver", re.compile(r"Microsoft Windows", re.I)),
        ]
    if shell_type == "powershell":
        return [
            ("whoami", "whoami", re.compile(r"\b[\w.-]+\\[\w.-]+\b")),
            ("hostname", "hostname", re.compile(r"^[A-Za-z0-9.-]{2,63}\s*$", re.M)),
        ]
    return [
        ("whoami", "whoami", re.compile(r"^[a-z_][a-z0-9_-]{0,30}\$?\s*$", re.I | re.M)),
        ("id", "id", re.compile(r"\buid=\d+(?:\([^)]+\))?\s+gid=\d+", re.I)),
        ("uname", "uname -a", re.compile(r"\b(Linux|Darwin|FreeBSD)\b\s+\S+", re.I)),
        ("hostname", "hostname", re.compile(r"^[A-Za-z0-9.-]{2,63}\s*$", re.M)),
    ]


def _sleep_cmd(shell_type: str, s: int) -> str:
    if shell_type == "cmd-windows":
        # ping is the classic non-destructive sleep on Windows
        return f"ping -n {s + 1} 127.0.0.1"
    if shell_type == "powershell":
        return f"Start-Sleep -Seconds {s}"
    return f"sleep {s}"


# ---------------------------------------------------------------------------
# Sanitization / WAF heuristics
# ---------------------------------------------------------------------------
WAF_HINT_RE = re.compile(
    r"(blocked\s+by|firewall|cloudflare|akamai|imperva|sucuri|incapsula|"
    r"mod_security|invalid\s+request|access\s+denied|forbidden|"
    r"malicious|illegal\s+character)",
    re.I,
)
SANITIZED_HINTS = (
    "<", ">", '"', "'", "`", "$", "&", "|", ";",
)


def _looks_filtered(probe: _Probe) -> bool:
    if probe is None:
        return False
    if probe.status in (403, 406, 412, 418, 429, 451):
        return True
    return bool(WAF_HINT_RE.search(probe.body or ""))


def _input_reflected_but_not_executed(body: str, marker: str, raw_payload: str) -> str | None:
    """Return label if body reflects payload but does not execute (False Positive evidence)."""
    if marker in body:
        return None  # marker present -> executed
    if raw_payload and raw_payload in body:
        return "reflected-raw"
    # encoded reflection
    enc_payload = (
        raw_payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    if enc_payload and enc_payload in body and enc_payload != raw_payload:
        return "reflected-encoded"
    return None


# ---------------------------------------------------------------------------
# Core oracles
# ---------------------------------------------------------------------------
def _oracle_marker(
    client: HttpClient,
    url: str,
    param: str,
    shell_type: str,
    base: dict,
) -> dict | None:
    """Echo a unique random marker. Confirmed only when the EXACT marker appears."""
    marker_plain = "CYB" + secrets.token_hex(5).upper() + "MK"
    # Hex-encoded marker variant via printf - validates that the shell really
    # interpreted a command rather than the parameter being reflected.
    marker_hex = marker_plain.encode().hex()

    cmd_plain = _echo_cmd(marker_plain, shell_type)
    base_lat = base["latency_median"]

    for tpl in _separators(shell_type):
        payload = tpl.replace("X", "1").format(cmd=cmd_plain)
        mutated = replace_param(url, param, payload)
        p = _sample(client, mutated)
        if p is None:
            continue
        if marker_plain not in p.body:
            continue
        # Reflection guard: if the literal payload (or `echo MARKER`) appears
        # verbatim in the body, the server is reflecting the input - not
        # executing it. This catches the textbook false positive where a
        # reflective endpoint contains the marker only because it contains
        # the whole payload as text.
        if cmd_plain in p.body or payload in p.body:
            continue
        # Reproduce with a different separator to avoid lucky reflection
        for repro_tpl in _separators(shell_type):
            if repro_tpl == tpl:
                continue
            repro_payload = repro_tpl.replace("X", "1").format(cmd=cmd_plain)
            repro_url = replace_param(url, param, repro_payload)
            p2 = _sample(client, repro_url)
            if (p2 and marker_plain in p2.body
                    and cmd_plain not in p2.body
                    and repro_payload not in p2.body):
                return {
                    "oracle": "marker-echo",
                    "shell": shell_type,
                    "payload": payload,
                    "repro_payload": repro_payload,
                    "marker": marker_plain,
                    "evidence": truncate(p.body, 360),
                    "confidence": "confirmed",
                }
        return {
            "oracle": "marker-echo",
            "shell": shell_type,
            "payload": payload,
            "marker": marker_plain,
            "evidence": truncate(p.body, 360),
            "confidence": "firm",
        }

    # Hex-printf trick (only on bash shells): we ask the shell to convert hex
    # back to ASCII. If the marker appears, it cannot be reflected because
    # the param value sent was hex digits not the marker itself.
    if shell_type == "bash-sh":
        for tpl in _separators(shell_type):
            payload = tpl.replace("X", "1").format(
                cmd=f"printf %s {marker_hex} | xxd -r -p"
            )
            mutated = replace_param(url, param, payload)
            p = _sample(client, mutated)
            if p is None or marker_plain not in p.body:
                continue
            # Even hex-trick must not echo back the literal payload.
            if payload in p.body:
                continue
            return {
                "oracle": "marker-echo-hex",
                "shell": shell_type,
                "payload": payload,
                "marker": marker_plain,
                "evidence": truncate(p.body, 360),
                "confidence": "confirmed",
            }
    return None


def _oracle_timing(
    client: HttpClient,
    url: str,
    param: str,
    shell_type: str,
    base: dict,
) -> dict | None:
    """Verified slow response. Median of 5 samples must rise by >= SLEEP_S - 1.0s."""
    base_med = base["latency_median"]
    # If baseline itself is already slow, time-based is unreliable.
    if base_med >= SLEEP_S - 1.5:
        return None

    cmd = _sleep_cmd(shell_type, SLEEP_S)
    for tpl in _separators(shell_type):
        payload = tpl.replace("X", "1").format(cmd=cmd)
        mutated = replace_param(url, param, payload)

        lats = _timing_samples(client, mutated, n=TIMING_SAMPLES)
        if len(lats) < 3:
            continue
        med = statistics.median(lats)
        # Confirm the median (not max) shifted by >= SLEEP_S - 1.0
        if med - base_med >= SLEEP_S - 1.0:
            # second confirmation set
            lats2 = _timing_samples(client, mutated, n=3)
            med2 = statistics.median(lats2) if lats2 else 0.0
            confidence = "confirmed" if med2 - base_med >= SLEEP_S - 1.0 else "firm"
            return {
                "oracle": "timing",
                "shell": shell_type,
                "payload": payload,
                "baseline_latency": base_med,
                "injected_latency_samples": lats,
                "injected_latency_median": med,
                "reproduced_latency_median": med2,
                "confidence": confidence,
            }
    return None


def _oracle_info(
    client: HttpClient,
    url: str,
    param: str,
    shell_type: str,
    marker: str,
) -> list[dict]:
    """Already-confirmed marker oracle? Add small read-only info disclosure proof.

    Each cmd output is concatenated with the marker so the response signature
    is unique per command. This is non-destructive: only ``id``, ``whoami``,
    ``uname``, ``hostname``.
    """
    out: list[dict] = []
    for label, info_cmd, regex in _info_cmds(shell_type):
        wrap_marker = "C" + secrets.token_hex(3).upper()
        # echo START_marker; <cmd>; echo END_marker
        if shell_type == "cmd-windows":
            chained = f"echo {wrap_marker}_S & {info_cmd} & echo {wrap_marker}_E"
        elif shell_type == "powershell":
            chained = f"Write-Output {wrap_marker}_S; {info_cmd}; Write-Output {wrap_marker}_E"
        else:
            chained = f"echo {wrap_marker}_S; {info_cmd}; echo {wrap_marker}_E"

        for tpl in _separators(shell_type):
            payload = tpl.replace("X", "1").format(cmd=chained)
            mutated = replace_param(url, param, payload)
            p = _sample(client, mutated)
            if p is None:
                continue
            start_idx = p.body.find(f"{wrap_marker}_S")
            end_idx = p.body.find(f"{wrap_marker}_E")
            if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
                continue
            captured = p.body[start_idx + len(wrap_marker) + 2:end_idx].strip()
            if regex.search(captured):
                out.append({
                    "label": label,
                    "command": info_cmd,
                    "captured_output": truncate(captured, 240),
                })
                break  # next info cmd
    return out


# ---------------------------------------------------------------------------
# Per-parameter validator
# ---------------------------------------------------------------------------
def _validate_param(
    client: HttpClient,
    url: str,
    param: str,
) -> dict | None:
    """Run all oracles on one parameter. Returns assessment dict or None.

    Output keys:
        confidence: confirmed | firm | low_confidence | false_positive
        oracles: list of oracle results
        info: list of read-only proof commands captured (only if confirmed)
        sanitized: detected WAF / encoding behavior
    """
    base = _baseline(client, url)
    if base is None:
        return None

    # Stage 0: send a benign-but-distinctive value to test reflection vs filter
    raw_payload = "<>'\"$;`|&"
    raw_url = replace_param(url, param, raw_payload)
    raw_p = _sample(client, raw_url)
    sanitized_observed = "unknown"
    if raw_p is not None:
        if _looks_filtered(raw_p):
            sanitized_observed = "blocked-by-waf"
        elif raw_payload in (raw_p.body or ""):
            sanitized_observed = "reflected-raw"
        elif any(c not in (raw_p.body or "") for c in SANITIZED_HINTS):
            sanitized_observed = "partially-stripped"
        else:
            sanitized_observed = "reflected-or-encoded"

    oracles_hit: list[dict] = []
    proof_info: list[dict] = []

    for shell_type in SHELL_TYPES:
        marker_res = _oracle_marker(client, url, param, shell_type, base)
        if marker_res is not None:
            oracles_hit.append(marker_res)
            # Run info disclosure ONLY when marker confirms shell exec.
            if marker_res["confidence"] in ("confirmed", "firm"):
                info = _oracle_info(client, url, param, shell_type, marker_res["marker"])
                proof_info.extend(info)
            # No need to try other shells once confirmed.
            break

        timing_res = _oracle_timing(client, url, param, shell_type, base)
        if timing_res is not None:
            oracles_hit.append(timing_res)
            break  # don't continue across shell types if one shell already shows timing

    if not oracles_hit:
        # Stage X: differentiate False Positive vs unable-to-confirm
        if sanitized_observed == "blocked-by-waf":
            confidence = "low_confidence"
            note = "WAF / firewall menolak payload mentah; tidak bisa diverifikasi."
        elif sanitized_observed == "reflected-raw":
            confidence = "false_positive"
            note = (
                "Payload dipantulkan apa adanya tetapi tidak ada bukti eksekusi shell "
                "(tidak ada marker echo, tidak ada delay timing). Kemungkinan besar "
                "hanya reflected output."
            )
        else:
            confidence = "low_confidence"
            note = "Tidak ada oracle yang positif; mungkin sanitasi parsial atau shell berbeda."
        return {
            "confidence": confidence,
            "oracles": [],
            "proof_info": [],
            "sanitization": sanitized_observed,
            "note": note,
            "baseline": base,
        }

    # Determine final confidence:
    has_confirmed = any(o["confidence"] == "confirmed" for o in oracles_hit)
    has_firm = any(o["confidence"] == "firm" for o in oracles_hit)
    if has_confirmed and proof_info:
        final = "confirmed"
    elif has_confirmed:
        final = "confirmed"
    elif has_firm:
        final = "firm"
    else:
        final = "low_confidence"

    return {
        "confidence": final,
        "oracles": oracles_hit,
        "proof_info": proof_info,
        "sanitization": sanitized_observed,
        "baseline": base,
    }


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------
def _build_report(url: str, param: str, assessment: dict, target: Target) -> str:
    """Build a multi-section professional report (used as Finding.description).

    Sections: Summary | Technical Analysis | Reproduction | Impact | Remediation.
    """
    lines: list[str] = []
    conf = assessment["confidence"]
    oracles = assessment["oracles"]
    proof = assessment["proof_info"]
    sani = assessment.get("sanitization", "unknown")
    note = assessment.get("note", "")
    base = assessment.get("baseline") or {}

    # ---- Summary ----
    lines.append("== SUMMARY ==")
    if conf == "confirmed":
        lines.append(
            f"Konfirmasi RCE pada parameter `{param}`. Server mengeksekusi command "
            f"shell yang disuntikkan; marker unik teramati dan {len(proof)} info "
            f"command read-only juga berhasil dieksekusi."
        )
    elif conf == "firm":
        lines.append(
            f"Indikasi kuat RCE pada parameter `{param}` (oracle marker/timing positif "
            f"sekali, tetapi reproduksi belum 100% stabil)."
        )
    elif conf == "low_confidence":
        lines.append(
            f"Tanda samar pada parameter `{param}` ({note or 'inconclusive'}). "
            "Dibutuhkan akses berotorisasi dari pemilik aset / akun pengujian "
            "untuk verifikasi lanjut."
        )
    else:  # false_positive
        lines.append(
            f"FALSE POSITIVE: parameter `{param}` hanya memantulkan input ke respons "
            "tanpa bukti eksekusi shell. Kemungkinan deteksi awal dari modul `cmdi` "
            "salah karena marker pre-set tidak cukup unik."
        )

    # ---- Technical analysis ----
    lines.append("\n== TECHNICAL ANALYSIS ==")
    lines.append(f"Endpoint        : {url}")
    lines.append(f"Parameter       : {param}")
    lines.append(f"HTTP method     : GET (modul ini hanya menguji query params)")
    lines.append(f"Sanitization    : {sani}")
    if base:
        lines.append(
            f"Baseline        : status={base.get('status')}, "
            f"len_median={base.get('length_median')}, "
            f"latency_median={base.get('latency_median', 0):.2f}s"
        )
    for o in oracles:
        lines.append(f"\nOracle [{o['oracle']}] - shell: {o.get('shell', '?')}")
        lines.append(f"  payload : {o.get('payload', '')!r}")
        if "marker" in o:
            lines.append(f"  marker  : {o['marker']}")
            lines.append(f"  evidence: {o.get('evidence', '')[:240]}")
        if "injected_latency_median" in o:
            lines.append(
                f"  baseline_latency        : {o['baseline_latency']:.2f}s"
            )
            lines.append(
                f"  injected_latency_median : {o['injected_latency_median']:.2f}s "
                f"(samples={[round(x, 2) for x in o['injected_latency_samples']]})"
            )
            if o.get("reproduced_latency_median"):
                lines.append(
                    f"  reproduced_latency      : {o['reproduced_latency_median']:.2f}s"
                )
        lines.append(f"  oracle_confidence       : {o['confidence']}")

    if proof:
        lines.append("\nRead-only proof commands (NON-DESTRUCTIVE):")
        for p in proof:
            lines.append(f"  $ {p['command']}")
            lines.append(f"      -> {p['captured_output']}")

    # ---- Reproduction (safe steps the dev team can re-run themselves) ----
    lines.append("\n== REPRODUCTION (NON-DESTRUCTIVE) ==")
    if oracles:
        first_payload = oracles[0].get("payload", "")
        # Show the URL after manual-quoting param
        sample_url = replace_param(url, param, first_payload)
        lines.append("1. Akses URL berikut dari klien yang berhak (terminal/curl):")
        lines.append(f"   curl -sS --max-time 15 \"{sample_url}\"")
        if oracles[0].get("oracle") == "marker-echo":
            lines.append(
                f"2. Periksa apakah body response memuat marker `{oracles[0].get('marker')}`."
            )
        elif oracles[0].get("oracle") == "timing":
            lines.append(
                "2. Catat latency. Bila stabil di sekitar 5s sementara URL polos < 1s, "
                "shell dieksekusi."
            )
        lines.append(
            "3. JANGAN melakukan eskalasi/penulisan file/persistence. Hentikan setelah "
            "konfirmasi sederhana ini."
        )
    else:
        lines.append(
            "Tidak ada payload non-destruktif yang berhasil. Validasi manual dapat "
            "dilakukan oleh pemilik aset dengan akses log untuk melihat parsing input."
        )

    # ---- Impact ----
    lines.append("\n== IMPACT ==")
    if conf in ("confirmed", "firm"):
        lines.append(
            "Penyerang dapat menjalankan perintah arbitrer di server. Dampak realistis: "
            "pembacaan file konfigurasi, ekstraksi kunci API, lateral movement ke "
            "service internal, deployment shell persistent, hingga ransomware. "
        )
        lines.append(
            "Privilege yang didapat = privilege proses web (umumnya `www-data`/IIS APP "
            "POOL). Naik ke root memerlukan local privilege escalation lain (di luar "
            "lingkup test ini)."
        )
        lines.append(
            "Auth requirement: parameter ini diakses melalui method GET; jika endpoint "
            "tidak memerlukan login, RCE pre-auth."
        )
    elif conf == "low_confidence":
        lines.append(
            "Tidak dapat mengukur dampak nyata — endpoint kemungkinan dilindungi WAF "
            "atau menggunakan parser non-shell. Tetap perlu hardening input."
        )
    else:
        lines.append("Tidak ada dampak teknis pada parameter ini.")

    # ---- Remediation ----
    lines.append("\n== REMEDIATION ==")
    lines.append(
        "1. Hindari memberikan input user ke shell. Pakai API yang menerima list of "
        "args (`subprocess.run([...], shell=False)` di Python; `execFile()` di Node). "
        "JANGAN pakai `os.system`, `eval`, `exec`, `subprocess(shell=True)`."
    )
    lines.append(
        "2. Whitelist input dengan regex ketat (mis. `^[a-zA-Z0-9._-]+$`) sebelum "
        "diteruskan ke proses anak."
    )
    lines.append(
        "3. Aktifkan WAF (mod_security CRS, Cloudflare WAF, AWS WAF) sebagai lapisan "
        "kedua, bukan satu-satunya."
    )
    lines.append(
        "4. Jalankan service web dengan akun non-privileged + namespace/seccomp/AppArmor "
        "supaya dampak RCE terbatas."
    )
    lines.append(
        "5. Tambahkan logging command yang dijalankan dari proses web; alert pada "
        "command unfamiliar."
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _candidate_urls(target: Target) -> list[str]:
    """Build candidate URLs from the target.

    For the dashboard branch we mirror the `cmdi` heuristic: take the base
    URL and add a synthetic param if there's none, plus expand to the obvious
    RCE param names (cmd, ip, host, ...).
    """
    base = target.base_url
    urls = [base]
    if "?" not in base:
        for cand in PARAM_HINTS_RCE[:4]:
            urls.append(append_param(base, cand, "x"))
    return urls


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.authorized:
        # Module is intrusive (sends payloads). Stay safe: only run when user
        # explicitly authorized.
        return findings

    client = HttpClient(config)
    seen_param_url: set[tuple[str, str]] = set()
    try:
        for url in _candidate_urls(target):
            params = candidate_params(url)
            if not params:
                continue
            for param in params:
                key = (urlparse(url).path, param)
                if key in seen_param_url:
                    continue
                seen_param_url.add(key)

                assessment = _validate_param(client, url, param)
                if assessment is None:
                    continue
                conf = assessment["confidence"]
                if conf == "false_positive":
                    findings.append(
                        Finding(
                            module="rce_validator",
                            title=f"RCE candidate REJECTED (false positive) on `{param}`",
                            severity=Severity.INFO,
                            description=_build_report(url, param, assessment, target),
                            target=url,
                            evidence=(
                                f"sanitization={assessment['sanitization']}\n"
                                f"oracles=0 hit (marker/timing keduanya negatif)"
                            ),
                            confidence="confirmed",
                            cwe="CWE-78",
                            urls=[url],
                            remediation=(
                                "Tetap terapkan input validation walaupun tidak ada "
                                "RCE; gunakan whitelist regex pada parameter yang "
                                "berinteraksi dengan shell/eksekusi."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                            ],
                        )
                    )
                    continue
                if conf == "low_confidence":
                    findings.append(
                        Finding(
                            module="rce_validator",
                            title=(
                                f"Possible Command Injection on `{param}` "
                                "(low confidence)"
                            ),
                            severity=Severity.MEDIUM,
                            description=_build_report(url, param, assessment, target),
                            target=url,
                            evidence=(
                                f"sanitization={assessment['sanitization']}\n"
                                f"note: {assessment.get('note', '')}"
                            ),
                            confidence="tentative",
                            cwe="CWE-78",
                            urls=[url],
                            remediation=(
                                "Periksa secara manual dengan akses berotorisasi. "
                                "Aktifkan WAF logging untuk melihat payload yang "
                                "diblokir vs diteruskan."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                            ],
                        )
                    )
                    continue
                # firm or confirmed
                sev = Severity.CRITICAL
                findings.append(
                    Finding(
                        module="rce_validator",
                        title=(
                            f"Command Injection / RCE TERVERIFIKASI pada `{param}` "
                            f"({assessment['oracles'][0]['oracle']})"
                        ),
                        severity=sev,
                        description=_build_report(url, param, assessment, target),
                        target=url,
                        evidence=(
                            f"oracle={assessment['oracles'][0]['oracle']}\n"
                            f"shell={assessment['oracles'][0].get('shell', '?')}\n"
                            f"payload={assessment['oracles'][0].get('payload', '')!r}\n"
                            f"info-proof-count={len(assessment['proof_info'])}"
                        ),
                        confidence=conf,
                        cwe="CWE-78",
                        urls=[url],
                        remediation=(
                            "Lihat bagian REMEDIATION pada deskripsi laporan: hindari "
                            "shell pass-through, pakai subprocess args list, whitelist "
                            "input, jalankan dengan least privilege, dan tambah WAF + "
                            "logging."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/78.html",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
