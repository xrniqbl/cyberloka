"""Command injection — verification-first (arithmetic marker + differential timing).

Masalah pendekatan lama (masih ada di versi sebelumnya):
  - Marker `;echo cyberlokaCMD` lalu mencari `cyberlokaCMD`. String itu ADA di
    payload, jadi aplikasi yang sekadar memantulkan input (refleksi/halaman error)
    memunculkannya TANPA shell pernah berjalan. Cek `"echo cyberlokaCMD" not in text`
    pun mudah dielakkan oleh refleksi parsial / input yang dipecah.
  - Time-based 1 sampel dengan ambang `elapsed >= sleep-0.5` → jitter jaringan lolos.

Pendekatan baru — hanya lapor bila TERBUKTI shell mengevaluasi sesuatu yang tak
mungkin muncul dari refleksi mentah:
  1) Marker aritmatika: kirim `$((A+B))`. Bila dieksekusi, respons memuat HASIL
     penjumlahan (mis. `CLK1379291END`), bukan teks `$((655123+724168))`. Kita cek
     HASIL ada DAN ekspresi literalnya tidak — kebal refleksi.
  2) Time-based diferensial: ukur baseline, lalu `sleep N` dan `sleep 2N`; hanya
     diterima bila delay berskala linear dengan N dan dikonfirmasi dua kali.
"""
from __future__ import annotations

import random

from cyberloka.active._helpers import (
    baseline_timing,
    candidate_urls,
    fetch,
    fuzz_forms,
    iter_param_urls,
    param_names,
    replace_param,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

SLEEP_S = 4


def _arith_payloads(a: int, b: int) -> list[str]:
    core = f"echo CLK$(({a}+{b}))END"
    return [f"; {core}", f"| {core}", f"&& {core}", f"`{core}`", f"$({core})", f"%0a{core}"]


def _sleep_payloads(seconds: int) -> list[str]:
    return [
        f"; sleep {seconds}",
        f"| sleep {seconds}",
        f"&& sleep {seconds}",
        f"`sleep {seconds}`",
        f"$(sleep {seconds})",
    ]


def _marker_finding(param: str, target_url: str, evidence: str, is_form: bool) -> Finding:
    where = f"field form `{param}`" if is_form else f"`{param}`"
    return Finding(
        module="cmdi",
        title=f"Command Injection TERVERIFIKASI pada {where}",
        severity=Severity.CRITICAL,
        confidence="confirmed",
        description=(
            "Shell sistem mengeksekusi ekspresi aritmatika yang disuntikkan: respons memuat "
            "HASIL perhitungan, bukan teks payload yang dipantulkan. Bukti pasti perintah "
            "arbitrer dapat dijalankan attacker."
        ),
        target=target_url,
        evidence=evidence,
        cwe="CWE-78",
        remediation=(
            "JANGAN passing input user ke shell (`os.system`, `exec`, `subprocess(shell=True)`). "
            "Pakai API yang menerima list of args, validasi whitelist parameter, atau hindari shell."
        ),
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
    )


def _confirm_marker_url(client: HttpClient, url: str, param: str) -> tuple[str, str] | None:
    a, b = random.randint(100_000, 999_999), random.randint(100_000, 999_999)
    expected, literal = f"CLK{a + b}END", f"$(({a}+{b}))"
    for payload in _arith_payloads(a, b):
        mutated = replace_param(url, param, "1" + payload)
        s = fetch(client, mutated)
        if s is None:
            continue
        if expected in s.text and literal not in s.text:
            return mutated, f"shell evaluated {literal} -> {expected}"
    return None


def _confirm_timing_url(client: HttpClient, url: str, param: str) -> tuple[str, str] | None:
    base = baseline_timing(client, url, rounds=3)
    for tpl in _sleep_payloads(SLEEP_S):
        mutated = replace_param(url, param, "1" + tpl)
        s1 = fetch(client, mutated)
        if s1 is None or s1.elapsed < base + SLEEP_S * 0.7:
            continue
        double = replace_param(url, param, "1" + tpl.replace(f"sleep {SLEEP_S}", f"sleep {SLEEP_S * 2}"))
        if double == mutated:
            continue
        s2 = fetch(client, double)
        if s2 is None:
            continue
        if s2.elapsed >= base + SLEEP_S * 2 * 0.7 and s2.elapsed > s1.elapsed + 1.0:
            return double, (
                f"baseline={base:.2f}s | sleep {SLEEP_S}={s1.elapsed:.2f}s | "
                f"sleep {SLEEP_S * 2}={s2.elapsed:.2f}s (skala linear → bukan jitter)"
            )
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        urls = candidate_urls(target, config, "cmd", "ping")

        # 1) Marker aritmatika anti-refleksi (paling tak ambigu).
        for scan_url in urls:
            for param in param_names(scan_url):
                hit = _confirm_marker_url(client, scan_url, param)
                if hit:
                    findings.append(_marker_finding(param, hit[0], hit[1], is_form=False))
                    return findings

        # 2) Blind time-based diferensial.
        for scan_url in urls:
            for param in param_names(scan_url):
                hit = _confirm_timing_url(client, scan_url, param)
                if hit:
                    f = _marker_finding(param, hit[0], hit[1], is_form=False)
                    f.title = f"Blind Command Injection TERVERIFIKASI (time-based) pada `{param}`"
                    f.description = (
                        "Waktu respons bertambah linear mengikuti durasi `sleep` yang disuntikkan "
                        "dan dikonfirmasi dua kali — pola yang tak bisa muncul dari jitter jaringan."
                    )
                    findings.append(f)
                    return findings

        # 3) Form fuzzing — marker aritmatika juga self-verifying di sini.
        a, b = random.randint(100_000, 999_999), random.randint(100_000, 999_999)
        expected, literal = f"CLK{a + b}END", f"$(({a}+{b}))"
        for payload in _arith_payloads(a, b):
            for field, action, resp in fuzz_forms(client, config, "1" + payload):
                text = resp.text or ""
                if expected in text and literal not in text:
                    findings.append(_marker_finding(field, action, f"shell evaluated {literal} -> {expected}", is_form=True))
                    return findings
    finally:
        client.close()
    return findings
