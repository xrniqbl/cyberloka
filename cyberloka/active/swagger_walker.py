"""Parse Swagger/OpenAPI publik, lalu UJI tiap endpoint tanpa autentikasi.

Beda dengan api_discovery (yang hanya cek apakah swagger.json publik), modul
ini benar-benar:
  1. Download spec OpenAPI/Swagger.
  2. Untuk tiap path GET yang TIDAK butuh path-parameter (atau parameter-nya
     punya example), coba akses tanpa Authorization header.
  3. Validasi: status 200 + body JSON yang berisi data nyata (bukan {} / pesan
     error). Kalau spec menyatakan endpoint butuh auth (security:[bearer]) tapi
     tetap mengembalikan data tanpa header, itu broken auth = CRITICAL.

Modul ini menemukan IDOR / broken-auth nyata, bukan sekadar 'swagger publik'.
"""
from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

SPEC_PATHS = (
    "v3/api-docs", "v2/api-docs", "swagger.json", "openapi.json",
    "api-docs", "api/swagger.json", "api/v1/swagger.json",
    "swagger/v1/swagger.json", "docs/swagger.json",
)


def _fetch_spec(client: HttpClient, base: str) -> tuple[dict, str] | None:
    for p in SPEC_PATHS:
        url = urljoin(base, p)
        r = client.get(url)
        if r is None or r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        if isinstance(data, dict) and ("paths" in data or "swagger" in data or "openapi" in data):
            return data, url
    return None


def _resolve_server_base(spec: dict, target_base: str) -> str:
    if "servers" in spec and spec["servers"]:
        s = spec["servers"][0]
        url = s.get("url") if isinstance(s, dict) else s
        if url:
            if url.startswith("/"):
                return urljoin(target_base, url)
            return url
    if "host" in spec:
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{spec['host']}{spec.get('basePath', '')}"
    return target_base


def _endpoint_requires_auth(op: dict, spec_security: list) -> bool:
    """Kalau spec bilang endpoint butuh auth (security non-empty atau bearer/apikey)."""
    sec = op.get("security", spec_security) or []
    return bool(sec) and any(s for s in sec if s)


def _path_is_concrete(path: str, op: dict) -> str | None:
    """Return concrete URL path atau None kalau ada {param} tanpa example."""
    if "{" not in path:
        return path
    out = path
    params = {p["name"]: p for p in (op.get("parameters") or []) if isinstance(p, dict)}
    for ph in [s.split("}")[0] for s in path.split("{")[1:]]:
        ex = None
        if ph in params:
            ex = params[ph].get("example") or (params[ph].get("schema") or {}).get("example")
        if ex is None:
            ex = "1" if ph.lower() in ("id", "userid", "user_id", "n", "page", "limit") else None
        if ex is None:
            return None
        out = out.replace("{" + ph + "}", str(ex), 1)
    return out


def _looks_like_real_data(body: str) -> bool:
    if not body or len(body) < 20:
        return False
    try:
        d = json.loads(body)
    except Exception:
        return False
    if isinstance(d, list):
        return len(d) > 0
    if isinstance(d, dict):
        return any(
            isinstance(v, (list, dict, int, str, float))
            and (not isinstance(v, str) or len(v) > 0)
            for v in d.values()
        ) and not any(
            (isinstance(v, str) and v.lower() in ("unauthorized", "forbidden", "no token"))
            for v in d.values()
        )
    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        result = _fetch_spec(client, base)
        if result is None:
            return findings
        spec, spec_url = result

        api_base = _resolve_server_base(spec, base)
        # Pastikan tetap di host target supaya tidak scan host lain
        if urlparse(api_base).netloc and urlparse(api_base).netloc != target.host:
            api_base = urljoin(base, urlparse(api_base).path or "/")

        spec_security = spec.get("security") or []
        broken_auth: list[tuple[str, int, int]] = []  # (url, status, len)
        publicly_protected: list[str] = []

        paths = spec.get("paths", {}) or {}
        tested = 0
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            op = methods.get("get") or {}
            if not op:
                continue
            concrete = _path_is_concrete(path, op)
            if not concrete:
                continue
            full = urljoin(api_base.rstrip("/") + "/", concrete.lstrip("/"))
            requires_auth = _endpoint_requires_auth(op, spec_security)
            r = client.get(full)
            tested += 1
            if r is None:
                continue
            if r.status_code == 200 and _looks_like_real_data(r.text or ""):
                if requires_auth:
                    broken_auth.append((full, r.status_code, len(r.text or "")))
                else:
                    publicly_protected.append(full)
            if tested >= 20:
                break

        if not (broken_auth or publicly_protected):
            findings.append(Finding(
                module="swagger_walker",
                target=spec_url,
                title="Spec OpenAPI/Swagger publik (tidak ada broken auth terdeteksi)",
                severity=Severity.LOW,
                description=(
                    f"Spec API publik di {spec_url}. {tested} endpoint diuji tanpa "
                    "header Authorization - tidak ada yang mengembalikan data sensitif. "
                    "Tetap rekomendasi untuk membatasi spec ke jaringan internal."
                ),
                evidence=f"spec={spec_url}, tested={tested}",
                cwe="CWE-200",
                confidence="confirmed",
                urls=[spec_url],
                remediation="Pindahkan dokumentasi API ke jaringan internal / di belakang auth.",
            ))
            return findings

        if broken_auth:
            findings.append(Finding(
                module="swagger_walker",
                target=spec_url,
                title=f"Broken auth pada {len(broken_auth)} endpoint API (spec menyebut butuh auth)",
                severity=Severity.CRITICAL,
                description=(
                    "Spec OpenAPI menyatakan endpoint berikut MEMBUTUHKAN autentikasi "
                    "(security: bearer/apiKey), tetapi mereka tetap mengembalikan data "
                    "valid 200 saat diakses tanpa header Authorization. Ini broken "
                    "authentication murni - akses data yang seharusnya privileged."
                ),
                evidence="\n".join(
                    f"{u} -> HTTP {s}, body {l} bytes"
                    for u, s, l in broken_auth[:10]
                ),
                cwe="CWE-287",
                confidence="confirmed",
                urls=[u for u, _, _ in broken_auth],
                remediation=(
                    "1. Periksa middleware autentikasi - tampaknya tidak terpasang di "
                    "router yang seharusnya protected.\n"
                    "2. Tambahkan integration test yang memverifikasi tiap endpoint "
                    "protected return 401 tanpa token.\n"
                    "3. Audit semua data yang sudah ter-leak via endpoint ini."
                ),
                references=[
                    "https://owasp.org/www-project-api-security/",
                ],
            ))

        if publicly_protected:
            findings.append(Finding(
                module="swagger_walker",
                target=spec_url,
                title=f"{len(publicly_protected)} endpoint publik (tanpa security di spec)",
                severity=Severity.MEDIUM,
                description=(
                    "Endpoint berikut secara eksplisit publik di spec dan mengembalikan "
                    "data nyata. Audit apakah memang seharusnya publik (mis. /health, "
                    "/version) atau harusnya butuh auth."
                ),
                evidence="\n".join(publicly_protected[:10]),
                cwe="CWE-200",
                confidence="confirmed",
                urls=publicly_protected,
                remediation="Audit kebutuhan auth untuk tiap endpoint publik di spec.",
            ))
    finally:
        client.close()
    return findings
