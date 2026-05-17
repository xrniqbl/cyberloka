"""OpenAPI / Swagger spec discovery & endpoint import.

Mencari spec di lokasi umum:
  /openapi.json, /openapi.yaml, /swagger.json, /swagger.yaml,
  /api/openapi.json, /api/swagger.json, /v1/openapi.json,
  /api-docs, /swagger-ui/swagger.json

Bila ditemukan, parse paths dan attach setiap endpoint ke
`target.discovered.endpoints` agar modul aktif (XSS/SQLi/SSRF/JWT/dll.)
ikut menguji endpoint API.

Mendukung JSON dan YAML (jika PyYAML tersedia).
"""
from __future__ import annotations

import json
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


CANDIDATE_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v1/openapi.json",
    "/v2/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger-ui/swagger.json",
    "/swagger-resources",
)


def _parse(text: str, ctype: str) -> dict | None:
    text = text.strip()
    if not text:
        return None
    if "json" in ctype.lower() or text.startswith("{"):
        try:
            return json.loads(text)
        except (ValueError, json.JSONDecodeError):
            return None
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return data
        except yaml.YAMLError:
            return None
    return None


def _walk_paths(spec: dict, base_origin: str) -> list[dict]:
    """Yield endpoint dicts: {url, method, params}."""
    out: list[dict] = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return out

    # base url dari spec.servers[0].url, fallback ke origin
    server_url = base_origin.rstrip("/")
    servers = spec.get("servers") if isinstance(spec.get("servers"), list) else None
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        srv = servers[0]["url"]
        if srv.startswith("http"):
            server_url = srv.rstrip("/")
        else:
            server_url = base_origin.rstrip("/") + "/" + srv.lstrip("/")
            server_url = server_url.rstrip("/")

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(op, dict):
                continue
            params = []
            for p in op.get("parameters") or []:
                if isinstance(p, dict) and p.get("name"):
                    params.append(p["name"])
            # pad path params dengan placeholder agar URL valid
            url_path = path
            for p in op.get("parameters") or []:
                if isinstance(p, dict) and p.get("in") == "path" and p.get("name"):
                    url_path = url_path.replace("{" + p["name"] + "}", "1")
            full = server_url + url_path
            out.append({"url": full, "method": method.upper(), "params": params})
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    found_spec: dict | None = None
    found_url: str | None = None
    try:
        for p in CANDIDATE_PATHS:
            url = urljoin(target.origin + "/", p.lstrip("/"))
            resp = client.get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            ctype = resp.headers.get("Content-Type", "")
            spec = _parse(resp.text or "", ctype)
            if spec and ("paths" in spec or "swagger" in spec or "openapi" in spec):
                found_spec = spec
                found_url = url
                break

        if not found_spec or not found_url:
            return findings

        endpoints = _walk_paths(found_spec, target.origin)
        # Attach ke target.discovered (atau buat objek minimal)
        from cyberloka.recon.crawler import CrawlResult, DiscoveredEndpoint
        discovered = getattr(target, "discovered", None)
        if discovered is None:
            discovered = CrawlResult()
            setattr(target, "discovered", discovered)

        before = len(discovered.endpoints)
        for e in endpoints:
            discovered.endpoints.append(
                DiscoveredEndpoint(
                    url=e["url"],
                    method=e["method"],
                    params=e["params"],
                    source="openapi",
                )
            )
        added = len(discovered.endpoints) - before

        info = found_spec.get("info") or {}
        findings.append(
            Finding(
                module="openapi",
                title=f"OpenAPI/Swagger spec ditemukan & diimport ({added} endpoint)",
                severity=Severity.INFO,
                description=(
                    "Spec API publik digunakan untuk memperluas cakupan scan. "
                    "Bila spec ini bocor di production tanpa otorisasi, attacker "
                    "mendapatkan blueprint API Anda secara gratis."
                ),
                target=found_url,
                evidence=(
                    f"title={info.get('title')!r} "
                    f"version={info.get('version')!r} "
                    f"endpoints_imported={added}"
                ),
                remediation=(
                    "Jika spec tidak ditujukan untuk publik, batasi aksesnya (auth, "
                    "internal-only). Jika untuk publik (developer portal), pastikan "
                    "tidak memuat endpoint admin internal."
                ),
            )
        )
    finally:
        client.close()
    return findings
