"""Verification (deep re-scan) of previously discovered findings.

Given a scan bundle JSON file, re-test each candidate finding using
*different* techniques than the initial detection. The goal is to:

  * separate false-positives from real vulnerabilities,
  * raise confidence (`tentative` -> `firm` -> `confirmed`),
  * collect stronger evidence (response diff, timing, content match),
  * produce a reproducible PoC (curl command).

This module is read-only with respect to the target scope. It does NOT
exploit findings (no data exfiltration, no destructive payloads); it only
runs additional probing payloads similar in shape to the original detector
but covering more variants. The default rate limiter still applies.
"""
from __future__ import annotations

import json
import re
import statistics
import time
import urllib.parse as up
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.logger import get_logger
from cyberloka.core.target import parse_target
from cyberloka.core.util import truncate


# ---------------------------------------------------------------------------
# Verification result data
# ---------------------------------------------------------------------------


_STATUS_LADDER = ("false_positive", "tentative", "firm", "confirmed")


@dataclass
class Attempt:
    """One verification probe."""

    technique: str
    payload: str
    success: bool
    detail: str = ""


@dataclass
class VerificationResult:
    """Outcome of verifying one finding."""

    status: str  # one of _STATUS_LADDER
    attempts: list[Attempt] = field(default_factory=list)
    evidence_strong: str = ""
    poc: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "attempts": [
                {
                    "technique": a.technique,
                    "payload": a.payload,
                    "success": a.success,
                    "detail": a.detail,
                }
                for a in self.attempts
            ],
            "evidence_strong": self.evidence_strong,
            "poc": self.poc,
        }

    @property
    def is_real(self) -> bool:
        return self.status in ("firm", "confirmed")


def _curl_for(url: str, *, headers: dict | None = None, method: str = "GET") -> str:
    parts = ["curl", "-sk"]
    if method != "GET":
        parts += ["-X", method]
    if headers:
        for k, v in headers.items():
            parts += ["-H", f"'{k}: {v}'"]
    parts.append(f"'{url}'")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Per-module verifiers
# ---------------------------------------------------------------------------


_SQL_ERROR_RE = re.compile(
    r"sql syntax|warning.*mysql|sqlstate\[|odbc.*sql server|"
    r"postgresql.*error|sqlite\.|sqlite3::sqlexception|ora-\d{4,}|"
    r"you have an error in your sql syntax|unclosed quotation mark|"
    r"quoted string not properly terminated",
    re.I,
)


def _replace_query_value(url: str, key: str, value: str) -> str:
    """Replace a single query parameter while preserving order/encoding."""
    parsed = up.urlparse(url)
    params = up.parse_qsl(parsed.query, keep_blank_values=True)
    out = [(k, value if k == key else v) for k, v in params]
    return up.urlunparse(parsed._replace(query=up.urlencode(out, doseq=True)))


def _parse_param_from_title(title: str) -> str | None:
    """Findings encode the vulnerable parameter as `param`."""
    m = re.search(r"`([^`]+)`", title)
    return m.group(1) if m else None


# ----- SQL Injection ----------------------------------------------------------

def _verify_sqli(client: HttpClient, finding: dict[str, Any]) -> VerificationResult:
    target = finding.get("target", "")
    param = _parse_param_from_title(finding.get("title", "")) or "id"
    if "?" not in target or param not in up.parse_qs(up.urlparse(target).query):
        target = target + ("&" if "?" in target else "?") + f"{param}=1"

    baseline_url = _replace_query_value(target, param, "1")
    baseline = client.get(baseline_url)
    if baseline is None:
        return VerificationResult(status="tentative")

    base_text = baseline.text or ""
    base_status = baseline.status_code

    attempts: list[Attempt] = []
    success_count = 0

    # 1. Error-based — multiple quote variants
    for q in ("'", '"', "')", "';--"):
        url = _replace_query_value(target, param, "1" + q)
        r = client.get(url)
        if r is None:
            continue
        m = _SQL_ERROR_RE.search(r.text or "")
        ok = m is not None
        attempts.append(
            Attempt("error-based", q, ok, truncate(m.group(0), 80) if m else "")
        )
        if ok:
            success_count += 1
            break  # one error variant is enough to confirm error-based

    # 2. Boolean-based — true vs false length diff vs baseline
    true_url = _replace_query_value(target, param, "1 AND 1=1-- -")
    false_url = _replace_query_value(target, param, "1 AND 1=2-- -")
    r_true = client.get(true_url)
    r_false = client.get(false_url)
    if r_true is not None and r_false is not None:
        diff = abs(len(r_true.text) - len(r_false.text))
        # require a meaningful diff *and* true ~ baseline
        ok = (
            r_true.status_code == base_status
            and diff > 200
            and abs(len(r_true.text) - len(base_text)) < diff
        )
        attempts.append(
            Attempt(
                "boolean-based",
                "1 AND 1=1 vs 1=2",
                ok,
                f"len(true)={len(r_true.text)} len(false)={len(r_false.text)} diff={diff}",
            )
        )
        if ok:
            success_count += 1

    # 3. Time-based — sleep(0) baseline vs sleep(3)
    timings: list[float] = []
    for s in (0, 3):
        url = _replace_query_value(target, param, f"1' AND SLEEP({s})-- -")
        t0 = time.monotonic()
        r = client.get(url)
        dt = time.monotonic() - t0
        if r is not None:
            timings.append(dt)
    if len(timings) == 2:
        delta = timings[1] - timings[0]
        ok = delta >= 2.5  # sleep(3) should add at least ~3s
        attempts.append(
            Attempt(
                "time-based",
                "SLEEP(0) vs SLEEP(3)",
                ok,
                f"delta={delta:.2f}s",
            )
        )
        if ok:
            success_count += 1

    # Decide status
    if success_count >= 2:
        status = "confirmed"
    elif success_count == 1:
        status = "firm"
    elif all(not a.success for a in attempts):
        status = "false_positive"
    else:
        status = "tentative"

    poc_url = _replace_query_value(target, param, "1' AND 1=1-- -")
    return VerificationResult(
        status=status,
        attempts=attempts,
        evidence_strong=(
            "; ".join(a.detail for a in attempts if a.success and a.detail)[:200]
        ),
        poc=_curl_for(poc_url),
    )


# ----- Reflected XSS ---------------------------------------------------------

_XSS_PROBES = [
    ("html-tag",   "<cybl{nonce}>",          re.compile(r"<cybl{nonce}>",          re.I)),
    ("script",     "<script>cybl{nonce}</script>", re.compile(r"<script>cybl{nonce}</script>", re.I)),
    ("svg-event",  "<svg onload=cybl{nonce}>", re.compile(r"<svg[^>]*onload=cybl{nonce}", re.I)),
    ("attr-break", '"x=cybl{nonce}',         re.compile(r'"x=cybl{nonce}',         re.I)),
    ("js-context", "';cybl{nonce};//",       re.compile(r"';cybl{nonce};//",       re.I)),
]


def _verify_xss(client: HttpClient, finding: dict[str, Any]) -> VerificationResult:
    target = finding.get("target", "")
    param = _parse_param_from_title(finding.get("title", "")) or "q"
    if "?" not in target:
        target = target + f"?{param}=test"

    nonce = f"x{int(time.time())%100000}"
    attempts: list[Attempt] = []
    success_count = 0
    successful_payload: str | None = None

    for name, payload, pattern in _XSS_PROBES:
        rendered = payload.replace("{nonce}", nonce)
        url = _replace_query_value(target, param, rendered)
        r = client.get(url)
        if r is None:
            attempts.append(Attempt(name, rendered, False, "no response"))
            continue
        body = r.text or ""
        # Match the rendered pattern (with nonce filled in) — case-insensitive.
        rendered_re = re.compile(
            re.escape(rendered).replace(re.escape(nonce), nonce), re.I
        )
        ok = rendered_re.search(body) is not None
        # Sanity check: nonce must appear unencoded
        if ok and (nonce not in body or "&lt;" in body[:body.find(nonce)+200]
                   and "<" not in body[:body.find(nonce)+200]):
            ok = False
            detail = "encoded (likely safe)"
        else:
            detail = "reflected unescaped" if ok else "not reflected / encoded"
        attempts.append(Attempt(name, rendered, ok, detail))
        if ok:
            success_count += 1
            successful_payload = rendered

    if success_count >= 2:
        status = "confirmed"
    elif success_count == 1:
        status = "firm"
    elif all(not a.success for a in attempts):
        status = "false_positive"
    else:
        status = "tentative"

    poc = ""
    if successful_payload:
        poc = _curl_for(_replace_query_value(target, param, successful_payload))
    return VerificationResult(
        status=status,
        attempts=attempts,
        evidence_strong=(
            f"{success_count}/{len(attempts)} payload variants reflected unescaped"
            if success_count
            else ""
        ),
        poc=poc,
    )


# ----- LFI / Path Traversal --------------------------------------------------

_LFI_MARKERS = [
    re.compile(r"root:[x*]?:0:0:", re.I),
    re.compile(r"\[boot loader\]", re.I),
    re.compile(r"daemon:[x*]?:1:1:", re.I),
]


def _verify_lfi(client: HttpClient, finding: dict[str, Any]) -> VerificationResult:
    target = finding.get("target", "")
    param = _parse_param_from_title(finding.get("title", "")) or "file"
    if "?" not in target:
        target = target + f"?{param}=index.html"

    payloads = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
    ]
    attempts: list[Attempt] = []
    successful_payload: str | None = None
    for p in payloads:
        url = _replace_query_value(target, param, p)
        r = client.get(url)
        if r is None:
            attempts.append(Attempt("traversal", p, False, "no response"))
            continue
        body = r.text or ""
        ok = any(m.search(body) for m in _LFI_MARKERS) or (
            "php://filter" in p and re.match(r"^[A-Za-z0-9+/=\s]+$", body[:200].strip())
        )
        attempts.append(
            Attempt(
                "traversal" if "filter" not in p else "php-filter",
                p,
                ok,
                "passwd/boot.ini marker matched" if ok else f"status={r.status_code} len={len(body)}",
            )
        )
        if ok and successful_payload is None:
            successful_payload = p

    successes = sum(1 for a in attempts if a.success)
    if successes >= 2:
        status = "confirmed"
    elif successes == 1:
        status = "firm"
    elif all(not a.success for a in attempts):
        status = "false_positive"
    else:
        status = "tentative"
    poc = (
        _curl_for(_replace_query_value(target, param, successful_payload))
        if successful_payload
        else ""
    )
    return VerificationResult(
        status=status,
        attempts=attempts,
        evidence_strong=f"{successes} traversal depth(s) succeeded" if successes else "",
        poc=poc,
    )


# ----- Open Redirect ---------------------------------------------------------

_REDIR_TARGET = "evil.example.org"


def _verify_redirect(client: HttpClient, finding: dict[str, Any]) -> VerificationResult:
    target = finding.get("target", "")
    param = _parse_param_from_title(finding.get("title", "")) or "url"
    if "?" not in target:
        target = target + f"?{param}=/"

    payloads = [
        f"https://{_REDIR_TARGET}/",
        f"//{_REDIR_TARGET}/",
        f"/\\{_REDIR_TARGET}/",
        f"https:%2F%2F{_REDIR_TARGET}/",
        f"https://{_REDIR_TARGET}@trusted.example.com/",
    ]
    attempts: list[Attempt] = []
    succ = 0
    poc_payload = None
    for p in payloads:
        url = _replace_query_value(target, param, p)
        r = client.request("GET", url, allow_redirects=False)
        if r is None:
            attempts.append(Attempt("redirect", p, False, "no response"))
            continue
        loc = (r.headers.get("Location") or "").lower()
        ok = (300 <= r.status_code < 400) and (_REDIR_TARGET in loc)
        attempts.append(
            Attempt(
                "redirect", p, ok, f"status={r.status_code} location={truncate(loc, 80)}"
            )
        )
        if ok:
            succ += 1
            if poc_payload is None:
                poc_payload = p

    if succ >= 2:
        status = "confirmed"
    elif succ == 1:
        status = "firm"
    elif all(not a.success for a in attempts):
        status = "false_positive"
    else:
        status = "tentative"
    poc = (
        _curl_for(_replace_query_value(target, param, poc_payload))
        if poc_payload
        else ""
    )
    return VerificationResult(
        status=status,
        attempts=attempts,
        evidence_strong=f"{succ}/{len(attempts)} bypass technique(s) redirected off-host"
        if succ
        else "",
        poc=poc,
    )


# ----- Command Injection (time-based only — safe) ---------------------------

def _verify_cmdi(client: HttpClient, finding: dict[str, Any]) -> VerificationResult:
    target = finding.get("target", "")
    param = _parse_param_from_title(finding.get("title", "")) or "cmd"
    if "?" not in target:
        target = target + f"?{param}=1"

    # Multiple platform-specific sleep variants, with a baseline first.
    payloads = [
        ("baseline", "1"),
        ("nix-pipe", "1;sleep 3"),
        ("nix-bg", "1`sleep 3`"),
        ("nix-and", "1&&sleep 3"),
        ("win-timeout", "1&timeout /T 3"),
    ]
    timings: dict[str, float] = {}
    attempts: list[Attempt] = []
    for name, p in payloads:
        url = _replace_query_value(target, param, p)
        # Take median of 2 to reduce jitter
        ts: list[float] = []
        for _ in range(2):
            t0 = time.monotonic()
            r = client.get(url)
            ts.append(time.monotonic() - t0)
            if r is None:
                break
        if len(ts) < 2:
            attempts.append(Attempt(name, p, False, "no response"))
            continue
        timings[name] = statistics.median(ts)

    base = timings.get("baseline")
    if base is None:
        return VerificationResult(status="tentative")

    succ = 0
    successful_payload = None
    for name, p in payloads[1:]:
        if name not in timings:
            continue
        delta = timings[name] - base
        ok = delta >= 2.5
        attempts.append(Attempt(name, p, ok, f"delta={delta:.2f}s vs baseline"))
        if ok:
            succ += 1
            if successful_payload is None:
                successful_payload = p

    if succ >= 2:
        status = "confirmed"
    elif succ == 1:
        status = "firm"
    elif all(not a.success for a in attempts):
        status = "false_positive"
    else:
        status = "tentative"
    poc = (
        _curl_for(_replace_query_value(target, param, successful_payload))
        if successful_payload
        else ""
    )
    return VerificationResult(
        status=status,
        attempts=attempts,
        evidence_strong=f"{succ} sleep variant(s) added >=2.5s vs baseline" if succ else "",
        poc=poc,
    )


# ----- Sensitive Files -------------------------------------------------------

_SENSITIVE_PATTERNS: dict[str, re.Pattern[str]] = {
    ".env":      re.compile(r"^[A-Z][A-Z0-9_]+=[^\n]+", re.M),
    ".git":      re.compile(r"^\[core\]|ref:\s+refs/", re.M | re.I),
    "phpinfo":   re.compile(r"phpinfo\(\)|<title>\s*phpinfo", re.I),
    "backup":    re.compile(r"PK\x03\x04|^-----BEGIN", re.M),
    "config":    re.compile(r"DB_PASSWORD|SECRET_KEY|api_key", re.I),
}


def _verify_sensitive_file(
    client: HttpClient, finding: dict[str, Any]
) -> VerificationResult:
    url = finding.get("target", "")
    r = client.get(url)
    if r is None:
        return VerificationResult(status="tentative",
                                  attempts=[Attempt("fetch", url, False, "no response")])

    attempts: list[Attempt] = []
    if r.status_code != 200 or len(r.content) == 0:
        attempts.append(Attempt("fetch", url, False, f"status={r.status_code}"))
        return VerificationResult(
            status="false_positive",
            attempts=attempts,
            evidence_strong=f"status={r.status_code} (file no longer accessible)",
        )

    body = r.text[:5000]  # limit scan window
    matched: list[str] = []
    for label, pattern in _SENSITIVE_PATTERNS.items():
        if pattern.search(body):
            matched.append(label)
    attempts.append(
        Attempt(
            "content-classify",
            url,
            bool(matched),
            f"matched: {','.join(matched)}" if matched else "no sensitive pattern matched",
        )
    )

    if matched:
        status = "confirmed"
        evidence = f"file contains: {', '.join(matched)}"
    else:
        # File accessible but content doesn't look sensitive — likely a placeholder.
        status = "firm"  # still publicly accessible, but lower-impact
        evidence = "publicly accessible, but content does not match sensitive patterns"

    return VerificationResult(
        status=status, attempts=attempts, evidence_strong=evidence, poc=_curl_for(url)
    )


# ----- Headers / Cookies / TLS / Dirlist (passive re-check) ------------------


def _verify_headers(client: HttpClient, finding: dict[str, Any]) -> VerificationResult:
    """Re-fetch and confirm the missing header is still missing.

    A missing-header finding can flake when the original request hit a CDN
    edge that stripped the header. We re-fetch with a fresh connection and
    no-cache header to confirm.
    """
    url = finding.get("target", "")
    title = finding.get("title", "")
    m = re.search(r"hilang:\s*([A-Za-z0-9-]+)", title) or re.search(
        r"missing:\s*([A-Za-z0-9-]+)", title, re.I
    )
    header = m.group(1) if m else None
    r = client.get(url, headers={"Cache-Control": "no-cache", "Pragma": "no-cache"})
    if r is None or header is None:
        return VerificationResult(status="tentative",
                                  attempts=[Attempt("re-fetch", url, False, "no response or unknown header")])
    present = header.lower() in (k.lower() for k in r.headers)
    attempts = [
        Attempt(
            "re-fetch", url, not present,
            f"{header} {'still absent' if not present else 'now present'} on re-fetch"
        )
    ]
    if present:
        return VerificationResult(
            status="false_positive",
            attempts=attempts,
            evidence_strong=f"{header} present on re-fetch (likely CDN cache flake on first scan)",
        )
    return VerificationResult(
        status="confirmed",
        attempts=attempts,
        evidence_strong=f"{header} confirmed absent across two requests with no-cache",
        poc=_curl_for(url, headers={"Cache-Control": "no-cache"}),
    )


def _verify_dirlist(client: HttpClient, finding: dict[str, Any]) -> VerificationResult:
    url = finding.get("target", "")
    r = client.get(url)
    if r is None or r.status_code != 200:
        return VerificationResult(
            status="false_positive",
            attempts=[Attempt("re-fetch", url, False, f"status={r.status_code if r else 'n/a'}")],
            evidence_strong="endpoint no longer returns 200",
        )
    body = r.text or ""
    markers = ("Index of /", "<title>Index of", "Parent Directory")
    matched = [m for m in markers if m in body]
    if matched:
        return VerificationResult(
            status="confirmed",
            attempts=[Attempt("marker", url, True, f"matched: {matched[0]}")],
            evidence_strong=f"directory listing markers: {', '.join(matched)}",
            poc=_curl_for(url),
        )
    return VerificationResult(
        status="false_positive",
        attempts=[Attempt("marker", url, False, "no listing markers")],
        evidence_strong="page returns 200 but contains no directory-listing markers",
    )


def _verify_cookies(client: HttpClient, finding: dict[str, Any]) -> VerificationResult:
    """Re-fetch and confirm the cookie still misses Secure/HttpOnly flags."""
    url = finding.get("target", "")
    title = finding.get("title", "")
    m = re.search(r"`([^`]+)`", title)
    cookie_name = m.group(1) if m else None
    r = client.get(url)
    if r is None:
        return VerificationResult(status="tentative")
    set_cookies = r.headers.get("Set-Cookie", "") or ""
    if cookie_name and cookie_name not in set_cookies:
        return VerificationResult(
            status="false_positive",
            attempts=[Attempt("re-fetch", url, False, f"cookie {cookie_name} not set on re-fetch")],
            evidence_strong=f"cookie {cookie_name} no longer present",
        )
    cookie_part = ""
    if cookie_name:
        for piece in set_cookies.split(","):
            if cookie_name + "=" in piece:
                cookie_part = piece
                break
    else:
        cookie_part = set_cookies
    has_secure = re.search(r"\bSecure\b", cookie_part, re.I) is not None
    has_httponly = re.search(r"\bHttpOnly\b", cookie_part, re.I) is not None
    has_samesite = re.search(r"\bSameSite=", cookie_part, re.I) is not None
    missing = [
        n for n, ok in (("Secure", has_secure),
                        ("HttpOnly", has_httponly),
                        ("SameSite", has_samesite)) if not ok
    ]
    if not missing:
        return VerificationResult(
            status="false_positive",
            attempts=[Attempt("re-fetch", url, False, "all flags now present")],
            evidence_strong="cookie has Secure, HttpOnly, and SameSite — issue resolved",
        )
    return VerificationResult(
        status="confirmed",
        attempts=[Attempt("re-fetch", url, True, f"missing: {', '.join(missing)}")],
        evidence_strong=truncate(cookie_part.strip(), 200),
        poc=_curl_for(url) + "  # inspect Set-Cookie",
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


_VERIFIERS: dict[str, Callable[[HttpClient, dict[str, Any]], VerificationResult]] = {
    "sqli": _verify_sqli,
    "xss": _verify_xss,
    "lfi": _verify_lfi,
    "redirect": _verify_redirect,
    "cmdi": _verify_cmdi,
    "sensitive_files": _verify_sensitive_file,
    "dirlist": _verify_dirlist,
    "headers": _verify_headers,
    "cookies": _verify_cookies,
}


SUPPORTED_MODULES: tuple[str, ...] = tuple(_VERIFIERS)


# Severity adjustment after verification.
def _severity_after(original: Severity, status: str) -> Severity:
    if status == "false_positive":
        return Severity.INFO
    if status == "confirmed" and original == Severity.HIGH:
        # confirmed high with strong PoC stays high; we don't auto-promote to critical
        # for non-injection categories — caller can review.
        return Severity.HIGH
    return original


def verify_findings(
    target: Target, config: ScanConfig, findings: list[Finding]
) -> list[Finding]:
    """Run verifiers across findings and return updated Finding list.

    Findings whose module is not supported are returned unchanged. Verified
    findings get an `extra["verification"]` payload, an updated `confidence`,
    and possibly an adjusted severity (false_positive -> info).
    """
    log = get_logger()
    client = HttpClient(config)
    out: list[Finding] = []
    try:
        for f in findings:
            verifier = _VERIFIERS.get(f.module)
            if verifier is None:
                out.append(f)
                continue
            try:
                log.info(
                    "[bold]Verifying:[/bold] %s (%s)",
                    f.title,
                    f.module,
                )
                result = verifier(client, f.to_dict())
            except Exception as e:  # noqa: BLE001
                log.warning("Verifier %s raised: %s", f.module, e)
                out.append(f)
                continue

            new_conf = (
                "confirmed" if result.status == "confirmed"
                else "firm" if result.status == "firm"
                else "tentative" if result.status == "tentative"
                else "tentative"  # false_positive keeps tentative for transparency
            )
            new_sev = _severity_after(f.severity, result.status)
            new_evidence = f.evidence
            if result.evidence_strong:
                if new_evidence:
                    new_evidence = new_evidence + " | " + result.evidence_strong
                else:
                    new_evidence = result.evidence_strong

            new_extra = dict(f.extra) if f.extra else {}
            new_extra["verification"] = result.to_dict()

            updated = Finding(
                module=f.module,
                title=f.title + (" [FALSE POSITIVE]" if result.status == "false_positive" else ""),
                severity=new_sev,
                description=f.description,
                target=f.target,
                evidence=new_evidence,
                remediation=f.remediation,
                references=list(f.references),
                cwe=f.cwe,
                confidence=new_conf,
                detected_at=f.detected_at,
                extra=new_extra,
            )
            log.info(
                "  -> %s: %s (severity %s -> %s)",
                f.module,
                result.status,
                f.severity.value,
                new_sev.value,
            )
            out.append(updated)
    finally:
        client.close()
    return out


# ---------------------------------------------------------------------------
# Bundle loader / writer (for CLI --verify mode)
# ---------------------------------------------------------------------------


def load_findings_from_bundle(path: str | Path) -> tuple[Target, list[Finding]]:
    """Reconstruct (Target, [Finding]) from a previously written scan bundle."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("tool") != "cyberloka":
        raise ValueError(f"{path}: not a Cyberloka scan bundle")
    target_info = data.get("target", {})
    raw = (
        target_info.get("base_url")
        or target_info.get("raw")
        or target_info.get("host")
    )
    if not raw:
        raise ValueError(f"{path}: target info missing")
    target = parse_target(raw)

    findings: list[Finding] = []
    for f in data.get("findings", []):
        try:
            sev = Severity(f.get("severity", "info"))
        except ValueError:
            sev = Severity.INFO
        findings.append(
            Finding(
                module=f.get("module", "unknown"),
                title=f.get("title", ""),
                severity=sev,
                description=f.get("description", ""),
                target=f.get("target", ""),
                evidence=f.get("evidence", "") or "",
                remediation=f.get("remediation", "") or "",
                references=list(f.get("references", []) or []),
                cwe=f.get("cwe"),
                confidence=f.get("confidence", "firm"),
                detected_at=f.get("detected_at", datetime.now(timezone.utc).isoformat()),
                extra=dict(f.get("extra", {}) or {}),
            )
        )
    return target, findings
