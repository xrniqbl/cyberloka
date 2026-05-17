"""Cyberloka CLI entry."""
from __future__ import annotations

import argparse
import sys

from cyberloka import __version__
from cyberloka.core.auth import AuthConfig
from cyberloka.core.config import ScanConfig
from cyberloka.core.logger import get_console, get_logger
from cyberloka.core.target import parse_target
from cyberloka.reporting import console as console_report
from cyberloka.reporting.html_report import write_html
from cyberloka.reporting.json_report import write_json
from cyberloka.scanner import MODULE_MAP, run_scan

ETHICS_NOTICE = (
    "[bold yellow]CYBERLOKA - LEGAL & ETHICS NOTICE[/bold yellow]\n"
    "Tool ini hanya boleh dipakai pada target yang Anda miliki sendiri\n"
    "atau yang telah memberi izin tertulis. Penggunaan tanpa izin dapat\n"
    "melanggar hukum (UU ITE, CFAA, dll). Anda bertanggung jawab penuh."
)


def parse_cookies(s: str | None) -> dict[str, str]:
    if not s:
        return {}
    out: dict[str, str] = {}
    for part in s.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def parse_headers(values: list[str] | None) -> dict[str, str]:
    if not values:
        return {}
    out: dict[str, str] = {}
    for v in values:
        if ":" not in v:
            continue
        k, val = v.split(":", 1)
        out[k.strip()] = val.strip()
    return out


def parse_form_fields(values: list[str] | None) -> dict[str, str]:
    if not values:
        return {}
    out: dict[str, str] = {}
    for v in values:
        if "=" not in v:
            continue
        k, val = v.split("=", 1)
        out[k.strip()] = val.strip()
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberloka",
        description="Cyberloka - Web vulnerability scanner & remediation advisor.",
    )
    p.add_argument("-t", "--target", required=True, help="URL atau IP target (mis. https://example.com)")
    p.add_argument(
        "--mode",
        choices=("passive", "active", "full"),
        default="passive",
        help="Profil scan (default: passive)",
    )
    p.add_argument(
        "--modules",
        help=f"Daftar modul (comma-separated). Pilihan: {', '.join(sorted(MODULE_MAP))}",
    )
    p.add_argument("--authorized", action="store_true", help="Konfirmasi izin men-scan target")
    p.add_argument("--simulate-attack", action="store_true", help="Aktifkan modul simulate (burst, rate-limit)")
    p.add_argument("--login-url", help="URL endpoint login (untuk rate-limit test)")
    p.add_argument("--login-user-field", default="username")
    p.add_argument("--login-pass-field", default="password")
    p.add_argument("--login-test-user", default="admin")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--rate", type=float, default=10.0, help="Maks request/detik per client")
    p.add_argument("--user-agent", default=None)
    p.add_argument("--cookies", help="`k=v;k2=v2`")
    p.add_argument("--header", action="append", default=[], help="Tambah header `Name: value` (boleh diulang)")
    p.add_argument("--no-verify-tls", action="store_true")
    p.add_argument("--proxy", help="HTTP proxy URL (mis. http://127.0.0.1:8080)")

    # Crawler
    p.add_argument("--crawl", action="store_true", help="Aktifkan crawler/spider untuk discover endpoint")
    p.add_argument("--crawl-max-pages", type=int, default=60)
    p.add_argument("--crawl-max-depth", type=int, default=3)

    # Authenticated scan
    p.add_argument("--auth-method", choices=("none", "form", "bearer"), default="none",
                   help="Metode otentikasi sebelum scan")
    p.add_argument("--auth-login-url", help="URL form login (untuk --auth-method form)")
    p.add_argument("--auth-user", help="Username untuk form login")
    p.add_argument("--auth-pass", help="Password untuk form login")
    p.add_argument("--auth-user-field", default="username")
    p.add_argument("--auth-pass-field", default="password")
    p.add_argument("--auth-form-field", action="append", default=[],
                   help="Field form tambahan `key=value` (boleh diulang)")
    p.add_argument("--auth-token", help="Bearer token (untuk --auth-method bearer)")
    p.add_argument("--auth-success-marker", help="Regex yang harus muncul setelah login berhasil")
    p.add_argument("--auth-failure-marker", help="Regex yang menandakan login gagal")

    # Output
    p.add_argument("--json", dest="json_out", help="Path output JSON")
    p.add_argument("--html", dest="html_out", help="Path output HTML")
    p.add_argument("--narrative", dest="narrative_out", nargs="?", const="-",
                   help="Cetak ringkasan naratif bahasa Indonesia. Tambah path untuk simpan ke file (mis. --narrative report.txt)")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--yes", action="store_true", help="Lewati prompt konfirmasi")
    p.add_argument("--version", action="version", version=f"cyberloka {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    # Subcommand: cyberloka diff <old.json> <new.json> [--json out.json]
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "diff":
        return _diff_main(raw[1:])

    args = build_parser().parse_args(argv)
    console = get_console()
    log = get_logger()

    console.print(ETHICS_NOTICE)
    console.print()

    try:
        target = parse_target(args.target)
    except ValueError as e:
        log.error("Target tidak valid: %s", e)
        return 2

    auth = AuthConfig(
        method=args.auth_method,
        login_url=args.auth_login_url,
        username=args.auth_user,
        password=args.auth_pass,
        user_field=args.auth_user_field,
        pass_field=args.auth_pass_field,
        extra_form_fields=parse_form_fields(args.auth_form_field),
        bearer_token=args.auth_token,
        success_marker=args.auth_success_marker,
        failure_marker=args.auth_failure_marker,
    )

    cfg = ScanConfig(
        target=args.target,
        mode=args.mode,
        modules=[m.strip() for m in args.modules.split(",")] if args.modules else [],
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate,
        user_agent=args.user_agent or ScanConfig.__dataclass_fields__["user_agent"].default,
        cookies=parse_cookies(args.cookies),
        headers=parse_headers(args.header),
        verify_tls=not args.no_verify_tls,
        authorized=args.authorized,
        simulate_attack=args.simulate_attack,
        login_url=args.login_url,
        login_user_field=args.login_user_field,
        login_pass_field=args.login_pass_field,
        login_test_user=args.login_test_user,
        quiet=args.quiet,
        json_out=args.json_out,
        html_out=args.html_out,
        proxy=args.proxy,
        auth=auth,
        crawl=args.crawl,
        crawl_max_pages=args.crawl_max_pages,
        crawl_max_depth=args.crawl_max_depth,
    )

    needs_intrusive = cfg.mode in ("active", "full") or cfg.simulate_attack
    if needs_intrusive and not cfg.authorized:
        if args.yes:
            cfg.authorized = True
        else:
            console.print(
                "[bold red]Mode aktif/simulasi memerlukan flag --authorized "
                "(atau --yes) untuk konfirmasi izin.[/bold red]"
            )
            try:
                ans = input("Apakah Anda berwenang men-scan target ini? (yes/N) ").strip().lower()
            except EOFError:
                ans = ""
            if ans not in ("yes", "y"):
                console.print("[red]Dibatalkan.[/red]")
                return 1
            cfg.authorized = True

    console_report.render_banner(target.base_url, cfg.mode, cfg.resolve_modules())

    findings = run_scan(target, cfg)

    # Perkaya finding dengan impact / attack scenario / fix examples / manual steps
    from cyberloka.reporting.enrich import enrich_findings
    findings = enrich_findings(findings)

    console.print()
    console_report.render_findings(findings)
    console.print()
    if not cfg.quiet:
        for i, f in enumerate(
            sorted(findings, key=lambda x: (x.severity.order, x.module)), 1
        ):
            console_report.render_finding_detail(f, i)
    console_report.render_summary(findings)

    if cfg.json_out:
        write_json(cfg.json_out, target, cfg, findings)
        log.info("[green]JSON report ditulis ke %s[/green]", cfg.json_out)
    if cfg.html_out:
        write_html(cfg.html_out, target, cfg, findings)
        log.info("[green]HTML report ditulis ke %s[/green]", cfg.html_out)

    # Narrative report (Indonesian, human-friendly)
    if args.narrative_out is not None:
        from cyberloka.reporting.narrative import build_narrative
        text = build_narrative(target.base_url, findings)
        if args.narrative_out == "-":
            console.print()
            console.print(text)
        else:
            with open(args.narrative_out, "w", encoding="utf-8") as fp:
                fp.write(text)
            log.info("[green]Narrative report ditulis ke %s[/green]", args.narrative_out)
            console.print()
            console.print(text)

    # Exit code: 0 = no high+ findings; 1 = ada high/critical
    if any(f.severity.value in ("critical", "high") for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())




def _diff_main(argv: list[str]) -> int:
    """Subcommand: cyberloka diff <old.json> <new.json> [--json out.json]"""
    parser = argparse.ArgumentParser(
        prog="cyberloka diff",
        description="Bandingkan dua report JSON Cyberloka.",
    )
    parser.add_argument("old", help="Path report JSON sebelumnya")
    parser.add_argument("new", help="Path report JSON terbaru")
    parser.add_argument("--json", dest="json_out", help="Tulis hasil diff sebagai JSON")
    parser.add_argument("--fail-on-new", action="store_true",
                        help="Exit code != 0 bila ada finding baru")
    args = parser.parse_args(argv)

    from cyberloka.reporting.diff import diff_files, render_text

    diff = diff_files(args.old, args.new)
    console = get_console()
    console.print(render_text(diff))
    if args.json_out:
        import json as _json
        with open(args.json_out, "w", encoding="utf-8") as fp:
            _json.dump(diff.to_dict(), fp, indent=2, ensure_ascii=False)
        console.print(f"[green]Diff JSON ditulis ke {args.json_out}[/green]")
    if args.fail_on_new and diff.new:
        return 2
    return 0
