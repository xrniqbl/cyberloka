"""Cyberloka CLI entry."""
from __future__ import annotations

import argparse
import sys

from cyberloka import __version__
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
    p.add_argument("--login-url", help="URL endpoint login (untuk auth + rate-limit test)")
    p.add_argument("--login-user-field", default="username")
    p.add_argument("--login-pass-field", default="password")
    p.add_argument("--login-test-user", default="admin")
    p.add_argument("--login-username", help="Username asli untuk authenticated scan")
    p.add_argument("--login-password", help="Password untuk authenticated scan")
    p.add_argument("--auth-bearer", help="Bearer token (Authorization: Bearer ...)")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--rate", type=float, default=10.0, help="Maks request/detik per client")
    p.add_argument("--user-agent", default=None)
    p.add_argument("--cookies", help="`k=v;k2=v2`")
    p.add_argument("--header", action="append", default=[], help="Tambah header `Name: value` (boleh diulang)")
    p.add_argument("--no-verify-tls", action="store_true")
    p.add_argument("--proxy", help="HTTP proxy URL (mis. http://127.0.0.1:8080)")
    p.add_argument("--json", dest="json_out", help="Path output JSON")
    p.add_argument("--html", dest="html_out", help="Path output HTML")
    p.add_argument(
        "--pdf",
        dest="pdf_out",
        nargs="?",
        const="__auto__",
        default="__auto__",
        help=(
            "Path output PDF. Tanpa nilai akan auto-naming: "
            "`cyberloka-report-<host>-<timestamp>.pdf`. "
            "Default tanpa flag: PDF tetap dihasilkan otomatis."
        ),
    )
    p.add_argument(
        "--no-pdf",
        action="store_true",
        help="Nonaktifkan generate PDF (default: aktif).",
    )
    p.add_argument(
        "--report-dir",
        default=None,
        help="Direktori output untuk auto-named PDF (default: working directory).",
    )
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--yes", action="store_true", help="Lewati prompt konfirmasi")
    p.add_argument(
        "--poc",
        action="store_true",
        help=(
            "Aktifkan Safe Proof-of-Concept: buktikan RCE/SQLi dengan payload "
            "JINAK & read-only (echo nonce, id, baca versi DB). Tidak merusak, "
            "tidak menanam apa pun. Wajib bareng --authorized."
        ),
    )
    p.add_argument("--version", action="version", version=f"cyberloka {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
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
        poc=args.poc,
        simulate_attack=args.simulate_attack,
        login_url=args.login_url,
        login_user_field=args.login_user_field,
        login_pass_field=args.login_pass_field,
        login_test_user=args.login_test_user,
        login_username=args.login_username,
        login_password=args.login_password,
        auth_bearer_token=args.auth_bearer,
        quiet=args.quiet,
        json_out=args.json_out,
        html_out=args.html_out,
        proxy=args.proxy,
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

    # PDF: enabled by default, disabled with --no-pdf
    if not args.no_pdf:
        pdf_path_arg: str | None
        if args.pdf_out == "__auto__":
            pdf_path_arg = None  # let writer auto-name
        else:
            pdf_path_arg = args.pdf_out
        try:
            # Lazy import: reportlab is heavy and only needed for PDF.
            from cyberloka.reporting.pdf_report import write_pdf
            actual_pdf = write_pdf(
                pdf_path_arg, target, cfg, findings, out_dir=args.report_dir
            )
            log.info("[green]PDF report ditulis ke %s[/green]", actual_pdf)
        except ImportError as e:
            log.error(
                "Gagal menulis PDF report: %s. "
                "Pastikan paket `reportlab` terpasang: pip install reportlab",
                e,
            )
        except Exception as e:  # noqa: BLE001
            log.error("Gagal menulis PDF report: %s", e)

    # Exit code: 0 = no high+ findings; 1 = ada high/critical
    if any(f.severity.value in ("critical", "high") for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
