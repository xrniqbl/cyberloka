"""Cyberloka CLI entry."""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from cyberloka import __version__
from cyberloka.active.verify import (
    SUPPORTED_MODULES as VERIFY_SUPPORTED,
    load_findings_from_bundle,
    verify_findings,
)
from cyberloka.core.config import LoginSession, ScanConfig
from cyberloka.core.logger import get_console, get_logger
from cyberloka.core.target import parse_target
from cyberloka.reporting import console as console_report
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


def _slug(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", s.strip())
    return s.strip("-") or "target"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberloka",
        description=(
            "Cyberloka - Web vulnerability scanner & remediation advisor.\n"
            "Jalankan tanpa argumen untuk membuka menu interaktif."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--menu",
        action="store_true",
        help="Buka menu interaktif (default jika dijalankan tanpa argumen).",
    )
    # --target is required for normal scans, but optional in --verify mode.
    p.add_argument(
        "-t",
        "--target",
        required=False,
        help="URL atau IP target (mis. https://example.com). Wajib kecuali memakai --verify.",
    )
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
    p.add_argument(
        "--login-config",
        metavar="LOGIN.json",
        help=(
            "Path ke JSON config untuk authenticated session "
            "(form/header/cookie). Lihat README untuk format."
        ),
    )
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
    p.add_argument("--txt", dest="txt_out", nargs="?", const="__auto__", help=(
        "Tulis laporan TXT. Tanpa value, otomatis pakai nama default "
        "atau folder --reports-dir."
    ))
    p.add_argument("--pdf", dest="pdf_out", nargs="?", const="__auto__", help=(
        "Tulis laporan PDF (butuh ReportLab; install: pip install 'cyberloka[pdf]'). "
        "Tanpa value, otomatis pakai nama default atau folder --reports-dir."
    ))
    p.add_argument(
        "--reports-dir",
        help=(
            "Direktori output. Akan otomatis menulis JSON+HTML "
            "(plus TXT/PDF kalau --txt/--pdf disetel) dengan nama bertanggal di sini "
            "(kompatibel dengan dashboard)."
        ),
    )
    p.add_argument(
        "--open-dashboard",
        action="store_true",
        help="Setelah scan selesai, buka Web Dashboard secara otomatis.",
    )
    p.add_argument(
        "--no-compliance",
        action="store_true",
        help="Sembunyikan tabel compliance di console.",
    )
    # --- Verify (deep re-scan) options ----------------------------------
    p.add_argument(
        "--verify",
        metavar="SCAN.json",
        help=(
            "Mode verifikasi: load bundle JSON hasil scan sebelumnya dan "
            "lakukan re-test mendalam pada finding yang ditemukan untuk "
            f"memastikan apakah benar-benar exploitable. Modul yang didukung: "
            f"{', '.join(VERIFY_SUPPORTED)}."
        ),
    )
    p.add_argument(
        "--verify-after-scan",
        action="store_true",
        help=(
            "Setelah scan biasa selesai, langsung jalankan verifikasi pada "
            "finding yang baru ditemukan (one-shot scan + verify)."
        ),
    )
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--yes", action="store_true", help="Lewati prompt konfirmasi")
    p.add_argument("--version", action="version", version=f"cyberloka {__version__}")
    return p


def _resolve_outputs(
    args: argparse.Namespace, target_host: str, *, suffix: str = ""
) -> dict[str, str | None]:
    """Combine --json/--html/--txt/--pdf + --reports-dir into output paths."""
    json_out = args.json_out
    html_out = args.html_out
    txt_out = args.txt_out
    pdf_out = args.pdf_out

    def _auto(ext: str) -> str | None:
        if args.reports_dir:
            base = Path(args.reports_dir)
            base.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return str(base / f"{_slug(target_host)}{suffix}-{ts}.{ext}")
        return f"{_slug(target_host)}{suffix}.{ext}"

    if args.reports_dir and not json_out:
        json_out = _auto("json")
    if args.reports_dir and not html_out:
        html_out = _auto("html")
    if txt_out == "__auto__":
        txt_out = _auto("txt")
    elif txt_out is None and args.reports_dir is None:
        txt_out = None  # only emit if explicitly requested
    if pdf_out == "__auto__":
        pdf_out = _auto("pdf")
    elif pdf_out is None and args.reports_dir is None:
        pdf_out = None

    return {
        "json_out": json_out,
        "html_out": html_out,
        "txt_out": txt_out,
        "pdf_out": pdf_out,
    }


def _load_login_config(path: str, log) -> LoginSession | None:
    """Load and validate a login config file. Returns None if path missing."""
    p = Path(path)
    if not p.exists():
        log.error("--login-config tidak ditemukan: %s", path)
        return None
    try:
        return LoginSession.from_file(p)
    except Exception as e:  # noqa: BLE001
        log.error("Gagal memuat login config %s: %s", path, e)
        return None


def _build_config_from_args(args: argparse.Namespace, target_url: str) -> ScanConfig:
    """Construct a ScanConfig from CLI args, given an effective target URL."""
    log = get_logger()
    login_session: LoginSession | None = None
    if args.login_config:
        login_session = _load_login_config(args.login_config, log)
        if login_session is None:
            # Hard fail: user explicitly asked for auth and we can't honour it.
            raise SystemExit(2)
    return ScanConfig(
        target=target_url,
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
        login_session=login_session,
        quiet=args.quiet,
        proxy=args.proxy,
    )


def _ensure_authorized(cfg: ScanConfig, console, args: argparse.Namespace) -> bool:
    if cfg.authorized:
        return True
    if args.yes:
        cfg.authorized = True
        return True
    console.print(
        "[bold red]Mode aktif/simulasi/verifikasi memerlukan flag --authorized "
        "(atau --yes) untuk konfirmasi izin.[/bold red]"
    )
    try:
        ans = input("Apakah Anda berwenang men-scan target ini? (yes/N) ").strip().lower()
    except EOFError:
        ans = ""
    if ans not in ("yes", "y"):
        console.print("[red]Dibatalkan.[/red]")
        return False
    cfg.authorized = True
    return True


def _run_verify_only(args: argparse.Namespace) -> int:
    """Handle `cyberloka --verify scan.json` — load + re-test + write."""
    console = get_console()
    log = get_logger()

    bundle_path = Path(args.verify)
    if not bundle_path.exists():
        log.error("File tidak ditemukan: %s", bundle_path)
        return 2

    try:
        target, findings = load_findings_from_bundle(bundle_path)
    except Exception as e:  # noqa: BLE001
        log.error("Gagal memuat bundle %s: %s", bundle_path, e)
        return 2

    cfg = _build_config_from_args(args, target.base_url)

    # Verification reaches the live target -> it counts as intrusive.
    if not _ensure_authorized(cfg, console, args):
        return 1

    # Default outputs: when --reports-dir is set, write a `.verified` file.
    outs = _resolve_outputs(args, target.host, suffix=".verified")
    cfg.json_out = outs["json_out"]
    cfg.html_out = outs["html_out"]
    cfg.txt_out = outs["txt_out"]
    cfg.pdf_out = outs["pdf_out"]

    console_report.render_banner(
        target.base_url, "verify", [f.module for f in findings if f.module in VERIFY_SUPPORTED] or ["(none)"]
    )
    console.print(f"[dim]Memuat {len(findings)} finding dari {bundle_path}[/dim]\n")

    verified = verify_findings(target, cfg, findings)
    return _emit_reports(target, cfg, verified, args, console=console, log=log)


def _emit_reports(
    target,
    cfg: ScanConfig,
    findings,
    args: argparse.Namespace,
    *,
    console,
    log,
) -> int:
    """Render console output + write JSON/HTML/TXT/PDF if requested."""
    console.print()
    console_report.render_executive_summary(findings)
    console.print()
    console_report.render_findings(findings)
    console.print()
    if not args.no_compliance:
        console_report.render_compliance_summary(findings)
        console.print()
    # Verification table (only if any finding has been verified)
    if any(f.extra and f.extra.get("verification") for f in findings):
        console_report.render_verification_summary(findings)
        console.print()
    if not cfg.quiet:
        from cyberloka.core.risk import score_finding
        for i, f in enumerate(
            sorted(
                findings,
                key=lambda x: (-score_finding(x), x.severity.order, x.module),
            ),
            1,
        ):
            console_report.render_finding_detail(f, i)
    console_report.render_summary(findings)

    if cfg.json_out:
        write_json(cfg.json_out, target, cfg, findings)
        log.info("[green]JSON report ditulis ke %s[/green]", cfg.json_out)
    if cfg.html_out:
        try:
            from cyberloka.reporting.html_report import write_html
        except ImportError as e:
            log.warning("Lewati output HTML (jinja2 tidak tersedia: %s).", e)
        else:
            write_html(cfg.html_out, target, cfg, findings)
            log.info("[green]HTML report ditulis ke %s[/green]", cfg.html_out)
    if cfg.txt_out:
        from cyberloka.reporting.txt_report import write_txt
        write_txt(cfg.txt_out, target, cfg, findings)
        log.info("[green]TXT report ditulis ke %s[/green]", cfg.txt_out)
    if cfg.pdf_out:
        try:
            from cyberloka.reporting.pdf_report import write_pdf
        except ImportError as e:
            log.warning(
                "Lewati output PDF (%s). Install: pip install 'cyberloka[pdf]'", e
            )
        else:
            try:
                write_pdf(cfg.pdf_out, target, cfg, findings)
                log.info("[green]PDF report ditulis ke %s[/green]", cfg.pdf_out)
            except ImportError as e:
                log.warning("Lewati output PDF: %s", e)

    # Optional: launch dashboard right after writing reports.
    if args.open_dashboard and args.reports_dir:
        _launch_dashboard(args.reports_dir, console, log)

    if any(f.severity.value in ("critical", "high") for f in findings):
        return 1
    return 0


def _launch_dashboard(reports_dir: str, console, log) -> None:
    """Start the dashboard as a subprocess and open the browser."""
    import subprocess
    cmd = [
        sys.executable,
        "-m", "cyberloka.dashboard.app",
        "--reports-dir", reports_dir,
        "--open",
    ]
    console.print(
        f"\n[bold green]Memulai dashboard...[/bold green] "
        f"(reports-dir: [cyan]{reports_dir}[/cyan])"
    )
    try:
        # Detached: user can Ctrl+C the dashboard separately.
        subprocess.Popen(cmd)
    except FileNotFoundError:
        log.error("Gagal memulai dashboard. Install: pip install 'cyberloka[dashboard]'")


def main(argv: list[str] | None = None) -> int:
    # If user runs `cyberloka` with no args, drop into the interactive menu.
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv == ["--menu"]:
        from cyberloka.menu import run_menu
        return run_menu(lambda subargs: main(subargs))

    args = build_parser().parse_args(argv)
    console = get_console()
    log = get_logger()

    console.print(ETHICS_NOTICE)
    console.print()

    # Verify-only mode
    if args.verify:
        return _run_verify_only(args)

    # Standard scan mode requires --target
    if not args.target:
        log.error(
            "--target wajib diisi (kecuali memakai --verify atau --menu)."
        )
        return 2

    try:
        target = parse_target(args.target)
    except ValueError as e:
        log.error("Target tidak valid: %s", e)
        return 2

    outs = _resolve_outputs(args, target.host)

    cfg = _build_config_from_args(args, args.target)
    cfg.json_out = outs["json_out"]
    cfg.html_out = outs["html_out"]
    cfg.txt_out = outs["txt_out"]
    cfg.pdf_out = outs["pdf_out"]

    needs_intrusive = (
        cfg.mode in ("active", "full")
        or cfg.simulate_attack
        or args.verify_after_scan
    )
    if needs_intrusive and not _ensure_authorized(cfg, console, args):
        return 1

    console_report.render_banner(target.base_url, cfg.mode, cfg.resolve_modules())

    findings = run_scan(target, cfg)

    if args.verify_after_scan:
        console.print(
            "\n[bold magenta]Memulai verifikasi mendalam pada finding...[/bold magenta]"
        )
        findings = verify_findings(target, cfg, findings)

    return _emit_reports(target, cfg, findings, args, console=console, log=log)


if __name__ == "__main__":
    sys.exit(main())
