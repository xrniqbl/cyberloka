"""Interactive menu for Cyberloka.

When users run `cyberloka` with no arguments (or `cyberloka --menu`), they
get a friendly menu instead of the usual argparse error. The menu lets
them pick:

  1. Quick scan (passive, paling aman)
  2. Full scan (recon + passive + active)
  3. Verify temuan dari scan sebelumnya
  4. Buka Web Dashboard
  5. Lihat laporan terakhir
  6. Konfigurasi login session
  0. Keluar

Each option prompts for the few inputs it needs (target URL, output format)
and then calls into the same CLI machinery as the flag-based interface.
This keeps a single source of truth for scan execution.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from cyberloka import __version__
from cyberloka.core.logger import get_console


_DEFAULT_REPORTS_DIR = "reports"
_DEFAULT_LOGIN_CONFIG = "login.json"


def _build_args(**kwargs: object) -> list[str]:
    """Convert keyword args to CLI argv tokens."""
    out: list[str] = []
    for k, v in kwargs.items():
        if v is None or v is False:
            continue
        flag = "--" + k.replace("_", "-")
        if v is True:
            out.append(flag)
        else:
            out.extend([flag, str(v)])
    return out


def _input_target(console) -> str | None:
    while True:
        target = Prompt.ask(
            "[bold]Target URL[/bold] (mis. https://example.com)",
            default="",
        ).strip()
        if not target:
            console.print("[yellow]Dibatalkan.[/yellow]")
            return None
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target


def _input_output_formats(console) -> dict[str, bool]:
    """Ask which report formats the user wants."""
    console.print("\n[bold]Format laporan:[/bold]")
    return {
        "json": Confirm.ask("  JSON?", default=True),
        "html": Confirm.ask("  HTML (responsive, print/PDF)?", default=True),
        "txt":  Confirm.ask("  TXT (plain text, mudah dibaca)?", default=False),
        "pdf":  Confirm.ask("  PDF (formal, untuk laporan)?", default=False),
    }


def _ensure_reports_dir(console) -> str:
    reports_dir = Prompt.ask(
        "[bold]Folder output[/bold]",
        default=_DEFAULT_REPORTS_DIR,
    )
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    console.print(f"  -> reports akan ditulis ke [cyan]{reports_dir}[/cyan]")
    return reports_dir


def _maybe_login_config(console) -> str | None:
    if not Confirm.ask(
        "Aplikasi memerlukan login (scan di balik authentication)?", default=False
    ):
        return None
    path = Prompt.ask(
        "  Path ke login config JSON",
        default=_DEFAULT_LOGIN_CONFIG,
    )
    if not Path(path).exists():
        if Confirm.ask(
            f"  File [yellow]{path}[/yellow] belum ada. Buat sekarang dari prompt?",
            default=True,
        ):
            _scaffold_login_config(console, path)
        else:
            console.print("[yellow]Lanjut tanpa login session.[/yellow]")
            return None
    return path


def _scaffold_login_config(console, path: str) -> None:
    """Walk the user through filling in a minimal login.json."""
    console.print(Panel.fit(
        "Membuat config login. Tekan Enter untuk skip field optional.",
        border_style="cyan",
    ))
    method = Prompt.ask(
        "Metode login",
        choices=["form", "header", "cookie"],
        default="form",
    )
    cfg: dict[str, object] = {"method": method}
    if method == "form":
        cfg["url"] = Prompt.ask("URL login (POST endpoint)").strip()
        cfg["username"] = Prompt.ask("Username")
        cfg["password"] = Prompt.ask("Password", password=True)
        cfg["user_field"] = Prompt.ask("Nama field username", default="username")
        cfg["pass_field"] = Prompt.ask("Nama field password", default="password")
        si = Prompt.ask("Success indicator (substring di body, optional)", default="")
        if si:
            cfg["success_indicator"] = si
        csrf = Prompt.ask("URL CSRF token (optional)", default="")
        if csrf:
            cfg["csrf_url"] = csrf
            cfg["csrf_field"] = Prompt.ask("Nama field CSRF", default="csrf_token")
    elif method == "header":
        cfg["headers"] = {}
        console.print("  Tambah header (kosongkan nama untuk berhenti):")
        while True:
            name = Prompt.ask("    nama header", default="").strip()
            if not name:
                break
            value = Prompt.ask(f"    nilai untuk {name}").strip()
            cfg["headers"][name] = value
    elif method == "cookie":
        raw = Prompt.ask(
            "Cookie string (k=v;k2=v2)",
        ).strip()
        cookies: dict[str, str] = {}
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        cfg["cookies"] = cookies
    Path(path).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    console.print(f"[green]Login config disimpan ke {path} (mode 600).[/green]")


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------


def _action_quick_scan(console, run_cli: Callable[[list[str]], int]) -> int:
    target = _input_target(console)
    if not target:
        return 1
    fmts = _input_output_formats(console)
    reports_dir = _ensure_reports_dir(console)
    args = _build_args(
        target=target,
        mode="passive",
        reports_dir=reports_dir,
        json=False,
        html=False,
        txt=fmts["txt"],
        pdf=fmts["pdf"],
    )
    # Force-enable JSON and HTML by removing them from args because they're
    # produced by reports-dir already; we just want to honour user txt/pdf
    # choices here. (--reports-dir already writes JSON+HTML.)
    if not fmts["json"]:
        # If they don't want JSON, they probably don't want HTML either —
        # but we still need JSON for the dashboard to work, so we leave it.
        pass
    return run_cli(args)


def _action_full_scan(console, run_cli: Callable[[list[str]], int]) -> int:
    target = _input_target(console)
    if not target:
        return 1
    console.print(
        "[bold yellow]Mode full menjalankan probe aktif (SQLi/XSS/LFI/etc).\n"
        "Pastikan Anda berwenang men-scan target ini.[/bold yellow]"
    )
    if not Confirm.ask("Lanjutkan?", default=False):
        return 1
    fmts = _input_output_formats(console)
    reports_dir = _ensure_reports_dir(console)
    login_cfg = _maybe_login_config(console)
    verify = Confirm.ask(
        "Jalankan verifikasi mendalam setelah scan?",
        default=True,
    )

    args = _build_args(
        target=target,
        mode="full",
        authorized=True,
        reports_dir=reports_dir,
        login_config=login_cfg,
        verify_after_scan=verify,
        txt=fmts["txt"],
        pdf=fmts["pdf"],
    )
    return run_cli(args)


def _list_recent_bundles(reports_dir: Path, limit: int = 10) -> list[Path]:
    if not reports_dir.exists():
        return []
    bundles = sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return bundles[:limit]


def _action_verify(console, run_cli: Callable[[list[str]], int]) -> int:
    reports_dir_str = Prompt.ask(
        "[bold]Folder reports[/bold]",
        default=_DEFAULT_REPORTS_DIR,
    )
    reports_dir = Path(reports_dir_str)
    bundles = _list_recent_bundles(reports_dir)
    if not bundles:
        console.print(
            f"[yellow]Tidak ada bundle JSON di {reports_dir}/[/yellow]\n"
            "Jalankan scan dulu, atau ketik path file JSON langsung."
        )
        path = Prompt.ask("Path bundle JSON", default="")
        if not path:
            return 1
        bundle_path = path
    else:
        table = Table(title="Bundle scan terbaru", expand=False)
        table.add_column("#", style="dim")
        table.add_column("File")
        table.add_column("Modified")
        for i, b in enumerate(bundles, 1):
            mtime = datetime.fromtimestamp(b.stat().st_mtime, timezone.utc).strftime(
                "%Y-%m-%d %H:%M"
            )
            table.add_row(str(i), b.name, mtime)
        console.print(table)
        idx = IntPrompt.ask(
            f"Pilih nomor [1-{len(bundles)}] atau 0 untuk batal",
            default=1,
        )
        if idx <= 0 or idx > len(bundles):
            return 1
        bundle_path = str(bundles[idx - 1])

    args = _build_args(verify=bundle_path, authorized=True, reports_dir=str(reports_dir))
    return run_cli(args)


def _action_dashboard(console) -> int:
    reports_dir = Prompt.ask(
        "[bold]Folder reports[/bold]",
        default=_DEFAULT_REPORTS_DIR,
    )
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    port = IntPrompt.ask("Port", default=5005)
    open_browser = Confirm.ask("Buka di browser otomatis?", default=True)

    cmd = [
        sys.executable, "-m", "cyberloka.dashboard.app",
        "--reports-dir", reports_dir,
        "--port", str(port),
    ]
    if open_browser:
        cmd.append("--open")
    console.print(
        f"\n[bold green]Memulai dashboard...[/bold green]\n"
        f"  URL: [cyan]http://127.0.0.1:{port}/[/cyan]\n"
        "  (Tekan Ctrl+C untuk berhenti)\n"
    )
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 0
    except FileNotFoundError as e:
        console.print(f"[red]Gagal memulai dashboard: {e}[/red]")
        console.print(
            "Install dengan: [cyan]pip install 'cyberloka[dashboard]'[/cyan]"
        )
        return 1


def _action_view_last_report(console) -> int:
    reports_dir = Path(Prompt.ask(
        "[bold]Folder reports[/bold]", default=_DEFAULT_REPORTS_DIR
    ))
    htmls = sorted(reports_dir.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not htmls:
        console.print(f"[yellow]Tidak ada laporan HTML di {reports_dir}/[/yellow]")
        return 1
    table = Table(title="Laporan terbaru", expand=False)
    table.add_column("#", style="dim")
    table.add_column("File")
    table.add_column("Modified")
    for i, h in enumerate(htmls[:10], 1):
        mtime = datetime.fromtimestamp(h.stat().st_mtime, timezone.utc).strftime(
            "%Y-%m-%d %H:%M"
        )
        table.add_row(str(i), h.name, mtime)
    console.print(table)
    idx = IntPrompt.ask(f"Pilih nomor [1-{min(10, len(htmls))}] atau 0 untuk batal", default=1)
    if idx <= 0 or idx > min(10, len(htmls)):
        return 1
    chosen = htmls[idx - 1]
    url = chosen.resolve().as_uri()
    console.print(f"Membuka [cyan]{chosen}[/cyan] di browser...")
    webbrowser.open(url)
    return 0


def _action_login_config(console) -> int:
    path = Prompt.ask("Path file login config", default=_DEFAULT_LOGIN_CONFIG)
    if Path(path).exists() and not Confirm.ask(
        f"[yellow]{path} sudah ada. Overwrite?[/yellow]", default=False
    ):
        return 1
    _scaffold_login_config(console, path)
    return 0


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


_BANNER = r"""
   ____      _               _       _
  / ___|   _| |__   ___ _ __| | ___ | | ____ _
 | |  | | | | '_ \ / _ \ '__| |/ _ \| |/ / _` |
 | |__| |_| | |_) |  __/ |  | | (_) |   < (_| |
  \____\__, |_.__/ \___|_|  |_|\___/|_|\_\__,_|
       |___/
"""


def _print_banner(console) -> None:
    text = Text(_BANNER, style="bold magenta")
    text.append(
        f"  Web Vulnerability Scanner & Remediation Advisor\n"
        f"  v{__version__}\n",
        style="dim",
    )
    console.print(Panel.fit(text, border_style="magenta"))


def _print_menu(console) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("#", style="bold cyan", width=3)
    table.add_column("Aksi")
    table.add_row("1", "Quick Scan (passive, paling aman)")
    table.add_row("2", "Full Scan (recon + passive + active, butuh izin)")
    table.add_row("3", "Verify finding dari scan sebelumnya")
    table.add_row("4", "Buka Web Dashboard")
    table.add_row("5", "Lihat laporan HTML terakhir")
    table.add_row("6", "Setup login session (untuk scan di balik authentication)")
    table.add_row("0", "Keluar")
    console.print(Panel(table, title="[bold]Menu[/bold]", border_style="cyan"))


def run_menu(run_cli: Callable[[list[str]], int]) -> int:
    """Run the interactive menu loop. `run_cli` is the CLI dispatcher."""
    console = get_console()
    _print_banner(console)
    while True:
        _print_menu(console)
        try:
            choice = IntPrompt.ask("Pilih", default=1)
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Keluar.[/dim]")
            return 0
        try:
            if choice == 1:
                rc = _action_quick_scan(console, run_cli)
            elif choice == 2:
                rc = _action_full_scan(console, run_cli)
            elif choice == 3:
                rc = _action_verify(console, run_cli)
            elif choice == 4:
                return _action_dashboard(console)
            elif choice == 5:
                rc = _action_view_last_report(console)
            elif choice == 6:
                rc = _action_login_config(console)
            elif choice == 0:
                console.print("[dim]Keluar.[/dim]")
                return 0
            else:
                console.print("[yellow]Pilihan tidak dikenal.[/yellow]")
                continue
        except KeyboardInterrupt:
            console.print("\n[yellow]Dibatalkan.[/yellow]")
            continue
        if not Confirm.ask("\nKembali ke menu?", default=True):
            return rc if rc is not None else 0
