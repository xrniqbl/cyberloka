"""Interactive menu for Cyberloka.

Designed for one-handed use: pilih nomor, masukkan domain/IP, selesai.

Main menu (`cyberloka` tanpa argumen):
  1. Scan website
  2. Verifikasi finding (deep re-test)
  3. Buka Web Dashboard
  4. Lihat laporan terakhir
  5. Setup login session
  0. Keluar

Submenu Scan:
  1. Quick Scan      (passive, paling aman)
  2. Full Scan       (recon + passive + active, butuh izin)
  3. Authenticated   (scan di balik login - butuh login.json)
  0. Kembali

All actions use sensible defaults: reports/ folder, all formats (JSON, HTML,
TXT, PDF kalau reportlab tersedia), verify-after-scan untuk full mode,
auto-open dashboard kalau sudah ada flask.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Callable

from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from cyberloka import __version__
from cyberloka.core.logger import get_console


_REPORTS_DIR = "reports"
_LOGIN_CONFIG = "login.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _normalize_target(raw: str) -> str:
    """Tambahkan https:// kalau user cuma ngetik domain/IP polos."""
    raw = raw.strip().rstrip("/")
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return raw
    return "https://" + raw


def _ask_target(console) -> str | None:
    """Tanya target. Boleh berupa domain (example.com) atau IP atau URL penuh."""
    while True:
        raw = Prompt.ask(
            "[bold cyan]>>[/bold cyan] Masukkan domain atau IP target",
            default="",
        )
        target = _normalize_target(raw)
        if not target:
            console.print("[yellow]Dibatalkan.[/yellow]")
            return None
        # Validasi sederhana: harus ada titik atau localhost
        host_part = target.split("://", 1)[1].split("/")[0].split(":")[0]
        if not host_part or (
            "." not in host_part
            and host_part not in ("localhost",)
            and not host_part.replace(":", "").isdigit()
        ):
            console.print(
                f"[red]Target tidak valid: '{raw}'. "
                "Contoh: example.com, 192.168.1.1, https://example.com[/red]"
            )
            continue
        console.print(f"  -> Target: [cyan]{target}[/cyan]")
        return target


def _has_module(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _smart_defaults() -> dict:
    """Return default scan options based on what's installed."""
    Path(_REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    return {
        "reports_dir": _REPORTS_DIR,
        "txt": True,                          # selalu tulis txt (no extra dep)
        "pdf": _has_module("reportlab"),       # kalau reportlab ada
        "open_dashboard": _has_module("flask"),  # kalau flask ada
    }


# ---------------------------------------------------------------------------
# Login config scaffolding
# ---------------------------------------------------------------------------

def _scaffold_login_config(console, path: str) -> None:
    """Walk the user through filling in a minimal login.json."""
    console.print(Panel.fit(
        "Setup login config. Tekan Enter untuk skip field optional.",
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
        raw = Prompt.ask("Cookie string (k=v;k2=v2)").strip()
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
    console.print(f"[green]Login config disimpan ke {path}[/green]")


# ---------------------------------------------------------------------------
# Scan submenu
# ---------------------------------------------------------------------------

def _print_scan_submenu(console) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("#", style="bold cyan", width=3)
    table.add_column("Jenis Scan")
    table.add_column("Deskripsi", style="dim")
    table.add_row("1", "Quick Scan", "Passive only - paling aman, no izin needed")
    table.add_row("2", "Full Scan", "Recon + passive + active (SQLi/XSS/dll)")
    table.add_row("3", "Authenticated", "Full scan di balik login (butuh login.json)")
    table.add_row("0", "Kembali ke menu utama", "")
    console.print(Panel(table, title="[bold]Pilih Jenis Scan[/bold]", border_style="cyan"))


def _action_scan(console, run_cli: Callable[[list[str]], int]) -> int:
    """Submenu scan: pilih jenis scan, lalu masukkan target."""
    while True:
        _print_scan_submenu(console)
        try:
            choice = IntPrompt.ask("Pilih [0-3]", default=1)
        except (EOFError, KeyboardInterrupt):
            return 0

        if choice == 0:
            return 0
        if choice not in (1, 2, 3):
            console.print("[yellow]Pilihan tidak dikenal.[/yellow]")
            continue

        # Step 2: minta target
        target = _ask_target(console)
        if not target:
            return 1

        defaults = _smart_defaults()

        if choice == 1:
            console.print("\n[bold green]>> Quick Scan (passive)[/bold green]\n")
            args = _build_args(
                target=target,
                mode="passive",
                reports_dir=defaults["reports_dir"],
                txt=defaults["txt"],
                pdf=defaults["pdf"],
                yes=True,  # no extra prompt
            )
            return run_cli(args)

        if choice == 2:
            console.print(
                "\n[bold yellow]>> Full Scan (active probes: SQLi/XSS/LFI/dll)[/bold yellow]"
            )
            console.print(
                "[yellow]   Pastikan Anda berwenang men-scan target ini.[/yellow]"
            )
            if not Confirm.ask("Lanjutkan?", default=True):
                continue
            args = _build_args(
                target=target,
                mode="full",
                authorized=True,
                reports_dir=defaults["reports_dir"],
                txt=defaults["txt"],
                pdf=defaults["pdf"],
                verify_after_scan=True,
                open_dashboard=defaults["open_dashboard"],
                yes=True,
            )
            return run_cli(args)

        if choice == 3:  # Authenticated scan
            console.print("\n[bold magenta]>> Authenticated Scan[/bold magenta]\n")
            login_path = Path(_LOGIN_CONFIG)
            if not login_path.exists():
                console.print(
                    f"[yellow]File [bold]{login_path}[/bold] belum ada.[/yellow]"
                )
                if Confirm.ask("Buat sekarang?", default=True):
                    _scaffold_login_config(console, str(login_path))
                else:
                    continue
            console.print(
                "[yellow]   Pastikan Anda berwenang men-scan target ini.[/yellow]"
            )
            if not Confirm.ask("Lanjutkan?", default=True):
                continue
            args = _build_args(
                target=target,
                mode="full",
                authorized=True,
                login_config=str(login_path),
                reports_dir=defaults["reports_dir"],
                txt=defaults["txt"],
                pdf=defaults["pdf"],
                verify_after_scan=True,
                open_dashboard=defaults["open_dashboard"],
                yes=True,
            )
            return run_cli(args)


# ---------------------------------------------------------------------------
# Other top-level actions
# ---------------------------------------------------------------------------

def _list_recent_files(reports_dir: Path, ext: str, limit: int = 10) -> list[Path]:
    if not reports_dir.exists():
        return []
    files = sorted(reports_dir.glob(f"*.{ext}"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit]


def _action_verify(console, run_cli: Callable[[list[str]], int]) -> int:
    """Pick recent JSON bundle by number, verify it."""
    reports_dir = Path(_REPORTS_DIR)
    bundles = _list_recent_files(reports_dir, "json")
    if not bundles:
        console.print(
            f"[yellow]Belum ada hasil scan di {reports_dir}/[/yellow]\n"
            "Jalankan scan dulu (menu 1)."
        )
        return 1

    table = Table(title="Hasil scan terbaru", expand=False)
    table.add_column("#", style="bold cyan", width=3)
    table.add_column("File")
    table.add_column("Tanggal", style="dim")
    for i, b in enumerate(bundles, 1):
        mtime = datetime.fromtimestamp(b.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        table.add_row(str(i), b.name, mtime)
    console.print(table)

    try:
        idx = IntPrompt.ask(f"Pilih nomor [1-{len(bundles)}] atau 0 untuk batal", default=1)
    except (EOFError, KeyboardInterrupt):
        return 0
    if idx <= 0 or idx > len(bundles):
        return 0
    bundle_path = str(bundles[idx - 1])
    console.print(f"\n[bold green]>> Verifying {Path(bundle_path).name}...[/bold green]\n")

    args = _build_args(
        verify=bundle_path,
        authorized=True,
        reports_dir=str(reports_dir),
        yes=True,
    )
    return run_cli(args)


def _action_dashboard(console) -> int:
    """Buka dashboard. No prompt - pakai default port + reports folder + auto-open."""
    Path(_REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    console.print(
        f"\n[bold green]>> Memulai Web Dashboard...[/bold green]\n"
        f"  URL: [cyan]http://127.0.0.1:5005/[/cyan]\n"
        "  (Tekan Ctrl+C untuk berhenti)\n"
    )
    cmd = [
        sys.executable, "-m", "cyberloka.dashboard.app",
        "--reports-dir", _REPORTS_DIR,
        "--open",
    ]
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 0
    except FileNotFoundError as e:
        console.print(f"[red]Gagal memulai dashboard: {e}[/red]")
        console.print("Install: [cyan]pip install 'cyberloka[dashboard]'[/cyan]")
        return 1


def _action_view_last_report(console) -> int:
    """Pilih laporan HTML terbaru by number, buka di browser."""
    htmls = _list_recent_files(Path(_REPORTS_DIR), "html")
    if not htmls:
        console.print(f"[yellow]Belum ada laporan HTML di {_REPORTS_DIR}/[/yellow]")
        return 1
    table = Table(title="Laporan HTML terbaru", expand=False)
    table.add_column("#", style="bold cyan", width=3)
    table.add_column("File")
    table.add_column("Tanggal", style="dim")
    for i, h in enumerate(htmls, 1):
        mtime = datetime.fromtimestamp(h.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        table.add_row(str(i), h.name, mtime)
    console.print(table)
    try:
        idx = IntPrompt.ask(f"Pilih nomor [1-{len(htmls)}] atau 0 untuk batal", default=1)
    except (EOFError, KeyboardInterrupt):
        return 0
    if idx <= 0 or idx > len(htmls):
        return 0
    chosen = htmls[idx - 1]
    console.print(f"Membuka [cyan]{chosen.name}[/cyan] di browser...")
    webbrowser.open(chosen.resolve().as_uri())
    return 0


def _action_login_config(console) -> int:
    path = _LOGIN_CONFIG
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
    table.add_column("Deskripsi", style="dim")
    table.add_row("1", "Scan Website", "Pilih jenis scan (quick / full / authenticated)")
    table.add_row("2", "Verifikasi Finding", "Re-test finding untuk pisahkan real vs false-positive")
    table.add_row("3", "Buka Web Dashboard", "Lihat semua scan + grade trend di browser")
    table.add_row("4", "Lihat Laporan Terakhir", "Buka laporan HTML di browser")
    table.add_row("5", "Setup Login Session", "Buat login.json untuk authenticated scan")
    table.add_row("6", "Daftar Module", "Lihat semua modul deteksi & mode mana yang menjalankan")
    table.add_row("0", "Keluar", "")
    console.print(Panel(table, title="[bold]Menu Utama[/bold]", border_style="cyan"))


def run_menu(run_cli: Callable[[list[str]], int]) -> int:
    """Run the interactive menu loop. `run_cli` is the CLI dispatcher."""
    console = get_console()
    _print_banner(console)
    while True:
        _print_menu(console)
        try:
            choice = IntPrompt.ask("Pilih [0-6]", default=1)
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Keluar.[/dim]")
            return 0
        try:
            if choice == 1:
                rc = _action_scan(console, run_cli)
            elif choice == 2:
                rc = _action_verify(console, run_cli)
            elif choice == 3:
                return _action_dashboard(console)
            elif choice == 4:
                rc = _action_view_last_report(console)
            elif choice == 5:
                rc = _action_login_config(console)
            elif choice == 6:
                rc = run_cli(["--list-modules"])
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
