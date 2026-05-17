"""Flask web dashboard for Cyberloka scan reports."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

try:
    from flask import (
        Flask,
        abort,
        jsonify,
        render_template,
        request,
    )
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "Flask is not installed. Install the optional dashboard extras with:\n"
        "    pip install 'cyberloka[dashboard]'"
    ) from e

from cyberloka import __version__
from cyberloka.dashboard.helpers import diff_findings, filter_findings
from cyberloka.dashboard.storage import ReportStore


def create_app(reports_dir: str | Path) -> Flask:
    """Application factory."""
    pkg_root = Path(__file__).parent
    app = Flask(
        __name__,
        template_folder=str(pkg_root / "templates"),
        static_folder=str(pkg_root / "static"),
    )
    store = ReportStore(reports_dir)
    store.ensure()

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {
            "tool_version": __version__,
            "reports_dir": str(store.reports_dir),
        }

    # ------------------------------------------------------------------
    # Pages
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        scans = store.list_scans()
        host_filter = request.args.get("host") or ""
        if host_filter:
            scans = [s for s in scans if s.host == host_filter]
        hosts = sorted({s.host for s in store.list_scans() if s.host})
        # latest grade per host (for the dashboard cards)
        latest_per_host: dict[str, dict] = {}
        for s in store.list_scans():
            if s.host and s.host not in latest_per_host:
                latest_per_host[s.host] = s.to_dict()
        return render_template(
            "index.html",
            scans=[s.to_dict() for s in scans],
            hosts=hosts,
            host_filter=host_filter,
            latest_per_host=latest_per_host,
        )

    @app.route("/scan/<scan_id>")
    def scan_detail(scan_id: str):
        bundle = store.get_bundle(scan_id)
        if bundle is None:
            abort(404)

        # filters
        severity = request.args.get("severity")
        module = request.args.get("module")
        framework = request.args.get("framework")
        clause = request.args.get("clause")
        q = request.args.get("q")
        verification = request.args.get("verification")
        all_findings = bundle.get("findings", [])
        filtered = filter_findings(
            all_findings, severity, module, framework, clause, q, verification
        )

        modules_present = sorted({f.get("module", "") for f in all_findings if f.get("module")})

        return render_template(
            "scan.html",
            scan_id=scan_id,
            bundle=bundle,
            findings=filtered,
            total_unfiltered=len(all_findings),
            modules_present=modules_present,
            current_filters={
                "severity": severity or "",
                "module": module or "",
                "framework": framework or "",
                "clause": clause or "",
                "q": q or "",
                "verification": verification or "",
            },
        )

    @app.route("/host/<host>")
    def host_view(host: str):
        scans = [s.to_dict() for s in store.list_scans() if s.host == host]
        if not scans:
            abort(404)
        return render_template("host.html", host=host, scans=scans)

    @app.route("/compare")
    def compare():
        scan_a = request.args.get("a")
        scan_b = request.args.get("b")
        all_scans = [s.to_dict() for s in store.list_scans()]
        if not scan_a or not scan_b:
            return render_template(
                "compare.html",
                all_scans=all_scans,
                scan_a=scan_a,
                scan_b=scan_b,
                bundle_a=None,
                bundle_b=None,
                diff=None,
            )
        bundle_a = store.get_bundle(scan_a)
        bundle_b = store.get_bundle(scan_b)
        if bundle_a is None or bundle_b is None:
            abort(404)
        diff = diff_findings(
            bundle_a.get("findings", []),
            bundle_b.get("findings", []),
        )
        return render_template(
            "compare.html",
            all_scans=all_scans,
            scan_a=scan_a,
            scan_b=scan_b,
            bundle_a=bundle_a,
            bundle_b=bundle_b,
            diff=diff,
        )

    # ------------------------------------------------------------------
    # JSON API (used by the chart in the host view)
    # ------------------------------------------------------------------
    @app.route("/api/scans")
    def api_scans():
        return jsonify([s.to_dict() for s in store.list_scans()])

    @app.route("/api/host/<host>/trend")
    def api_host_trend(host: str):
        return jsonify(store.trend_for_host(host))

    @app.route("/api/scan/<scan_id>")
    def api_scan(scan_id: str):
        bundle = store.get_bundle(scan_id)
        if bundle is None:
            abort(404)
        return jsonify(bundle)

    return app


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cyberloka-dashboard",
        description="Web dashboard untuk visualisasi laporan Cyberloka.",
    )
    parser.add_argument(
        "--reports-dir",
        default=os.environ.get("CYBERLOKA_REPORTS_DIR", "reports"),
        help="Direktori berisi file JSON laporan (default: ./reports).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=5005, help="Bind port (default: 5005).")
    parser.add_argument("--debug", action="store_true", help="Mode debug (auto-reload).")
    args = parser.parse_args(argv)

    app = create_app(args.reports_dir)
    print(
        f"Cyberloka Dashboard v{__version__}\n"
        f"  Reports dir : {Path(args.reports_dir).resolve()}\n"
        f"  Listening   : http://{args.host}:{args.port}\n"
        "  (Ctrl+C to stop)"
    )
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
