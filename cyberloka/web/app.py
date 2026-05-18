"""FastAPI application factory for the Cyberloka dashboard."""
from __future__ import annotations

import io
import json
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cyberloka import __version__
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.scanner import MODULE_MAP
from cyberloka.web import diff as diff_mod
from cyberloka.web.db import Database
from cyberloka.web.runner import ensure_scheduler, start_scan_thread

WEB_DIR = Path(__file__).parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"


def get_db() -> Database:
    return Database()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Cyberloka Dashboard",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
    )

    @app.on_event("startup")
    def _startup() -> None:
        ensure_scheduler()

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.globals["tool_version"] = __version__

    def _format_dt(value: str | None) -> str:
        if not value:
            return "—"
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime(
                "%Y-%m-%d %H:%M"
            )
        except ValueError:
            return value

    templates.env.filters["format_dt"] = _format_dt
    templates.env.filters["from_json"] = lambda s: json.loads(s) if s else None

    SEVERITY_PILL = {
        "critical": "bg-red-600 text-white",
        "high": "bg-orange-600 text-white",
        "medium": "bg-amber-500 text-white",
        "low": "bg-blue-600 text-white",
        "info": "bg-slate-500 text-white",
    }
    templates.env.globals["sev_pill"] = SEVERITY_PILL

    # ------------------------------------------------------------------
    # Pages
    # ------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, db: Database = Depends(get_db)) -> Response:
        stats = db.overview_stats()
        return templates.TemplateResponse(
            "home.html",
            {"request": request, "stats": stats, "page": "home"},
        )

    @app.get("/targets", response_class=HTMLResponse)
    def targets_page(request: Request, db: Database = Depends(get_db)) -> Response:
        return templates.TemplateResponse(
            "targets.html",
            {"request": request, "targets": db.list_targets(), "page": "targets"},
        )

    @app.post("/targets")
    def create_target(
        url: str = Form(...),
        label: str = Form(""),
        notes: str = Form(""),
        db: Database = Depends(get_db),
    ) -> Response:
        try:
            parsed = parse_target(url)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        db.upsert_target(parsed.base_url, label.strip() or None, notes.strip() or None)
        return RedirectResponse("/targets", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/targets/{target_id}/delete")
    def delete_target(target_id: int, db: Database = Depends(get_db)) -> Response:
        db.delete_target(target_id)
        return RedirectResponse("/targets", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/scans/new", response_class=HTMLResponse)
    def new_scan_form(
        request: Request,
        target: int | None = None,
        db: Database = Depends(get_db),
    ) -> Response:
        return templates.TemplateResponse(
            "scan_new.html",
            {
                "request": request,
                "targets": db.list_targets(),
                "selected_target": target,
                "modules": sorted(MODULE_MAP.keys()),
                "page": "scans",
            },
        )

    @app.post("/scans")
    def start_scan(
        target_id: int = Form(...),
        mode: str = Form("full"),
        modules: str = Form(""),
        rate: float = Form(8.0),
        threads: int = Form(8),
        timeout: float = Form(10.0),
        max_crawl_pages: int = Form(30),
        authorized: bool = Form(False),
        simulate_attack: bool = Form(False),
        login_url: str = Form(""),
        login_username: str = Form(""),
        login_password: str = Form(""),
        auth_bearer: str = Form(""),
        db: Database = Depends(get_db),
    ) -> Response:
        target = db.get_target(target_id)
        if not target:
            raise HTTPException(404, "Target not found")
        modules_list = [m.strip() for m in modules.split(",") if m.strip()]
        cfg = ScanConfig(
            target=target["url"],
            mode=mode,
            modules=modules_list,
            threads=threads,
            timeout=timeout,
            rate_limit=rate,
            max_crawl_pages=max_crawl_pages,
            authorized=authorized or mode == "passive",
            simulate_attack=simulate_attack,
            login_url=login_url.strip() or None,
            login_username=login_username.strip() or None,
            login_password=login_password or None,
            auth_bearer_token=auth_bearer.strip() or None,
        )
        resolved = cfg.resolve_modules()
        if simulate_attack:
            resolved = list(resolved) + ["burst"]
        scan_id = db.create_scan(target_id, mode, resolved, len(resolved))
        start_scan_thread(db, scan_id, target["url"], cfg)
        return RedirectResponse(f"/scans/{scan_id}", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/scans", response_class=HTMLResponse)
    def scans_index(request: Request, db: Database = Depends(get_db)) -> Response:
        return templates.TemplateResponse(
            "scan_list.html",
            {"request": request, "scans": db.list_scans(), "page": "scans"},
        )

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan_detail(
        scan_id: int,
        request: Request,
        db: Database = Depends(get_db),
    ) -> Response:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(404)
        findings = db.list_findings(scan_id) if scan["status"] == "done" else []
        previous = []
        if scan["status"] == "done":
            previous = [
                s for s in db.list_done_scans_for_target(scan["target_id"], 10)
                if s["id"] != scan_id
            ]
        return templates.TemplateResponse(
            "scan_detail.html",
            {
                "request": request,
                "scan": scan,
                "findings": findings,
                "previous_scans": previous,
                "page": "scans",
            },
        )

    @app.post("/scans/{scan_id}/delete")
    def delete_scan(scan_id: int, db: Database = Depends(get_db)) -> Response:
        db.delete_scan(scan_id)
        return RedirectResponse("/scans", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_detail(
        finding_id: int,
        request: Request,
        db: Database = Depends(get_db),
    ) -> Response:
        f = db.get_finding(finding_id)
        if not f:
            raise HTTPException(404)
        scan = db.get_scan(f["scan_id"])
        return templates.TemplateResponse(
            "finding_detail.html",
            {"request": request, "f": f, "scan": scan, "page": "scans"},
        )

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------
    @app.get("/scans/{scan_id}/diff", response_class=HTMLResponse)
    def scan_diff(
        scan_id: int,
        previous: int,
        request: Request,
        db: Database = Depends(get_db),
    ) -> Response:
        curr = db.get_scan(scan_id)
        prev = db.get_scan(previous)
        if not curr or not prev:
            raise HTTPException(404)
        result = diff_mod.diff_scans(
            db.list_findings(prev["id"]),
            db.list_findings(curr["id"]),
        )
        return templates.TemplateResponse(
            "scan_diff.html",
            {"request": request, "curr": curr, "prev": prev,
             "diff": result, "page": "scans"},
        )

    # ------------------------------------------------------------------
    # PDF / HTML export
    # ------------------------------------------------------------------
    @app.get("/scans/{scan_id}/report.html")
    def scan_report_html(scan_id: int, db: Database = Depends(get_db)) -> Response:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(404)
        findings = db.list_findings(scan_id)
        from collections import Counter
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        from cyberloka.reporting.explainer import (
            CATEGORIES, GLOSSARY, SEVERITY_ACTION,
            build_executive_summary, explain_finding,
        )
        from cyberloka.reporting.html_report import (
            CATEGORY_DESCRIPTIONS, _action_buckets, _categorize, _owasp_distribution,
        )

        env_template = Path(WEB_DIR.parent / "reporting" / "templates" / "report.html")
        env = Environment(
            loader=FileSystemLoader(str(env_template.parent)),
            autoescape=select_autoescape(["html"]),
        )
        tpl = env.get_template("report.html")

        sev = scan.get("summary", {}).get("by_severity", {}) if scan.get("summary") else {}
        target_obj = type("T", (), {
            "host": scan.get("target_url", ""),
            "scheme": "https",
            "port": "",
            "base_url": scan.get("target_url", ""),
        })
        risk_score = scan.get("risk_score", 0)
        risk_label = scan.get("risk_label") or "—"

        findings_dicts = [explain_finding(f) for f in findings]
        summary = {"total": sum(sev.values()), "by_severity": {
            "critical": sev.get("critical", 0),
            "high": sev.get("high", 0),
            "medium": sev.get("medium", 0),
            "low": sev.get("low", 0),
            "info": sev.get("info", 0),
        }}

        pdp_pii = sum(1 for f in findings_dicts if f.get("module") == "pii_leak")
        pdp_idor = sum(1 for f in findings_dicts if f.get("module") == "idor_generic")
        pdp_cookie = sum(1 for f in findings_dicts if f.get("module") in ("cookies", "session"))
        pdp_tls = sum(1 for f in findings_dicts if f.get("module") == "tls")

        html = tpl.render(
            target=target_obj,
            scan={"mode": scan.get("mode"), "modules": scan.get("modules", [])},
            summary=summary,
            findings=findings_dicts,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            tool_version=__version__,
            risk_score=risk_score,
            risk_label=risk_label,
            exec=build_executive_summary(
                findings_dicts, risk_score, risk_label, scan.get("target_url", "")
            ),
            categories=_categorize(findings_dicts),
            category_labels=CATEGORIES,
            category_descriptions=CATEGORY_DESCRIPTIONS,
            action_buckets=_action_buckets(findings_dicts),
            severity_action=SEVERITY_ACTION,
            owasp_distribution=_owasp_distribution(findings_dicts),
            pdp_pii=pdp_pii,
            pdp_idor=pdp_idor,
            pdp_cookie=pdp_cookie,
            pdp_tls=pdp_tls,
            glossary=GLOSSARY,
        )
        return HTMLResponse(html)

    @app.get("/scans/{scan_id}/report.pdf")
    def scan_report_pdf(scan_id: int, db: Database = Depends(get_db)) -> Response:
        # Try to convert via weasyprint or wkhtmltopdf if available;
        # otherwise fall back to a server-rendered HTML the user can print to PDF
        # via the browser.
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(404)
        html_resp = scan_report_html(scan_id, db)  # type: ignore[arg-type]
        html_bytes = html_resp.body if isinstance(html_resp, HTMLResponse) else b""
        # Try weasyprint
        try:
            from weasyprint import HTML  # type: ignore

            buf = io.BytesIO()
            HTML(string=html_bytes.decode("utf-8")).write_pdf(buf)
            buf.seek(0)
            return StreamingResponse(
                buf,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=cyberloka-scan-{scan_id}.pdf"},
            )
        except Exception:
            pass
        # Fallback: HTML with print stylesheet hint
        return HTMLResponse(
            html_bytes,
            headers={
                "X-Cyberloka-PDF-Fallback": "weasyprint-not-installed",
                "Content-Disposition": f"inline; filename=cyberloka-scan-{scan_id}.html",
            },
        )

    # ------------------------------------------------------------------
    # Schedules
    # ------------------------------------------------------------------
    @app.get("/schedules", response_class=HTMLResponse)
    def schedules_page(request: Request, db: Database = Depends(get_db)) -> Response:
        return templates.TemplateResponse(
            "schedules.html",
            {
                "request": request,
                "schedules": db.list_schedules(),
                "targets": db.list_targets(),
                "page": "schedules",
            },
        )

    @app.post("/schedules")
    def create_schedule(
        target_id: int = Form(...),
        interval_hours: float = Form(24.0),
        mode: str = Form("passive"),
        db: Database = Depends(get_db),
    ) -> Response:
        db.create_schedule(target_id, interval_hours, mode)
        return RedirectResponse("/schedules", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/schedules/{schedule_id}/delete")
    def delete_schedule(schedule_id: int, db: Database = Depends(get_db)) -> Response:
        db.delete_schedule(schedule_id)
        return RedirectResponse("/schedules", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/schedules/{schedule_id}/toggle")
    def toggle_schedule(schedule_id: int, db: Database = Depends(get_db)) -> Response:
        scheds = {s["id"]: s for s in db.list_schedules()}
        s = scheds.get(schedule_id)
        if not s:
            raise HTTPException(404)
        db.update_schedule(schedule_id, enabled=0 if s["enabled"] else 1)
        return RedirectResponse("/schedules", status_code=status.HTTP_303_SEE_OTHER)

    # ------------------------------------------------------------------
    # Notifiers
    # ------------------------------------------------------------------
    @app.get("/notifiers", response_class=HTMLResponse)
    def notifiers_page(request: Request, db: Database = Depends(get_db)) -> Response:
        return templates.TemplateResponse(
            "notifiers.html",
            {"request": request, "notifiers": db.list_notifiers(), "page": "notifiers"},
        )

    @app.post("/notifiers")
    def create_notifier(
        kind: str = Form(...),
        url: str = Form(...),
        min_severity: str = Form("high"),
        db: Database = Depends(get_db),
    ) -> Response:
        if kind not in ("webhook", "slack", "email"):
            raise HTTPException(400, "kind harus webhook|slack|email")
        db.create_notifier(kind, url.strip(), min_severity)
        return RedirectResponse("/notifiers", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/notifiers/{nid}/delete")
    def delete_notifier(nid: int, db: Database = Depends(get_db)) -> Response:
        db.delete_notifier(nid)
        return RedirectResponse("/notifiers", status_code=status.HTTP_303_SEE_OTHER)

    # ------------------------------------------------------------------
    # HTMX partials & JSON API
    # ------------------------------------------------------------------
    @app.get("/scans/{scan_id}/progress", response_class=HTMLResponse)
    def scan_progress(
        scan_id: int,
        request: Request,
        db: Database = Depends(get_db),
    ) -> Response:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(404)
        return templates.TemplateResponse(
            "_progress.html",
            {"request": request, "scan": scan},
        )

    @app.get("/api/scans/{scan_id}")
    def api_scan(scan_id: int, db: Database = Depends(get_db)) -> JSONResponse:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(404)
        scan["findings"] = db.list_findings(scan_id)
        return JSONResponse(scan)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/robots.txt", response_class=PlainTextResponse)
    def robots() -> str:
        return "User-agent: *\nDisallow: /\n"

    return app


app = create_app()
