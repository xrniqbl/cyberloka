"""FastAPI application factory for the Cyberloka dashboard."""
from __future__ import annotations

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
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cyberloka import __version__
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.scanner import MODULE_MAP
from cyberloka.web.db import Database
from cyberloka.web.runner import start_scan_thread

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
            {
                "request": request,
                "targets": db.list_targets(),
                "page": "targets",
            },
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
            # Mode passive di Cyberloka hanya melakukan observasi, jadi
            # selalu dianggap authorized. Mode lain butuh konfirmasi.
            authorized=authorized or mode == "passive",
            simulate_attack=simulate_attack,
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
            {
                "request": request,
                "scans": db.list_scans(),
                "page": "scans",
            },
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
        return templates.TemplateResponse(
            "scan_detail.html",
            {
                "request": request,
                "scan": scan,
                "findings": findings,
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
