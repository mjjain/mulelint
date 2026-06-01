from __future__ import annotations

import math
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.core.engine import ComplianceEngine
from app.core.extractor import (
    ExtractionError,
    cleanup_temp_dir,
    create_temp_dir,
    extract_zip,
    validate_upload,
)
from app.core.parser import parse_project
from app.core.reporter import generate_report
from app.models import ComplianceReport

APP_DIR = Path(__file__).resolve().parent

app = FastAPI(title="MuleSoft Compliance Checker")
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

# In-memory report store (for demo purposes; swap for a DB in production)
_reports: dict[str, ComplianceReport] = {}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "error": None})


@app.post("/api/check")
async def check_compliance(request: Request, file: UploadFile = File(...)):
    tmp_dir: str | None = None
    try:
        # Read file into memory to get size
        contents = await file.read()
        validate_upload(file.filename or "unknown.zip", len(contents))

        # Write to temp file, extract
        tmp_dir = create_temp_dir()
        zip_path = os.path.join(tmp_dir, file.filename or "upload.zip")
        with open(zip_path, "wb") as f:
            f.write(contents)

        project_root = extract_zip(zip_path, tmp_dir)

        # Parse
        project = parse_project(project_root)

        # Run compliance engine
        engine = ComplianceEngine()
        findings = engine.run(project)

        # Generate report
        report = generate_report(findings, engine.enabled_rules(), project.project_name)

        # Store report
        _reports[report.report_id] = report

        # Redirect to report page
        return RedirectResponse(
            url=f"/report/{report.report_id}",
            status_code=303,
        )

    except ExtractionError as e:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": str(e)},
            status_code=400,
        )
    except Exception as e:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": f"Unexpected error: {e}"},
            status_code=500,
        )
    finally:
        if tmp_dir:
            cleanup_temp_dir(tmp_dir)


@app.get("/report/{report_id}", response_class=HTMLResponse)
async def view_report(request: Request, report_id: str):
    report = _reports.get(report_id)
    if not report:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": "Report not found. Please upload your project again."},
            status_code=404,
        )

    # Compute donut chart values
    circumference = 2 * math.pi * 52  # radius = 52
    dash_filled = circumference * report.overall_score / 100
    dash_empty = circumference - dash_filled

    grade_colors = {
        "A": ("#22c55e", "text-green-600"),
        "B": ("#84cc16", "text-lime-600"),
        "C": ("#eab308", "text-yellow-600"),
        "D": ("#f97316", "text-orange-600"),
        "F": ("#ef4444", "text-red-600"),
    }
    grade_color, grade_text_color = grade_colors.get(
        report.letter_grade.value, ("#ef4444", "text-red-600")
    )

    # Group checked rules by category for the template
    from collections import OrderedDict
    rules_by_category: dict[str, list] = OrderedDict()
    for cr in report.checked_rules:
        cat_label = cr.category.value
        rules_by_category.setdefault(cat_label, []).append(cr)

    return templates.TemplateResponse("report.html", {
        "request": request,
        "report": report,
        "dash_filled": f"{dash_filled:.1f}",
        "dash_empty": f"{dash_empty:.1f}",
        "grade_color": grade_color,
        "grade_text_color": grade_text_color,
        "rules_by_category": rules_by_category,
    })


@app.get("/api/report/{report_id}/json")
async def download_report_json(report_id: str):
    report = _reports.get(report_id)
    if not report:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    return JSONResponse(
        content=report.model_dump(mode="json"),
        headers={"Content-Disposition": f"attachment; filename=compliance-report-{report_id}.json"},
    )
