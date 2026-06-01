"""End-to-end test: extract sample ZIP, parse, run engine, generate report."""
import json
from pathlib import Path

from app.core.engine import ComplianceEngine
from app.core.extractor import create_temp_dir, extract_zip, cleanup_temp_dir
from app.core.parser import parse_project
from app.core.reporter import generate_report

ZIP_PATH = str(Path(__file__).parent / "sample-mule-app.zip")


def main():
    tmp = create_temp_dir()
    try:
        root = extract_zip(ZIP_PATH, tmp)
        print(f"Extracted to: {root}")

        project = parse_project(root)
        print(f"Project: {project.project_name}")
        print(f"  Flows: {len(project.flows)}")
        print(f"  Global configs: {len(project.global_configs)}")
        print(f"  Dependencies: {len(project.dependencies)}")
        print(f"  Properties files: {len(project.properties_files)}")
        print(f"  XML files: {len(project.xml_files)}")

        engine = ComplianceEngine()
        findings = engine.run(project)
        report = generate_report(findings, engine.enabled_rules(), project.project_name)

        print(f"\n{'='*60}")
        print(f"COMPLIANCE REPORT: {report.project_name}")
        print(f"{'='*60}")
        print(f"Score: {report.overall_score}% ({report.letter_grade.value})")
        print(f"Rules: {report.total_rules_checked} checked, "
              f"{report.total_passed} passed, "
              f"{report.total_failed} failed, "
              f"{report.total_warnings} warnings")
        print()

        for cs in report.category_scores:
            print(f"  [{cs.category.value}] {cs.score_pct}% "
                  f"({cs.passed}/{cs.total_rules} passed, {cs.failed} failed, {cs.warnings} warn)")

        print(f"\nFindings ({len(report.findings)}):")
        for f in report.findings:
            sev = f.severity.value.upper()
            loc = f"{f.file_path}:{f.line_number}" if f.file_path else ""
            print(f"  [{sev:7s}] {f.rule_id} - {f.message}")
            if loc:
                print(f"           @ {loc}")

    finally:
        cleanup_temp_dir(tmp)


if __name__ == "__main__":
    main()
