"""CLI entry point for the MuleSoft Compliance Checker.

Usage:
    python -m app.cli --path /path/to/mule-project
    python -m app.cli --path . --threshold 80 --output report.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from app.core.engine import ComplianceEngine
from app.core.parser import parse_project
from app.core.reporter import generate_report
from app.models import ComplianceReport, Severity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run MuleSoft compliance checks on a Mule 4 project.",
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Path to the Mule project directory (default: current directory).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=80.0,
        help="Minimum passing score 0-100 (default: 80).",
    )
    parser.add_argument(
        "--custom-rules",
        default=None,
        help="Path to a custom rules YAML file.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to write the JSON report.",
    )
    parser.add_argument(
        "--format",
        choices=["summary", "json"],
        default="summary",
        help="Output format: markdown summary table or raw JSON (default: summary).",
    )
    parser.add_argument(
        "--summary-file",
        default=None,
        help="Path to write the markdown summary (for GitHub Action integration).",
    )
    args = parser.parse_args(argv)

    project_path = _resolve_project_path(args.path)
    if project_path is None:
        print(f"ERROR: No Mule project found at '{args.path}'", file=sys.stderr)
        return 1

    project = parse_project(project_path)

    engine = ComplianceEngine(custom_rules_path=args.custom_rules)
    findings = engine.run(project)
    report = generate_report(findings, engine.enabled_rules(), project.project_name)

    if args.format == "json":
        _print_json(report)
    else:
        md = build_markdown_summary(report, args.threshold)
        print(md)
        _write_github_step_summary(md)
        if args.summary_file:
            Path(args.summary_file).write_text(md)

    # Write structured outputs for GitHub Action consumption
    _write_github_outputs(report, report.overall_score >= args.threshold)

    if args.output:
        Path(args.output).write_text(
            json.dumps(report.model_dump(mode="json"), indent=2)
        )
        print(f"\nJSON report written to {args.output}", file=sys.stderr)

    passed = report.overall_score >= args.threshold
    if not passed:
        print(
            f"\nFAILED: Score {report.overall_score}% is below threshold {args.threshold}%",
            file=sys.stderr,
        )
    return 0 if passed else 1


# ---------------------------------------------------------------------------
# Markdown report builder
# ---------------------------------------------------------------------------

COMMENT_MARKER = "<!-- mulesoft-compliance-checker -->"


def build_markdown_summary(report: ComplianceReport, threshold: float) -> str:
    passed = report.overall_score >= threshold
    status = "PASSED" if passed else "FAILED"

    lines = [
        COMMENT_MARKER,
        "## MuleSoft Compliance Report",
        "",
        f"**Score: {report.overall_score}% ({report.letter_grade.value})** "
        f"&mdash; {status} (threshold: {threshold}%)",
        "",
        "| Category | Score | Passed | Failed | Warnings |",
        "|----------|-------|--------|--------|----------|",
    ]

    for cs in report.category_scores:
        lines.append(
            f"| {cs.category.value} | {cs.score_pct}% | {cs.passed} | "
            f"{cs.failed} | {cs.warnings} |"
        )

    lines.append("")

    # All rules checklist
    lines.append("<details>")
    lines.append(f"<summary><strong>All Rules Checked ({report.total_rules_checked})</strong></summary>")
    lines.append("")
    lines.append("| Status | Rule | Description | Severity |")
    lines.append("|--------|------|-------------|----------|")
    for cr in report.checked_rules:
        if cr.status.value == "passed":
            icon = "&#9989;"  # green check
        elif cr.status.value == "failed":
            icon = "&#10060;"  # red X
        elif cr.status.value == "warning":
            icon = "&#9888;&#65039;"  # warning
        else:
            icon = "&#8505;&#65039;"  # info
        lines.append(
            f"| {icon} | **{cr.rule_id}** {cr.name} | {cr.description} | {cr.severity.value} |"
        )
    lines.append("")
    lines.append("</details>")
    lines.append("")

    if report.findings:
        lines.append(f"### Findings ({len(report.findings)})")
        lines.append("")
        # Show up to 20 findings to keep PR comments readable
        for f in report.findings[:20]:
            sev_label = f.severity.value.upper()
            loc = ""
            if f.file_path:
                loc = f" `{f.file_path}"
                if f.line_number:
                    loc += f":{f.line_number}"
                loc += "`"
            lines.append(f"- **[{sev_label}] {f.rule_id}** {f.message}{loc}")
        if len(report.findings) > 20:
            lines.append(f"- _... and {len(report.findings) - 20} more_")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_project_path(path_arg: str) -> str | None:
    """Find the Mule project root, walking up if needed."""
    p = Path(path_arg).resolve()
    if _is_mule_project(p):
        return str(p)
    # Check immediate children (mono-repo case)
    if p.is_dir():
        for child in p.iterdir():
            if child.is_dir() and _is_mule_project(child):
                return str(child)
    return None


def _is_mule_project(p: Path) -> bool:
    return (p / "pom.xml").exists() or (p / "mule-artifact.json").exists()


def _print_json(report: ComplianceReport) -> None:
    print(json.dumps(report.model_dump(mode="json"), indent=2))


def _write_github_step_summary(md: str) -> None:
    """Write to $GITHUB_STEP_SUMMARY if running inside GitHub Actions."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(md + "\n")


def _write_github_outputs(report: ComplianceReport, passed: bool) -> None:
    """Write structured outputs to $GITHUB_OUTPUT for downstream action steps."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a") as f:
        f.write(f"score={report.overall_score}\n")
        f.write(f"grade={report.letter_grade.value}\n")
        f.write(f"passed={'true' if passed else 'false'}\n")
        f.write(f"total-rules={report.total_rules_checked}\n")
        f.write(f"total-passed={report.total_passed}\n")
        f.write(f"total-failed={report.total_failed}\n")
        f.write(f"total-warnings={report.total_warnings}\n")


if __name__ == "__main__":
    sys.exit(main())
