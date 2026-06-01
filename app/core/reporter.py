from __future__ import annotations

from app.models import (
    CategoryScore,
    CheckedRule,
    ComplianceReport,
    Finding,
    LetterGrade,
    RuleCategory,
    RuleStatus,
    Severity,
)
from app.rules.base import BaseRule


def generate_report(
    findings: list[Finding],
    enabled_rules: list[BaseRule],
    project_name: str = "",
) -> ComplianceReport:
    report = ComplianceReport(project_name=project_name)

    failed_rule_ids = {f.rule_id for f in findings if f.severity == Severity.ERROR}
    warning_rule_ids = {f.rule_id for f in findings if f.severity == Severity.WARNING}
    info_rule_ids = {f.rule_id for f in findings if f.severity == Severity.INFO}

    all_finding_rule_ids = failed_rule_ids | warning_rule_ids | info_rule_ids
    passed_rule_ids = {r.rule_id for r in enabled_rules} - all_finding_rule_ids

    report.total_rules_checked = len(enabled_rules)
    report.total_passed = len(passed_rule_ids)
    report.total_failed = len(failed_rule_ids)
    report.total_warnings = len(warning_rule_ids)
    report.findings = findings

    # Build the full checked-rules list with status
    for r in enabled_rules:
        if r.rule_id in failed_rule_ids:
            status = RuleStatus.FAILED
        elif r.rule_id in warning_rule_ids:
            status = RuleStatus.WARNING
        elif r.rule_id in info_rule_ids:
            status = RuleStatus.INFO
        else:
            status = RuleStatus.PASSED
        report.checked_rules.append(CheckedRule(
            rule_id=r.rule_id,
            name=r.name,
            description=r.description,
            category=r.category,
            severity=r.severity,
            status=status,
        ))

    # Category breakdown
    categories_seen: dict[RuleCategory, dict] = {}
    for r in enabled_rules:
        bucket = categories_seen.setdefault(r.category, {
            "total": 0, "passed": 0, "failed": 0, "warnings": 0,
        })
        bucket["total"] += 1
        if r.rule_id in failed_rule_ids:
            bucket["failed"] += 1
        elif r.rule_id in warning_rule_ids:
            bucket["warnings"] += 1
        else:
            bucket["passed"] += 1

    for cat, counts in categories_seen.items():
        total = counts["total"]
        score_pct = (counts["passed"] / total * 100) if total else 100.0
        report.category_scores.append(CategoryScore(
            category=cat,
            total_rules=total,
            passed=counts["passed"],
            failed=counts["failed"],
            warnings=counts["warnings"],
            score_pct=round(score_pct, 1),
        ))

    # Overall score: errors weigh full, warnings weigh half, info doesn't penalize
    if report.total_rules_checked > 0:
        penalty = len(failed_rule_ids) + 0.5 * len(warning_rule_ids)
        raw = max(0, (report.total_rules_checked - penalty) / report.total_rules_checked * 100)
        report.overall_score = round(raw, 1)
    else:
        report.overall_score = 100.0

    report.letter_grade = _score_to_grade(report.overall_score)
    return report


def _score_to_grade(score: float) -> LetterGrade:
    if score >= 90:
        return LetterGrade.A
    if score >= 80:
        return LetterGrade.B
    if score >= 70:
        return LetterGrade.C
    if score >= 60:
        return LetterGrade.D
    return LetterGrade.F
