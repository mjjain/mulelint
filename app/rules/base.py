from __future__ import annotations

from abc import ABC, abstractmethod

from app.models import Finding, MuleProject, RuleCategory, RuleDefinition, Severity


class BaseRule(ABC):
    """Every compliance rule inherits from this class."""

    rule_id: str = ""
    name: str = ""
    description: str = ""
    category: RuleCategory = RuleCategory.BEST_PRACTICES
    severity: Severity = Severity.ERROR
    enabled: bool = True

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            category=self.category,
            severity=self.severity,
            enabled=self.enabled,
        )

    @abstractmethod
    def check(self, project: MuleProject) -> list[Finding]:
        """Run the rule against a parsed project and return findings (failures)."""
        ...

    def _finding(
        self,
        message: str,
        remediation: str = "",
        file_path: str = "",
        line_number: int | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
            severity=self.severity,
            file_path=file_path,
            line_number=line_number,
            message=message,
            remediation=remediation,
        )
