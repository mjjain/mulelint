from __future__ import annotations

from pathlib import Path

import yaml

from app.models import (
    DefaultRulesConfig,
    Finding,
    MuleProject,
    RuleCategory,
    Severity,
)
from app.rules.base import BaseRule

_RULE_REGISTRY: list[type[BaseRule]] = []
_RULES_IMPORTED = False


def _ensure_rules_imported() -> None:
    global _RULES_IMPORTED
    if _RULES_IMPORTED:
        return
    _RULES_IMPORTED = True
    import app.rules.best_practices  # noqa: F401
    import app.rules.security  # noqa: F401
    import app.rules.api_standards  # noqa: F401


def register_rule(cls: type[BaseRule]) -> type[BaseRule]:
    """Class decorator that registers a rule in the global registry."""
    _RULE_REGISTRY.append(cls)
    return cls


def get_all_rule_classes() -> list[type[BaseRule]]:
    _ensure_rules_imported()
    return list(_RULE_REGISTRY)


class ComplianceEngine:
    """Instantiates all registered rules, applies config overrides, and runs them."""

    def __init__(
        self,
        config_path: str | None = None,
        custom_rules_path: str | None = None,
    ):
        _ensure_rules_imported()
        self.rules: list[BaseRule] = []
        overrides = self._load_overrides(config_path)

        for cls in _RULE_REGISTRY:
            instance = cls()
            if instance.rule_id in overrides:
                ov = overrides[instance.rule_id]
                instance.enabled = ov.get("enabled", instance.enabled)
                if "severity" in ov and ov["severity"]:
                    instance.severity = Severity(ov["severity"])
            self.rules.append(instance)

        # Load custom YAML-driven rules
        from app.rules.custom import load_custom_rule_instances
        for custom_rule in load_custom_rule_instances(custom_rules_path):
            if custom_rule.rule_id in overrides:
                ov = overrides[custom_rule.rule_id]
                custom_rule.enabled = ov.get("enabled", custom_rule.enabled)
                if "severity" in ov and ov["severity"]:
                    custom_rule.severity = Severity(ov["severity"])
            self.rules.append(custom_rule)

    def run(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                findings.extend(rule.check(project))
            except Exception:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=Severity.WARNING,
                        message=f"Rule {rule.rule_id} encountered an internal error.",
                    )
                )
        return findings

    def enabled_rules(self) -> list[BaseRule]:
        return [r for r in self.rules if r.enabled]

    def rules_by_category(self) -> dict[RuleCategory, list[BaseRule]]:
        grouped: dict[RuleCategory, list[BaseRule]] = {}
        for r in self.rules:
            grouped.setdefault(r.category, []).append(r)
        return grouped

    @staticmethod
    def _load_overrides(config_path: str | None) -> dict[str, dict]:
        if not config_path:
            default = Path(__file__).resolve().parent.parent.parent / "rules_config" / "default_rules.yaml"
            if default.exists():
                config_path = str(default)
            else:
                return {}
        try:
            data = yaml.safe_load(Path(config_path).read_text())
            cfg = DefaultRulesConfig.model_validate(data or {})
            return {
                ov.rule_id: {
                    "enabled": ov.enabled,
                    "severity": ov.severity.value if ov.severity else None,
                }
                for ov in cfg.overrides
            }
        except Exception:
            return {}
