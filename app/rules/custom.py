from __future__ import annotations

from pathlib import Path

import yaml
from lxml import etree

from app.core.engine import register_rule
from app.models import (
    CustomRuleConfig,
    CustomRulesFile,
    Finding,
    MuleProject,
    RuleCategory,
    Severity,
)
from app.rules.base import BaseRule

MULE_NS = "http://www.mulesoft.org/schema/mule/core"
HTTP_NS = "http://www.mulesoft.org/schema/mule/http"
EE_NS = "http://www.mulesoft.org/schema/mule/ee/core"
APIKIT_NS = "http://www.mulesoft.org/schema/mule/mule-apikit"

DEFAULT_NSMAP = {
    "mule": MULE_NS,
    "http": HTTP_NS,
    "ee": EE_NS,
    "apikit": APIKIT_NS,
}


def load_custom_rules(config_path: str | None = None) -> list[CustomRuleConfig]:
    if config_path is None:
        config_path = str(
            Path(__file__).resolve().parent.parent.parent / "rules_config" / "custom_rules.yaml"
        )
    path = Path(config_path)
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text())
        if not data:
            return []
        crf = CustomRulesFile.model_validate(data)
        return crf.rules
    except Exception:
        return []


class CustomXPathRule(BaseRule):
    """A rule driven by YAML config that evaluates an XPath expression."""

    category = RuleCategory.CUSTOM

    def __init__(self, config: CustomRuleConfig):
        self.rule_id = config.id
        self.name = config.name
        self.description = config.description
        self.severity = config.severity
        self.enabled = True
        self._xpath = config.xpath
        self._message_template = config.message or f"Custom rule {config.id} violated."
        self._remediation = config.remediation

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue

            nsmap = dict(DEFAULT_NSMAP)
            if tree.nsmap:
                for prefix, uri in tree.nsmap.items():
                    if prefix:
                        nsmap[prefix] = uri

            try:
                results = tree.xpath(self._xpath, namespaces=nsmap)
            except etree.XPathError:
                findings.append(self._finding(
                    message=f"Invalid XPath expression for rule {self.rule_id}: {self._xpath}",
                    file_path=rel_path,
                ))
                continue

            if isinstance(results, list):
                for match in results:
                    line = getattr(match, "sourceline", None)
                    flow_name = ""
                    if hasattr(match, "get"):
                        flow_name = match.get("name", "")
                    msg = self._message_template.replace("{flow_name}", flow_name)
                    findings.append(self._finding(
                        message=msg,
                        remediation=self._remediation,
                        file_path=rel_path,
                        line_number=line,
                    ))
            elif results:
                findings.append(self._finding(
                    message=self._message_template,
                    remediation=self._remediation,
                    file_path=rel_path,
                ))
        return findings


def load_custom_rule_instances(config_path: str | None = None) -> list[CustomXPathRule]:
    """Load custom rules from YAML and return instantiated rule objects."""
    configs = load_custom_rules(config_path)
    return [CustomXPathRule(cfg) for cfg in configs]
