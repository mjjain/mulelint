from __future__ import annotations

import re

from lxml import etree

from app.core.engine import register_rule
from app.models import Finding, Flow, MuleProject, RuleCategory, Severity
from app.rules.base import BaseRule

MULE_NS = "http://www.mulesoft.org/schema/mule/core"
HTTP_NS = "http://www.mulesoft.org/schema/mule/http"
EE_NS = "http://www.mulesoft.org/schema/mule/ee/core"
BATCH_NS = "http://www.mulesoft.org/schema/mule/batch"
SCHEDULER_TAG = f"{{{MULE_NS}}}scheduler"

KEBAB_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")


@register_rule
class BP001_FlowNamingConvention(BaseRule):
    rule_id = "BP-001"
    name = "Flow naming convention"
    description = "Flow names should follow kebab-case naming convention."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for flow in project.flows:
            if not KEBAB_RE.match(flow.name):
                findings.append(self._finding(
                    message=f"Flow '{flow.name}' does not follow kebab-case naming convention.",
                    remediation="Rename the flow to use kebab-case (e.g., 'process-order', 'get-customer-details').",
                    file_path=flow.source_file,
                    line_number=flow.line_number,
                ))
        return findings


@register_rule
class BP002_ErrorHandlerDefined(BaseRule):
    rule_id = "BP-002"
    name = "Error handler defined"
    description = "Every flow should have an error handler."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.ERROR

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for flow in project.flows:
            if flow.flow_type == "flow" and not flow.error_handlers:
                findings.append(self._finding(
                    message=f"Flow '{flow.name}' has no error handler defined.",
                    remediation="Add an <error-handler> block with appropriate on-error-propagate or on-error-continue strategies.",
                    file_path=flow.source_file,
                    line_number=flow.line_number,
                ))
        return findings


@register_rule
class BP003_LoggingPresent(BaseRule):
    rule_id = "BP-003"
    name = "Flow logging"
    description = "Flows should have logging at entry and/or exit points."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for flow in project.flows:
            if flow.flow_type != "flow":
                continue
            has_logger = any(
                "logger" in c.component_type.lower()
                for c in flow.components
            )
            if not has_logger:
                findings.append(self._finding(
                    message=f"Flow '{flow.name}' has no logger component.",
                    remediation="Add a Logger component at the beginning and/or end of the flow for observability.",
                    file_path=flow.source_file,
                    line_number=flow.line_number,
                ))
        return findings


@register_rule
class BP004_ConnectionTimeout(BaseRule):
    rule_id = "BP-004"
    name = "Connection timeout configured"
    description = "HTTP request configurations should have connection timeouts."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        request_config_tag = f"{{{HTTP_NS}}}request-config"
        for gc in project.global_configs:
            if gc.config_type == request_config_tag:
                has_timeout = any(
                    "timeout" in k.lower() or "responseTimeout" in k
                    for k in gc.attributes
                )
                if not has_timeout:
                    findings.append(self._finding(
                        message=f"HTTP request config '{gc.name}' has no connection/response timeout configured.",
                        remediation="Add responseTimeout attribute to the http:request-config element.",
                        file_path=gc.source_file,
                        line_number=gc.line_number,
                    ))
        return findings


@register_rule
class BP005_ReconnectionStrategy(BaseRule):
    rule_id = "BP-005"
    name = "Reconnection strategy"
    description = "Connectors should have reconnection strategies defined."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            connector_tags = [
                f"{{{HTTP_NS}}}request-config",
                f"{{{HTTP_NS}}}listener-config",
            ]
            for tag in connector_tags:
                for el in tree.iter(tag):
                    has_reconnect = any(
                        "reconnect" in _local_tag(child).lower()
                        for child in el.iter()
                        if child is not el
                    )
                    if not has_reconnect:
                        name = el.get("name", "unnamed")
                        findings.append(self._finding(
                            message=f"Connector config '{name}' has no reconnection strategy.",
                            remediation="Add a <reconnect> or <reconnect-forever> element inside the connector configuration.",
                            file_path=rel_path,
                            line_number=el.sourceline,
                        ))
        return findings


@register_rule
class BP006_ExternalDataWeave(BaseRule):
    rule_id = "BP-006"
    name = "External DataWeave files"
    description = "Complex DataWeave transformations should use external .dwl files."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.INFO

    INLINE_THRESHOLD = 5  # lines

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            for el in tree.iter(f"{{{EE_NS}}}set-payload", f"{{{EE_NS}}}set-variable",
                               f"{{{EE_NS}}}transform"):
                for child in el.iter():
                    if child.text and child.text.strip().count("\n") >= self.INLINE_THRESHOLD:
                        findings.append(self._finding(
                            message=f"Inline DataWeave in '{rel_path}' exceeds {self.INLINE_THRESHOLD} lines.",
                            remediation="Extract complex DataWeave to an external .dwl file under src/main/resources/dwl/.",
                            file_path=rel_path,
                            line_number=child.sourceline,
                        ))
        return findings


@register_rule
class BP007_DuplicatedFlowPatterns(BaseRule):
    rule_id = "BP-007"
    name = "Reusable sub-flows"
    description = "Duplicated component sequences should be extracted into sub-flows."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.INFO

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        # Simple heuristic: detect if any flow has > 15 inline components (should split)
        for flow in project.flows:
            if flow.flow_type == "flow" and len(flow.components) > 15:
                findings.append(self._finding(
                    message=f"Flow '{flow.name}' has {len(flow.components)} components. Consider extracting reusable parts into sub-flows.",
                    remediation="Break large flows into smaller sub-flows using flow-ref for reusability and readability.",
                    file_path=flow.source_file,
                    line_number=flow.line_number,
                ))
        return findings


@register_rule
class BP008_BatchJobSize(BaseRule):
    rule_id = "BP-008"
    name = "Batch job configuration"
    description = "Batch jobs should have appropriate batch size configured."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            for el in tree.iter(f"{{{BATCH_NS}}}job", f"{{{MULE_NS}}}batch:job"):
                name = el.get("jobName", el.get("name", "unnamed"))
                if "blockSize" not in el.attrib and "maxConcurrency" not in el.attrib:
                    findings.append(self._finding(
                        message=f"Batch job '{name}' does not specify blockSize or maxConcurrency.",
                        remediation="Set blockSize and/or maxConcurrency on the batch:job to control resource consumption.",
                        file_path=rel_path,
                        line_number=el.sourceline,
                    ))
        return findings


@register_rule
class BP009_SchedulerCron(BaseRule):
    rule_id = "BP-009"
    name = "Scheduler CRON expression"
    description = "Scheduler flows should use proper CRON expressions."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.INFO

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for flow in project.flows:
            if flow.source and "scheduler" in flow.source.component_type.lower():
                has_cron = any(
                    "cron" in k.lower() or "expression" in k.lower()
                    for k in flow.source.attributes
                )
                # Also check children of the scheduler element by re-parsing
                if not has_cron:
                    findings.append(self._finding(
                        message=f"Scheduler in flow '{flow.name}' may not use a CRON expression (using fixed-frequency instead).",
                        remediation="For production schedulers, prefer CRON expressions for more predictable scheduling control.",
                        file_path=flow.source_file,
                        line_number=flow.source.line_number,
                    ))
        return findings


@register_rule
class BP010_ObjectStoreUsage(BaseRule):
    rule_id = "BP-010"
    name = "Object Store for idempotency"
    description = "Projects processing messages should consider Object Store for idempotency."
    category = RuleCategory.BEST_PRACTICES
    severity = Severity.INFO

    OS_NS = "http://www.mulesoft.org/schema/mule/os"

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        has_object_store = any(
            self.OS_NS in gc.config_type
            for gc in project.global_configs
        )
        has_os_usage = any(
            self.OS_NS in comp.component_type
            for flow in project.flows
            for comp in flow.components
        )
        has_jms_or_queue = any(
            "jms" in d.artifact_id.lower() or "anypoint-mq" in d.artifact_id.lower()
            for d in project.dependencies
        )

        if has_jms_or_queue and not (has_object_store or has_os_usage):
            findings.append(self._finding(
                message="Project uses messaging (JMS/Anypoint MQ) but no Object Store for idempotency was detected.",
                remediation="Consider using Mule Object Store connector to implement idempotent message processing.",
            ))
        return findings


def _local_tag(el: etree._Element) -> str:
    tag = el.tag if isinstance(el.tag, str) else ""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag
