from __future__ import annotations

from lxml import etree

from app.core.engine import register_rule
from app.models import Finding, MuleProject, RuleCategory, Severity
from app.rules.base import BaseRule

MULE_NS = "http://www.mulesoft.org/schema/mule/core"
HTTP_NS = "http://www.mulesoft.org/schema/mule/http"
APIKIT_NS = "http://www.mulesoft.org/schema/mule/mule-apikit"
AUTODISCOVERY_NS = "http://www.mulesoft.org/schema/mule/api-gateway"
EE_NS = "http://www.mulesoft.org/schema/mule/ee/core"


@register_rule
class API001_AutodiscoveryConfigured(BaseRule):
    rule_id = "API-001"
    name = "API autodiscovery"
    description = "API implementations should have autodiscovery configured for API Manager."
    category = RuleCategory.API_STANDARDS
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        has_autodiscovery = any(
            gc.config_type == "api-gateway:autodiscovery"
            for gc in project.global_configs
        )
        has_http_listener = any(
            f.source and "listener" in f.source.component_type.lower()
            for f in project.flows
        )
        if has_http_listener and not has_autodiscovery:
            findings.append(self._finding(
                message="API autodiscovery is not configured for this project.",
                remediation="Add an api-gateway:autodiscovery element referencing the main API flow and your API Manager instance.",
            ))
        return findings


@register_rule
class API002_SpecFilePresent(BaseRule):
    rule_id = "API-002"
    name = "API spec file present"
    description = "API projects should include a RAML or OAS specification file."
    category = RuleCategory.API_STANDARDS
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        has_http_listener = any(
            f.source and "listener" in f.source.component_type.lower()
            for f in project.flows
        )
        if has_http_listener and not project.has_raml and not project.has_oas:
            findings.append(self._finding(
                message="No RAML or OpenAPI specification file found in the project.",
                remediation="Include a RAML (.raml) or OpenAPI (.yaml/.json) spec under src/main/resources/api/.",
            ))
        return findings


@register_rule
class API003_APIkitRouter(BaseRule):
    rule_id = "API-003"
    name = "APIkit router usage"
    description = "API implementations should use the APIkit router for spec-driven development."
    category = RuleCategory.API_STANDARDS
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        has_apikit_config = any(
            APIKIT_NS in gc.config_type
            for gc in project.global_configs
        )
        has_apikit_router = False
        for flow in project.flows:
            for comp in flow.components:
                if APIKIT_NS in comp.component_type and "router" in comp.component_type.lower():
                    has_apikit_router = True
                    break

        has_api_spec = project.has_raml or project.has_oas
        if has_api_spec and not (has_apikit_config or has_apikit_router):
            findings.append(self._finding(
                message="API spec found but no APIkit router is used.",
                remediation="Scaffold your API using APIkit to generate flows from the spec and use the apikit:router.",
            ))
        return findings


@register_rule
class API004_HTTPStatusCodes(BaseRule):
    rule_id = "API-004"
    name = "HTTP status codes in error responses"
    description = "Error handlers should set appropriate HTTP status codes."
    category = RuleCategory.API_STANDARDS
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for flow in project.flows:
            if flow.flow_type != "flow":
                continue
            is_api_flow = flow.source and "listener" in (flow.source.component_type or "").lower()
            if not is_api_flow:
                continue

            for eh in flow.error_handlers:
                has_status_code = any(
                    "statusCode" in comp.attributes or "status" in comp.component_type.lower()
                    for comp in eh.components
                )
                if not has_status_code:
                    # Check the raw XML for httpStatus references
                    has_http_status = any(
                        "httpStatus" in str(comp.attributes)
                        for comp in eh.components
                    )
                    if not has_http_status:
                        findings.append(self._finding(
                            message=f"Error handler in flow '{flow.name}' may not set an HTTP status code.",
                            remediation="Set httpStatus in the error response to return appropriate HTTP status codes (400, 404, 500, etc.).",
                            file_path=flow.source_file,
                            line_number=flow.line_number,
                        ))
        return findings


@register_rule
class API005_ContentTypeHeaders(BaseRule):
    rule_id = "API-005"
    name = "Content-type headers"
    description = "HTTP responses should specify content-type headers."
    category = RuleCategory.API_STANDARDS
    severity = Severity.INFO

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            for el in tree.iter(f"{{{HTTP_NS}}}listener"):
                # Check if the listener response has content-type set
                config_ref = el.get("config-ref", "")
                response_el = el.find(f"{{{HTTP_NS}}}response")
                if response_el is not None:
                    headers = response_el.find(f"{{{HTTP_NS}}}headers")
                    if headers is None:
                        findings.append(self._finding(
                            message=f"HTTP listener response in '{rel_path}' does not set response headers.",
                            remediation="Add explicit content-type header in the HTTP listener response configuration.",
                            file_path=rel_path,
                            line_number=el.sourceline,
                        ))
        return findings


@register_rule
class API006_Versioning(BaseRule):
    rule_id = "API-006"
    name = "API versioning"
    description = "API base path should include a version indicator."
    category = RuleCategory.API_STANDARDS
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        listener_tag = f"{{{HTTP_NS}}}listener-config"
        for gc in project.global_configs:
            if gc.config_type == listener_tag:
                base_path = gc.attributes.get("basePath", "")
                if base_path and not _has_version_in_path(base_path):
                    findings.append(self._finding(
                        message=f"HTTP listener config '{gc.name}' base path '{base_path}' has no version indicator.",
                        remediation="Include a version prefix in the base path (e.g., /api/v1).",
                        file_path=gc.source_file,
                        line_number=gc.line_number,
                    ))

        # Also check listener paths in flows
        for flow in project.flows:
            if flow.source and "listener" in flow.source.component_type.lower():
                path = flow.source.attributes.get("path", "")
                if path and not _has_version_in_path(path):
                    pass  # Versioning in listener-config base path is sufficient
        return findings


@register_rule
class API007_HealthCheckEndpoint(BaseRule):
    rule_id = "API-007"
    name = "Health check endpoint"
    description = "API projects should expose a health check endpoint."
    category = RuleCategory.API_STANDARDS
    severity = Severity.INFO

    HEALTH_PATTERNS = ("health", "ping", "status", "heartbeat", "ready", "alive")

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        has_http_listener = any(
            f.source and "listener" in f.source.component_type.lower()
            for f in project.flows
        )
        if not has_http_listener:
            return findings

        has_health = False
        for flow in project.flows:
            name_lower = flow.name.lower()
            if any(p in name_lower for p in self.HEALTH_PATTERNS):
                has_health = True
                break
            if flow.source:
                path = flow.source.attributes.get("path", "").lower()
                if any(p in path for p in self.HEALTH_PATTERNS):
                    has_health = True
                    break

        if not has_health:
            findings.append(self._finding(
                message="No health check endpoint detected (e.g., /health, /ping).",
                remediation="Add a lightweight health check flow with an HTTP listener on /health that returns 200 OK.",
            ))
        return findings


@register_rule
class API008_ConsistentErrorFormat(BaseRule):
    rule_id = "API-008"
    name = "Consistent error response format"
    description = "Error responses should follow a consistent format across all flows."
    category = RuleCategory.API_STANDARDS
    severity = Severity.INFO

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        api_flows = [
            f for f in project.flows
            if f.flow_type == "flow"
            and f.source
            and "listener" in f.source.component_type.lower()
        ]
        if len(api_flows) < 2:
            return findings

        error_payloads: list[str] = []
        for flow in api_flows:
            for eh in flow.error_handlers:
                for comp in eh.components:
                    ct = comp.component_type.lower()
                    if "payload" in ct or "transform" in ct:
                        error_payloads.append(comp.component_type)

        if api_flows and not error_payloads:
            findings.append(self._finding(
                message="API flows have error handlers but no consistent error response payload is set.",
                remediation="Define a standard error response format (e.g., {\"error\": ..., \"message\": ...}) and apply it in all error handlers.",
            ))
        return findings


def _has_version_in_path(path: str) -> bool:
    import re
    return bool(re.search(r"/v\d", path, re.IGNORECASE))
