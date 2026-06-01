from __future__ import annotations

import re

from lxml import etree

from app.core.engine import register_rule
from app.models import Finding, MuleProject, RuleCategory, Severity
from app.rules.base import BaseRule

MULE_NS = "http://www.mulesoft.org/schema/mule/core"
HTTP_NS = "http://www.mulesoft.org/schema/mule/http"
TLS_NS = "http://www.mulesoft.org/schema/mule/tls"
SECURE_PROPS_NS = "http://www.mulesoft.org/schema/mule/secure-properties"

SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api[_\-]?key|token|credential|client[_\-]?secret|"
    r"private[_\-]?key|access[_\-]?key|auth)",
    re.IGNORECASE,
)

PROPERTY_PLACEHOLDER = re.compile(r"\$\{[^}]+\}")

SENSITIVE_LOG_PATTERN = re.compile(
    r"(password|secret|token|credential|api[_\-]?key|authorization)",
    re.IGNORECASE,
)


@register_rule
class SEC001_HardcodedCredentialsXML(BaseRule):
    rule_id = "SEC-001"
    name = "No hardcoded credentials in XML"
    description = "XML configs should not contain hardcoded passwords or secrets."
    category = RuleCategory.SECURITY
    severity = Severity.ERROR

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            for el in tree.iter():
                for attr_name, attr_val in el.attrib.items():
                    if SECRET_KEY_PATTERN.search(attr_name) and attr_val:
                        if not PROPERTY_PLACEHOLDER.search(attr_val):
                            findings.append(self._finding(
                                message=f"Possible hardcoded credential in attribute '{attr_name}' in {rel_path}.",
                                remediation="Use a property placeholder like ${secure::password} or externalize to a secure properties file.",
                                file_path=rel_path,
                                line_number=el.sourceline,
                            ))
        return findings


@register_rule
class SEC002_HardcodedSecretsProperties(BaseRule):
    rule_id = "SEC-002"
    name = "No hardcoded secrets in properties"
    description = "Properties files should not contain plaintext secrets."
    category = RuleCategory.SECURITY
    severity = Severity.ERROR

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for pf in project.properties_files:
            if pf.is_secure:
                continue
            for key, value in pf.entries.items():
                if SECRET_KEY_PATTERN.search(key) and value:
                    if not PROPERTY_PLACEHOLDER.search(value) and not value.startswith("!["):
                        findings.append(self._finding(
                            message=f"Possible plaintext secret for key '{key}' in {pf.filename}.",
                            remediation="Move sensitive values to a secure (encrypted) properties file or use vault references.",
                            file_path=pf.path,
                        ))
        return findings


@register_rule
class SEC003_SecurePropertiesUsed(BaseRule):
    rule_id = "SEC-003"
    name = "Secure properties file used"
    description = "Projects with secrets should use the Mule Secure Properties module."
    category = RuleCategory.SECURITY
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        has_secure_config = any(
            SECURE_PROPS_NS in gc.config_type
            for gc in project.global_configs
        )
        has_secure_dependency = any(
            "secure-properties" in d.artifact_id.lower() or
            "secure-configuration-property" in d.artifact_id.lower()
            for d in project.dependencies
        )
        has_secrets_in_props = any(
            SECRET_KEY_PATTERN.search(key)
            for pf in project.properties_files
            for key in pf.entries
        )

        if has_secrets_in_props and not (has_secure_config or has_secure_dependency):
            findings.append(self._finding(
                message="Project has properties with sensitive keys but no Secure Properties module configured.",
                remediation="Add the mule-secure-configuration-property module and encrypt sensitive values.",
            ))
        return findings


@register_rule
class SEC004_HTTPSEnforced(BaseRule):
    rule_id = "SEC-004"
    name = "HTTPS enforcement"
    description = "External endpoints should use HTTPS, not plain HTTP."
    category = RuleCategory.SECURITY
    severity = Severity.ERROR

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        request_config_tag = f"{{{HTTP_NS}}}request-config"
        for gc in project.global_configs:
            if gc.config_type == request_config_tag:
                protocol = gc.attributes.get("protocol", "").upper()
                host = gc.attributes.get("host", "")
                base_path = gc.attributes.get("basePath", "")
                # Skip localhost/internal references
                if host and ("localhost" in host or "127.0.0.1" in host):
                    continue
                if protocol == "HTTP" or (not protocol and "https" not in host.lower()):
                    findings.append(self._finding(
                        message=f"HTTP request config '{gc.name}' uses plain HTTP for external communication.",
                        remediation="Change protocol to HTTPS and configure a TLS context.",
                        file_path=gc.source_file,
                        line_number=gc.line_number,
                    ))
        return findings


@register_rule
class SEC005_TLSConfigured(BaseRule):
    rule_id = "SEC-005"
    name = "TLS context configuration"
    description = "HTTPS connectors should have a proper TLS context configured."
    category = RuleCategory.SECURITY
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        tls_tag = f"{{{TLS_NS}}}context"
        has_tls = any(gc.config_type == tls_tag for gc in project.global_configs)

        https_configs = [
            gc for gc in project.global_configs
            if gc.config_type == f"{{{HTTP_NS}}}request-config"
            and gc.attributes.get("protocol", "").upper() == "HTTPS"
        ]
        listener_configs = [
            gc for gc in project.global_configs
            if gc.config_type == f"{{{HTTP_NS}}}listener-config"
            and gc.attributes.get("protocol", "").upper() == "HTTPS"
        ]

        for gc in https_configs + listener_configs:
            tls_ref = gc.attributes.get("tlsContext", gc.attributes.get("tls:context", ""))
            if not tls_ref and not has_tls:
                findings.append(self._finding(
                    message=f"HTTPS config '{gc.name}' has no TLS context reference.",
                    remediation="Configure a tls:context with appropriate trust/key stores and reference it.",
                    file_path=gc.source_file,
                    line_number=gc.line_number,
                ))
        return findings


@register_rule
class SEC006_SensitiveDataInLogs(BaseRule):
    rule_id = "SEC-006"
    name = "No sensitive data in logs"
    description = "Logger components should not log sensitive data like passwords or tokens."
    category = RuleCategory.SECURITY
    severity = Severity.ERROR

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            for el in tree.iter(f"{{{MULE_NS}}}logger"):
                msg = el.get("message", "")
                if SENSITIVE_LOG_PATTERN.search(msg):
                    findings.append(self._finding(
                        message=f"Logger may expose sensitive data in '{rel_path}'.",
                        remediation="Remove or mask sensitive fields (password, token, etc.) from log messages.",
                        file_path=rel_path,
                        line_number=el.sourceline,
                    ))
        return findings


@register_rule
class SEC007_OAuthOverBasicAuth(BaseRule):
    rule_id = "SEC-007"
    name = "Prefer OAuth over Basic Auth"
    description = "Client credentials or OAuth should be used instead of basic authentication."
    category = RuleCategory.SECURITY
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            for el in tree.iter():
                tag = el.tag if isinstance(el.tag, str) else ""
                if "basic-authentication" in tag.lower() or "basic-auth" in tag.lower():
                    findings.append(self._finding(
                        message=f"Basic authentication used in '{rel_path}'.",
                        remediation="Consider upgrading to OAuth 2.0 client credentials or token-based authentication.",
                        file_path=rel_path,
                        line_number=el.sourceline,
                    ))
        return findings


@register_rule
class SEC008_CORSPolicy(BaseRule):
    rule_id = "SEC-008"
    name = "CORS configuration"
    description = "HTTP listeners exposed as APIs should have CORS configured if browser-facing."
    category = RuleCategory.SECURITY
    severity = Severity.INFO

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        listener_tag = f"{{{HTTP_NS}}}listener-config"
        listeners = [gc for gc in project.global_configs if gc.config_type == listener_tag]
        if not listeners:
            return findings

        has_cors = False
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            for el in tree.iter():
                tag = el.tag if isinstance(el.tag, str) else ""
                if "cors" in tag.lower():
                    has_cors = True
                    break

        if not has_cors and listeners:
            findings.append(self._finding(
                message="No CORS configuration detected for HTTP listener(s).",
                remediation="If this API is accessed from browsers, configure CORS interceptors on the HTTP listener.",
            ))
        return findings


@register_rule
class SEC009_AuthOnInbound(BaseRule):
    rule_id = "SEC-009"
    name = "Authentication on inbound endpoints"
    description = "Inbound HTTP endpoints should enforce authentication or API key validation."
    category = RuleCategory.SECURITY
    severity = Severity.WARNING

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        http_listener_flows = [
            f for f in project.flows
            if f.source and "listener" in f.source.component_type.lower()
        ]
        if not http_listener_flows:
            return findings

        has_auth_policy = any(
            gc.config_type == "api-gateway:autodiscovery"
            for gc in project.global_configs
        )
        has_auth_component = False
        for flow in http_listener_flows:
            for comp in flow.components:
                ct = comp.component_type.lower()
                if any(kw in ct for kw in ("validate", "authenticate", "authorization", "policy")):
                    has_auth_component = True
                    break

        if not has_auth_policy and not has_auth_component:
            findings.append(self._finding(
                message="HTTP listener flows do not appear to enforce authentication.",
                remediation="Apply API autodiscovery with policies, or add authentication validation in the flow.",
            ))
        return findings


@register_rule
class SEC010_ExternalizedProperties(BaseRule):
    rule_id = "SEC-010"
    name = "Environment-specific properties externalized"
    description = "Environment-specific values should use property placeholders, not hardcoded values."
    category = RuleCategory.SECURITY
    severity = Severity.WARNING

    ENV_KEYS = re.compile(r"(host|port|url|uri|endpoint|base[_\-]?path)", re.IGNORECASE)

    def check(self, project: MuleProject) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, raw_xml in project.xml_files.items():
            try:
                tree = etree.fromstring(raw_xml)
            except etree.XMLSyntaxError:
                continue
            for el in tree.iter():
                for attr_name, attr_val in el.attrib.items():
                    if self.ENV_KEYS.search(attr_name) and attr_val:
                        if not PROPERTY_PLACEHOLDER.search(attr_val) and "://" in attr_val:
                            findings.append(self._finding(
                                message=f"Hardcoded URL/endpoint in attribute '{attr_name}' in {rel_path}.",
                                remediation="Use a property placeholder like ${http.host} and define per-environment properties files.",
                                file_path=rel_path,
                                line_number=el.sourceline,
                            ))
        return findings
