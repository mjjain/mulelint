from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class RuleCategory(str, Enum):
    BEST_PRACTICES = "Best Practices"
    SECURITY = "Security"
    API_STANDARDS = "API Standards"
    CUSTOM = "Custom"


class LetterGrade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


# ---------------------------------------------------------------------------
# Mule project model (populated by the parser)
# ---------------------------------------------------------------------------

class MuleComponent(BaseModel):
    name: str = ""
    component_type: str = ""
    attributes: Dict[str, str] = Field(default_factory=dict)
    source_file: str = ""
    line_number: Optional[int] = None


class ErrorHandler(BaseModel):
    handler_type: str = ""  # on-error-propagate, on-error-continue
    error_type: str = ""
    components: List[MuleComponent] = Field(default_factory=list)
    source_file: str = ""
    line_number: Optional[int] = None


class Flow(BaseModel):
    name: str
    flow_type: str = "flow"  # flow | sub-flow
    source: Optional[MuleComponent] = None
    components: List[MuleComponent] = Field(default_factory=list)
    error_handlers: List[ErrorHandler] = Field(default_factory=list)
    source_file: str = ""
    line_number: Optional[int] = None


class Connector(BaseModel):
    name: str
    connector_type: str = ""
    config_ref: str = ""
    attributes: Dict[str, str] = Field(default_factory=dict)
    source_file: str = ""
    line_number: Optional[int] = None


class GlobalConfig(BaseModel):
    name: str
    config_type: str = ""
    attributes: Dict[str, str] = Field(default_factory=dict)
    source_file: str = ""
    line_number: Optional[int] = None


class Dependency(BaseModel):
    group_id: str
    artifact_id: str
    version: str = ""
    classifier: str = ""
    scope: str = ""


class PropertiesFile(BaseModel):
    filename: str
    path: str
    entries: Dict[str, str] = Field(default_factory=dict)
    is_secure: bool = False


class MuleProject(BaseModel):
    """In-memory representation of a parsed Mule 4 project."""
    project_name: str = ""
    mule_version: str = ""
    flows: List[Flow] = Field(default_factory=list)
    connectors: List[Connector] = Field(default_factory=list)
    global_configs: List[GlobalConfig] = Field(default_factory=list)
    dependencies: List[Dependency] = Field(default_factory=list)
    properties_files: List[PropertiesFile] = Field(default_factory=list)
    xml_files: Dict[str, bytes] = Field(default_factory=dict)
    has_raml: bool = False
    has_oas: bool = False
    has_mule_artifact_json: bool = False
    base_path: str = ""


# ---------------------------------------------------------------------------
# Rule & finding models
# ---------------------------------------------------------------------------

class RuleDefinition(BaseModel):
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity = Severity.ERROR
    enabled: bool = True


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    category: RuleCategory
    severity: Severity
    file_path: str = ""
    line_number: Optional[int] = None
    message: str = ""
    remediation: str = ""


# ---------------------------------------------------------------------------
# Report models
# ---------------------------------------------------------------------------

class RuleStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    INFO = "info"


class CheckedRule(BaseModel):
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    status: RuleStatus = RuleStatus.PASSED


class CategoryScore(BaseModel):
    category: RuleCategory
    total_rules: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    score_pct: float = 0.0


class ComplianceReport(BaseModel):
    report_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    project_name: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    overall_score: float = 0.0
    letter_grade: LetterGrade = LetterGrade.F
    category_scores: List[CategoryScore] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    checked_rules: List[CheckedRule] = Field(default_factory=list)
    total_rules_checked: int = 0
    total_passed: int = 0
    total_failed: int = 0
    total_warnings: int = 0


# ---------------------------------------------------------------------------
# Custom rule config (loaded from YAML)
# ---------------------------------------------------------------------------

class CustomRuleConfig(BaseModel):
    id: str
    name: str
    description: str = ""
    severity: Severity = Severity.WARNING
    xpath: str
    message: str = ""
    remediation: str = ""


class CustomRulesFile(BaseModel):
    rules: List[CustomRuleConfig] = Field(default_factory=list)


class DefaultRuleOverride(BaseModel):
    rule_id: str
    enabled: bool = True
    severity: Optional[Severity] = None


class DefaultRulesConfig(BaseModel):
    overrides: List[DefaultRuleOverride] = Field(default_factory=list)
