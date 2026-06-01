from __future__ import annotations

import re
from pathlib import Path

from lxml import etree

from app.models import (
    Connector,
    Dependency,
    ErrorHandler,
    Flow,
    GlobalConfig,
    MuleComponent,
    MuleProject,
    PropertiesFile,
)

MULE_NS = "http://www.mulesoft.org/schema/mule/core"
HTTP_NS = "http://www.mulesoft.org/schema/mule/http"
APIKIT_NS = "http://www.mulesoft.org/schema/mule/mule-apikit"
EE_NS = "http://www.mulesoft.org/schema/mule/ee/core"
BATCH_NS = "http://www.mulesoft.org/schema/mule/batch"
OS_NS = "http://www.mulesoft.org/schema/mule/os"
TLS_NS = "http://www.mulesoft.org/schema/mule/tls"
AUTODISCOVERY_NS = "http://www.mulesoft.org/schema/mule/api-gateway"
SECURE_PROPS_NS = "http://www.mulesoft.org/schema/mule/secure-properties"
DB_NS = "http://www.mulesoft.org/schema/mule/db"

NS_MAP = {
    "mule": MULE_NS,
    "http": HTTP_NS,
    "apikit": APIKIT_NS,
    "ee": EE_NS,
    "batch": BATCH_NS,
    "os": OS_NS,
    "tls": TLS_NS,
    "api-gateway": AUTODISCOVERY_NS,
    "secure-properties": SECURE_PROPS_NS,
    "db": DB_NS,
}

# Patterns that likely indicate secrets in property values
SECRET_PATTERNS = re.compile(
    r"(password|secret|api[_-]?key|token|credential|client[_-]?secret|"
    r"private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)


def parse_project(project_root: str) -> MuleProject:
    root = Path(project_root)
    project = MuleProject(base_path=project_root)

    _parse_pom(root, project)
    _detect_api_specs(root, project)
    _detect_mule_artifact(root, project)
    _parse_mule_xml_files(root, project)
    _parse_properties_files(root, project)

    return project


# ---------------------------------------------------------------------------
# pom.xml
# ---------------------------------------------------------------------------

def _parse_pom(root: Path, project: MuleProject) -> None:
    pom_path = root / "pom.xml"
    if not pom_path.exists():
        return

    tree = etree.parse(str(pom_path))
    pom_root = tree.getroot()
    pom_ns = {"m": "http://maven.apache.org/POM/4.0.0"}

    name_el = pom_root.find("m:artifactId", pom_ns)
    if name_el is not None and name_el.text:
        project.project_name = name_el.text

    for dep in pom_root.findall(".//m:dependency", pom_ns):
        gid = dep.findtext("m:groupId", default="", namespaces=pom_ns)
        aid = dep.findtext("m:artifactId", default="", namespaces=pom_ns)
        ver = dep.findtext("m:version", default="", namespaces=pom_ns)
        clf = dep.findtext("m:classifier", default="", namespaces=pom_ns)
        scope = dep.findtext("m:scope", default="", namespaces=pom_ns)
        project.dependencies.append(
            Dependency(
                group_id=gid,
                artifact_id=aid,
                version=ver,
                classifier=clf,
                scope=scope,
            )
        )


# ---------------------------------------------------------------------------
# Detect RAML / OAS spec files
# ---------------------------------------------------------------------------

def _detect_api_specs(root: Path, project: MuleProject) -> None:
    for p in root.rglob("*"):
        suffix = p.suffix.lower()
        name_lower = p.name.lower()
        if suffix == ".raml":
            project.has_raml = True
        if suffix in (".yaml", ".yml", ".json"):
            if "openapi" in name_lower or "swagger" in name_lower:
                project.has_oas = True


def _detect_mule_artifact(root: Path, project: MuleProject) -> None:
    project.has_mule_artifact_json = (root / "mule-artifact.json").exists()


# ---------------------------------------------------------------------------
# Mule XML parsing
# ---------------------------------------------------------------------------

def _parse_mule_xml_files(root: Path, project: MuleProject) -> None:
    mule_dir = root / "src" / "main" / "mule"
    xml_dirs = [mule_dir] if mule_dir.is_dir() else []
    # Also pick up XML files directly under src/main/resources (global.xml, etc.)
    resources_dir = root / "src" / "main" / "resources"
    if resources_dir.is_dir():
        xml_dirs.append(resources_dir)

    for xml_dir in xml_dirs:
        for xml_path in xml_dir.rglob("*.xml"):
            rel_path = str(xml_path.relative_to(root))
            try:
                raw = xml_path.read_bytes()
                project.xml_files[rel_path] = raw
                tree = etree.parse(str(xml_path))
                _parse_xml_tree(tree, rel_path, project)
            except etree.XMLSyntaxError:
                pass  # skip unparseable files


def _parse_xml_tree(tree: etree._ElementTree, rel_path: str, project: MuleProject) -> None:
    root_el = tree.getroot()
    nsmap = _build_nsmap(root_el)

    # Flows and sub-flows
    for tag, flow_type in [
        (f"{{{MULE_NS}}}flow", "flow"),
        (f"{{{MULE_NS}}}sub-flow", "sub-flow"),
    ]:
        for flow_el in root_el.iter(tag):
            flow = _parse_flow(flow_el, flow_type, rel_path)
            project.flows.append(flow)

    # Global configs (HTTP listeners/request configs, TLS, DB, etc.)
    _extract_global_configs(root_el, rel_path, project)

    # Connectors used inside flows are captured as MuleComponents already,
    # but we also collect top-level connector configs.
    _extract_connectors(root_el, rel_path, project)


def _parse_flow(flow_el: etree._Element, flow_type: str, rel_path: str) -> Flow:
    name = flow_el.get("name", "unnamed")
    line = flow_el.sourceline

    source = None
    components: list[MuleComponent] = []
    error_handlers: list[ErrorHandler] = []

    for child in flow_el:
        tag = _local_tag(child)

        if tag == "error-handler":
            for eh_child in child:
                eh_tag = _local_tag(eh_child)
                eh = ErrorHandler(
                    handler_type=eh_tag,
                    error_type=eh_child.get("type", ""),
                    source_file=rel_path,
                    line_number=eh_child.sourceline,
                )
                for comp in eh_child:
                    eh.components.append(_element_to_component(comp, rel_path))
                error_handlers.append(eh)
            continue

        comp = _element_to_component(child, rel_path)
        # The first component with a "listener" or "scheduler" flavour is the source
        if source is None and _is_source_component(child):
            source = comp
        else:
            components.append(comp)

    return Flow(
        name=name,
        flow_type=flow_type,
        source=source,
        components=components,
        error_handlers=error_handlers,
        source_file=rel_path,
        line_number=line,
    )


def _element_to_component(el: etree._Element, rel_path: str) -> MuleComponent:
    return MuleComponent(
        name=el.get("name", el.get("doc:name", "")),
        component_type=_full_tag(el),
        attributes={k: v for k, v in el.attrib.items()},
        source_file=rel_path,
        line_number=el.sourceline,
    )


def _is_source_component(el: etree._Element) -> bool:
    tag = _local_tag(el)
    return tag in ("listener", "scheduler", "poll")


def _extract_global_configs(root_el: etree._Element, rel_path: str, project: MuleProject) -> None:
    config_tags = [
        f"{{{HTTP_NS}}}listener-config",
        f"{{{HTTP_NS}}}request-config",
        f"{{{TLS_NS}}}context",
        f"{{{DB_NS}}}config",
        f"{{{SECURE_PROPS_NS}}}config",
        f"{{{APIKIT_NS}}}config",
    ]
    for tag in config_tags:
        for el in root_el.iter(tag):
            project.global_configs.append(
                GlobalConfig(
                    name=el.get("name", ""),
                    config_type=_full_tag(el),
                    attributes={k: v for k, v in el.attrib.items()},
                    source_file=rel_path,
                    line_number=el.sourceline,
                )
            )

    # Also pick up api-gateway:autodiscovery
    for el in root_el.iter(f"{{{AUTODISCOVERY_NS}}}autodiscovery"):
        project.global_configs.append(
            GlobalConfig(
                name=el.get("apiId", ""),
                config_type="api-gateway:autodiscovery",
                attributes={k: v for k, v in el.attrib.items()},
                source_file=rel_path,
                line_number=el.sourceline,
            )
        )


def _extract_connectors(root_el: etree._Element, rel_path: str, project: MuleProject) -> None:
    connector_patterns = [
        f"{{{HTTP_NS}}}listener-config",
        f"{{{HTTP_NS}}}request-config",
        f"{{{DB_NS}}}config",
    ]
    for tag in connector_patterns:
        for el in root_el.iter(tag):
            project.connectors.append(
                Connector(
                    name=el.get("name", ""),
                    connector_type=_full_tag(el),
                    config_ref=el.get("config-ref", ""),
                    attributes={k: v for k, v in el.attrib.items()},
                    source_file=rel_path,
                    line_number=el.sourceline,
                )
            )


# ---------------------------------------------------------------------------
# Properties files
# ---------------------------------------------------------------------------

def _parse_properties_files(root: Path, project: MuleProject) -> None:
    resources = root / "src" / "main" / "resources"
    if not resources.is_dir():
        return

    for prop_file in resources.rglob("*.properties"):
        pf = _parse_single_properties(prop_file, root)
        project.properties_files.append(pf)

    for yaml_file in resources.rglob("*.yaml"):
        if yaml_file.name.lower() in ("openapi.yaml", "swagger.yaml"):
            continue
        pf = _parse_single_properties(yaml_file, root)
        project.properties_files.append(pf)


def _parse_single_properties(filepath: Path, root: Path) -> PropertiesFile:
    rel = str(filepath.relative_to(root))
    entries: dict[str, str] = {}
    is_secure = "secure" in filepath.stem.lower()

    if filepath.suffix == ".properties":
        for line in filepath.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                entries[key.strip()] = value.strip()
    # YAML properties handled as flat key-value for basic checking
    elif filepath.suffix in (".yaml", ".yml"):
        try:
            import yaml
            data = yaml.safe_load(filepath.read_text(errors="replace"))
            if isinstance(data, dict):
                entries = _flatten_dict(data)
        except Exception:
            pass

    return PropertiesFile(
        filename=filepath.name,
        path=rel,
        entries=entries,
        is_secure=is_secure,
    )


def _flatten_dict(d: dict, prefix: str = "") -> dict[str, str]:
    items: dict[str, str] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            items.update(_flatten_dict(v, key))
        else:
            items[key] = str(v)
    return items


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def _local_tag(el: etree._Element) -> str:
    tag = el.tag
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _full_tag(el: etree._Element) -> str:
    return el.tag


def _build_nsmap(root: etree._Element) -> dict[str, str]:
    nsmap = {}
    for prefix, uri in (root.nsmap or {}).items():
        if prefix:
            nsmap[prefix] = uri
    return nsmap
