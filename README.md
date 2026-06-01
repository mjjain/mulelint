# MuleSoft Compliance Checker

A web application that analyzes MuleSoft Mule 4 applications for compliance with best practices, security standards, API design guidelines, and custom organizational rules.

## Features

- **Upload & Analyze**: Upload a Mule project ZIP and get an instant compliance report
- **40+ Built-in Rules** across four categories:
  - Best Practices (naming, error handling, logging, timeouts)
  - Security (hardcoded secrets, HTTPS, TLS, authentication)
  - API Standards (autodiscovery, versioning, health checks)
  - Custom Rules (YAML-configurable XPath-based checks)
- **Visual Dashboard**: Compliance score, category breakdowns, filterable findings
- **Export**: Download reports as JSON

## Quick Start

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open http://localhost:8000 in your browser.

## Custom Rules

Add custom compliance rules in `rules_config/custom_rules.yaml`:

```yaml
rules:
  - id: CUSTOM-001
    name: Require global error handler
    description: All flows must reference the org global error handler
    severity: error
    xpath: "//mule:flow[not(.//mule:error-handler)]"
    message: "Flow '{flow_name}' does not use the global error handler"
```

## Project Structure

```
app/
  main.py              # FastAPI routes and app config
  models.py            # Pydantic data models
  core/
    extractor.py       # ZIP upload handling
    parser.py          # Mule XML/properties/pom parser
    engine.py          # Rule execution engine
    reporter.py        # Report generation and scoring
  rules/
    base.py            # Base rule class
    best_practices.py  # BP-001 through BP-010
    security.py        # SEC-001 through SEC-010
    api_standards.py   # API-001 through API-008
    custom.py          # YAML-driven custom rules
  templates/           # Jinja2 HTML templates
  static/              # CSS assets
rules_config/          # Rule configuration files
```
