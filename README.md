# MuleLint — MuleSoft Application Best Practices Checker

Analyze MuleSoft Mule 4 applications for compliance with best practices, security standards, API design guidelines, and custom organizational rules. Available as a **Web UI**, **CLI**, and **GitHub Action**.

## Features

- **40+ Built-in Rules** across four categories:
  - **Best Practices** — naming conventions, error handling, logging, timeouts, flow size
  - **Security** — hardcoded secrets, HTTPS enforcement, TLS, authentication
  - **API Standards** — autodiscovery, versioning, health checks, content types
  - **Custom Rules** — YAML-configurable XPath-based checks
- **Visual Dashboard**: Compliance score, letter grade, category breakdowns, filterable findings
- **Multiple interfaces**: Web UI, CLI, and GitHub Action
- **Export**: JSON and Markdown reports

---

## Usage

### 1. GitHub Action (CI/CD)

Add this to your Mule project's `.github/workflows/mulelint.yml`:

```yaml
name: MuleLint

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Compliance Check
        id: compliance
        uses: mjjain/mulelint@main
        with:
          path: "."
          threshold: "80"
          post-comment: "true"

      - name: Fail if non-compliant
        if: steps.compliance.outputs.passed == 'false'
        run: exit 1
```

#### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to the Mule project directory |
| `threshold` | `80` | Minimum passing score (0–100) |
| `custom-rules` | | Path to a custom rules YAML file |
| `post-comment` | `true` | Post summary as a PR comment |
| `output` | | Path to write the full JSON report |

#### Outputs

| Output | Description |
|--------|-------------|
| `score` | Overall compliance score (0–100) |
| `grade` | Letter grade (A–F) |
| `passed` | Whether the check passed the threshold (`true`/`false`) |
| `total-rules` | Total number of rules checked |
| `total-passed` | Number of rules that passed |
| `total-failed` | Number of rules that failed |
| `total-warnings` | Number of warnings |
| `markdown` | Full markdown compliance report |

### 2. CLI

```bash
pip install -r requirements.txt

# Basic check
python -m app.cli --path /path/to/mule-project

# With threshold and JSON output
python -m app.cli --path . --threshold 80 --format json

# With custom rules
python -m app.cli --path . --custom-rules rules_config/custom_rules.yaml
```

### 3. Web UI

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://localhost:8000, upload a Mule project ZIP/JAR, and view the compliance report.

---

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

---

## Project Structure

```
action.yml             # GitHub Action manifest
entrypoint.sh          # GitHub Action entry point
app/
  main.py              # FastAPI routes and app config
  cli.py               # Command-line interface
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

## License

MIT
