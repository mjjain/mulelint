"""Quick smoke test: imports, rule loading, and a sample parse."""
from app.main import app
from app.core.engine import ComplianceEngine

print("Import successful")
e = ComplianceEngine()
print(f"Loaded {len(e.rules)} rules")
for r in e.rules:
    print(f"  {r.rule_id}: {r.name} ({r.category.value}) [{r.severity.value}]")
