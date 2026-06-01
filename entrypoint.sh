#!/usr/bin/env bash
set -euo pipefail

# Resolve the directory where this action lives
ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Inputs (set by action.yml as environment variables)
PROJECT_PATH="${INPUT_PATH:-.}"
THRESHOLD="${INPUT_THRESHOLD:-80}"
CUSTOM_RULES="${INPUT_CUSTOM_RULES:-}"
OUTPUT_FILE="${INPUT_OUTPUT:-}"

# Build CLI arguments
CLI_ARGS=(
    --path "$PROJECT_PATH"
    --threshold "$THRESHOLD"
    --format summary
    --summary-file "$RUNNER_TEMP/compliance-summary.md"
)

if [[ -n "$CUSTOM_RULES" ]]; then
    CLI_ARGS+=(--custom-rules "$CUSTOM_RULES")
fi

if [[ -n "$OUTPUT_FILE" ]]; then
    CLI_ARGS+=(--output "$OUTPUT_FILE")
fi

# Run the compliance checker
PYTHONPATH="$ACTION_DIR" python3 -m app.cli "${CLI_ARGS[@]}" || EXIT_CODE=$?
EXIT_CODE=${EXIT_CODE:-0}

# Write the markdown summary as a multiline output
if [[ -f "$RUNNER_TEMP/compliance-summary.md" ]]; then
    {
        echo 'markdown<<COMPLIANCE_SUMMARY_EOF'
        cat "$RUNNER_TEMP/compliance-summary.md"
        echo 'COMPLIANCE_SUMMARY_EOF'
    } >> "$GITHUB_OUTPUT"
fi

exit "$EXIT_CODE"
