#!/bin/bash
# duramen pre-tool-use hook for Copilot CLI
# Reads tool call payload from stdin, evaluates via duramen, returns permission decision.

# Verify that jq exists AND responds to a basic flag (Integrity check)
# A missing or malformed jq command could lead to a silent bypass of the policy engine.
if ! command -v jq >/dev/null 2>&1 || ! jq --version >/dev/null 2>&1; then
  echo '{"permissionDecision":"deny","permissionDecisionReason":"Duramen hook: valid jq not found (fail-closed)"}'
  exit 1
fi

# Pure-shell fallback for JSON construction
# Escapes backslashes, double quotes, and tabs safely without jq
safe_json_reason() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | tr -d '\n'
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Use local binary if present, otherwise fall back to PATH
if [ -x "$SCRIPT_DIR/duramen" ]; then
    DURAMEN="$SCRIPT_DIR/duramen"
else
    DURAMEN="duramen"
fi

INPUT=$(cat)

# Run duramen check with copilot-cli normalizer
RESULT=$(echo "$INPUT" | "$DURAMEN" check --agent copilot-cli 2>/dev/null)
EXIT_CODE=$?

case $EXIT_CODE in
  0)
    echo '{"permissionDecision": "allow"}'
    ;;
  1)
    # If jq is broken here, these simply become empty strings, which is safe.
    POLICY_NAME=$(echo "$RESULT" | jq -r '.policy_name // empty' 2>/dev/null)
    POLICY_DESC=$(echo "$RESULT" | jq -r '.policy_description // empty' 2>/dev/null)
    REASON=$(echo "$RESULT" | jq -r '.message // empty' 2>/dev/null)
    [ -z "$REASON" ] && REASON="Blocked by policy"

    if [ -n "$POLICY_NAME" ]; then
      REASON="$REASON [$POLICY_NAME"
      if [ -n "$POLICY_DESC" ]; then
        REASON="$REASON: $POLICY_DESC"
      fi
      REASON="$REASON]"
    fi

    # Try jq first, fallback to pure-shell construction if jq fails/is removed mid-execution
    jq -n --arg reason "$REASON" '{"permissionDecision":"deny","permissionDecisionReason":$reason}' 2>/dev/null || \
      echo "{\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"$(safe_json_reason "$REASON")\"}"
    ;;
  2)
    POLICY_NAME=$(echo "$RESULT" | jq -r '.policy_name // empty' 2>/dev/null)
    POLICY_DESC=$(echo "$RESULT" | jq -r '.policy_description // empty' 2>/dev/null)
    REASON=$(echo "$RESULT" | jq -r '.message // empty' 2>/dev/null)
    [ -z "$REASON" ] && REASON="Requires approval"

    if [ -n "$POLICY_NAME" ]; then
      REASON="$REASON [$POLICY_NAME"
      if [ -n "$POLICY_DESC" ]; then
        REASON="$REASON: $POLICY_DESC"
      fi
      REASON="$REASON]"
    fi

    # Try jq first, fallback to pure-shell construction if jq fails/is removed mid-execution
    jq -n --arg reason "$REASON" '{"permissionDecision":"ask","permissionDecisionReason":$reason}' 2>/dev/null || \
      echo "{\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"$(safe_json_reason "$REASON")\"}"
    ;;
  *)
    # Fail-closed on system errors — security systems must never fail-open
    echo '{"permissionDecision": "deny", "permissionDecisionReason": "Duramen system error (fail-closed)"}'
    ;;
esac