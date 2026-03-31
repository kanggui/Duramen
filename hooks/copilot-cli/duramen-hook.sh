#!/bin/bash
# duramen pre-tool-use hook for Copilot CLI
# Reads tool call payload from stdin, evaluates via duramen, returns permission decision.

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
    POLICY_NAME=$(echo "$RESULT" | jq -r '.policy_name // empty')
    POLICY_DESC=$(echo "$RESULT" | jq -r '.policy_description // empty')
    REASON=$(echo "$RESULT" | jq -r '.message // "Blocked by policy"')
    if [ -n "$POLICY_NAME" ]; then
      REASON="$REASON [$POLICY_NAME"
      if [ -n "$POLICY_DESC" ]; then
        REASON="$REASON: $POLICY_DESC"
      fi
      REASON="$REASON]"
    fi
    jq -n --arg reason "$REASON" '{"permissionDecision":"deny","permissionDecisionReason":$reason}'
    ;;
  2)
    POLICY_NAME=$(echo "$RESULT" | jq -r '.policy_name // empty')
    POLICY_DESC=$(echo "$RESULT" | jq -r '.policy_description // empty')
    REASON=$(echo "$RESULT" | jq -r '.message // "Requires approval"')
    if [ -n "$POLICY_NAME" ]; then
      REASON="$REASON [$POLICY_NAME"
      if [ -n "$POLICY_DESC" ]; then
        REASON="$REASON: $POLICY_DESC"
      fi
      REASON="$REASON]"
    fi
    jq -n --arg reason "$REASON" '{"permissionDecision":"ask","permissionDecisionReason":$reason}'
    ;;
  *)
    # Fail-closed on system errors — security systems must never fail-open
    echo '{"permissionDecision": "deny", "permissionDecisionReason": "Duramen system error (fail-closed)"}'
    ;;
esac
