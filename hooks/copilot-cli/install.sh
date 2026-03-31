#!/bin/bash
# Install Duramen Copilot CLI hooks into a target repository.
# Usage: ./install.sh /path/to/repo

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_PATH="${1:?Usage: $0 <repo-path>}"

if [ ! -d "$REPO_PATH" ]; then
    echo "Error: '$REPO_PATH' is not a directory"
    exit 1
fi

if [ ! -d "$REPO_PATH/.git" ]; then
    echo "Warning: '$REPO_PATH' does not appear to be a git repository"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

HOOKS_DIR="$REPO_PATH/.github/hooks"
mkdir -p "$HOOKS_DIR"

cp "$SCRIPT_DIR/duramen.json" "$HOOKS_DIR/"
cp "$SCRIPT_DIR/duramen-hook.sh" "$HOOKS_DIR/"
cp "$SCRIPT_DIR/duramen-hook.ps1" "$HOOKS_DIR/"

chmod +x "$HOOKS_DIR/duramen-hook.sh"

echo "Duramen hooks installed to $HOOKS_DIR/"
echo "  - duramen.json"
echo "  - duramen-hook.sh"
echo "  - duramen-hook.ps1"
echo ""

if command -v duramen &> /dev/null; then
    echo "✓ duramen binary found in PATH"
else
    echo "⚠ duramen binary not found in PATH"
    echo "  Build with: cargo build --release"
    echo "  Then add target/release/ to your PATH"
fi
