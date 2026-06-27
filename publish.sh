#!/bin/bash
# Publish mcp-audit as a public GitHub repo. This is the IDENTITY step — run only with approval.
# Usage: bash publish.sh [owner/repo]   (default: alih552/mcp-audit)
set -euo pipefail
cd "$(dirname "$0")"
REPO="${1:-alih552/mcp-audit}"
gh repo create "$REPO" --public --source=. --remote=origin \
  --description "Find security holes and token bloat in your MCP servers. Zero dependencies." \
  --push
echo "✓ Published: https://github.com/$REPO"
echo "Next (from LAUNCH.md, also approval-gated): Show HN, awesome-list PRs, dev.to post."
