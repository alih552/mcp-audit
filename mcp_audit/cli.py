"""mcp-audit — find security holes & token bloat in your MCP servers.

  mcp-audit                      # auto-detect common MCP configs on this machine
  mcp-audit path/to/.mcp.json    # audit a specific config
  mcp-audit --json               # machine-readable output
  mcp-audit --tools tools.json   # include a tool-list export for accurate token estimates
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import audit_config
from .report import to_json, to_text

DEFAULT_LOCATIONS = [
    "~/Library/Application Support/Claude/claude_desktop_config.json",  # Claude Desktop (macOS)
    "~/.config/Claude/claude_desktop_config.json",                       # Claude Desktop (Linux)
    "~/.cursor/mcp.json", "./.cursor/mcp.json",                          # Cursor
    "./.mcp.json", "./.vscode/mcp.json",                                 # project / VS Code
    "~/.codeium/windsurf/mcp_config.json",                               # Windsurf
]


def discover() -> list:
    found = []
    for loc in DEFAULT_LOCATIONS:
        p = Path(loc).expanduser()
        if p.is_file():
            found.append(p)
    return found


def count_tools(tools_path: str | None):
    if not tools_path:
        return None
    try:
        data = json.loads(Path(tools_path).expanduser().read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict) and isinstance(data.get("tools"), list):
        return len(data["tools"])
    return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-audit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="*", help="MCP config file(s). Omit to auto-detect.")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--tools", help="a tool-list JSON export for accurate token estimates")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-cta", action="store_true", help="hide the upsell line")
    p.add_argument("--by-risk", action="store_true", help="group findings by risk class instead of severity")
    p.add_argument("--min-score", type=int, default=None,
                   help="exit non-zero if any config scores below this (for CI)")
    args = p.parse_args(argv)

    paths = [Path(x).expanduser() for x in args.paths] or discover()
    if not paths:
        print("No MCP config found. Pass a path, e.g.:  mcp-audit .mcp.json", file=sys.stderr)
        return 2

    tools_count = count_tools(args.tools)
    results = []
    for path in paths:
        if not path.is_file():
            print(f"skip (not found): {path}", file=sys.stderr)
            continue
        try:
            results.append(audit_config(path, tools_count))
        except json.JSONDecodeError as e:
            print(f"skip (invalid JSON): {path} — {e}", file=sys.stderr)

    if not results:
        return 2

    if args.json:
        print(json.dumps([json.loads(to_json(r)) for r in results], indent=2))
    else:
        for r in results:
            print(to_text(r, color=not args.no_color, cta=not args.no_cta, by_risk=args.by_risk))

    if args.min_score is not None and any(r.score < args.min_score for r in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
