"""Render an AuditResult as a human terminal report or machine JSON."""
from __future__ import annotations

import json
from dataclasses import asdict

from .audit import AuditResult, SEVERITIES, risk_class

COLOR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[96m", "INFO": "\033[90m"}
GREEN, RESET, BOLD, DIM = "\033[92m", "\033[0m", "\033[1m", "\033[2m"
ICON = {"HIGH": "✖", "MEDIUM": "▲", "LOW": "•", "INFO": "·"}


def to_json(res: AuditResult) -> str:
    return json.dumps({
        "source": res.source, "servers": res.servers, "est_tokens": res.est_tokens,
        "score": res.score, "grade": res.grade, "counts": res.counts(),
        "findings": [{**asdict(f), "risk_class": risk_class(f.id)} for f in res.findings],
    }, indent=2)


def _cta(paint) -> str:
    return ("\n" + paint("─" * 64, DIM) +
            "\n🛠  Fix all of this the right way — secure-by-default MCP server templates"
            "\n   (OAuth, rate limiting, SSRF-safe fetch, token-lean tools, tests, CI):"
            "\n   " + paint("MCP Forge Kit → https://alih552.github.io/mcp-forge/", BOLD) + "\n")


def to_text(res: AuditResult, color: bool = True, cta: bool = True, by_risk: bool = False) -> str:
    def paint(s, code):
        return f"{code}{s}{RESET}" if color else s

    def render_finding(f):
        return [
            paint(f"{ICON[f.severity]} [{f.severity}] {f.title}", COLOR[f.severity]) + "  " + paint(f"({f.server})", DIM),
            f"    {f.detail}",
            f"    {paint('fix:', BOLD)} {f.fix}",
            "",
        ]

    counts = res.counts()
    out = [paint(f"\nMCP Audit: {res.source}", BOLD)]
    out.append(f"  {res.servers} server(s) · ~{res.est_tokens:,} context tokens · "
               f"score {res.score}/100 ({res.grade})")
    if res.findings:
        out.append("  " + "  ".join(
            paint(f"{ICON[s]} {counts[s]} {s.lower()}", COLOR[s]) for s in SEVERITIES if counts[s]))
    else:
        out.append("  " + paint("✓ no issues found", GREEN))
    out.append("")

    if by_risk:
        for cls, items in res.by_risk():
            out.append(paint(f"## {cls}  ({len(items)})", BOLD))
            for f in items:
                out.extend(render_finding(f))
    else:
        for f in res.findings:
            out.extend(render_finding(f))
    if not res.findings:
        out.append("  Nothing to fix. Nicely done.")

    text = "\n".join(out)
    if cta:
        text += _cta(paint)
    return text
