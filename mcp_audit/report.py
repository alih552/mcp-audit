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


SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def to_sarif(res: AuditResult) -> str:
    """Emit SARIF 2.1.0 so the report drops into GitHub code scanning and CI."""
    from . import __version__
    rules, seen = [], set()
    for f in res.findings:
        if f.id in seen:
            continue
        seen.add(f.id)
        rules.append({
            "id": f.id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "helpUri": "https://github.com/alih552/mcp-audit",
            "properties": {"riskClass": risk_class(f.id)},
        })
    results = [{
        "ruleId": f.id,
        "level": SARIF_LEVEL.get(f.severity, "note"),
        "message": {"text": f"{f.title} ({f.server}). {f.detail} Fix: {f.fix}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": res.source}}}],
    } for f in res.findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcp-audit",
                "version": __version__,
                "informationUri": "https://github.com/alih552/mcp-audit",
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)


def _cta(paint) -> str:
    return ("\n" + paint("─" * 64, DIM) +
            "\n🛠  Fix all of this the right way with secure-by-default MCP server templates"
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
