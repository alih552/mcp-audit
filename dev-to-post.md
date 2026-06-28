---
title: I scanned my MCP setup and it scored 0/100. Here's what was wrong.
published: true
tags: mcp, ai, security, claude
canonical_url: https://alih552.github.io/mcp-forge/checklist.html
---

I've been adding MCP servers to Claude and Cursor for months — GitHub, a filesystem server, a couple of search servers, a little internal HTTP one I wrote. It works great. Then two things bugged me:

1. Some of those servers have **no authentication at all**. Anyone who can reach the URL can call my tools.
2. My context window felt *full* before I even typed a prompt.

Turns out it's not just me. A 2026 analysis of ~7,000 public MCP servers found **41% require no auth**, **36.7% are SSRF-vulnerable**, and only **8.5% use OAuth**. So I wrote a tiny tool to check my own config — and it scored **0 out of 100**.

## The tool

[`mcp-audit`](https://github.com/alih552/mcp-audit) is a zero-dependency CLI that reads your MCP config (Claude Desktop, Cursor, VS Code, Windsurf, or a plain `.mcp.json`) and tells you what's wrong. It runs **100% locally** — it never connects to your servers or sends your config anywhere.

```bash
pipx install git+https://github.com/alih552/mcp-audit
mcp-audit
```

Here's the kind of thing it flagged on my (deliberately messy) test config:

```
MCP Audit — ~/.cursor/mcp.json
  7 server(s) · ~13,160 context tokens · score 0/100 (F)
  ✖ 3 high  ▲ 8 medium  • 1 low

✖ [HIGH] Remote server with no authentication  (internal-api)
✖ [HIGH] Plaintext secret in config (GitHub token)  (github)
▲ [MED]  Unpinned auto-updating executable (npx -y)  (filesystem)
▲ [MED]  Over-broad filesystem root '/Users'  (filesystem)
• [LOW]  7 servers ≈ 13,160 context tokens loaded every request
```

## What each finding actually means

**No auth on a remote server.** If your MCP server is reachable over HTTP and doesn't check a token, the model — or anyone who finds the URL — can run your tools. With prompt injection in the wild, the *server* has to hold the line, not the model.

**Plaintext secrets in the config.** A `GITHUB_TOKEN` sitting in `.mcp.json` leaks through the file itself and through your git history. Move it to an env var or a secret manager.

**`npx -y` / `uvx` without a pinned version.** That silently runs whatever was published most recently. It's a supply-chain risk — pin the version and review updates.

**Over-broad filesystem roots.** A filesystem server pointed at `/Users` or `$HOME` lets the model read and write far more than your project. Scope it to the project directory.

**Token bloat.** This was the one I didn't expect. Every server loads its tool schemas into *every* request. Five servers commonly cost **50–75k tokens of context before you type a word** — that's real money and real latency. Disable the servers you aren't actively using.

## The fix

For the config issues: pin versions, move secrets to env vars, scope filesystem access, and put auth in front of anything remote. There's a full [MCP Server Security Checklist here](https://alih552.github.io/mcp-forge/checklist.html).

If you're *building* an MCP server and want it secure from commit one, I also put together [MCP Forge Kit](https://alih552.github.io/mcp-forge/) — a secure-by-default starter (bearer + JWT auth, SSRF-safe fetch, rate limiting, validation, tests, CI). But the auditor above is free and MIT, and it's genuinely useful on its own.

## Try it on your setup

```bash
pipx install git+https://github.com/alih552/mcp-audit
mcp-audit --json     # machine-readable, drop it in CI
```

I'd love feedback on the checks — especially **false positives** and checks you think are missing. Repo's here: https://github.com/alih552/mcp-audit
