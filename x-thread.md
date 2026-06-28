# X / Twitter thread (POSTED 2026-06-28 — dash-free version)

**1/**
I scanned my own MCP setup (the servers I hand to Claude and Cursor) and it scored 0/100.

Here's what was wrong, and the free tool I built to check yours 🧵

**2/**
A 2026 scan of ~7,000 public MCP servers:

• 41% require no auth
• 36.7% are SSRF-vulnerable
• only 8.5% use OAuth

If your AI's tools sit behind an unauthenticated URL, anyone who finds it can call them.

**3/**
The sneaky one: every MCP server loads its tool schemas into every request. 5 servers can cost 50-75k tokens of context before you even type a word. Real money, real latency.

So I built a tiny tool to check all of it.

**4/**
mcp-audit is free, MIT, zero-dependency, and 100% local. It scans your Claude, Cursor, or VS Code MCP config and flags every one of these.

pipx install git+https://github.com/alih552/mcp-audit

**5/**
Full writeup (what each finding means and how to fix it):
https://dev.to/alih552/i-scanned-my-mcp-setup-and-it-scored-0100-heres-what-was-wrong-28g

Repo: https://github.com/alih552/mcp-audit

Building an MCP server? A secure-by-default starter: https://alih552.github.io/mcp-forge/
