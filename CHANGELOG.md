# Changelog

## 0.1.3
- New `--by-risk` flag: groups findings by risk class (Authentication, Credentials & secrets, Network
  exposure, Code execution & supply chain, Over-broad access, Context cost) instead of severity. The
  JSON output now includes a `risk_class` on every finding too.

## 0.1.2
- New check: **credentials embedded in a server URL** (https://user:pass@host).
- New check: **inline code execution** (running code via `python -c`, `node -e`, etc. from the config).

## 0.1.1
- New check: **deprecated SSE transport** (recommend migrating to Streamable HTTP).
- New check: **secrets in a world/group-readable config file** (local-exposure risk; suggests `chmod 600`).

## 0.1.0
First release. Static security + token-bloat audit for MCP configs:
- Detects: remote servers with no auth, cleartext `http://`, plaintext secrets, unpinned
  auto-updating executables, shell/exec-capable servers, over-broad filesystem roots,
  server/tool token bloat, and redundant servers.
- Supports Claude Desktop, Cursor, VS Code, Windsurf, and plain `.mcp.json` formats.
- Text + `--json` output, `--min-score` CI gate, config auto-detection. Zero dependencies.
