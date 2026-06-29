# Changelog

## 0.1.6
- Two new checks: `curl-pipe-shell` (HIGH, a remote download piped into a shell) and `insecure-http-proxy` (MEDIUM, traffic routed through a cleartext http proxy).

## 0.1.5
- New `--sarif` output (SARIF 2.1.0) so mcp-audit drops straight into GitHub code scanning and CI.

## 0.1.4
- Three new checks: `tls-verify-disabled` (HIGH, catches NODE_TLS_REJECT_UNAUTHORIZED=0 and friends),
  `bind-all-interfaces` (MEDIUM, a server listening on 0.0.0.0), and `privileged-runner` (MEDIUM, sudo or
  a privileged container). Cleaned the last em-dashes out of the report text.

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
