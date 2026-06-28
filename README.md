# mcp-audit

**Find security holes and token bloat in your MCP servers — in one command, zero dependencies.**

The MCP ecosystem exploded in 2026, and most of it is dangerously misconfigured. A 2026 analysis of
~7,000 public MCP servers found **41% require no authentication at all**, **36.7% are SSRF-vulnerable**,
and only **8.5% use OAuth**. Meanwhile every server you add quietly loads its tool schemas into *every*
request — five servers commonly burn **50–75k tokens of context before you type a word.**

`mcp-audit` reads your MCP config (Claude Desktop, Cursor, VS Code, Windsurf, or a plain `.mcp.json`)
and tells you exactly what's wrong and how to fix it.

```bash
pipx install git+https://github.com/alih552/mcp-audit   # PyPI release coming soon
mcp-audit                    # auto-detects your MCP configs
```

```
MCP Audit — ~/.cursor/mcp.json
  7 server(s) · ~13,160 context tokens · score 0/100 (F)
  ✖ 3 high  ▲ 8 medium  • 1 low  · 1 info

✖ [HIGH] Remote server with no authentication  (internal-api)
    'internal-api' is a remote MCP server but no auth header/token is configured. 41% of public
    MCP servers require no auth at all — anyone who reaches the URL can call your tools.
    fix: Add an Authorization/x-api-key header (from a secret manager or env var).

✖ [HIGH] Plaintext secret in config (GitHub personal access token)  (github)
    A GitHub personal access token (ghp_Ab…) appears directly in 'github'. Anyone with the
    config file (or its git history) has it.
    fix: Move secrets to env vars or a secret manager; reference them, don't inline them. Rotate the key.

▲ [MEDIUM] Over-broad filesystem root  (filesystem)
    'filesystem' is granted a very broad path ('/Users'). The model can read/write far more than it needs.
    fix: Scope filesystem access to the specific project directory, not $HOME or /.

• [LOW] 7 MCP servers configured  (*)
    ~13,160 tokens of tool definitions are loaded into every request before you type anything.
    fix: Disable servers you aren't using; load niche servers on demand instead of always-on.
```

## What it checks

**Security**
- 🔴 Remote servers with **no authentication**
- 🔴 **Cleartext `http://`** endpoints (SSRF / MITM / token leakage)
- 🔴 **Plaintext secrets** in the config (OpenAI, Anthropic, GitHub, AWS, Slack, Google, bearer tokens…)
- 🟠 **Unpinned auto-updating executables** (`npx -y` / `uvx` / `@latest`) — silent supply-chain risk
- 🟠 **Shell/exec-capable** servers with a large blast radius
- 🟠 **Over-broad filesystem** roots (`$HOME`, `/`, `/Users`)

**Token / context bloat**
- 🔵 Total servers and an **estimated context-token cost** loaded on every request
- ⚪ **Redundant servers** covering the same capability (two search servers, etc.)

## Usage

```bash
mcp-audit                          # auto-detect common configs on this machine
mcp-audit .mcp.json other.json     # audit specific files
mcp-audit --json                   # machine-readable output (for tooling)
mcp-audit --tools tools.json       # include a tool-list export for an accurate token estimate
mcp-audit --by-risk                # group findings by risk class (auth, secrets, code exec, etc.)
mcp-audit --min-score 80           # exit non-zero below the threshold — drop it into CI
```

Exit codes: `0` ok · `1` below `--min-score` · `2` no config found / unreadable.

### In CI (GitHub Actions)
Use the action:
```yaml
- uses: alih552/mcp-audit@v0.1.1
  with:
    path: .mcp.json
    min-score: "80"   # fail the job below this score
```
Or run it directly: `pipx install git+https://github.com/alih552/mcp-audit && mcp-audit .mcp.json --min-score 80`

## Privacy
100% local and offline. It never connects to your servers and never sends your config anywhere.
No dependencies, no telemetry — read the ~300 lines of source yourself.

## Supported config formats
Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`), VS Code (`.vscode/mcp.json`
and `mcp.servers`), Windsurf, and any `{ "mcpServers": { … } }` / `{ "servers": { … } }` file.

---

<a id="mcp-forge-kit"></a>
### Going further — MCP Forge Kit
`mcp-audit` finds the problems. **MCP Forge Kit** fixes them: a production-grade, **secure-by-default
MCP server starter** — bearer + JWT auth, rate limiting, SSRF-safe outbound fetch, input validation,
token-lean tool schemas, 21 tests, CI, and Docker/Node deploy configs, with a security checklist and
setup guide. Ship a server that scores **A** from day one.

> 🚀 **[Get MCP Forge Kit →](https://alih552.github.io/mcp-forge/)** — €39, one-time, secure checkout via Polar.

## License
MIT.
