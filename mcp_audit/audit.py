"""Static security + token-bloat audit for MCP server configurations.

Reads an MCP config (Claude Desktop, Cursor, VS Code, or a plain `.mcp.json`) and
flags the real problems found across the public MCP ecosystem in 2026:
no auth on remote servers, cleartext http, secrets pasted in plaintext, unpinned
auto-updating executables, over-broad filesystem/shell access, and context/token
bloat from too many servers and tools.

Pure standard library, no dependencies, no network calls. Safe to run anywhere.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

SEVERITIES = ["HIGH", "MEDIUM", "LOW", "INFO"]
SEV_PENALTY = {"HIGH": 25, "MEDIUM": 10, "LOW": 4, "INFO": 0}

# Group findings by the kind of risk, not just severity. A score is the hook; the
# risk class plus the per-finding fix is the remediation path.
RISK_CLASS = {
    "remote-no-auth": "Authentication",
    "credentials-in-url": "Credentials & secrets",
    "plaintext-secret": "Credentials & secrets",
    "world-readable-config": "Credentials & secrets",
    "cleartext-http": "Network exposure",
    "deprecated-sse": "Network exposure",
    "tls-verify-disabled": "Network exposure",
    "bind-all-interfaces": "Network exposure",
    "unpinned-exec": "Code execution & supply chain",
    "inline-code-exec": "Code execution & supply chain",
    "shell-exec": "Code execution & supply chain",
    "privileged-runner": "Code execution & supply chain",
    "curl-pipe-shell": "Code execution & supply chain",
    "insecure-http-proxy": "Network exposure",
    "broad-filesystem": "Over-broad access",
    "server-bloat": "Context cost",
    "redundant-servers": "Context cost",
    "no-servers": "Info",
}
RISK_ORDER = ["Authentication", "Credentials & secrets", "Network exposure",
              "Code execution & supply chain", "Over-broad access", "Context cost", "Other", "Info"]


def risk_class(finding_id: str) -> str:
    return RISK_CLASS.get(finding_id, "Other")

# Rough heuristic: each exposed tool's JSON schema costs the model context window.
TOKENS_PER_TOOL = 220          # conservative average for a real-world tool schema
TOKENS_PER_SERVER_BASE = 120   # per-server framing overhead

# Secret patterns that should never sit in a plaintext config.
SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI-style secret key"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "Anthropic API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub personal access token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{30,}"), "GitHub fine-grained PAT"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{30,}"), "Google API key"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"), "Bearer token"),
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), "long base64-ish secret"),
]
ENV_SECRET_HINT = re.compile(r"(?i)(token|secret|api[_-]?key|password|passwd|access[_-]?key|private)")
AUTH_HEADER_HINT = re.compile(r"(?i)(authorization|x-api-key|api-key|token|bearer)")
UNPINNED_RUNNERS = {"npx", "uvx", "bunx", "pnpm", "dlx"}
INTERPRETERS = {"python", "python3", "node", "ruby", "bash", "sh", "zsh", "deno", "bun", "perl"}
BROAD_FS_ROOTS = {"/", "~", "$HOME", "/Users", "/home", "C:\\", "/etc", "/var"}
SHELLY = re.compile(r"(?i)(shell|exec|command|terminal|bash|subprocess|run[_-]?command)")


@dataclass
class Finding:
    id: str
    severity: str
    server: str
    title: str
    detail: str
    fix: str


@dataclass
class AuditResult:
    source: str
    servers: int = 0
    est_tokens: int = 0
    findings: list = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(SEV_PENALTY[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"

    def counts(self) -> dict:
        c = {sev: 0 for sev in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def by_risk(self):
        """Return [(risk_class, [findings])] in a sensible order."""
        groups: dict = {}
        for f in self.findings:
            groups.setdefault(risk_class(f.id), []).append(f)
        ordered = [(c, groups[c]) for c in RISK_ORDER if c in groups]
        extra = [(c, fs) for c, fs in groups.items() if c not in RISK_ORDER]
        return ordered + extra


def extract_servers(data: dict) -> dict:
    """Normalize the many MCP config shapes into {name: server_dict}."""
    for key in ("mcpServers", "servers", "mcp_servers"):
        if isinstance(data.get(key), dict):
            return data[key]
    # VS Code nests under {"mcp": {"servers": {...}}}
    if isinstance(data.get("mcp"), dict) and isinstance(data["mcp"].get("servers"), dict):
        return data["mcp"]["servers"]
    # Bare server map (heuristic: values look like server dicts)
    if data and all(isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values()):
        return data
    return {}


def is_remote(srv: dict) -> bool:
    return bool(srv.get("url") or srv.get("type") in ("http", "sse", "streamable-http", "streamable_http"))


def has_auth(srv: dict) -> bool:
    headers = srv.get("headers") or {}
    if any(AUTH_HEADER_HINT.search(str(k)) for k in headers):
        return True
    env = srv.get("env") or {}
    if any(ENV_SECRET_HINT.search(str(k)) for k in env):
        return True
    url = str(srv.get("url") or "")
    return bool(re.search(r"(?i)(token|key|secret)=", url))


def find_secrets(blob: str) -> list:
    hits = []
    for pat, label in SECRET_PATTERNS:
        for m in pat.findall(blob):
            sample = m if isinstance(m, str) else m[0]
            if len(sample) >= 16:
                hits.append((label, sample[:6] + "…"))
    return hits


def audit_server(name: str, srv: dict) -> list:
    findings = []
    blob = json.dumps(srv)

    if is_remote(srv):
        url = str(srv.get("url") or "")
        if not has_auth(srv):
            findings.append(Finding(
                "remote-no-auth", "HIGH", name, "Remote server with no authentication",
                f"'{name}' is a remote MCP server but no auth header/token is configured. "
                "41% of public MCP servers require no auth at all, so anyone who reaches the URL can call your tools.",
                "Add an Authorization/x-api-key header (from a secret manager or env var), and require auth server-side."))
        if url.startswith("http://"):
            findings.append(Finding(
                "cleartext-http", "HIGH", name, "Cleartext HTTP (no TLS)",
                f"'{name}' uses http://, so traffic and tokens are sent unencrypted and the endpoint is SSRF/MITM-prone.",
                "Use https:// with a valid certificate; never send tokens over plaintext http."))
        try:
            if urlparse(url).username:
                findings.append(Finding(
                    "credentials-in-url", "HIGH", name, "Credentials embedded in the server URL",
                    f"'{name}' has a username or password inside its URL. Credentials in a URL leak through "
                    "logs, shell history, and proxies.",
                    "Move credentials to an Authorization header or an env var, never the URL."))
        except ValueError:
            pass

    for label, sample in find_secrets(blob):
        findings.append(Finding(
            "plaintext-secret", "HIGH", name, f"Plaintext secret in config ({label})",
            f"A {label} ({sample}) appears directly in '{name}'. Anyone with the config file (or its git history) has it.",
            "Move secrets to environment variables or a secret manager; reference them, don't inline them. Rotate the exposed key."))

    cmd = str(srv.get("command") or "").lower()
    args = [str(a) for a in (srv.get("args") or [])]
    runner = Path(cmd).name
    if runner in UNPINNED_RUNNERS:
        joined = " ".join(args).lower()
        if "-y" in args or "@latest" in joined or not re.search(r"@\d", joined):
            findings.append(Finding(
                "unpinned-exec", "MEDIUM", name, "Unpinned auto-updating executable",
                f"'{name}' runs via {runner} without a pinned version (-y/@latest/no @version). "
                "It silently executes whatever the latest published package is, a supply-chain risk.",
                "Pin an exact version (e.g. package@1.2.3) and review updates before adopting them."))

    if srv.get("type") == "sse":
        findings.append(Finding(
            "deprecated-sse", "LOW", name, "Deprecated SSE transport",
            f"'{name}' uses the SSE transport, which is deprecated in MCP in favor of Streamable HTTP.",
            'Migrate to the Streamable HTTP transport (type: "http").'))

    if SHELLY.search(name) or SHELLY.search(cmd):
        findings.append(Finding(
            "shell-exec", "MEDIUM", name, "Shell/exec-capable server",
            f"'{name}' looks able to run shell commands. That's a large blast radius if the model is prompt-injected.",
            "Restrict to an allowlist of commands, run sandboxed, and require confirmation for destructive actions."))

    if Path(cmd).name in INTERPRETERS and any(a in ("-c", "-e", "--eval", "--exec") for a in args):
        findings.append(Finding(
            "inline-code-exec", "MEDIUM", name, "Runs inline code from the config",
            f"'{name}' runs inline code via {Path(cmd).name} with -c or -e. Inline code in a config is hard to "
            "review and easy to tamper with.",
            "Move the logic into a versioned, reviewed package or script instead of inlining it."))

    for a in args + list((srv.get("env") or {}).values()):
        a = str(a)
        if a.strip().rstrip("/\\") in {r.rstrip("/\\") for r in BROAD_FS_ROOTS}:
            findings.append(Finding(
                "broad-filesystem", "MEDIUM", name, "Over-broad filesystem root",
                f"'{name}' is granted a very broad path ('{a}'). The model can read/write far more than it needs.",
                "Scope filesystem access to the specific project directory, not $HOME or /."))
            break

    env = srv.get("env") or {}
    for k, v in env.items():
        ks, vs = str(k).upper(), str(v).strip().lower()
        if (ks == "NODE_TLS_REJECT_UNAUTHORIZED" and vs in ("0", "false")) \
           or (ks == "PYTHONHTTPSVERIFY" and vs in ("0", "false")) \
           or (ks in ("SSL_VERIFY", "TLS_VERIFY", "CURL_INSECURE") and vs in ("0", "false", "no")):
            findings.append(Finding(
                "tls-verify-disabled", "HIGH", name, "TLS certificate verification disabled",
                f"'{name}' sets {k}={v}, which turns off TLS certificate checks. Every https call it makes "
                "can be silently intercepted (man in the middle).",
                "Remove the override and fix the underlying certificate instead of disabling verification."))
            break

    surface = " ".join(args) + " " + str(srv.get("url") or "") + " " + " ".join(f"{x}" for x in env.values())
    if re.search(r"(?:^|[^\d.])0\.0\.0\.0(?![\d.])", surface):
        findings.append(Finding(
            "bind-all-interfaces", "MEDIUM", name, "Server bound to all network interfaces",
            f"'{name}' binds to 0.0.0.0, which exposes it on every network interface, not just localhost.",
            "Bind to 127.0.0.1 for a local server, or put it behind an authenticated reverse proxy."))

    argl = [a.lower() for a in args]
    if runner == "sudo" or "--privileged" in argl or "--cap-add" in argl:
        findings.append(Finding(
            "privileged-runner", "MEDIUM", name, "Runs with elevated privileges",
            f"'{name}' launches with elevated privileges (sudo or a privileged container). A prompt-injected "
            "tool then runs with that power.",
            "Run the server as an unprivileged user in a sandboxed container with no extra capabilities."))

    if re.search(r"(?:curl|wget|iwr|invoke-webrequest)\b.*\|\s*(?:sh|bash|zsh|iex|python)", (cmd + " " + " ".join(args)).lower()):
        findings.append(Finding(
            "curl-pipe-shell", "HIGH", name, "Pipes a download straight into a shell",
            f"'{name}' fetches a remote script and pipes it into a shell. Whoever controls that URL runs code on your machine.",
            "Download, pin, and review the script first. Never pipe a remote download into sh or bash."))

    for pk, pv in env.items():
        if str(pk).upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") and str(pv).lower().startswith("http://"):
            findings.append(Finding(
                "insecure-http-proxy", "MEDIUM", name, "Cleartext HTTP proxy",
                f"'{name}' routes traffic through a cleartext http proxy ({pk}). The proxy can read and alter everything, including tokens.",
                "Use an https proxy, or remove the proxy override."))
            break

    return findings


def estimate_tokens(servers: dict, tools_count: int | None) -> int:
    base = len(servers) * TOKENS_PER_SERVER_BASE
    if tools_count is not None:
        return base + tools_count * TOKENS_PER_TOOL
    # No tool list available: assume a typical ~8 tools/server.
    return base + len(servers) * 8 * TOKENS_PER_TOOL


def audit_config(path: Path, tools_count: int | None = None) -> AuditResult:
    raw_text = Path(path).read_text()
    data = json.loads(raw_text)
    servers = extract_servers(data)
    res = AuditResult(source=str(path), servers=len(servers))
    if not servers:
        res.findings.append(Finding("no-servers", "INFO", "-", "No MCP servers found",
                                    f"Could not find an MCP server map in {path}.",
                                    "Point mcp-audit at a Claude/Cursor/VS Code MCP config or a .mcp.json."))
        return res

    for name, srv in servers.items():
        if isinstance(srv, dict):
            res.findings.extend(audit_server(name, srv))

    # File-level: secrets sitting in a world/group-readable config file
    try:
        if (os.stat(path).st_mode & 0o077) and find_secrets(raw_text):
            res.findings.append(Finding(
                "world-readable-config", "HIGH", "*", "Secrets in a world/group-readable config file",
                f"{path} is readable by other users on this machine and contains a secret, so any local "
                "user or compromised process can read it.",
                "chmod 600 the config file, and prefer env vars / a secret manager over inlined secrets."))
    except OSError:
        pass

    res.est_tokens = estimate_tokens(servers, tools_count)
    # Token-bloat heuristics
    if len(servers) >= 5:
        res.findings.append(Finding(
            "server-bloat", "LOW", "*", f"{len(servers)} MCP servers configured",
            f"~{res.est_tokens:,} tokens of tool definitions are loaded into every request before you type anything. "
            "Five servers commonly cost 50 to 75k tokens of context.",
            "Disable servers you aren't actively using; load niche servers on demand instead of always-on."))

    # Redundancy heuristic by capability keyword in server names
    buckets: dict[str, list] = {}
    for name in servers:
        for kw in ("search", "browser", "git", "fs", "file", "db", "sql", "memory"):
            if kw in name.lower():
                buckets.setdefault(kw, []).append(name)
    for kw, names in buckets.items():
        if len(names) > 1:
            res.findings.append(Finding(
                "redundant-servers", "INFO", ", ".join(names), f"Possibly redundant '{kw}' servers",
                f"Multiple servers look like they cover '{kw}': {', '.join(names)}. Overlap wastes context tokens.",
                "Keep the one you actually use; remove the rest to reclaim context."))

    res.findings.sort(key=lambda f: SEVERITIES.index(f.severity))
    return res
