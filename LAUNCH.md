# mcp-audit — launch kit (DRAFTS — publishing needs human approval)

All posting below happens under the user's real identity → gated to approval. These are drafts.
Golden rules: lead with value, link the free tool (not the paid kit), never astroturf, follow each
community's self-promo rules, respond to every comment.

---

## 1) Show HN (news.ycombinator.com/submit)
**Title:** `Show HN: mcp-audit – find security holes and token bloat in your MCP servers`
**URL:** `https://github.com/alih552/mcp-audit`

**First comment (post immediately after):**
> I kept adding MCP servers to Claude/Cursor and noticed two things: (1) a lot of them ship with no
> auth or over `http://`, and (2) my context was full of tool schemas before I typed anything. A 2026
> scan of ~7,000 public MCP servers found 41% need no auth and only 8.5% use OAuth, so it's not just me.
>
> `mcp-audit` is a zero-dependency CLI that reads your MCP config (Claude Desktop, Cursor, VS Code,
> Windsurf, or a plain .mcp.json) and flags: remote servers with no auth, cleartext http, secrets pasted
> in plaintext, unpinned `npx -y`/`uvx` runners, shell/exec servers, over-broad filesystem roots, and an
> estimate of how many context tokens your servers cost per request. It's 100% local — never connects to
> your servers, never phones home.
>
> `pipx install mcp-audit && mcp-audit`
>
> It's MIT. I'd love feedback on the checks — especially false positives and checks you'd add. (I'm also
> building a paid secure-by-default server starter, but the auditor is and stays free.)

Tips: submit Tue–Thu ~8–10am ET; reply fast; be humble; expect harsh feedback and engage with it.

---

## 2) dev.to / Hashnode post
**Title:** `I scanned my MCP setup and it scored 0/100. Here's what was wrong.`
Outline: the 2026 MCP security stats → walk the insecure example output finding by finding → the fix for
each → token-bloat section (why 5 servers = 50–75k tokens) → `pipx install mcp-audit` → "audit yours,
tell me what checks to add." Tag: `#mcp #ai #security #claude`. End with the repo link, soft mention of
the kit.

---

## 3) awesome-mcp / awesome-claude list PRs
Targets (verify each list's contribution rules first): `punkpeye/awesome-mcp-servers`,
`appcypher/awesome-mcp-servers`, and Claude/Cursor awesome lists under a **Security / Tooling** section.
**Entry:**
> - [mcp-audit](https://github.com/alih552/mcp-audit) — Audit MCP configs for security holes (no-auth,
>   cleartext http, plaintext secrets) and context token bloat. Zero deps, runs locally.

---

## 4) r/mcp and r/ClaudeAI (value-first, check each sub's self-promo rule)
**Title:** `Made a free local CLI to audit MCP configs for security + token bloat`
> Sharing a small free/MIT tool I built because most MCP configs I see have no auth or leak the whole
> context budget. It runs locally, no network. Quick example of what it flags: [paste 3–4 finding lines].
> Repo: [link]. Genuinely want check ideas / false-positive reports.

Post, then actually participate — answer questions, don't drop-and-run.

---

## 5) Product Hunt (optional, later)
Launch once there are some GitHub stars and a couple of testimonials. Tagline:
`mcp-audit — security & token-bloat scanner for your MCP servers`.
