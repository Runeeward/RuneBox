# Rune Box adapters

Client libraries and agent-framework integrations for
[Rune Box](https://github.com/Runeeward/RuneBox) — the open-source
**governance harness** for AI agents (formerly Runeward Sandbox). The Python package is
`rune-box` on PyPI (import `runebox`), the npm package is `@runebox/sdk`, and
the CLI is `runebox`.

## Why governed tools matter for agents

Giving an agent a raw shell is easy; giving it a *safe* one is the hard part.
The moment an agent can run commands, write files, or reach the network, three
questions appear: what is it allowed to do, who signs off on the risky parts, and
what actually happened? Rune Box answers those by routing **every** tool call
through one path:

```
policy check  →  approval gate  →  cost/loop guardrails  →  sandbox exec  →  audit ledger
```

The result is a tool surface that is safe to hand to an autonomous agent:
work runs in a disposable, deny-by-default Citadel; sensitive actions are blocked
or escalated to a human; and everything is recorded in a tamper-evident Chronicle
you can replay and verify. These adapters make that governed surface a
first-class citizen in the frameworks agents are already built with — the agent
calls a tool exactly as it would any other, but now with a policy engine and a
human-in-the-loop behind it.

The single behavioral contract every adapter preserves:

- **`allow`** — the action ran (for shell, still check `exit_code`).
- **`deny`** — policy refused it. **Do not retry the same action**; choose an
  allowed approach or report the block.
- **`require-approval`** — a human must sign off. **Pause** and surface the
  `approval_id`; don't route around the gate.
- **refused** — anything else the server refused before it ran carries a
  `refusal` object (`reason`, `retryable`, `request_id`, `message`); both
  SDKs raise it as `RefusedError`. Retry only when `retryable` is true, and
  quote the `request_id` when reporting a failure.

## What's here

| Path | What it is |
| --- | --- |
| [`../dist/skill/SKILL.md`](../dist/skill/SKILL.md) | An agent **skill** teaching a model when and how to use Rune Box — MCP tool names, the REST fallback, how approvals and denials work, and safety notes. Drop it into a Cursor/Claude skill directory. |
| [`../dist/mcp/`](../dist/mcp/) | The MCP registry **`server.json`** manifest plus a README on publishing Rune Box to MCP registries and wiring it into Claude Desktop / Cursor. |
| [`python/`](./python/) | The **`rune-box`** Python package (import `runebox`): a pure-stdlib `RuneboxClient` plus lazy-loaded LangChain, CrewAI, LlamaIndex, OpenAI Agents SDK, and Strands tool factories. |
| [`typescript/`](./typescript/) | The **`@runebox/sdk`** package: a `fetch`-based `RuneboxClient` plus Vercel AI SDK, LangChain.js, and Strands `tool(...)` wrappers. |

## Choosing an adapter

- **Using an MCP client** (Claude Desktop, Cursor, …)? You don't need these
  adapters — point the client at the Rune Box MCP server (`runebox mcp`). See
  [`../dist/mcp/README.md`](../dist/mcp/README.md).
- **Building a LangChain, CrewAI, LlamaIndex, OpenAI Agents SDK, or Strands
  agent in Python?** Use [`python/`](./python/).
- **Building on the Vercel AI SDK, LangChain.js, or Strands / a TS agent?** Use
  [`typescript/`](./typescript/).
- **Rolling your own?** Both `RuneboxClient`s are thin, typed wrappers over the
  REST control plane and are usable standalone with zero third-party runtime
  dependencies.

All adapters target the same control plane started with `runebox serve`
(default `http://localhost:8080`) and expose the same method surface, mirroring
the governed tool set: `create_sandbox`, `shell`, `python`, `node`,
`read_file`/`write_file`/`list_files`/`search_files`, `list_approvals`/`approve`/
`deny`, `kill_sandbox`, plus `audit`/`verify_audit`, and the workspace and
context surface: `fork_citadel`/`sleep_citadel`/`wake_citadel`/
`workspace_status`, resumable agent turns (`agent_turn`, `cancel_agent_turn`),
schedules, Cohort shared memory, and task notes, briefs, children and context
(camelCase in TypeScript). (The client method names
keep their original spellings; the `runebox mcp` server's tools are now
`runebox_create_citadel`, `runebox_kill_citadel`, and `runebox_list_conclave`.)
