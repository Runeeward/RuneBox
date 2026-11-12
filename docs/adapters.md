# Adapters

**Adapters make Rune Box's governed tools a first-class citizen in the agent
frameworks you already use.** Instead of hand-rolling HTTP calls to the control
plane, you import a small client (or a ready-made set of framework "tools") and
hand them to your agent. The agent then calls `runebox_shell`,
`runebox_python`, `runebox_read_file`, … exactly as it would any other tool —
but every call is routed through the full governance path:

```
policy check  →  approval gate  →  cost/loop guardrails  →  sandbox exec  →  audit ledger
```

So work runs in a disposable, deny-by-default Citadel; risky actions are blocked
or escalated to a human; and everything is recorded in a tamper-evident Chronicle.

## Which one do I want?

- **Using an MCP client** (Claude Desktop, Cursor, VS Code)? You don't need an
  adapter at all — point the client at the Rune Box MCP server (`runebox mcp`).
  See the [REST API](rest-api.md) and the `dist/mcp/` manifest.
- **Building a Python agent** with LangChain, CrewAI, LlamaIndex, the OpenAI
  Agents SDK, or Strands? Use the [`runebox` Python package](#python-runebox).
- **Building a TypeScript agent** on the Vercel AI SDK, LangChain.js, or Strands?
  Use the [`@runebox/sdk` package](#typescript-runeboxsdk).
- **Rolling your own?** Both `RuneboxClient`s are thin, typed wrappers over the
  REST control plane and work standalone with zero third-party runtime
  dependencies.

All adapters target the same control plane started with `runebox serve` (default
`http://localhost:8080`) and expose the same method surface, mirroring the
governed tool set: `create_sandbox`, `shell`, `python`, `node`,
`read_file`/`write_file`/`list_files`/`search_files`,
`list_approvals`/`approve`/`deny`, `kill_sandbox`, plus `audit`/`verify_audit`.
(The client method names keep their original spellings even though the matching
MCP tools are now `runebox_create_citadel`, `runebox_kill_citadel`, and
`runebox_list_conclave`.)

## The governance contract every adapter preserves

Every tool call resolves to one of three verdicts. Adapters surface these
consistently — as typed exceptions on the raw client, and as short,
model-readable strings on the framework tools:

- **`allow`** — the action ran (for shell, still check `exit_code`).
- **`deny`** — policy refused it. **Do not retry the same action;** choose an
  allowed approach or report the block.
- **`require-approval`** — a human must sign off. **Pause** and surface the
  `approval_id`; don't route around the gate.

!!! note "Authentication"
    If `runebox serve` is started with a token (`--token` / `RUNEBOX_API_TOKEN`)
    or RBAC, pass it to the client — `RuneboxClient(..., token="...")` in Python
    or `new RuneboxClient({ token: "..." })` in TypeScript.

## Python (`runebox`)

The core client uses **only the Python standard library** (`urllib`). Framework
helpers are optional extras, imported lazily, so the base client works with
nothing else installed.

```bash
python -m pip install runee-box
python -m pip install 'runee-box[langchain]'
python -m pip install 'runee-box[crewai]'
python -m pip install 'runee-box[llamaindex]'
python -m pip install 'runee-box[openai-agents]'
python -m pip install 'runee-box[strands]'
```

For repository development, use `python -m pip install -e ./adapters/python`.

### Raw client

```python
from runebox import RuneboxClient, RuneboxDenied, RuneboxApprovalRequired

rw = RuneboxClient("http://localhost:8080")
sbx = rw.create_sandbox("dev")
print(rw.shell(sbx["id"], ["python3", "--version"])["stdout"])

try:
    rw.shell(sbx["id"], ["rm", "-rf", "/"])
except RuneboxDenied as e:
    print("blocked by policy:", e.reason)        # do NOT retry
except RuneboxApprovalRequired as e:
    print("needs a human:", e.approval_id)        # pause for an operator

rw.kill_sandbox(sbx["id"])
```

### Framework tools

Each framework module exposes a single `make_runebox_tools(client)` factory that
returns that framework's native tool objects, all named `runebox_*`:

```python
from runebox import RuneboxClient

client = RuneboxClient("http://localhost:8080")

# Pick one, matching your framework:
from runebox.langchain_tools import make_runebox_tools       # LangChain
from runebox.crewai_tools import make_runebox_tools          # CrewAI
from runebox.llamaindex_tools import make_runebox_tools      # LlamaIndex
from runebox.openai_agents_tools import make_runebox_tools   # OpenAI Agents SDK
from runebox.strands_tools import make_runebox_tools         # Strands Agents SDK

tools = make_runebox_tools(client)
# LangChain:     pass `tools` to an AgentExecutor / create_react_agent(...)
# CrewAI:        crewai.Agent(tools=tools, ...)
# LlamaIndex:    FunctionAgent(tools=tools, ...) / ReActAgent
# OpenAI Agents: agents.Agent(name="...", tools=tools)
# Strands:       strands.Agent(tools=tools)
```

See the [Python adapter README](https://github.com/Runeeward/RuneBox/tree/main/adapters/python)
for full, per-framework examples.

## TypeScript (`@runebox/sdk`)

The core `RuneboxClient` uses the global `fetch` and has **no runtime
dependencies** (Node 18+, Deno, Bun, browsers). Tool wrappers require optional
peer dependencies, imported lazily.

```bash
npm install @runebox/sdk                            # core client
npm install @runebox/sdk ai zod                     # + Vercel AI SDK tools
npm install @runebox/sdk @langchain/core zod
npm install @runebox/sdk @strands-agents/sdk zod
```

For repository development, use `npm install ./adapters/typescript`.

### Raw client

```ts
import { RuneboxClient, RuneboxDenied } from "@runebox/sdk";

const rw = new RuneboxClient({ baseUrl: "http://localhost:8080" });
const sbx = await rw.createSandbox("dev");
console.log((await rw.shell(sbx.id, ["node", "--version"])).stdout);
await rw.killSandbox(sbx.id);
```

### Vercel AI SDK

```ts
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { RuneboxClient } from "@runebox/sdk";
import { makeRuneboxTools } from "@runebox/sdk/ai-tools";

const tools = await makeRuneboxTools(new RuneboxClient());
await generateText({ model: openai("gpt-4o"), tools, maxSteps: 8, prompt: "…" });
```

### LangChain.js

```ts
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { RuneboxClient } from "@runebox/sdk";
import { makeRuneboxTools } from "@runebox/sdk/langchain-tools";

const tools = await makeRuneboxTools(new RuneboxClient());
const agent = createReactAgent({ llm: new ChatOpenAI({ model: "gpt-4o" }), tools });
```

### Strands Agents SDK

```ts
import { Agent } from "@strands-agents/sdk";
import { RuneboxClient } from "@runebox/sdk";
import { makeRuneboxTools } from "@runebox/sdk/strands-tools";

const tools = await makeRuneboxTools(new RuneboxClient());
const agent = new Agent({ tools });
await agent.invoke("Create a dev sandbox, run `node --version`, then tear it down.");
```

See the [TypeScript adapter README](https://github.com/Runeeward/RuneBox/tree/main/adapters/typescript)
for more.

## Notes

- **`deny` is a policy decision, not a transient error.** Don't retry the same
  action; pick a different, allowed approach.
- **`require-approval` is a hard pause.** Surface the approval id to a human and
  wait for the outcome (resolve it via the dashboard, the CLI, or
  `POST /v1/conclave/{id}/{approve,deny}`).
- Prefer the tightest Charter that lets the task succeed.
