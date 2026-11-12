/**
 * Strands Agents SDK tool wrappers around {@link RuneboxClient}.
 *
 * `@strands-agents/sdk` and `zod` are **optional peer dependencies** — this
 * module imports them at call time inside {@link makeRuneboxTools} so the core
 * client stays dependency-free. Install them where you use the tools:
 *
 * ```bash
 * npm install @strands-agents/sdk zod
 * ```
 *
 * The optional peers are imported through a `string`-typed specifier so this
 * package type-checks and builds without them installed (and stays immune to
 * Strands type churn across major versions); the tool input shapes are typed
 * explicitly from the client instead of inferred from the framework.
 *
 * Each tool converts governance verdicts into a short, model-readable string
 * (rather than throwing) so the model can reason about a denial or an approval
 * gate: a `deny` must not be retried blindly, and a `require-approval` is a hard
 * pause for a human.
 */

import { RuneboxApprovalRequired, RuneboxClient, RuneboxDenied } from "./client.js";

/** Turn a governance error into a model-friendly instruction; rethrow otherwise. */
function describeGovernance(err: unknown): string {
  if (err instanceof RuneboxDenied) {
    return (
      `DENIED by policy: ${err.reason}. Do not retry this action; choose a ` +
      `different, allowed approach or tell the human it was blocked.`
    );
  }
  if (err instanceof RuneboxApprovalRequired) {
    return (
      `APPROVAL REQUIRED (approval_id=${err.approvalId}): ` +
      `${err.reason || "a human must sign off before this runs"}. ` +
      `Pause the task and ask the human to approve or deny.`
    );
  }
  throw err;
}

/** Run `fn`, converting governance verdicts to strings for the model. */
async function guarded<T>(fn: () => Promise<T>): Promise<string> {
  try {
    const result = await fn();
    return typeof result === "string" ? result : JSON.stringify(result);
  } catch (err) {
    return describeGovernance(err);
  }
}

/**
 * Build an array of Strands Agents SDK tools bound to `client`, named to match
 * the runebox MCP tools. Pass them to `new Agent({ tools })`.
 *
 * @example
 * ```ts
 * import { Agent } from "@strands-agents/sdk";
 * import { RuneboxClient } from "@runebox/sdk";
 * import { makeRuneboxTools } from "@runebox/sdk/strands-tools";
 *
 * const tools = await makeRuneboxTools(new RuneboxClient());
 * const agent = new Agent({ tools });
 * await agent.invoke("Create a dev Citadel, run `node --version`, then tear it down.");
 * ```
 */
export async function makeRuneboxTools(client: RuneboxClient) {
  // Dynamic imports keep `@strands-agents/sdk` and `zod` as optional peers. The
  // `as string` specifier makes these fully dynamic so tsc does not require the
  // packages to be installed to build this file.
  const { tool } = await import("@strands-agents/sdk" as string);
  const { z } = await import("zod" as string);

  return [
    tool({
      name: "runebox_create_citadel",
      description:
        "Provision a governed Citadel from a runebox Charter (e.g. 'dev'). Returns Citadel metadata including its id.",
      inputSchema: z.object({
        profile: z.string().describe("Charter name, e.g. 'dev' or 'governed'."),
      }),
      callback: (input: { profile: string }) =>
        guarded(() => client.createSandbox(input.profile)),
    }),

    tool({
      name: "runebox_shell",
      description:
        "Run a shell command (as an argv array, e.g. ['ls','-la']) in a Citadel. Returns verdict, exit_code, stdout, stderr.",
      inputSchema: z.object({
        sandbox: z.string().describe("Citadel id from create_citadel."),
        command: z.array(z.string()).describe("argv array, e.g. ['ls','-la']."),
        workdir: z.string().optional().describe("Optional working directory."),
      }),
      callback: (input: { sandbox: string; command: string[]; workdir?: string }) =>
        guarded(() => client.shell(input.sandbox, input.command, input.workdir ?? "")),
    }),

    tool({
      name: "runebox_python",
      description: "Run a Python code snippet inside the Citadel.",
      inputSchema: z.object({
        sandbox: z.string(),
        code: z.string().describe("Python source to execute."),
      }),
      callback: (input: { sandbox: string; code: string }) =>
        guarded(() => client.python(input.sandbox, input.code)),
    }),

    tool({
      name: "runebox_node",
      description: "Run a Node.js code snippet inside the Citadel.",
      inputSchema: z.object({
        sandbox: z.string(),
        code: z.string().describe("JavaScript source to execute."),
      }),
      callback: (input: { sandbox: string; code: string }) =>
        guarded(() => client.node(input.sandbox, input.code)),
    }),

    tool({
      name: "runebox_read_file",
      description: "Read a file's contents from the Citadel.",
      inputSchema: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to read."),
      }),
      callback: (input: { sandbox: string; path: string }) =>
        guarded(() => client.readFile(input.sandbox, input.path)),
    }),

    tool({
      name: "runebox_write_file",
      description: "Write content to a file in the Citadel.",
      inputSchema: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to write."),
        content: z.string().describe("Content to write."),
      }),
      callback: (input: { sandbox: string; path: string; content: string }) =>
        guarded(async () => `wrote ${await client.writeFile(input.sandbox, input.path, input.content)} bytes to ${input.path}`),
    }),

    tool({
      name: "runebox_list_files",
      description: "List a directory in the Citadel.",
      inputSchema: z.object({
        sandbox: z.string(),
        path: z.string().describe("Directory path to list."),
      }),
      callback: (input: { sandbox: string; path: string }) =>
        guarded(() => client.listFiles(input.sandbox, input.path)),
    }),

    tool({
      name: "runebox_search_files",
      description: "Search for a query string under a path in the Citadel.",
      inputSchema: z.object({
        sandbox: z.string(),
        query: z.string().describe("Search query."),
        path: z.string().describe("Path to search under."),
      }),
      callback: (input: { sandbox: string; query: string; path: string }) =>
        guarded(() => client.searchFiles(input.sandbox, input.query, input.path)),
    }),

    tool({
      name: "runebox_list_conclave",
      description: "List pending human-in-the-loop Conclave requests.",
      inputSchema: z.object({}),
      callback: () => guarded(() => client.listApprovals()),
    }),

    tool({
      name: "runebox_kill_citadel",
      description: "Tear down a Citadel when the task is finished.",
      inputSchema: z.object({
        sandbox: z.string(),
      }),
      callback: (input: { sandbox: string }) =>
        guarded(async () => {
          await client.killSandbox(input.sandbox);
          return `Citadel ${input.sandbox} terminated`;
        }),
    }),
  ];
}
