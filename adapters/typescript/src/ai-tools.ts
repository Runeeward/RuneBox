/**
 * Vercel AI SDK tool wrappers around {@link RuneboxClient}.
 *
 * `ai` and `zod` are **optional peer dependencies** — this module imports them
 * at call time inside {@link makeRuneboxTools} so the core client stays
 * dependency-free. Install them where you use the tools:
 *
 * ```bash
 * npm install ai zod
 * ```
 *
 * The optional peers are imported through a `string`-typed specifier so this
 * package type-checks and builds without them installed (and stays immune to
 * AI-SDK type churn across major versions); the tool argument shapes are typed
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
 * Build a map of Vercel AI SDK tools bound to `client`, keyed by the runebox
 * MCP tool names. Spread the result into a `tools` object passed to
 * `generateText` / `streamText`.
 *
 * @example
 * ```ts
 * import { generateText } from "ai";
 * import { openai } from "@ai-sdk/openai";
 * import { RuneboxClient } from "@runebox/sdk";
 * import { makeRuneboxTools } from "@runebox/sdk/ai-tools";
 *
 * const tools = await makeRuneboxTools(new RuneboxClient());
 * await generateText({ model: openai("gpt-4o"), tools, prompt: "..." });
 * ```
 */
export async function makeRuneboxTools(client: RuneboxClient) {
  // Dynamic imports keep `ai` and `zod` as optional peers. The `as string`
  // specifier makes these fully dynamic so tsc does not require the packages
  // to be installed to build this file.
  const { tool } = await import("ai" as string);
  const { z } = await import("zod" as string);

  return {
    runebox_create_citadel: tool({
      description:
        "Provision a governed Citadel from a runebox Charter (e.g. 'dev'). Returns Citadel metadata including its id.",
      parameters: z.object({
        profile: z.string().describe("Charter name, e.g. 'dev' or 'governed'."),
      }),
      execute: ({ profile }: { profile: string }) =>
        guarded(() => client.createSandbox(profile)),
    }),

    runebox_shell: tool({
      description:
        "Run a shell command (as an argv array, e.g. ['ls','-la']) in a Citadel. Returns verdict, exit_code, stdout, stderr.",
      parameters: z.object({
        sandbox: z.string().describe("Citadel id from create_citadel."),
        command: z.array(z.string()).describe("argv array, e.g. ['ls','-la']."),
        workdir: z.string().optional().describe("Optional working directory."),
      }),
      execute: ({ sandbox, command, workdir }: { sandbox: string; command: string[]; workdir?: string }) =>
        guarded(() => client.shell(sandbox, command, workdir ?? "")),
    }),

    runebox_python: tool({
      description: "Run a Python code snippet inside the Citadel.",
      parameters: z.object({
        sandbox: z.string(),
        code: z.string().describe("Python source to execute."),
      }),
      execute: ({ sandbox, code }: { sandbox: string; code: string }) =>
        guarded(() => client.python(sandbox, code)),
    }),

    runebox_node: tool({
      description: "Run a Node.js code snippet inside the Citadel.",
      parameters: z.object({
        sandbox: z.string(),
        code: z.string().describe("JavaScript source to execute."),
      }),
      execute: ({ sandbox, code }: { sandbox: string; code: string }) =>
        guarded(() => client.node(sandbox, code)),
    }),

    runebox_read_file: tool({
      description: "Read a file's contents from the Citadel.",
      parameters: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to read."),
      }),
      execute: ({ sandbox, path }: { sandbox: string; path: string }) =>
        guarded(() => client.readFile(sandbox, path)),
    }),

    runebox_write_file: tool({
      description: "Write content to a file in the Citadel.",
      parameters: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to write."),
        content: z.string().describe("Content to write."),
      }),
      execute: ({ sandbox, path, content }: { sandbox: string; path: string; content: string }) =>
        guarded(async () => `wrote ${await client.writeFile(sandbox, path, content)} bytes to ${path}`),
    }),

    runebox_list_files: tool({
      description: "List a directory in the Citadel.",
      parameters: z.object({
        sandbox: z.string(),
        path: z.string().describe("Directory path to list."),
      }),
      execute: ({ sandbox, path }: { sandbox: string; path: string }) =>
        guarded(() => client.listFiles(sandbox, path)),
    }),

    runebox_search_files: tool({
      description: "Search for a query string under a path in the Citadel.",
      parameters: z.object({
        sandbox: z.string(),
        query: z.string().describe("Search query."),
        path: z.string().describe("Path to search under."),
      }),
      execute: ({ sandbox, query, path }: { sandbox: string; query: string; path: string }) =>
        guarded(() => client.searchFiles(sandbox, query, path)),
    }),

    runebox_list_conclave: tool({
      description: "List pending human-in-the-loop Conclave requests.",
      parameters: z.object({}),
      execute: () => guarded(() => client.listApprovals()),
    }),

    runebox_kill_citadel: tool({
      description: "Tear down a Citadel when the task is finished.",
      parameters: z.object({
        sandbox: z.string(),
      }),
      execute: ({ sandbox }: { sandbox: string }) =>
        guarded(async () => {
          await client.killSandbox(sandbox);
          return `Citadel ${sandbox} terminated`;
        }),
    }),
  };
}
