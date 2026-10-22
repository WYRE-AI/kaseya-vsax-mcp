import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { KaseyaVsaxClient } from "@wyre-ai/node-kaseya-vsax";
import { loadToolFlags, type ToolFlags } from "./config.js";
import { createClient, getCredentials, type VsaxCredentials } from "./credentials.js";
import { toSafeErrorMessage } from "./errors.js";
import { MAX_RESULT_CHARS, MAX_TOOL_INPUT_ELEMENTS, toolInputTooLarge, toolInputTooLargeResult } from "./input-limits.js";
import { annotationsFor, enabledTools, type ToolDef } from "./registry.js";
import { TOOLS } from "./tools.js";

export const SERVER_NAME = "kaseya-vsax-mcp";
// package.json sits one level above both src/ and dist/.
export const SERVER_VERSION: string = (createRequire(import.meta.url)("../package.json") as { version: string }).version;

export const SERVER_INSTRUCTIONS =
  "All tools in this server are read-only: they list and get Kaseya VSA X data and never change anything.";

export interface CreateServerOptions {
  /** Gateway-mode credentials. When omitted, env credentials are read per call. */
  credentials?: VsaxCredentials;
  flags?: ToolFlags;
  tools?: readonly ToolDef[];
  /** Test seam: replaces client construction. */
  clientFactory?: (creds: VsaxCredentials) => KaseyaVsaxClient;
}

function errorResult(text: string) {
  return { content: [{ type: "text" as const, text: `Error: ${text}` }], isError: true };
}

function jsonResult(value: unknown) {
  let text = JSON.stringify(value ?? null, null, 2);
  if (text.length > MAX_RESULT_CHARS) {
    text = `${text.slice(0, MAX_RESULT_CHARS)}\n…[truncated: result exceeded ${MAX_RESULT_CHARS} characters; narrow it with filter or a smaller top, or for assets, fewer include sections]`;
  }
  return { content: [{ type: "text" as const, text }] };
}

/** Runs a tool handler after the element-count guard; oversize input never reaches the handler. */
export async function dispatchTool(tool: ToolDef, client: KaseyaVsaxClient, args: Record<string, unknown>) {
  if (toolInputTooLarge(args)) return toolInputTooLargeResult();
  return jsonResult(await tool.handler({ client }, args));
}

/** Fresh server per request in HTTP mode (stateless); one per process on stdio. */
export function createMcpServer(options: CreateServerOptions = {}): McpServer {
  const flags = options.flags ?? loadToolFlags();
  const build = options.clientFactory ?? createClient;
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { instructions: SERVER_INSTRUCTIONS, maxToolInputElements: MAX_TOOL_INPUT_ELEMENTS }
  );

  // One client per server; breaker state itself lives in the shared store
  // passed by createClient, so it also survives per-request servers.
  let cached: { key: string; client: KaseyaVsaxClient } | undefined;
  const clientFor = (creds: VsaxCredentials): KaseyaVsaxClient => {
    const key = `${creds.serverUrl}\n${creds.tokenId}\n${creds.tokenSecret}`;
    if (cached?.key !== key) cached = { key, client: build(creds) };
    return cached.client;
  };

  for (const tool of enabledTools(options.tools ?? TOOLS, flags)) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: annotationsFor(tool.access),
      },
      async (args: Record<string, unknown>) => {
        const creds = options.credentials ?? getCredentials();
        if (!creds) {
          return errorResult(
            "No Kaseya VSA X credentials are set. Set KASEYA_VSAX_SERVER_URL, KASEYA_VSAX_TOKEN_ID and KASEYA_VSAX_TOKEN_SECRET."
          );
        }
        try {
          return await dispatchTool(tool, clientFor(creds), args);
        } catch (err) {
          return errorResult(toSafeErrorMessage(err, [creds.tokenSecret, creds.tokenId]));
        }
      }
    );
  }
  return server;
}
