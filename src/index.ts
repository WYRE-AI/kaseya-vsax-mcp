#!/usr/bin/env node
/**
 * Kaseya VSA X MCP Server (read-only, Phase 1)
 *
 * Tools for the Kaseya VSA X (VSA 10) REST API v3. Credentials come from
 * environment variables (env mode / stdio) or per-request HTTP headers
 * (gateway mode). Gateway mode never falls back to KASEYA_VSAX_* env
 * credentials. Supports stdio (default) and HTTP (StreamableHTTP) transports.
 *
 * HTTP transport refuses to start unless CONDUIT_S2S_SECRET is a real secret.
 * MCP_ALLOW_INSECURE_DEV=1 is a local-only escape hatch: it logs a warning and
 * forces the listener onto 127.0.0.1. Known placeholder secrets are rejected
 * even with that flag. /health stays unauthenticated and does not read
 * credentials. stdio does not use S2S auth.
 */

import { createServer, IncomingMessage, ServerResponse, Server as HttpServer } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { CONFIG_PLACEHOLDER } from "./config.js";
import { parseGatewayCredentials, type VsaxCredentials } from "./credentials.js";
import { MAX_REQUEST_BODY_BYTES } from "./input-limits.js";
import { createMcpServer } from "./server.js";
import { verifyS2sHeader, S2S_HEADER } from "./s2s-verify.js";

export { createMcpServer } from "./server.js";
export { cleanCredential } from "./config.js";
export { getCredentials, createClient } from "./credentials.js";

// ---------------------------------------------------------------------------
// Transport: stdio (default)
// ---------------------------------------------------------------------------

async function startStdioTransport(): Promise<void> {
  const server = createMcpServer();
  await server.connect(new StdioServerTransport());
  console.error("Kaseya VSA X MCP server running on stdio");
}

// ---------------------------------------------------------------------------
// HTTP service-to-service auth
// ---------------------------------------------------------------------------

/**
 * Public example values. A copied placeholder must not verify as a real
 * secret. Matched case-insensitively after trim. Never log the value.
 * Unresolved `${...}` manifest placeholders are rejected too.
 */
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  "replace-with-a-real-secret",
  "your-s2s-secret",
  "your-secret",
  "changeme",
  "change-me",
  "placeholder",
  "secret",
  "example",
  "replace-me",
  "s2s-secret",
]);

const LOOPBACK_HOST = "127.0.0.1";

const MISSING_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty. " +
  "Set CONDUIT_S2S_SECRET to the gateway-provisioned secret (openssl rand -hex 32), " +
  "or set MCP_ALLOW_INSECURE_DEV=1 for local development only.";

const PLACEHOLDER_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is a known placeholder. " +
  "Generate a secret with openssl rand -hex 32 and set CONDUIT_S2S_SECRET to that value.";

const INSECURE_DEV_WARNING =
  "SECURITY WARNING: CONDUIT_S2S_SECRET is empty and MCP_ALLOW_INSECURE_DEV=1. " +
  "HTTP /mcp is not enforcing X-Gateway-S2S and is bound to 127.0.0.1 only. " +
  "Do not use this outside local development.";

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[(.+)\]$/, "$1");
  if (normalized === "localhost" || normalized === "::1") return true;
  const bare = normalized.startsWith("::ffff:") ? normalized.slice("::ffff:".length) : normalized;
  const parts = bare.split(".");
  if (parts.length !== 4) return false;
  if (parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return false;
  return parts[0] === "127";
}

/**
 * Secret for X-Gateway-S2S on /mcp. Read at HTTP startup, not module load.
 * Empty is fail-closed unless MCP_ALLOW_INSECURE_DEV=1. A known placeholder
 * always refuses to start. The secret value is never written to logs.
 * Throws (rather than exiting) so startup failure is testable; main() exits.
 */
export function resolveHttpS2sSecret(
  env: NodeJS.ProcessEnv = process.env
): { secret: string; insecureDev: boolean } {
  const raw = (env.CONDUIT_S2S_SECRET ?? "").trim();
  if (KNOWN_PLACEHOLDER_SECRETS.has(raw.toLowerCase()) || CONFIG_PLACEHOLDER.test(raw)) {
    throw new Error(PLACEHOLDER_S2S_SECRET_ERROR);
  }
  if (raw) return { secret: raw, insecureDev: false };
  if (env.MCP_ALLOW_INSECURE_DEV === "1") {
    console.error(INSECURE_DEV_WARNING);
    return { secret: "", insecureDev: true };
  }
  throw new Error(MISSING_S2S_SECRET_ERROR);
}

/**
 * With a real secret, honor MCP_HTTP_HOST (default 127.0.0.1 when unset).
 * Without a secret the insecure-dev bypass forces 127.0.0.1, including when
 * MCP_HTTP_HOST is a wider address such as 0.0.0.0.
 */
export function resolveBindHost(hasRealSecret: boolean, env: NodeJS.ProcessEnv = process.env): string {
  const configured = (env.MCP_HTTP_HOST ?? "").trim();
  if (hasRealSecret) return configured || LOOPBACK_HOST;
  if (configured && !isLoopbackHost(configured)) {
    console.error(
      `WARNING: MCP_HTTP_HOST=${configured} is not a loopback address. ` +
        "MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET forces the listener to 127.0.0.1 only."
    );
  }
  return LOOPBACK_HOST;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

// ---------------------------------------------------------------------------
// Transport: HTTP (StreamableHTTPServerTransport)
// ---------------------------------------------------------------------------

let httpServer: HttpServer | undefined;

export async function startHttpTransport(): Promise<HttpServer> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const { secret: s2sSecret, insecureDev } = resolveHttpS2sSecret();
  const host = resolveBindHost(!insecureDev);
  const isGatewayMode = (process.env.AUTH_MODE || "env") === "gateway";

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

    // Health endpoint — unauthenticated liveness. Must not read credentials.
    if (url.pathname === "/health") {
      sendJson(res, 200, {
        status: "ok",
        transport: "http",
        authMode: isGatewayMode ? "gateway" : "env",
        timestamp: new Date().toISOString(),
      });
      return;
    }

    if (url.pathname !== "/mcp") {
      sendJson(res, 404, { error: "Not found", endpoints: ["/mcp", "/health"] });
      return;
    }

    // Empty s2sSecret is only reachable when MCP_ALLOW_INSECURE_DEV=1.
    // A configured secret is always enforced, before credential extraction.
    if (s2sSecret && !verifyS2sHeader(headerValue(req.headers[S2S_HEADER]), s2sSecret)) {
      sendJson(res, 401, {
        error: "Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.",
      });
      return;
    }

    if (req.method !== "POST") {
      sendJson(res, 405, { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
      return;
    }

    // Gateway mode: credentials come from headers only, never process.env.
    let gatewayCredentials: VsaxCredentials | undefined;
    if (isGatewayMode) {
      const parsed = parseGatewayCredentials(req.headers);
      if (!parsed.ok) {
        sendJson(res, parsed.status, { error: parsed.error, message: parsed.message });
        return;
      }
      gatewayCredentials = parsed.creds;
    }

    // Body cap runs after S2S and credential checks so unauthenticated callers
    // still get 401, and before any parsing.
    const contentLength = Number(req.headers["content-length"]);
    if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
      sendJson(res, 413, {
        jsonrpc: "2.0",
        error: { code: -32600, message: `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes` },
        id: null,
      });
      return;
    }

    // Stateless: fresh server + transport per request. Must stay stateless so
    // per-request tenant credentials cannot leak across a long-lived session.
    const mcp = createMcpServer({ credentials: gatewayCredentials });
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
      maxRequestBodySize: MAX_REQUEST_BODY_BYTES,
    });

    res.on("close", () => {
      void transport.close();
      void mcp.close();
    });

    mcp
      .connect(transport as unknown as Transport)
      .then(() => transport.handleRequest(req, res))
      .catch((err) => {
        console.error("MCP transport error:", err instanceof Error ? err.name : "unknown");
        if (!res.headersSent) {
          sendJson(res, 500, { jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
        }
      });
  });
  httpServer = server;

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    server.once("error", onError);
    server.listen(port, host, () => {
      server.off("error", onError);
      console.error(`Kaseya VSA X MCP server listening on http://${host}:${port}/mcp`);
      console.error(`Health check available at http://${host}:${port}/health`);
      console.error(`Authentication mode: ${isGatewayMode ? "gateway (header-based)" : "env (environment variables)"}`);
      resolve();
    });
  });

  return server;
}

// ---------------------------------------------------------------------------
// Graceful shutdown + main
// ---------------------------------------------------------------------------

function setupShutdownHandlers(): void {
  const shutdown = async () => {
    console.error("Shutting down Kaseya VSA X MCP server...");
    if (httpServer) {
      await new Promise<void>((resolve, reject) => {
        httpServer!.close((err) => (err ? reject(err) : resolve()));
      });
    }
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function main(): Promise<void> {
  setupShutdownHandlers();
  if ((process.env.MCP_TRANSPORT || "stdio") === "http") {
    await startHttpTransport();
  } else {
    await startStdioTransport();
  }
}

// Guard the bootstrap so importing this module in tests does not start a server
// (vitest sets NODE_ENV=test by default).
if (process.env.NODE_ENV !== "test") {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : "Fatal startup error");
    process.exit(1);
  });
}
