import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { startHttpTransport, resolveHttpS2sSecret, resolveBindHost } from "../src/index.js";
import { parseGatewayCredentials } from "../src/credentials.js";
import { MAX_REQUEST_BODY_BYTES } from "../src/input-limits.js";

const SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GW = {
  "x-kaseya-vsax-server-url": "acme.vsax.net",
  "x-kaseya-vsax-token-id": "id-1",
  "x-kaseya-vsax-token-secret": "secret-1",
};
const RPC = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });

function s2s(secret = SECRET): Record<string, string> {
  const t = Math.floor(Date.now() / 1000);
  return { "x-gateway-s2s": `t=${t},v1=${createHmac("sha256", secret).update(`t=${t}`).digest("hex")}` };
}

const ENV_KEYS = [
  "CONDUIT_S2S_SECRET", "MCP_ALLOW_INSECURE_DEV", "MCP_HTTP_HOST", "MCP_HTTP_PORT", "AUTH_MODE",
  "KASEYA_VSAX_SERVER_URL", "KASEYA_VSAX_TOKEN_ID", "KASEYA_VSAX_TOKEN_SECRET",
];
let saved: NodeJS.ProcessEnv;
let server: Server | undefined;

beforeEach(() => {
  saved = { ...process.env };
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.MCP_HTTP_PORT = "0";
  process.env.MCP_HTTP_HOST = "127.0.0.1";
});
afterEach(async () => {
  process.env = saved;
  if (server) await new Promise((r) => server!.close(r));
  server = undefined;
});

async function start(env: Record<string, string>): Promise<string> {
  Object.assign(process.env, env);
  server = await startHttpTransport();
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const post = (base: string, headers: Record<string, string>, body: string = RPC) =>
  fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body,
  });

describe("S2S fail-closed startup", () => {
  it.each(["", "   ", "changeme", "Your-S2S-Secret", "secret", "${user_config.s2s}"])(
    "refuses to start with secret %j",
    async (value) => {
      process.env.CONDUIT_S2S_SECRET = value;
      await expect(startHttpTransport()).rejects.toThrow(/Refusing to start HTTP transport/);
    }
  );

  it("placeholder is refused even with MCP_ALLOW_INSECURE_DEV=1", () => {
    expect(() => resolveHttpS2sSecret({ CONDUIT_S2S_SECRET: "changeme", MCP_ALLOW_INSECURE_DEV: "1" })).toThrow();
  });

  it("insecure dev (only exactly 1) allows an empty secret and forces 127.0.0.1", () => {
    expect(resolveHttpS2sSecret({ MCP_ALLOW_INSECURE_DEV: "1" })).toEqual({ secret: "", insecureDev: true });
    expect(() => resolveHttpS2sSecret({ MCP_ALLOW_INSECURE_DEV: "true" })).toThrow();
    expect(resolveBindHost(false, { MCP_HTTP_HOST: "0.0.0.0" })).toBe("127.0.0.1");
    expect(resolveBindHost(true, { MCP_HTTP_HOST: "0.0.0.0" })).toBe("0.0.0.0");
    expect(resolveBindHost(true, {})).toBe("127.0.0.1");
  });

  it("insecure dev server binds loopback even when 0.0.0.0 is requested", async () => {
    await start({ MCP_ALLOW_INSECURE_DEV: "1", MCP_HTTP_HOST: "0.0.0.0", AUTH_MODE: "gateway" });
    expect((server!.address() as AddressInfo).address).toBe("127.0.0.1");
  });
});

describe("HTTP endpoints", () => {
  it("/health is unauthenticated and does not need credentials", async () => {
    const base = await start({ CONDUIT_S2S_SECRET: SECRET, AUTH_MODE: "gateway" });
    const r = await fetch(`${base}/health`);
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ status: "ok", authMode: "gateway" });
  });

  it("/mcp requires a valid X-Gateway-S2S header", async () => {
    const base = await start({ CONDUIT_S2S_SECRET: SECRET, AUTH_MODE: "gateway" });
    expect((await post(base, GW)).status).toBe(401);
    expect((await post(base, { ...GW, ...s2s("other-secret-value") })).status).toBe(401);
    expect((await post(base, { ...GW, ...s2s() })).status).toBe(200);
  });

  it("gateway mode: missing headers -> 401, bad host -> 400 without echo, no env fallback", async () => {
    const base = await start({
      CONDUIT_S2S_SECRET: SECRET,
      AUTH_MODE: "gateway",
      KASEYA_VSAX_SERVER_URL: "env.vsax.net",
      KASEYA_VSAX_TOKEN_ID: "env-id",
      KASEYA_VSAX_TOKEN_SECRET: "env-secret",
    });
    // env credentials are set but must not be used
    expect((await post(base, s2s())).status).toBe(401);
    const { "x-kaseya-vsax-token-secret": _omit, ...partial } = GW;
    expect((await post(base, { ...partial, ...s2s() })).status).toBe(401);

    const bad = await post(base, { ...GW, "x-kaseya-vsax-server-url": "evil.example.com", ...s2s() });
    expect(bad.status).toBe(400);
    const text = await bad.text();
    expect(text).not.toContain("evil.example.com");
    expect(text).not.toContain("secret-1");

    const ok = await post(base, { ...GW, ...s2s() });
    expect(ok.status).toBe(200);
    expect(JSON.stringify(await ok.json())).toContain("vsax_devices_list");
  });

  it("rejects a Content-Length above the cap with a 413 JSON-RPC error before parsing", async () => {
    const base = await start({ CONDUIT_S2S_SECRET: SECRET, AUTH_MODE: "gateway" });
    const big = "x".repeat(MAX_REQUEST_BODY_BYTES + 1);
    const r = await post(base, { ...GW, ...s2s() }, big);
    expect(r.status).toBe(413);
    const body = await r.json();
    expect(body.jsonrpc).toBe("2.0");
    expect(body.error.code).toBe(-32600);
  });

  it("unauthenticated oversize requests still get 401, not 413", async () => {
    const base = await start({ CONDUIT_S2S_SECRET: SECRET, AUTH_MODE: "gateway" });
    const r = await post(base, s2s(), "x".repeat(MAX_REQUEST_BODY_BYTES + 1));
    expect(r.status).toBe(401);
  });

  it("env mode serves /mcp after S2S without gateway headers", async () => {
    const base = await start({ CONDUIT_S2S_SECRET: SECRET, AUTH_MODE: "env" });
    expect((await post(base, s2s())).status).toBe(200);
  });

  it("rejects non-POST on /mcp and unknown paths", async () => {
    const base = await start({ CONDUIT_S2S_SECRET: SECRET, AUTH_MODE: "gateway" });
    expect((await fetch(`${base}/mcp`, { headers: s2s() })).status).toBe(405);
    expect((await fetch(`${base}/nope`)).status).toBe(404);
  });
});

describe("parseGatewayCredentials", () => {
  it("never reads process.env", () => {
    process.env.KASEYA_VSAX_SERVER_URL = "env.vsax.net";
    process.env.KASEYA_VSAX_TOKEN_ID = "i";
    process.env.KASEYA_VSAX_TOKEN_SECRET = "s";
    expect(parseGatewayCredentials({})).toMatchObject({ ok: false, status: 401 });
  });
  it("treats placeholders as missing and rejects hosts outside vsax.net", () => {
    expect(parseGatewayCredentials({ ...GW, "x-kaseya-vsax-token-id": "${user_config.id}" })).toMatchObject({ status: 401 });
    for (const host of ["vsax.net.evil.com", "a.b.vsax.net", "127.0.0.1", "http://acme.vsax.net", "acme.vsax.net:8443"]) {
      expect(parseGatewayCredentials({ ...GW, "x-kaseya-vsax-server-url": host })).toMatchObject({ ok: false, status: 400 });
    }
    expect(parseGatewayCredentials(GW)).toMatchObject({ ok: true });
  });
});

describe("shared auth circuit across gateway requests", () => {
  const callTool = (base: string, headers: Record<string, string>) =>
    post(
      base,
      { ...headers, ...s2s() },
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "vsax_environment_get", arguments: {} } })
    ).then(async (r) => (await r.json()).result.content[0].text as string);

  const run = async (status: number, hostLabel: string) => {
    const calls: string[] = [];
    const realFetch = globalThis.fetch;
    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (!url.includes(".vsax.net")) return realFetch(input as string, init);
      calls.push(url);
      return new Response(JSON.stringify({ Meta: {} }), { status });
    });
    vi.stubGlobal("fetch", fetchMock);
    const base = await start({ CONDUIT_S2S_SECRET: SECRET, AUTH_MODE: "gateway" });
    const headers = { ...GW, "x-kaseya-vsax-server-url": `${hostLabel}.vsax.net`, "x-kaseya-vsax-token-id": `id-${hostLabel}` };
    return { calls, base, headers, realFetch };
  };

  afterEach(() => vi.unstubAllGlobals());

  it("401 twice locks the third request out without calling fetch; other token ids are unaffected", async () => {
    const { calls, base, headers } = await run(401, "tenant401");
    const want = /didn't accept the API token/;
    expect(await callTool(base, headers)).toMatch(want);
    expect(await callTool(base, headers)).toMatch(want);
    const before = calls.length;
    expect(await callTool(base, headers)).toMatch(/rejected the API token twice in a row.*paused for 5 minutes/);
    expect(calls.length).toBe(before);
    // different token id on the same host is not locked out
    expect(await callTool(base, { ...headers, "x-kaseya-vsax-token-id": "other-id" })).toMatch(want);
    expect(calls.length).toBe(before + 1);
  });

  it("403s do not lock out", async () => {
    const { calls, base, headers } = await run(403, "tenant403");
    for (let i = 0; i < 4; i++) {
      expect(await callTool(base, headers)).toMatch(/isn't allowed to call/);
    }
    expect(calls.length).toBe(4);
  });
});
