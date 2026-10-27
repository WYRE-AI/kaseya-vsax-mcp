import { describe, it, expect, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  KaseyaVsaxAuthCircuitOpenError,
  KaseyaVsaxAuthenticationError,
  KaseyaVsaxForbiddenError,
  KaseyaVsaxRateLimitError,
  KaseyaVsaxServerError,
  type KaseyaVsaxClient,
} from "@wyre-ai/node-kaseya-vsax";
import { readFileSync } from "node:fs";
import { KaseyaVsaxNotFoundError, KaseyaVsaxValidationError, KaseyaVsaxConfigError, KaseyaVsaxError } from "@wyre-ai/node-kaseya-vsax";
import { createMcpServer, dispatchTool, SERVER_VERSION, SERVER_INSTRUCTIONS } from "../src/server.js";
import { loadToolFlags } from "../src/config.js";
import { enabledTools, isToolEnabled, type ToolDef } from "../src/registry.js";
import { TOOLS } from "../src/tools.js";
import { toSafeErrorMessage } from "../src/errors.js";
import type { VsaxCredentials } from "../src/credentials.js";

const CREDS: VsaxCredentials = {
  serverUrl: "acme.vsax.net",
  tokenId: "tok-id-123",
  tokenSecret: "s3cr3t-value-xyz",
};

const EXPECTED = [
  "vsax_devices_list", "vsax_devices_get", "vsax_devices_notifications_list", "vsax_devices_antivirus_get",
  "vsax_devices_custom_fields_list", "vsax_devices_applied_policies_list", "vsax_assets_list", "vsax_assets_get",
  "vsax_notifications_list", "vsax_notifications_get", "vsax_organizations_list", "vsax_organizations_get",
  "vsax_sites_list", "vsax_sites_get", "vsax_groups_list", "vsax_groups_get", "vsax_custom_fields_list",
  "vsax_scopes_list", "vsax_scripts_list", "vsax_script_executions_list", "vsax_tasks_list",
  "vsax_task_executions_get", "vsax_workflows_list", "vsax_workflow_executions_list", "vsax_patch_policies_get",
  "vsax_endpoint_protection_policies_get", "vsax_audit_logs_list", "vsax_environment_get",
];

function fakeClient() {
  const fn = () => vi.fn().mockResolvedValue([]);
  const client = {
    devices: { list: fn(), get: fn(), notifications: fn(), antivirus: fn(), customFields: fn(), appliedPolicies: fn() },
    assets: { list: fn(), get: fn() },
    notifications: { list: fn(), get: fn() },
    organizations: { list: fn(), get: fn(), customFields: fn() },
    sites: { list: fn(), get: fn(), customFields: fn() },
    groups: { list: fn(), get: fn(), customFields: fn() },
    customFields: { list: fn() },
    scopes: { list: fn() },
    automation: {
      scripts: { list: fn(), get: fn(), executions: { list: fn(), get: fn() } },
      tasks: { list: fn(), get: fn(), getExecution: fn(), executionDevices: fn(), executionDeviceScripts: fn(), scriptOutput: fn() },
      workflows: { list: fn(), get: fn(), executions: { list: fn(), get: fn() } },
    },
    patchManagement: { getPolicy: fn(), getGlobalRules: fn() },
    endpointProtection: { getPolicy: fn() },
    auditLogs: { list: fn() },
    environment: { get: fn() },
  };
  return client;
}

async function connect(opts: { client?: ReturnType<typeof fakeClient>; tools?: ToolDef[]; flags?: { readOnlyMode: boolean; destructiveToolsEnabled: boolean } } = {}) {
  const fake = opts.client ?? fakeClient();
  const server = createMcpServer({
    credentials: CREDS,
    clientFactory: () => fake as unknown as KaseyaVsaxClient,
    tools: opts.tools,
    flags: opts.flags,
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = await client.callTool({ name, arguments: args });
    const text = (r.content as Array<{ text: string }>)[0].text;
    return { isError: !!r.isError, text, json: r.isError ? undefined : JSON.parse(text) };
  };
  return { client, call, fake };
}

describe("tool registration", () => {
  it("registers exactly the 28 Phase 1 tools, all read-only", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([...EXPECTED].sort());
    for (const t of tools) {
      expect(t.annotations?.readOnlyHint).toBe(true);
      expect(t.annotations?.destructiveHint).toBe(false);
      expect(t.description).toBeTruthy();
    }
  });

  it("has no write/destructive tool and no webhook/package/rate-limit tool", () => {
    expect(TOOLS.every((t) => t.access === "read")).toBe(true);
    expect(TOOLS.map((t) => t.name).join(" ")).not.toMatch(/webhook|package|ratelimit|create|update|delete|run|move|publish|cancel/);
  });

  it("list tools cap top at 100", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    for (const t of tools.filter((x) => x.name.endsWith("_list"))) {
      const props = t.inputSchema.properties as Record<string, { maximum?: number }> | undefined;
      if (props?.top) expect(props.top.maximum).toBe(100);
    }
  });
});

describe("read-only flags", () => {
  const write: ToolDef = { name: "vsax_x_create", title: "x", description: "x", access: "write", inputSchema: {}, handler: async () => ({}) };
  const destructive: ToolDef = { ...write, name: "vsax_x_delete", access: "destructive" };

  it("defaults to read-only with destructive tools disabled", () => {
    expect(loadToolFlags({})).toEqual({ readOnlyMode: true, destructiveToolsEnabled: false });
    expect(loadToolFlags({ READ_ONLY_MODE: "garbage", DESTRUCTIVE_TOOLS_ENABLED: "garbage" })).toEqual({
      readOnlyMode: true,
      destructiveToolsEnabled: false,
    });
  });

  it("gates write and destructive tools", () => {
    const names = (f: { readOnlyMode: boolean; destructiveToolsEnabled: boolean }) =>
      enabledTools([...TOOLS.slice(0, 1), write, destructive], f).map((t) => t.name);
    expect(names(loadToolFlags({}))).toEqual(["vsax_devices_list"]);
    // destructive flag alone does not lift read-only mode
    expect(names({ readOnlyMode: true, destructiveToolsEnabled: true })).toEqual(["vsax_devices_list"]);
    expect(names(loadToolFlags({ READ_ONLY_MODE: "false" }))).toEqual(["vsax_devices_list", "vsax_x_create"]);
    expect(names(loadToolFlags({ READ_ONLY_MODE: "false", DESTRUCTIVE_TOOLS_ENABLED: "true" }))).toHaveLength(3);
    expect(isToolEnabled("read", { readOnlyMode: true, destructiveToolsEnabled: false })).toBe(true);
  });

  it("server does not expose a write tool by default", async () => {
    const { client } = await connect({ tools: [...TOOLS, write, destructive] });
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).not.toContain("vsax_x_create");
    expect(tools.map((t) => t.name)).not.toContain("vsax_x_delete");
  });
});

describe("argument mapping", () => {
  it("devices_list maps paging/filter/scope and returns nextSkip on a full page", async () => {
    const { call, fake } = await connect();
    fake.devices.list.mockResolvedValue([{ Id: "a" }, { Id: "b" }]);
    const r = await call("vsax_devices_list", { top: 2, skip: 10, filter: "Name eq 'x'", orderby: "Name", scopeId: 7 });
    expect(fake.devices.list).toHaveBeenCalledWith({ top: 2, skip: 10, filter: "Name eq 'x'", orderby: "Name", scopeId: 7 });
    expect(r.json).toEqual({ items: [{ Id: "a" }, { Id: "b" }], nextSkip: 12 });
  });

  it("list defaults to top 50 and omits nextSkip on a short page", async () => {
    const { call, fake } = await connect();
    fake.sites.list.mockResolvedValue([{ Id: 1 }]);
    const r = await call("vsax_sites_list");
    expect(fake.sites.list).toHaveBeenCalledWith({ top: 50, skip: undefined, filter: undefined, orderby: undefined });
    expect(r.json).toEqual({ items: [{ Id: 1 }] });
  });

  it("assets_list defaults to slim sections and honours include", async () => {
    const { call, fake } = await connect();
    await call("vsax_assets_list");
    expect(fake.assets.list.mock.calls[0][0].include).toEqual(["AssetInfo", "IpAddresses"]);
    await call("vsax_assets_get", { deviceId: "d1", include: ["Disks"] });
    expect(fake.assets.get).toHaveBeenCalledWith("d1", ["Disks"]);
  });

  it("treats include: [] as the slim default", async () => {
    const { call, fake } = await connect();
    await call("vsax_assets_list", { include: [] });
    expect(fake.assets.list.mock.calls[0][0].include).toEqual(["AssetInfo", "IpAddresses"]);
    await call("vsax_assets_get", { deviceId: "d1", include: [] });
    expect(fake.assets.get).toHaveBeenCalledWith("d1", ["AssetInfo", "IpAddresses"]);
  });

  it("custom_fields_list routes by entityType", async () => {
    const { call, fake } = await connect();
    await call("vsax_custom_fields_list", { entityType: "site", entityId: 5 });
    expect(fake.sites.customFields).toHaveBeenCalledWith(5);
    await call("vsax_custom_fields_list", { entityType: "device", entityId: "dev-1" });
    expect(fake.devices.customFields).toHaveBeenCalledWith("dev-1");
    await call("vsax_custom_fields_list", {});
    expect(fake.customFields.list).toHaveBeenCalled();
    const bad = await call("vsax_custom_fields_list", { entityType: "group" });
    expect(bad.isError).toBe(true);
    expect(bad.text).toContain("entityId");
  });

  it("task_executions_get drills down by deviceId / scriptId", async () => {
    const { call, fake } = await connect();
    const t = fake.automation.tasks;
    await call("vsax_task_executions_get", { executionId: 9, deviceId: "d", scriptId: "s" });
    expect(t.scriptOutput).toHaveBeenCalledWith(9, "d", "s");
    await call("vsax_task_executions_get", { executionId: 9, deviceId: "d" });
    expect(t.executionDeviceScripts).toHaveBeenCalledWith(9, "d");
    await call("vsax_task_executions_get", { executionId: 9 });
    expect(t.getExecution).toHaveBeenCalledWith(9);
    expect((await call("vsax_task_executions_get", { executionId: 9, scriptId: "s" })).isError).toBe(true);
  });

  it("task_executions_get rejects invalid execution IDs before any request", async () => {
    const { call, fake } = await connect();
    const t = fake.automation.tasks;
    const message =
      "executionId must be a task execution ID, a whole number like 1234. Run a task to get one, or copy it from the task's Execution History in VSA X.";
    for (const executionId of ["abc", "0", "01", -1, 1.5, "12a", 0]) {
      for (const extra of [{}, { deviceId: "d" }, { deviceId: "d", scriptId: "s" }]) {
        const r = await call("vsax_task_executions_get", { executionId, ...extra });
        expect(r.isError).toBe(true);
        expect(r.text).toBe(`Error: ${message}`);
      }
    }
    for (const fn of [t.getExecution, t.executionDevices, t.executionDeviceScripts, t.scriptOutput]) {
      expect(fn).not.toHaveBeenCalled();
    }
  });

  it("task_executions_get accepts string and number execution IDs", async () => {
    const { call, fake } = await connect();
    const t = fake.automation.tasks;
    expect((await call("vsax_task_executions_get", { executionId: "1234" })).isError).toBe(false);
    expect(t.getExecution).toHaveBeenLastCalledWith("1234");
    expect((await call("vsax_task_executions_get", { executionId: 1234 })).isError).toBe(false);
    expect(t.getExecution).toHaveBeenLastCalledWith(1234);
  });

  it("task_executions_get does not request devices when the execution lookup fails", async () => {
    const { call, fake } = await connect();
    fake.automation.tasks.getExecution.mockRejectedValue(
      new KaseyaVsaxServerError("boom", { status: 500, path: "/automation/tasks/executions/999999999" })
    );
    const r = await call("vsax_task_executions_get", { executionId: 999999999 });
    expect(r.isError).toBe(true);
    expect(r.text).toBe("Error: No task execution found with that ID. Use an execution ID from a task run, then try again.");
    expect(fake.automation.tasks.executionDevices).not.toHaveBeenCalled();
  });

  it("antivirus_get returns a message for null/undefined and passes data through", async () => {
    const { call, fake } = await connect();
    for (const empty of [null, undefined]) {
      fake.devices.antivirus.mockResolvedValue(empty);
      const r = await call("vsax_devices_antivirus_get", { deviceId: "d" });
      expect(r.json).toEqual({ message: "No antivirus data for this device. Antivirus may not be installed, or it hasn't reported yet. Check the device in VSA X." });
    }
    fake.devices.antivirus.mockResolvedValue({ Name: "Defender" });
    expect((await call("vsax_devices_antivirus_get", { deviceId: "d" })).json).toEqual({ Name: "Defender" });
  });

  it("scripts / script executions / patch policies pick the right SDK call", async () => {
    const { call, fake } = await connect();
    await call("vsax_scripts_list", { scriptId: "sc1" });
    expect(fake.automation.scripts.get).toHaveBeenCalledWith("sc1");
    await call("vsax_script_executions_list", { scriptId: "s", deviceId: "d" });
    expect(fake.automation.scripts.executions.list).toHaveBeenCalledWith("s", "d", expect.objectContaining({ top: 50 }));
    await call("vsax_script_executions_list", { scriptId: "s", deviceId: "d", executionId: 3 });
    expect(fake.automation.scripts.executions.get).toHaveBeenCalledWith("s", "d", 3);
    await call("vsax_patch_policies_get", {});
    expect(fake.patchManagement.getGlobalRules).toHaveBeenCalledTimes(1);
    await call("vsax_patch_policies_get", { policyId: 4 });
    expect(fake.patchManagement.getPolicy).toHaveBeenCalledWith(4);
    await call("vsax_patch_policies_get", { policyId: 4, globalRules: true });
    expect(fake.patchManagement.getGlobalRules).toHaveBeenCalledTimes(2);
  });
});

describe("input caps", () => {
  it("rejects top > 100, oversize strings, oversize arrays and bad enums", async () => {
    const { call, fake } = await connect();
    expect((await call("vsax_devices_list", { top: 101 })).isError).toBe(true);
    expect((await call("vsax_devices_list", { filter: "x".repeat(1001) })).isError).toBe(true);
    expect((await call("vsax_devices_get", { deviceId: "x".repeat(129) })).isError).toBe(true);
    expect((await call("vsax_assets_list", { include: Array(11).fill("Disks") })).isError).toBe(true);
    expect((await call("vsax_assets_list", { include: ["Nope"] })).isError).toBe(true);
    expect(fake.devices.list).not.toHaveBeenCalled();
    expect(fake.assets.list).not.toHaveBeenCalled();
  });

  it("rejects tool input with more than MAX_TOOL_INPUT_ELEMENTS elements", async () => {
    const { call, fake } = await connect();
    const r = await call("vsax_devices_get", { deviceId: "d", junk: Array(10_001).fill(0) });
    expect(r.isError).toBe(true);
    expect(fake.devices.get).not.toHaveBeenCalled();
  });
});

describe("error mapping", () => {
  const secrets = [CREDS.tokenSecret, CREDS.tokenId];

  it("maps SDK errors to the documented safe messages", () => {
    expect(toSafeErrorMessage(new KaseyaVsaxForbiddenError("x", { path: "/api/v3/devices?token=abc" }), secrets)).toBe(
      "The Kaseya VSA X API token isn't allowed to call /api/v3/devices. In VSA X, open Configuration > API Access > Third-Party Tokens, edit the token, and on the Authorization tab grant that permission. If the token is limited to certain organizations, add the organization too."
    );
    expect(toSafeErrorMessage(new KaseyaVsaxAuthenticationError("x"), secrets)).toBe(
      "Kaseya VSA X didn't accept the API token. It may be wrong, expired or revoked. Check the Token ID and Token Secret, or create a new token under Configuration > API Access > Third-Party Tokens."
    );
    expect(toSafeErrorMessage(new KaseyaVsaxAuthCircuitOpenError(300_000), secrets)).toBe(
      "Kaseya VSA X rejected the API token twice in a row, so requests are paused for 5 minutes to avoid getting this server's IP blocked. Check the Token ID and Token Secret, then try again."
    );
    expect(toSafeErrorMessage(new KaseyaVsaxAuthCircuitOpenError(10), secrets)).toContain("paused for 1 minute ");
    expect(toSafeErrorMessage(new KaseyaVsaxRateLimitError("x", 12), secrets)).toBe("Kaseya VSA X rate limit reached. Wait 12 seconds, then try again.");
    expect(toSafeErrorMessage(new KaseyaVsaxRateLimitError("x"), secrets)).toBe("Kaseya VSA X rate limit reached. Wait a minute, then try again.");
    expect(toSafeErrorMessage(new KaseyaVsaxNotFoundError("x", { path: "/api/v3/devices/d" }), secrets)).toBe(
      "Kaseya VSA X has nothing at /api/v3/devices/d. Check the ID, for example with the matching list tool."
    );
    expect(toSafeErrorMessage(new KaseyaVsaxConfigError("Server host must be a single label under .vsax.net."), secrets)).toBe(
      "Kaseya VSA X connection settings aren't valid: Server host must be a single label under .vsax.net. Set the server URL to your tenant host, like acme.vsax.net, and copy the Token ID and Token Secret again from Configuration > API Access > Third-Party Tokens."
    );
  });

  it("uses err.detail for validation errors and the param name for invalid path params", () => {
    expect(
      toSafeErrorMessage(new KaseyaVsaxValidationError("Bad request (400): bad filter", { status: 400, detail: "bad filter." }), secrets)
    ).toBe("Kaseya VSA X rejected the request: bad filter. Check the filter, orderby and ID values.");
    expect(toSafeErrorMessage(new KaseyaVsaxValidationError("Bad request (400)", { status: 400 }), secrets)).toBe(
      "Kaseya VSA X rejected the request. Check the filter, orderby and ID values."
    );
    expect(
      toSafeErrorMessage(new KaseyaVsaxValidationError('Invalid path parameter "deviceId"', { code: "INVALID_PATH_PARAM" }), secrets)
    ).toBe('The deviceId value isn\'t valid (empty, ".", or contains "/"). Check the ID values.');
  });

  it("maps server, network, timeout, redirect, pagination and other codes without leaking codes", () => {
    const m = (code: string) => toSafeErrorMessage(new KaseyaVsaxError("x", { code, status: 302 }), secrets);
    expect(m("REDIRECT_REFUSED")).toContain("doesn't follow redirects");
    expect(m("PAGINATION_ERROR")).toContain("smaller top");
    expect(m("HTTP_ERROR")).toBe("The Kaseya VSA X request failed. Try again; if it keeps failing, check the connection settings.");
    for (const code of ["REDIRECT_REFUSED", "PAGINATION_ERROR", "HTTP_ERROR", "SERVER_ERROR", "NETWORK_ERROR"]) {
      expect(m(code)).not.toMatch(/\[|HTTP \d|[A-Z]+_[A-Z]+/);
    }
    expect(m("SERVER_ERROR")).toBe("Kaseya VSA X had a server error. Try again in a minute.");
    expect(m("NETWORK_ERROR")).toMatch(/^Couldn't reach Kaseya VSA X/);
  });

  it("maps SERVER_ERROR on task execution paths to not-found messages", () => {
    const m = (path: string) => toSafeErrorMessage(new KaseyaVsaxServerError("x", { status: 500, path }), secrets);
    const notFound = "No task execution found with that ID. Use an execution ID from a task run, then try again.";
    const notFoundDevice =
      "No task execution found for that execution ID and device. Use an execution ID from a task run and a device `Identifier` from that run, then try again.";
    expect(m("/automation/tasks/executions/123")).toBe(notFound);
    expect(m("/automation/tasks/executions/123/devices")).toBe(notFound);
    expect(m("/automation/tasks/executions/123?top=50")).toBe(notFound);
    expect(m("/automation/tasks/executions/123/devices/d1/scripts")).toBe(notFoundDevice);
    expect(m("/automation/tasks/executions/123/devices/d1/scripts/s1")).toBe(notFoundDevice);
    expect(m("/devices/abc")).toBe("Kaseya VSA X had a server error. Try again in a minute.");
  });

  it("logs only the error name for unexpected errors", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      class WeirdError extends Error {
        constructor(m: string) {
          super(m);
          this.name = "WeirdError";
        }
      }
      toSafeErrorMessage(new WeirdError(`leak ${CREDS.tokenSecret}`), secrets);
      const logged = spy.mock.calls.flat().join(" ");
      expect(logged).toContain("WeirdError");
      expect(logged).not.toContain(CREDS.tokenSecret);
      expect(logged).not.toContain("leak");
    } finally {
      spy.mockRestore();
    }
  });

  it("never leaks secrets or raw unknown error text", async () => {
    expect(toSafeErrorMessage(new KaseyaVsaxServerError(`boom ${CREDS.tokenSecret}`, { status: 500 }), secrets)).not.toContain(CREDS.tokenSecret);
    expect(toSafeErrorMessage(new Error(`leak ${CREDS.tokenSecret}`), secrets)).not.toContain(CREDS.tokenSecret);

    const { call, fake } = await connect();
    fake.devices.get.mockRejectedValue(new Error(`Authorization: Basic ${CREDS.tokenSecret}`));
    const r = await call("vsax_devices_get", { deviceId: "d" });
    expect(r.isError).toBe(true);
    expect(r.text).not.toContain(CREDS.tokenSecret);
    expect(r.text).not.toContain(CREDS.tokenId);

    fake.devices.get.mockRejectedValue(new KaseyaVsaxForbiddenError("nope", { path: "/api/v3/devices/d" }));
    const f = await call("vsax_devices_get", { deviceId: "d" });
    expect(f.text).toContain("isn't allowed to call /api/v3/devices/d");
  });

  it("returns a tool error (not a throw) when no credentials are configured", async () => {
    const server = createMcpServer({ clientFactory: () => fakeClient() as unknown as KaseyaVsaxClient });
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "t", version: "0" });
    await Promise.all([server.connect(a), client.connect(b)]);
    const saved = { ...process.env };
    delete process.env.KASEYA_VSAX_SERVER_URL;
    try {
      const r = await client.callTool({ name: "vsax_environment_get", arguments: {} });
      expect(r.isError).toBe(true);
      expect((r.content as Array<{ text: string }>)[0].text).toBe(
        "Error: No Kaseya VSA X credentials are set. Set KASEYA_VSAX_SERVER_URL, KASEYA_VSAX_TOKEN_ID and KASEYA_VSAX_TOKEN_SECRET."
      );
    } finally {
      process.env = saved;
    }
  });
});

describe("server metadata and copy", () => {
  it("SERVER_VERSION equals package.json version", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    expect(SERVER_VERSION).toBe(pkg.version);
  });

  it("states read-only in server instructions and every tool description", async () => {
    const { client } = await connect();
    expect(client.getInstructions()).toBe(SERVER_INSTRUCTIONS);
    expect(SERVER_INSTRUCTIONS).toMatch(/read-only/);
    const { tools } = await client.listTools();
    for (const t of tools) expect(t.description).toMatch(/Read-only\./);
  });

  it("dispatch refuses oversize input before the handler runs", async () => {
    const handler = vi.fn().mockResolvedValue({});
    const tool: ToolDef = { name: "t", title: "t", description: "t", access: "read", inputSchema: {}, handler };
    const r = await dispatchTool(tool, {} as KaseyaVsaxClient, { junk: Array(10_001).fill(0) });
    expect(r.isError).toBe(true);
    expect(handler).not.toHaveBeenCalled();
    const ok = await dispatchTool(tool, {} as KaseyaVsaxClient, { a: 1 });
    expect(ok.isError).toBeUndefined();
    expect(handler).toHaveBeenCalledTimes(1);
  });
});
