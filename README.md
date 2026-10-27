# Kaseya VSA X MCP Server

[![Release](https://github.com/WYRE-AI/kaseya-vsax-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/WYRE-AI/kaseya-vsax-mcp/actions/workflows/release.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Model Context Protocol (MCP) server for **Kaseya VSA X (VSA 10)**, built on
[`@wyre-ai/node-kaseya-vsax`](https://github.com/WYRE-AI/node-kaseya-vsax).
Exposes devices, assets, notifications, organizations, sites, groups, custom
fields, automation (scripts, tasks, workflows), patch and endpoint-protection
policies, and audit logs to AI assistants.

**Phase 1 is read-only.** Every tool carries `readOnlyHint: true`; no write
tool is registered.

### VSA 9 vs VSA X

VSA X (VSA 10) is a different product with a different API from classic VSA 9.
This server targets VSA X: REST API v3 at `https://<tenant>.vsax.net/api/v3`,
authenticated with an API **Token ID + Token Secret** (HTTP Basic). For classic
VSA 9 (on-prem tenant URL, `/api/v1.0`, username/password or Kaseya One) use
[`kaseya-vsa-mcp`](https://github.com/WYRE-AI/kaseya-vsa-mcp) instead. The two
use different credentials, tool names (`vsax_*` vs `kaseya_vsa_*`) and env vars.

## Tools

List tools take `top` (1-100, default 50), `skip`, `filter` (OData `$filter`)
and `orderby`, and return `{ items, nextSkip? }` (`nextSkip` is present when a
full page came back; the API's total count is not exposed by the SDK).

| Tool | Description |
|------|-------------|
| `vsax_devices_list` | List devices (optional `scopeId`). |
| `vsax_devices_get` | Get a device by ID. |
| `vsax_devices_notifications_list` | Notifications raised for a device. |
| `vsax_devices_antivirus_get` | Antivirus status for a device; returns `{ "message": "No antivirus data for this device." }` when VSA X has none. |
| `vsax_devices_custom_fields_list` | Custom field values on a device. |
| `vsax_devices_applied_policies_list` | Policies applied to a device. |
| `vsax_assets_list` | Asset inventory. `include` picks sections; default is slim (`AssetInfo`, `IpAddresses`), and an empty `include` also gives the slim default. |
| `vsax_assets_get` | Asset for one device (same `include` rules). |
| `vsax_notifications_list` / `vsax_notifications_get` | Tenant notifications / one notification. |
| `vsax_organizations_list` / `vsax_organizations_get` | Organizations. |
| `vsax_sites_list` / `vsax_sites_get` | Sites. |
| `vsax_groups_list` / `vsax_groups_get` | Device groups. |
| `vsax_custom_fields_list` | Custom field definitions; with `entityType` (`organization`, `site`, `group`, `device`) + `entityId`, that entity's custom field values. |
| `vsax_scopes_list` | Scopes. |
| `vsax_scripts_list` | Automation scripts; `scriptId` returns one. |
| `vsax_script_executions_list` | Executions of `scriptId` on `deviceId`; `executionId` returns one. |
| `vsax_tasks_list` | Automation tasks; `taskId` returns one. |
| `vsax_task_executions_get` | A task execution and its devices; `deviceId` lists its scripts; `deviceId` + `scriptId` returns script output. `executionId` is the Id returned when a task is run (also in the task's Execution History in VSA X) and must be a positive whole number. |
| `vsax_workflows_list` | Workflows; `workflowId` returns one. |
| `vsax_workflow_executions_list` | Workflow executions; `executionId` returns one. |
| `vsax_patch_policies_get` | A patch policy by `policyId`; global patch rules when omitted or `globalRules: true`. |
| `vsax_endpoint_protection_policies_get` | An endpoint protection policy. |
| `vsax_audit_logs_list` | Audit log entries. |
| `vsax_environment_get` | VSA X environment information. |

Group install-package downloads, webhooks and rate-limit endpoints are
deliberately not exposed.

VSA X rate limits (requests per hour and failed requests per minute) vary by tenant; when one is reached, the tool error says how long to wait.

## Configuration

Copy [`.env.example`](.env.example) and set the variables below.

| Variable | Required | Description |
|----------|----------|-------------|
| `KASEYA_VSAX_SERVER_URL` | For stdio and `AUTH_MODE=env` | Tenant host or URL, e.g. `acme.vsax.net`. Must be a single DNS label under `.vsax.net`. The Compose gateway service does not load this. |
| `KASEYA_VSAX_TOKEN_ID` | For stdio and `AUTH_MODE=env` | API Token ID. |
| `KASEYA_VSAX_TOKEN_SECRET` | For stdio and `AUTH_MODE=env` | API Token Secret (secret). |
| `READ_ONLY_MODE` | No | Default `true`. Only read tools are exposed. Phase 2 write tools will register only when this is `false`. |
| `DESTRUCTIVE_TOOLS_ENABLED` | No | Default `false`. Destructive tools additionally need this `true` **and** `READ_ONLY_MODE=false`. No effect in Phase 1. |
| `MCP_TRANSPORT` | No | `stdio` (default) or `http` |
| `AUTH_MODE` | No | `gateway` (Docker image and Compose default) or `env` (code default when unset). Gateway mode requires the `X-Kaseya-VSAX-*` headers on each `/mcp` request and never falls back to `KASEYA_VSAX_*`. `env` uses those variables only after S2S auth succeeds. |
| `CONDUIT_S2S_SECRET` | Yes for HTTP | Service-to-service secret. Generate with `openssl rand -hex 32`. The HTTP server logs an error and exits non-zero when this is empty or a known placeholder (`changeme`, `your-s2s-secret`, `secret`, `placeholder`, an unresolved `${...}` value, and similar). Compose will not start without it. Never commit a real value. The value is never logged. |
| `MCP_ALLOW_INSECURE_DEV` | No | Set to exactly `1` only for local development to start HTTP without `CONDUIT_S2S_SECRET`. Logs a warning, does not enforce `X-Gateway-S2S`, and forces the listener onto `127.0.0.1`. A known placeholder secret is still refused. |
| `MCP_HTTP_HOST` | No | Bind address when `MCP_TRANSPORT=http`. Defaults to `127.0.0.1`. A non-loopback host is only honored with a real `CONDUIT_S2S_SECRET`. The container image sets `0.0.0.0`. |
| `MCP_HTTP_PORT` | No | HTTP port. Defaults to `8080`. |

`/health` stays unauthenticated and does not read credentials. The stdio transport does not use `CONDUIT_S2S_SECRET`.

### Creating the API token

In VSA X go to **Configuration > API Access > Third-Party Tokens** and create a
token. Because this server only reads, grant the token **read-only
permissions** on the endpoints you want the assistant to use (devices, assets,
notifications, organizations/sites/groups, custom fields, scopes, automation,
patch management, endpoint protection, audit logs, environment) and nothing
else. If a tool reports *The Kaseya VSA X API token isn't allowed to call `<endpoint>`*,
open **Configuration > API Access > Third-Party Tokens**, edit the token, and on
the **Authorization** tab grant that permission (and add the organization if the
token is limited to certain organizations).

If your tenant restricts API access by source address, add the IP address(es)
of the host (or gateway egress) running this server to the token's **IP
allowlist**, otherwise requests are rejected. Two 401 responses in a row open
the SDK's auth circuit breaker and pause requests for 5 minutes (403 permission
errors do not). The pause is kept in memory per tenant host and Token ID, so in
gateway mode it also holds across requests. Fix the token, then try again.

## HTTP authentication

With `MCP_TRANSPORT=http` and `CONDUIT_S2S_SECRET` set, every `/mcp` request must include `X-Gateway-S2S`. The check is `verifyS2sHeader` in [`src/s2s-verify.ts`](src/s2s-verify.ts): the header value is `t=<unix seconds>,v1=<hex>`, where the hex is HMAC-SHA256 of the literal string `t=<unix seconds>` keyed with `CONDUIT_S2S_SECRET`. The timestamp must be within 300 seconds of the server clock. A missing or invalid header returns HTTP 401 before vendor credentials are read.

### Gateway headers

In `AUTH_MODE=gateway`, `/mcp` also requires:

| Header | Value |
|--------|-------|
| `X-Kaseya-VSAX-Server-Url` | Tenant host/URL, `<tenant>.vsax.net` only |
| `X-Kaseya-VSAX-Token-Id` | API Token ID |
| `X-Kaseya-VSAX-Token-Secret` | API Token Secret |

Those headers are the only credential source for that request. Missing headers return 401 and never fall back to `KASEYA_VSAX_*` in the process environment. A server URL that is not a single `*.vsax.net` label returns 400 with a generic message (the value is not echoed). Each accepted request creates a fresh, stateless server instance with isolated credentials.

## Security

- **Read-only by default**: only `readOnlyHint` tools are registered; write tools (Phase 2) are gated by `READ_ONLY_MODE` / `DESTRUCTIVE_TOOLS_ENABLED`.
- **Fail-closed S2S** on HTTP; `/health` is the only unauthenticated route.
- **SSRF / credential-exfiltration guard**: the SDK only sends credentials to `<one-label>.vsax.net` over HTTPS.
- **Secrets are never logged or returned.** SDK errors are mapped to fixed, safe messages (403 names the endpoint and points to Configuration > API Access > Third-Party Tokens; 401 "didn't accept the API token"; circuit open "rejected the API token twice in a row, so requests are paused for N minutes"; 429 says how long to wait; the HTTP 500 VSA X returns for an unknown task execution ID becomes "No task execution found"). Unknown errors are not passed through.
- **Input limits**: request bodies over 256 KiB get a 413 JSON-RPC error before parsing and the transport enforces the same `maxRequestBodySize`; tool inputs are limited to 10,000 elements; every tool schema caps string lengths (IDs 128, filter 1000, orderby 200), `top` (100) and array sizes. Tool results are truncated at 200,000 characters.

## Local development

```bash
npm install
npm run build
KASEYA_VSAX_SERVER_URL=acme.vsax.net \
  KASEYA_VSAX_TOKEN_ID=... \
  KASEYA_VSAX_TOKEN_SECRET=... \
  npm start
```

HTTP refuses to start until `CONDUIT_S2S_SECRET` is set:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" MCP_TRANSPORT=http npm start
curl http://127.0.0.1:8080/health
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` only and logs a warning:

```bash
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm start
```

Scripts: `npm run typecheck`, `npm run lint`, `npm test`, `npm run build`.

## Docker

The image listens on `0.0.0.0` inside the container and defaults to `AUTH_MODE=gateway`. Publish the port on loopback and pass the S2S secret. In gateway mode, VSA X credentials arrive on each request as headers; they are not read from the environment.

```bash
docker build -t kaseya-vsax-mcp .
docker run --rm \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -p 127.0.0.1:8080:8080 \
  kaseya-vsax-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset, sets `AUTH_MODE=gateway`, does not inject static `KASEYA_VSAX_*` credentials, and publishes `127.0.0.1:8080:8080`:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `KASEYA_VSAX_*`:

```bash
docker run --rm \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e AUTH_MODE=env \
  -e KASEYA_VSAX_SERVER_URL=acme.vsax.net \
  -e KASEYA_VSAX_TOKEN_ID=... \
  -e KASEYA_VSAX_TOKEN_SECRET=... \
  -p 127.0.0.1:8080:8080 \
  kaseya-vsax-mcp
```

## License

Apache-2.0
