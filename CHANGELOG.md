# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Kaseya VSA X (VSA 10) MCP server (read-only), built on `@wyre-ai/node-kaseya-vsax`.
- 28 read-only tools (`readOnlyHint: true`) covering devices, assets, notifications, organizations, sites, groups, custom fields, scopes, automation scripts/tasks/workflows and their executions, patch and endpoint-protection policies, audit logs and environment info. List tools accept `top` (max 100, default 50), `skip`, OData `filter` and `orderby` and return `{items, nextSkip?}`.
- Stdio and HTTP (StreamableHTTP) transports with `AUTH_MODE=gateway|env`. Gateway mode requires `X-Kaseya-VSAX-Server-Url`, `X-Kaseya-VSAX-Token-Id` and `X-Kaseya-VSAX-Token-Secret` on every `/mcp` request (401 if missing, never falls back to `KASEYA_VSAX_*`); the server URL is validated to a single `*.vsax.net` label (400 with a generic message otherwise).
- Fail-closed service-to-service auth: HTTP refuses to start when `CONDUIT_S2S_SECRET` is empty or a known placeholder, unless `MCP_ALLOW_INSECURE_DEV=1` (which forces `127.0.0.1`). `/health` is unauthenticated.
- `READ_ONLY_MODE` (default `true`) and `DESTRUCTIVE_TOOLS_ENABLED` (default `false`) flags plus a small tool registry so Phase 2 write tools can be gated. No write tools are registered in Phase 1.
- Input limits: `Content-Length` above 256 KiB returns a 413 JSON-RPC error before parsing, `maxRequestBodySize` on the transport, `maxToolInputElements` on the server, and per-field string/array caps in every tool schema.
- `vsax_task_executions_get` validates `executionId` (positive whole number) before any request and looks up the execution before its devices. The HTTP 500 VSA X returns for an unknown task execution ID maps to a "No task execution found" error. `vsax_devices_antivirus_get` returns a message when there is no antivirus data.
- SDK errors map to safe tool errors (403 names the endpoint and points to Configuration > API Access; 401; auth circuit open; 429 retry-after). Credentials are never logged or returned.
- Multi-stage `Dockerfile`, `docker-compose.yml` (gateway mode), semantic-release pipeline.
