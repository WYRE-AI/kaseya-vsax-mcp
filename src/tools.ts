/**
 * Phase 1 tool catalogue: read-only Kaseya VSA X tools.
 * Every tool here is `access: "read"`; write tools belong in Phase 2 and must
 * use `write` / `destructive` so the registry gates them.
 */
import { z } from "zod";
import type { AssetSection } from "@wyre-ai/node-kaseya-vsax";
import {
  MAX_FILTER_LENGTH,
  MAX_ID_LENGTH,
  MAX_ORDERBY_LENGTH,
} from "./input-limits.js";
import { ToolInputError, type ToolDef } from "./registry.js";

// ---------------------------------------------------------------------------
// Shared input fragments
// ---------------------------------------------------------------------------

export const DEFAULT_TOP = 50;
export const MAX_TOP = 100;
const MAX_SKIP = 1_000_000;

const id = (what: string) =>
  z.union([z.string().min(1).max(MAX_ID_LENGTH), z.number().int().nonnegative()]).describe(what);
const strId = (what: string) => z.string().min(1).max(MAX_ID_LENGTH).describe(what);

const listShape = {
  top: z.number().int().min(1).max(MAX_TOP).optional().describe(`Page size (default ${DEFAULT_TOP}, max ${MAX_TOP})`),
  skip: z.number().int().min(0).max(MAX_SKIP).optional().describe("Records to skip. For the next page, pass nextSkip from the previous result."),
  filter: z.string().max(MAX_FILTER_LENGTH).optional().describe("OData $filter expression"),
  orderby: z.string().max(MAX_ORDERBY_LENGTH).optional().describe("OData $orderby expression"),
};

const ASSET_SECTIONS = [
  "Tags",
  "Updates",
  "AvailableUpdates",
  "Security",
  "AssetInfo",
  "IpAddresses",
  "LocalIpAddresses",
  "Disks",
  "InstalledSoftware",
  "None",
] as const satisfies readonly AssetSection[];
/** Slim default: the heavy sections (software, updates, security) are opt-in. */
const DEFAULT_ASSET_SECTIONS: AssetSection[] = ["AssetInfo", "IpAddresses"];
/** Undefined or an empty list means the slim default (the SDK sends no include for [], which returns the heavy payload). */
function withDefaultSections(include: AssetSection[] | undefined): AssetSection[] {
  return include && include.length > 0 ? include : DEFAULT_ASSET_SECTIONS;
}
const includeShape = {
  include: z
    .array(z.enum(ASSET_SECTIONS))
    .max(ASSET_SECTIONS.length)
    .optional()
    .describe(`Sections to include (default ${DEFAULT_ASSET_SECTIONS.join(",")}). InstalledSoftware, Updates, AvailableUpdates and Security are large.`),
};

interface ListArgs {
  top?: number;
  skip?: number;
  filter?: string;
  orderby?: string;
}

function listParams(a: ListArgs) {
  return { top: a.top ?? DEFAULT_TOP, skip: a.skip, filter: a.filter, orderby: a.orderby };
}

/**
 * Wrap a page of results. The SDK's list calls return the page only (the
 * server's TotalCount is not surfaced), so totalCount is omitted and nextSkip
 * is present exactly when the page was full.
 */
export function toPage(result: unknown, a: ListArgs): { items: unknown[]; nextSkip?: number } {
  const items = Array.isArray(result) ? result : [];
  const top = a.top ?? DEFAULT_TOP;
  const skip = a.skip ?? 0;
  return items.length >= top ? { items, nextSkip: skip + items.length } : { items };
}

type Args<T> = T & Record<string, unknown>;
const a = <T>(args: Record<string, unknown>) => args as Args<T>;

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export const TOOLS: ToolDef[] = [
  // ----- devices -----
  {
    name: "vsax_devices_list",
    title: "List devices",
    description: "List devices managed in Kaseya VSA X. Read-only. Narrow with filter (OData, e.g. \"Name eq 'APP-01'\"), sort with orderby, or pass scopeId. Use a device's Identifier as deviceId in the other device tools.",
    access: "read",
    inputSchema: { ...listShape, scopeId: z.number().int().nonnegative().optional().describe("Restrict to this scope") },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { scopeId?: number }>(args);
      return toPage(await client.devices.list({ ...listParams(p), scopeId: p.scopeId }), p);
    },
  },
  {
    name: "vsax_devices_get",
    title: "Get device",
    description: "Get one device by its Identifier. Read-only.",
    access: "read",
    inputSchema: { deviceId: strId("Device Identifier (from vsax_devices_list)") },
    handler: ({ client }, args) => client.devices.get(a<{ deviceId: string }>(args).deviceId),
  },
  {
    name: "vsax_devices_notifications_list",
    title: "List device notifications",
    description: "List notifications (alerts) raised for a device. Read-only.",
    access: "read",
    inputSchema: { deviceId: strId("Device Identifier (from vsax_devices_list)"), ...listShape },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { deviceId: string }>(args);
      return toPage(await client.devices.notifications(p.deviceId, listParams(p)), p);
    },
  },
  {
    name: "vsax_devices_antivirus_get",
    title: "Get device antivirus",
    description: "Get antivirus / endpoint-protection status for a device. Read-only.",
    access: "read",
    inputSchema: { deviceId: strId("Device Identifier (from vsax_devices_list)") },
    handler: async ({ client }, args) => {
      const data = await client.devices.antivirus(a<{ deviceId: string }>(args).deviceId);
      return data ?? { message: "No antivirus data for this device." };
    },
  },
  {
    name: "vsax_devices_custom_fields_list",
    title: "List device custom fields",
    description: "List the custom field values set on one device. Read-only. For field definitions, use vsax_custom_fields_list.",
    access: "read",
    inputSchema: { deviceId: strId("Device Identifier (from vsax_devices_list)") },
    handler: async ({ client }, args) => ({
      items: await client.devices.customFields(a<{ deviceId: string }>(args).deviceId),
    }),
  },
  {
    name: "vsax_devices_applied_policies_list",
    title: "List device applied policies",
    description: "List policies applied to a device. Read-only.",
    access: "read",
    inputSchema: { deviceId: strId("Device Identifier (from vsax_devices_list)") },
    handler: async ({ client }, args) => ({
      items: await client.devices.appliedPolicies(a<{ deviceId: string }>(args).deviceId),
    }),
  },

  // ----- assets -----
  {
    name: "vsax_assets_list",
    title: "List assets",
    description: "List device assets (hardware/OS/network inventory). Read-only. Returns AssetInfo and IpAddresses unless you set include (an empty include also gives that default). Add InstalledSoftware, Updates, AvailableUpdates or Security only when needed, since they're large.",
    access: "read",
    inputSchema: { ...listShape, ...includeShape },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { include?: AssetSection[] }>(args);
      return toPage(await client.assets.list({ ...listParams(p), include: withDefaultSections(p.include) }), p);
    },
  },
  {
    name: "vsax_assets_get",
    title: "Get asset",
    description: "Get the asset record for a device. Read-only. Returns AssetInfo and IpAddresses unless you set include (an empty include also gives that default). Add InstalledSoftware, Updates, AvailableUpdates or Security only when needed, since they're large.",
    access: "read",
    inputSchema: { deviceId: strId("Device Identifier (from vsax_devices_list)"), ...includeShape },
    handler: ({ client }, args) => {
      const p = a<{ deviceId: string; include?: AssetSection[] }>(args);
      return client.assets.get(p.deviceId, withDefaultSections(p.include));
    },
  },

  // ----- notifications -----
  {
    name: "vsax_notifications_list",
    title: "List notifications",
    description: "List notifications (alerts) across the tenant. Read-only.",
    access: "read",
    inputSchema: listShape,
    handler: async ({ client }, args) => toPage(await client.notifications.list(listParams(a<ListArgs>(args))), a<ListArgs>(args)),
  },
  {
    name: "vsax_notifications_get",
    title: "Get notification",
    description: "Get one notification by ID. Read-only.",
    access: "read",
    inputSchema: { notificationId: id("Notification ID") },
    handler: ({ client }, args) => client.notifications.get(a<{ notificationId: string | number }>(args).notificationId),
  },

  // ----- organizations / sites / groups -----
  {
    name: "vsax_organizations_list",
    title: "List organizations",
    description: "List organizations, the top level above sites and groups. Read-only.",
    access: "read",
    inputSchema: listShape,
    handler: async ({ client }, args) => toPage(await client.organizations.list(listParams(a<ListArgs>(args))), a<ListArgs>(args)),
  },
  {
    name: "vsax_organizations_get",
    title: "Get organization",
    description: "Get one organization by ID. Read-only.",
    access: "read",
    inputSchema: { organizationId: id("Organization ID") },
    handler: ({ client }, args) => client.organizations.get(a<{ organizationId: string | number }>(args).organizationId),
  },
  {
    name: "vsax_sites_list",
    title: "List sites",
    description: "List sites. Each site belongs to an organization. Read-only.",
    access: "read",
    inputSchema: listShape,
    handler: async ({ client }, args) => toPage(await client.sites.list(listParams(a<ListArgs>(args))), a<ListArgs>(args)),
  },
  {
    name: "vsax_sites_get",
    title: "Get site",
    description: "Get one site by ID. Read-only.",
    access: "read",
    inputSchema: { siteId: id("Site ID") },
    handler: ({ client }, args) => client.sites.get(a<{ siteId: string | number }>(args).siteId),
  },
  {
    name: "vsax_groups_list",
    title: "List groups",
    description: "List device groups. Each group belongs to a site, and devices belong to a group. Read-only.",
    access: "read",
    inputSchema: listShape,
    handler: async ({ client }, args) => toPage(await client.groups.list(listParams(a<ListArgs>(args))), a<ListArgs>(args)),
  },
  {
    name: "vsax_groups_get",
    title: "Get group",
    description: "Get one group by ID. Read-only.",
    access: "read",
    inputSchema: { groupId: id("Group ID") },
    handler: ({ client }, args) => client.groups.get(a<{ groupId: string | number }>(args).groupId),
  },

  // ----- custom fields / scopes -----
  {
    name: "vsax_custom_fields_list",
    title: "List custom fields",
    description:
      "List custom field definitions. With entityType + entityId, list the custom field values assigned to that organization, site, group or device instead. top, skip, filter and orderby apply only when listing definitions. Read-only.",
    access: "read",
    inputSchema: {
      ...listShape,
      entityType: z.enum(["organization", "site", "group", "device"]).optional().describe("Read this entity's custom fields"),
      entityId: id("Entity ID (required with entityType)").optional(),
    },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { entityType?: "organization" | "site" | "group" | "device"; entityId?: string | number }>(args);
      if (!p.entityType) {
        if (p.entityId !== undefined) throw new ToolInputError("entityId needs entityType too. Set entityType to organization, site, group or device, or leave out entityId to list the field definitions.");
        return toPage(await client.customFields.list(listParams(p)), p);
      }
      if (p.entityId === undefined) throw new ToolInputError("entityType needs entityId too. Pass the ID of that organization, site, group or device.");
      switch (p.entityType) {
        case "organization":
          return { items: await client.organizations.customFields(p.entityId) };
        case "site":
          return { items: await client.sites.customFields(p.entityId) };
        case "group":
          return { items: await client.groups.customFields(p.entityId) };
        case "device":
          return { items: await client.devices.customFields(String(p.entityId)) };
      }
    },
  },
  {
    name: "vsax_scopes_list",
    title: "List scopes",
    description: "List scopes. Pass a scope's ID as scopeId to vsax_devices_list to see only its devices. Read-only.",
    access: "read",
    inputSchema: listShape,
    handler: async ({ client }, args) => toPage(await client.scopes.list(listParams(a<ListArgs>(args))), a<ListArgs>(args)),
  },

  // ----- automation -----
  {
    name: "vsax_scripts_list",
    title: "List or get scripts",
    description: "List automation scripts, or pass scriptId to get one script; paging and filters are then ignored. Read-only.",
    access: "read",
    inputSchema: { ...listShape, scriptId: strId("Return this script only").optional() },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { scriptId?: string }>(args);
      if (p.scriptId) return client.automation.scripts.get(p.scriptId);
      return toPage(await client.automation.scripts.list(listParams(p)), p);
    },
  },
  {
    name: "vsax_script_executions_list",
    title: "List or get script executions",
    description: "List executions of a script on a device, or pass executionId to get one execution; paging and filters are then ignored. Read-only.",
    access: "read",
    inputSchema: {
      ...listShape,
      scriptId: strId("Script ID"),
      deviceId: strId("Device Identifier (from vsax_devices_list)"),
      executionId: id("Return this execution only").optional(),
    },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { scriptId: string; deviceId: string; executionId?: string | number }>(args);
      if (p.executionId !== undefined) {
        return client.automation.scripts.executions.get(p.scriptId, p.deviceId, p.executionId);
      }
      return toPage(await client.automation.scripts.executions.list(p.scriptId, p.deviceId, listParams(p)), p);
    },
  },
  {
    name: "vsax_tasks_list",
    title: "List or get tasks",
    description: "List automation tasks, or pass taskId to get one task; paging and filters are then ignored. Read-only.",
    access: "read",
    inputSchema: { ...listShape, taskId: id("Return this task only").optional() },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { taskId?: string | number }>(args);
      if (p.taskId !== undefined) return client.automation.tasks.get(p.taskId);
      return toPage(await client.automation.tasks.list(listParams(p)), p);
    },
  },
  {
    name: "vsax_task_executions_get",
    title: "Get task execution",
    description:
      "Get a task execution and its devices. The executionId is the Id returned when a task is run, also shown in the task's Execution History in VSA X. Without deviceId, returns the first 50 devices only. With deviceId, list the scripts that ran on that device; with deviceId + scriptId, get the script output. Read-only.",
    access: "read",
    inputSchema: {
      // Looser than id(): the handler validates, so every bad value gets the same fix-it message.
      executionId: z.union([z.string().min(1).max(MAX_ID_LENGTH), z.number()]).describe("Task execution ID (the Id returned when a task is run)"),
      deviceId: strId("Device Identifier (from vsax_devices_list)").optional(),
      scriptId: strId("Script ID (requires deviceId)").optional(),
    },
    handler: async ({ client }, args) => {
      const p = a<{ executionId: string | number; deviceId?: string; scriptId?: string }>(args);
      const tasks = client.automation.tasks;
      const validId =
        typeof p.executionId === "number"
          ? Number.isSafeInteger(p.executionId) && p.executionId > 0
          : /^[1-9][0-9]{0,17}$/.test(p.executionId);
      if (!validId) throw new ToolInputError("executionId must be a task execution ID, a whole number like 1234. Run a task to get one, or copy it from the task's Execution History in VSA X.");
      if (p.scriptId && !p.deviceId) throw new ToolInputError("scriptId needs deviceId too. Pass the device's Identifier, which you can get by calling this tool with deviceId only to list its scripts.");
      if (p.deviceId && p.scriptId) return tasks.scriptOutput(p.executionId, p.deviceId, p.scriptId);
      if (p.deviceId) return { items: await tasks.executionDeviceScripts(p.executionId, p.deviceId) };
      const execution = await tasks.getExecution(p.executionId);
      const devices = await tasks.executionDevices(p.executionId, { top: DEFAULT_TOP });
      return { execution, devices };
    },
  },
  {
    name: "vsax_workflows_list",
    title: "List or get workflows",
    description: "List automation workflows, or pass workflowId to get one workflow; paging and filters are then ignored. Read-only.",
    access: "read",
    inputSchema: { ...listShape, workflowId: id("Return this workflow only").optional() },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { workflowId?: string | number }>(args);
      if (p.workflowId !== undefined) return client.automation.workflows.get(p.workflowId);
      return toPage(await client.automation.workflows.list(listParams(p)), p);
    },
  },
  {
    name: "vsax_workflow_executions_list",
    title: "List or get workflow executions",
    description: "List workflow executions, or pass executionId to get one execution; paging and filters are then ignored. Read-only.",
    access: "read",
    inputSchema: { ...listShape, executionId: id("Return this execution only").optional() },
    handler: async ({ client }, args) => {
      const p = a<ListArgs & { executionId?: string | number }>(args);
      if (p.executionId !== undefined) return client.automation.workflows.executions.get(p.executionId);
      return toPage(await client.automation.workflows.executions.list(listParams(p)), p);
    },
  },

  // ----- policies / audit / environment -----
  {
    name: "vsax_patch_policies_get",
    title: "Get patch policy",
    description: "Get a patch management policy by policyId, or the global patch rules when policyId is omitted or globalRules is true. If both are given, globalRules wins. Read-only.",
    access: "read",
    inputSchema: {
      policyId: id("Patch policy ID").optional(),
      globalRules: z.boolean().optional().describe("Return the global patch rules"),
    },
    handler: ({ client }, args) => {
      const p = a<{ policyId?: string | number; globalRules?: boolean }>(args);
      if (p.globalRules || p.policyId === undefined) return client.patchManagement.getGlobalRules();
      return client.patchManagement.getPolicy(p.policyId);
    },
  },
  {
    name: "vsax_endpoint_protection_policies_get",
    title: "Get endpoint protection policy",
    description: "Get an endpoint protection policy by ID. Read-only.",
    access: "read",
    inputSchema: { policyId: id("Endpoint protection policy ID") },
    handler: ({ client }, args) => client.endpointProtection.getPolicy(a<{ policyId: string | number }>(args).policyId),
  },
  {
    name: "vsax_audit_logs_list",
    title: "List audit logs",
    description: "List audit log entries. Read-only.",
    access: "read",
    inputSchema: listShape,
    handler: async ({ client }, args) => toPage(await client.auditLogs.list(listParams(a<ListArgs>(args))), a<ListArgs>(args)),
  },
  {
    name: "vsax_environment_get",
    title: "Get environment",
    description: "Get Kaseya VSA X environment details: product version, customer name and ID, SaaS or on-prem, language and license. Read-only.",
    access: "read",
    inputSchema: {},
    handler: ({ client }) => client.environment.get(),
  },
];
