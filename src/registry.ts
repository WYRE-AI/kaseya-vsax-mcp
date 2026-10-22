/**
 * Tiny tool registry helper. Every tool declares an access class; the
 * registry decides from the flags whether it is exposed at all, so Phase 2
 * write tools only need `access: "write" | "destructive"` to be gated.
 */
import type { ZodRawShape } from "zod";
import type { KaseyaVsaxClient } from "@wyre-ai/node-kaseya-vsax";
import type { ToolFlags } from "./config.js";

export type ToolAccess = "read" | "write" | "destructive";

export interface ToolContext {
  client: KaseyaVsaxClient;
}

export interface ToolDef {
  name: string;
  title: string;
  description: string;
  access: ToolAccess;
  inputSchema: ZodRawShape;
  handler: (ctx: ToolContext, args: Record<string, unknown>) => Promise<unknown>;
}

/** read: always. write: only when READ_ONLY_MODE=false. destructive: also needs DESTRUCTIVE_TOOLS_ENABLED=true. */
export function isToolEnabled(access: ToolAccess, flags: ToolFlags): boolean {
  if (access === "read") return true;
  if (flags.readOnlyMode) return false;
  return access === "write" || flags.destructiveToolsEnabled;
}

export function enabledTools(tools: readonly ToolDef[], flags: ToolFlags): ToolDef[] {
  return tools.filter((t) => isToolEnabled(t.access, flags));
}

export function annotationsFor(access: ToolAccess) {
  return {
    readOnlyHint: access === "read",
    destructiveHint: access === "destructive",
    idempotentHint: access === "read",
    openWorldHint: true,
  };
}

/** Thrown by handlers for caller mistakes that zod cannot express; message is safe to return. */
export class ToolInputError extends Error {}
