/**
 * Runtime feature flags and credential normalisation.
 *
 * Phase 1 registers read tools only. READ_ONLY_MODE and
 * DESTRUCTIVE_TOOLS_ENABLED are the gates Phase 2 write tools register
 * behind (see registry.ts).
 */

// An unresolved MCPB/DXT manifest placeholder, e.g. "${user_config.token_id}".
export const CONFIG_PLACEHOLDER = /^\$\{.*\}$/;

/** Trim a credential; empty, whitespace-only and `${...}` placeholders are "absent". */
export function cleanCredential(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed || CONFIG_PLACEHOLDER.test(trimmed)) return undefined;
  return trimmed;
}

export interface ToolFlags {
  /** When true (default) only read tools are exposed. */
  readOnlyMode: boolean;
  /** Extra opt-in (default false) required for destructive (delete-class) tools. */
  destructiveToolsEnabled: boolean;
}

function parseBool(raw: string | undefined, fallback: boolean): boolean {
  const v = raw?.trim().toLowerCase();
  if (!v) return fallback;
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  return fallback;
}

/** Unparseable values fall back to the safe default (read-only, destructive off). */
export function loadToolFlags(env: NodeJS.ProcessEnv = process.env): ToolFlags {
  return {
    readOnlyMode: parseBool(env.READ_ONLY_MODE, true),
    destructiveToolsEnabled: parseBool(env.DESTRUCTIVE_TOOLS_ENABLED, false),
  };
}
