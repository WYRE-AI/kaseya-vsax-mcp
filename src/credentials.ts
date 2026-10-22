import { KaseyaVsaxClient, normalizeServerUrl } from "@wyre-ai/node-kaseya-vsax";
import { cleanCredential } from "./config.js";

export interface VsaxCredentials {
  serverUrl: string;
  tokenId: string;
  tokenSecret: string;
}

/** Env-mode / stdio credentials. Null when any of the three is absent. */
export function getCredentials(env: NodeJS.ProcessEnv = process.env): VsaxCredentials | null {
  const serverUrl = cleanCredential(env.KASEYA_VSAX_SERVER_URL);
  const tokenId = cleanCredential(env.KASEYA_VSAX_TOKEN_ID);
  const tokenSecret = cleanCredential(env.KASEYA_VSAX_TOKEN_SECRET);
  if (!serverUrl || !tokenId || !tokenSecret) return null;
  return { serverUrl, tokenId, tokenSecret };
}

export function createClient(creds: VsaxCredentials): KaseyaVsaxClient {
  return new KaseyaVsaxClient({
    serverUrl: creds.serverUrl,
    tokenId: creds.tokenId,
    tokenSecret: creds.tokenSecret,
  });
}

export type GatewayCredentialResult =
  | { ok: true; creds: VsaxCredentials }
  | { ok: false; status: 400 | 401; error: string; message: string };

export const GATEWAY_HEADERS = {
  serverUrl: "x-kaseya-vsax-server-url",
  tokenId: "x-kaseya-vsax-token-id",
  tokenSecret: "x-kaseya-vsax-token-secret",
} as const;

function first(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  return typeof raw === "string" ? cleanCredential(raw) : undefined;
}

/**
 * Per-request gateway credentials. Never reads process.env. Error messages
 * name headers but never echo a supplied value.
 */
export function parseGatewayCredentials(
  headers: Record<string, string | string[] | undefined>
): GatewayCredentialResult {
  const serverUrl = first(headers[GATEWAY_HEADERS.serverUrl]);
  const tokenId = first(headers[GATEWAY_HEADERS.tokenId]);
  const tokenSecret = first(headers[GATEWAY_HEADERS.tokenSecret]);
  if (!serverUrl || !tokenId || !tokenSecret) {
    return {
      ok: false,
      status: 401,
      error: "Missing credentials",
      message:
        "Gateway mode requires X-Kaseya-VSAX-Server-Url, X-Kaseya-VSAX-Token-Id and X-Kaseya-VSAX-Token-Secret headers.",
    };
  }
  try {
    normalizeServerUrl(serverUrl);
  } catch {
    return {
      ok: false,
      status: 400,
      error: "Invalid server URL",
      message: "X-Kaseya-VSAX-Server-Url must be a https://<tenant>.vsax.net host.",
    };
  }
  const creds = { serverUrl, tokenId, tokenSecret };
  try {
    createClient(creds); // rejects malformed token values (e.g. ':' in the id, CR/LF)
  } catch {
    return {
      ok: false,
      status: 400,
      error: "Invalid credentials",
      message: "The Kaseya VSA X credential headers are malformed.",
    };
  }
  return { ok: true, creds };
}
