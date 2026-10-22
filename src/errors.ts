/**
 * Map SDK errors to safe tool-error text. Unknown errors are never passed
 * through verbatim, and any credential value is scrubbed from what is returned.
 */
import {
  KaseyaVsaxAuthCircuitOpenError,
  KaseyaVsaxAuthenticationError,
  KaseyaVsaxConfigError,
  KaseyaVsaxError,
  KaseyaVsaxForbiddenError,
  KaseyaVsaxNotFoundError,
  KaseyaVsaxRateLimitError,
  KaseyaVsaxTimeoutError,
  scrubSecrets,
} from "@wyre-ai/node-kaseya-vsax";
import { ToolInputError } from "./registry.js";

function safePath(path: string | undefined): string {
  return path ? path.replace(/[^A-Za-z0-9/_.%-]/g, "").slice(0, 200) || "this endpoint" : "this endpoint";
}

export function toSafeErrorMessage(err: unknown, secrets: readonly string[] = []): string {
  const scrub = (s: string) => scrubSecrets(s, secrets);
  if (err instanceof ToolInputError) return scrub(err.message);
  if (err instanceof KaseyaVsaxAuthCircuitOpenError) {
    return "VSA X authentication repeatedly failed; reconnect with a valid API token.";
  }
  if (err instanceof KaseyaVsaxForbiddenError) {
    return `the VSA X API token lacks permission for ${safePath(err.path)}; grant it under Configuration > API Access`;
  }
  if (err instanceof KaseyaVsaxAuthenticationError) {
    return "the VSA X API token is invalid or expired (401); check the Token ID and Secret.";
  }
  if (err instanceof KaseyaVsaxRateLimitError) {
    return err.retryAfterSeconds !== undefined
      ? `VSA X rate limit reached; retry after ${Math.ceil(err.retryAfterSeconds)} s`
      : "VSA X rate limit reached; retry later";
  }
  if (err instanceof KaseyaVsaxNotFoundError) return `not found: ${safePath(err.path)}`;
  if (err instanceof KaseyaVsaxConfigError) return "invalid VSA X connection settings (server URL or token)";
  if (err instanceof KaseyaVsaxTimeoutError) return "the VSA X request timed out";
  if (err instanceof KaseyaVsaxError) {
    const status = err.status ? ` (HTTP ${err.status})` : "";
    switch (err.code) {
      case "VALIDATION_ERROR":
      case "INVALID_PATH_PARAM":
        return scrub(`the VSA X request was rejected${status}: ${err.message}`);
      case "SERVER_ERROR":
        return `the VSA X server returned an error${status}`;
      case "NETWORK_ERROR":
        return "could not reach the VSA X server";
      default:
        return `VSA X request failed${status} [${err.code}]`;
    }
  }
  return "unexpected error while calling VSA X";
}
