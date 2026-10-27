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

function sentence(text: string): string {
  return text.trim().replace(/[.\s]+$/, "");
}

export function toSafeErrorMessage(err: unknown, secrets: readonly string[] = []): string {
  const scrub = (s: string) => scrubSecrets(s, secrets);
  if (err instanceof ToolInputError) return scrub(err.message);
  if (err instanceof KaseyaVsaxAuthCircuitOpenError) {
    const minutes = Math.max(1, Math.ceil(err.retryAfterMs / 60_000));
    return `Kaseya VSA X rejected the API token twice in a row, so requests are paused for ${minutes} ${minutes === 1 ? "minute" : "minutes"} to avoid getting this server's IP blocked. Check the Token ID and Token Secret, then try again.`;
  }
  if (err instanceof KaseyaVsaxForbiddenError) {
    return `The Kaseya VSA X API token isn't allowed to call ${safePath(err.path)}. In VSA X, open Configuration > API Access > Third-Party Tokens, edit the token, and on the Authorization tab grant that permission. If the token is limited to certain organizations, add the organization too.`;
  }
  if (err instanceof KaseyaVsaxAuthenticationError) {
    return "Kaseya VSA X didn't accept the API token. It may be wrong, expired or revoked. Check the Token ID and Token Secret, or create a new token under Configuration > API Access > Third-Party Tokens.";
  }
  if (err instanceof KaseyaVsaxRateLimitError) {
    return err.retryAfterSeconds !== undefined
      ? `Kaseya VSA X rate limit reached. Wait ${Math.ceil(err.retryAfterSeconds)} seconds, then try again.`
      : "Kaseya VSA X rate limit reached. Wait a minute, then try again.";
  }
  if (err instanceof KaseyaVsaxNotFoundError) {
    return `Kaseya VSA X has nothing at ${safePath(err.path)}. Check the ID, for example with the matching list tool.`;
  }
  if (err instanceof KaseyaVsaxConfigError) {
    return scrub(
      `Kaseya VSA X connection settings aren't valid: ${sentence(err.message)}. Set the server URL to your tenant host, like acme.vsax.net, and copy the Token ID and Token Secret again from Configuration > API Access > Third-Party Tokens.`
    );
  }
  if (err instanceof KaseyaVsaxTimeoutError) {
    return "The Kaseya VSA X request timed out. Try again, or narrow it with filter or a smaller top.";
  }
  if (err instanceof KaseyaVsaxError) {
    switch (err.code) {
      case "INVALID_PATH_PARAM": {
        const name = /^Invalid path parameter "([A-Za-z0-9_]{1,64})"/.exec(err.message)?.[1];
        return name
          ? `The ${name} value isn't valid (empty, ".", or contains "/"). Check the ID values.`
          : `One of the IDs isn't valid (empty, ".", or contains "/").`;
      }
      case "VALIDATION_ERROR":
        return err.detail
          ? scrub(`Kaseya VSA X rejected the request: ${sentence(err.detail)}. Check the filter, orderby and ID values.`)
          : "Kaseya VSA X rejected the request. Check the filter, orderby and ID values.";
      case "SERVER_ERROR": {
        // VSA X answers an unknown task execution ID with HTTP 500 rather than 404.
        const path = (err.path ?? "").split("?")[0];
        if (/^\/automation\/tasks\/executions\/[^/]+(\/devices)?$/.test(path)) {
          return "No task execution found with that ID. Use an execution ID from a task run, then try again.";
        }
        if (/^\/automation\/tasks\/executions\/[^/]+\/devices\/[^/]+\/scripts(\/[^/]+)?$/.test(path)) {
          return "No task execution found for that execution ID and device. Use an execution ID from a task run and a device `Identifier` from that run, then try again.";
        }
        return "Kaseya VSA X had a server error. Try again in a minute.";
      }
      case "NETWORK_ERROR":
        return "Couldn't reach Kaseya VSA X. Check the server URL and this server's network access, and the token's IP allowlist if it has one.";
      case "REDIRECT_REFUSED":
        return "Kaseya VSA X redirected the request, and this server doesn't follow redirects. Check that the server URL is your tenant host, like acme.vsax.net.";
      case "PAGINATION_ERROR":
        return "Kaseya VSA X returned paging data that couldn't be used. Try again with a smaller top or a narrower filter.";
      default:
        return "The Kaseya VSA X request failed. Try again; if it keeps failing, check the connection settings.";
    }
  }
  // Unexpected (non-SDK) error: log the class name only, never the message.
  console.error("Unexpected tool error:", err instanceof Error ? err.name : "unknown");
  return "Unexpected error while calling Kaseya VSA X. Try again; if it keeps failing, check the server logs.";
}
