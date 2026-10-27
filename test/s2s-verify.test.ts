import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { verifyS2sHeader } from "../src/s2s-verify.js";

const mint = (secret: string, t: number) => `t=${t},v1=${createHmac("sha256", secret).update(`t=${t}`).digest("hex")}`;
const now = () => Math.floor(Date.now() / 1000);

describe("verifyS2sHeader", () => {
  it("accepts a valid header and rejects wrong secret, stale, malformed and empty", () => {
    expect(verifyS2sHeader(mint("a-secret", now()), "a-secret")).toBe(true);
    expect(verifyS2sHeader(mint("other", now()), "a-secret")).toBe(false);
    expect(verifyS2sHeader(mint("a-secret", now() - 301), "a-secret")).toBe(false);
    expect(verifyS2sHeader("garbage", "a-secret")).toBe(false);
    expect(verifyS2sHeader(undefined, "a-secret")).toBe(false);
    expect(verifyS2sHeader(mint("", now()), "")).toBe(false);
  });
});
