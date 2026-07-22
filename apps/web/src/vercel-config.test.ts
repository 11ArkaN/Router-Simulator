// Vercel deployment contract for the browser runtime. The configured Vercel
// project uses apps/web as its root, so this test intentionally imports the
// configuration from that directory rather than accepting a repository-root
// file that the production deployment would ignore.

import { describe, expect, it } from "vitest";
import config from "../vercel.json";

describe("Vercel browser runtime headers", () => {
  it("publishes the isolation and security policies required by Wasm threads", () => {
    // One catch-all rule must cover the HTML document, JavaScript workers,
    // Wasm module and static assets. Splitting these headers across rules risks
    // an apparently healthy page whose Worker response is not isolated.
    const catchAll = config.headers.find((rule) => rule.source === "/(.*)");
    expect(catchAll).toBeDefined();
    const headers = new Map(catchAll!.headers.map((header) =>
      [header.key.toLowerCase(), header.value]));

    expect(headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(headers.get("cross-origin-embedder-policy")).toBe("require-corp");
    expect(headers.get("cross-origin-resource-policy")).toBe("same-origin");
    expect(headers.get("content-security-policy")).toContain("wasm-unsafe-eval");
    expect(headers.get("permissions-policy")).toContain("serial=()");
  });

  it("keeps client-side routes inside the unchanged static application", () => {
    // Vercel checks real files before applying rewrites, so this SPA fallback
    // does not replace hashed JavaScript, Worker or Wasm assets with index.html.
    expect(config.rewrites).toEqual([
      { source: "/(.*)", destination: "/index.html" }
    ]);
  });
});
