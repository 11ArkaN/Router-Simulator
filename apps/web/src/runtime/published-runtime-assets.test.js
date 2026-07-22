// Static runtime publication contract. The Vercel project builds from
// apps/web and cannot run the Windows-owned Emscripten toolchain, so the two
// locally verified core artifacts are versioned beside the browser sources.
// Vite copies these bytes without transforming them, while the normal local
// verification pipeline recompiles and republishes them before each commit.

import { readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const publicRuntime = resolve(dirname(fileURLToPath(import.meta.url)), "../../public/wasm");

describe("published WebAssembly runtime assets", () => {
  it("contains the Emscripten loader and a real WebAssembly module", () => {
    const loader = resolve(publicRuntime, "simulator.js");
    const module = resolve(publicRuntime, "simulator.wasm");

    // Empty placeholders would make the static URLs exist while preserving the
    // same production failure. Require executable content and the standardized
    // four-byte WebAssembly binary magic instead of testing only filenames.
    expect(statSync(loader).size).toBeGreaterThan(0);
    expect(statSync(module).size).toBeGreaterThan(4);
    expect([...readFileSync(module).subarray(0, 4)]).toEqual([0x00, 0x61, 0x73, 0x6d]);
  });
});
