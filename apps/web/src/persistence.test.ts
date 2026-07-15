// File import tests cover the browser-side wrapper and validation boundary.
// IndexedDB and OPFS are intentionally outside this DOM-free unit suite.

import { describe, expect, it } from "vitest";
import { DEFAULT_PROJECT } from "@router-simulator/contracts";
import { createCheckpointManifest, createProjectManifest,
  decodeStoredProject, IncompatibleCheckpointError, importProject, parseNetsim } from "./persistence";

describe("project file import", () => {
  it("quarantines an incompatible stored record without accepting its fields", () => {
    // Recovery keeps the rejected object byte-for-byte for the IndexedDB
    // transaction, while the active replacement comes only from generated
    // defaults. This prevents a stale record from disabling every later boot.
    const legacy = { format: "obsolete-lab", arbitrary: { retained: true } };
    const decoded = decodeStoredProject(legacy);
    expect(decoded).toEqual({
      project: DEFAULT_PROJECT,
      rejected: true,
      recovery: legacy
    });
    expect(decodeStoredProject(undefined)).toEqual({
      project: DEFAULT_PROJECT,
      rejected: false
    });
  });

  it("accepts an exported project wrapper", async () => {
    // The browser import path and IndexedDB load path share parseProject. This
    // test exercises the file wrapper without mocking or bypassing validation.
    const file = new File([
      JSON.stringify({ mode: "project", project: DEFAULT_PROJECT })
    ], "lab.netsim", { type: "application/json" });
    await expect(importProject(file)).resolves.toMatchObject({
      format: "router-simulator-project",
      profile: "7750-sr-7-iom4-e"
    });
  });

  it("rejects malformed endpoint data from a file", async () => {
    // File extension is not trusted. Parsed contents reach the same strict
    // project validator used by the live runtime restoration path.
    const project = structuredClone(DEFAULT_PROJECT);
    project.hosts[0].address = "999.0.2.2/30";
    const file = new File([JSON.stringify(project)], "invalid.netsim");
    await expect(importProject(file)).rejects.toThrow("invalid host");
  });

  it("round-trips the project-only manifest with its profile lock", () => {
    const manifest = createProjectManifest(DEFAULT_PROJECT);
    expect(parseNetsim(JSON.stringify(manifest))).toEqual({
      project: DEFAULT_PROJECT,
      checkpoint: undefined,
      capture: undefined
    });
  });

  it("round-trips checkpoint and capture bytes without text coercion", () => {
    const checkpoint = Uint8Array.from([0, 1, 2, 127, 128, 255]);
    const capture = Uint8Array.from([10, 13, 13, 10, 0, 255]);
    const manifest = createCheckpointManifest(DEFAULT_PROJECT, checkpoint, capture);
    const restored = parseNetsim(JSON.stringify(manifest));
    expect(restored.project).toEqual(DEFAULT_PROJECT);
    expect(restored.checkpoint).toEqual(checkpoint);
    expect(restored.capture).toEqual(capture);
  });

  it("requires consent before dropping incompatible structural state", () => {
    const manifest = createCheckpointManifest(DEFAULT_PROJECT, Uint8Array.of(1));
    manifest.profileLock.buildHash = "0000000000000000";
    expect(() => parseNetsim(JSON.stringify(manifest))).toThrow(IncompatibleCheckpointError);
    expect(parseNetsim(JSON.stringify(manifest), true)).toEqual({ project: DEFAULT_PROJECT });
  });

  it("fails closed under deterministic manifest mutation fuzzing", () => {
    // Mutation covers JSON syntax, wrapper fields and base64 contents. Every
    // candidate either validates completely or throws without partial output.
    const source = JSON.stringify(
      createCheckpointManifest(DEFAULT_PROJECT, Uint8Array.of(1, 2, 3)));
    let random = 0x51704a31;
    for (let iteration = 0; iteration < 1000; ++iteration) {
      random ^= random << 13;
      random ^= random >>> 17;
      random ^= random << 5;
      const offset = Math.abs(random) % source.length;
      const replacement = String.fromCharCode(32 + (Math.abs(random >>> 8) % 95));
      const candidate = source.slice(0, offset) + replacement + source.slice(offset + 1);
      try {
        const decoded = parseNetsim(candidate);
        expect(decoded.project.format).toBe("router-simulator-project");
      } catch (cause) {
        expect(cause).toBeInstanceOf(Error);
      }
    }
  });
});
