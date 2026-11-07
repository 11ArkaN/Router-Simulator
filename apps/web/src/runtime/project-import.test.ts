// Import bootstrap tests guard owner continuity: a checkpoint must reach a
// fresh client before any configuration replay can create protocol generations.

import { createEmptyProjectV4, type LabRuntimeSnapshotV6 } from
  "@router-simulator/contracts";
import { describe, expect, it, vi } from "vitest";
import { prepareProjectImport } from "./project-import";

const project = createEmptyProjectV4();
// This boundary transports the validated result without reading its fields.
const snapshot = {} as LabRuntimeSnapshotV6;
const key = new Uint8Array(32);

describe("detached project import", () => {
  it("restores complete checkpoint owners without creating replay generations", async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const target = { applyProject: vi.fn(async () => snapshot),
      restoreProjectCheckpoint: vi.fn(async () => snapshot) };
    expect(await prepareProjectImport(target, project, bytes, key)).toBe(snapshot);
    expect(target.restoreProjectCheckpoint).toHaveBeenCalledWith(project.projectId, bytes, key);
    expect(target.applyProject).not.toHaveBeenCalled();
  });
  it("replays portable intent when no checkpoint was supplied", async () => {
    const target = { applyProject: vi.fn(async () => snapshot),
      restoreProjectCheckpoint: vi.fn(async () => snapshot) };
    expect(await prepareProjectImport(target, project, undefined, key)).toBe(snapshot);
    expect(target.applyProject).toHaveBeenCalledWith(project, key);
    expect(target.restoreProjectCheckpoint).not.toHaveBeenCalled();
  });
  it("preserves checkpoint refusal without falling back to a different runtime", async () => {
    const target = { applyProject: vi.fn(async () => snapshot),
      restoreProjectCheckpoint: vi.fn(async () => { throw new Error("invalid checkpoint"); }) };
    await expect(prepareProjectImport(target, project, new Uint8Array(), key))
      .rejects.toThrow("invalid checkpoint");
    expect(target.applyProject).not.toHaveBeenCalled();
  });
});
