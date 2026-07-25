// @vitest-environment jsdom

// Autosave orchestration test. The browser owns durable project files,
// while the C++ Worker owns committed CLI configuration. This fixture proves
// that background persistence checkpoints the Worker before publishing the
// matching project head, so a completed save cannot omit CLI-only state.

import { describe, expect, it, vi } from "vitest";
import { createEmptyProjectV4 } from "@router-simulator/contracts";

const calls: string[] = [];
const checkpoint = new Uint8Array([7, 4, 1]);

vi.mock("../persistence", () => ({
  projectCheckpointNameV4: vi.fn(async () => {
    calls.push("name");
    return "recovery.checkpoint";
  }),
  saveProjectBinaryV4: vi.fn(async (
    _projectId: string, _name: string, bytes: Uint8Array) => {
    expect(bytes).toEqual(checkpoint);
    calls.push("checkpoint");
  }),
  saveLabProjectV4: vi.fn(async () => {
    calls.push("project");
  }),
  saveProjectPresentation: vi.fn(async () => {
    calls.push("presentation");
  })
}));

import {
  DurableProjectSaveQueue,
  persistDurableProject
} from "./durable-project-save";

describe("durable project autosave", () => {
  it("stores the runtime checkpoint before the project head", async () => {
    calls.length = 0;
    const project = createEmptyProjectV4(new Date("2026-07-24T00:00:00Z"));
    const client = {
      exportCheckpoint: vi.fn(async () => {
        calls.push("export");
        return checkpoint;
      })
    };

    // Only exportCheckpoint belongs to this narrow contract. The cast avoids
    // constructing an unrelated Worker for a persistence ordering test.
    await persistDurableProject(project, undefined, undefined, {}, [],
      client as never);

    expect(calls).toEqual([
      "export", "name", "checkpoint", "project", "presentation"
    ]);
  });

  it("cannot publish an older autosave after a newer autosave", async () => {
    calls.length = 0;
    const queue = new DurableProjectSaveQueue();
    const firstProject = {
      ...createEmptyProjectV4(new Date("2026-07-24T00:00:00Z")),
      name: "older"
    };
    const latestProject = { ...firstProject, name: "latest" };
    let releaseFirst: (() => void) | undefined;
    let markFirstStarted: (() => void) | undefined;
    const firstCheckpoint = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const firstStarted = new Promise<void>((resolve) => {
      markFirstStarted = resolve;
    });
    const firstClient = {
      exportCheckpoint: vi.fn(async () => {
        calls.push("first-export");
        markFirstStarted!();
        await firstCheckpoint;
        return checkpoint;
      })
    };
    const latestClient = {
      exportCheckpoint: vi.fn(async () => {
        calls.push("latest-export");
        return checkpoint;
      })
    };

    const older = queue.persist(firstProject, undefined, undefined, {}, [],
      firstClient as never);
    const latest = queue.persist(latestProject, undefined, undefined, {}, [],
      latestClient as never);
    await firstStarted;
    expect(calls).toEqual(["first-export"]);
    releaseFirst!();
    await Promise.all([older, latest]);

    expect(calls).toEqual([
      "first-export", "name", "checkpoint", "project", "presentation",
      "latest-export", "name", "checkpoint", "project", "presentation"
    ]);
  });
});
