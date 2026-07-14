import { describe, expect, it } from "vitest";
import { DEFAULT_PROJECT } from "@router-simulator/contracts";
import { importProject } from "./persistence";

describe("project file import", () => {
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
    const project = structuredClone(DEFAULT_PROJECT);
    project.hosts[0].address = "999.0.2.2/30";
    const file = new File([JSON.stringify(project)], "invalid.netsim");
    await expect(importProject(file)).rejects.toThrow("invalid host");
  });
});
