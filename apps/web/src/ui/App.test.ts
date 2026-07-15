// Tests for the React-to-runtime domain revision gate. The gate prevents an
// unrelated editor change from replaying physical hardware operations and is
// kept pure so its ownership rule can be checked without starting Workers.

import { createDefaultProject } from "@router-simulator/contracts";
import { describe, expect, it } from "vitest";
import { changedProjectDomains } from "./project-domains";

describe("project domain revisions", () => {
  it("applies every domain to a new runtime owner", () => {
    const project = createDefaultProject();
    expect(changedProjectDomains(undefined, project)).toEqual({
      hardware: true,
      runningConfig: true,
      links: true,
      hosts: true
    });
  });

  it("isolates a running configuration edit from hardware and links", () => {
    const project = createDefaultProject();
    const applied = {
      hardware: project.hardware,
      runningConfig: project.runningConfig,
      links: project.links,
      hosts: project.hosts
    };
    const edited = { ...project, runningConfig: {
      ...project.runningConfig, systemName: "edge-1"
    } };

    expect(changedProjectDomains(applied, edited)).toEqual({
      hardware: false,
      runningConfig: true,
      links: false,
      hosts: false
    });
  });
});
