// Demo launch guards. This module owns browser-only replacement decisions and
// has no dependency on React, runtime Workers or durable storage.

import type { LabProjectV4 } from "@router-simulator/contracts";

export function projectNeedsReplacementConfirmation(project: LabProjectV4,
  terminalSessionCount: number): boolean {
  return project.routers.length > 0 || project.hosts.length > 0 ||
    project.switches.length > 0 || project.links.length > 0 ||
    project.annotations.length > 0 || project.notes.trim().length > 0 ||
    terminalSessionCount > 0;
}
