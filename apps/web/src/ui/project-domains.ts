// Revision gate for portable project domains crossing from React into C++.
// The gate owns no state. App supplies the last acknowledged object references
// and uses the result to contact only the runtime owner whose intent changed.

import type { LabProject } from "@router-simulator/contracts";

export interface AppliedProjectDomains {
  // Object identity is a valid revision marker because every editor replaces
  // its domain immutably. These references describe acknowledged intent and
  // must never be populated from unvalidated intermediate form text.
  hardware: LabProject["hardware"];
  runningConfig: LabProject["runningConfig"];
  links: LabProject["links"];
  hosts: LabProject["hosts"];
}

export function changedProjectDomains(previous: AppliedProjectDomains | undefined,
  project: LabProject) {
  // Domains are compared independently. A system-name edit must not look like
  // a chassis pull, link timing change or host reconfiguration merely because
  // the parent LabProject object changed.
  return {
    hardware: previous?.hardware !== project.hardware,
    runningConfig: previous?.runningConfig !== project.runningConfig,
    links: previous?.links !== project.links,
    hosts: previous?.hosts !== project.hosts
  };
}
