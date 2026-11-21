// Import preparation belongs to the detached replacement client. Checkpoints
// restore their complete owner graph directly; configuration-only projects replay
// intent. This module retains no client, snapshot or wrapping-key material.

import type { LabProjectV4 } from "@router-simulator/contracts";
import type { MultiRouterRuntimeClient } from "./multi-router-client";

type ImportTarget = Pick<MultiRouterRuntimeClient,
  "applyProject" | "restoreProjectCheckpoint">;

// The caller owns a fresh client and publishes it only after this succeeds.
// An invalid checkpoint must reject without replaying configuration as fallback.
export function prepareProjectImport(target: ImportTarget, project: LabProjectV4,
  checkpoint?: Uint8Array, wrappingKey?: Uint8Array) {
  return checkpoint !== undefined
    ? target.restoreProjectCheckpoint(project.projectId, checkpoint, wrappingKey)
    : target.applyProject(project, wrappingKey);
}
