// Durable project-save orchestration owned by the browser application layer.
// The runtime owns live router and terminal state, while this module orders the
// browser persistence writes needed to publish one recoverable project head.
// It depends only on contracts, the runtime client boundary and persistence.

import type {
  LabProjectV4,
  LabRuntimeSnapshotV6,
  TerminalPresentationV2
} from "@router-simulator/contracts";
import type { MultiRouterRuntimeClient } from "../runtime/multi-router-client";
import {
  projectCheckpointNameV4,
  saveLabProjectV4,
  saveProjectBinaryV4,
  saveProjectPresentation
} from "../persistence";
import type { TerminalPanelPresentation } from "./terminal-contract";

export function terminalPresentationForSessions(
  activeSession: string | undefined,
  presentations: Readonly<Record<string, TerminalPanelPresentation>>,
  sessions: LabRuntimeSnapshotV6["sessions"]): TerminalPresentationV2 {
  const retained = sessions.flatMap((session) => {
    const value = presentations[session.id];
    return value ? [{
      sessionId: session.id,
      routerId: session.routerId,
      engine: session.engine,
      editors: value.editors,
      queuedInput: value.queuedInput,
      ...(value.pager ? { pager: value.pager } : {})
    }] : [];
  });

  // Closing a session updates the runtime snapshot asynchronously. During that
  // owner handoff React can still hold the prior active ID and renderer
  // presentation for one render. Publish an active ID only when its matching
  // retained row is part of this same generation, otherwise the strict
  // persistence parser correctly rejects the inconsistent object.
  const activeRetained = activeSession !== undefined &&
    retained.some((session) => session.sessionId === activeSession);
  return {
    version: 2,
    ...(activeRetained ? { activeSessionId: activeSession } : {}),
    sessions: retained
  };
}

export async function persistDurableProject(project: LabProjectV4,
  selectedNodeId: string | undefined, activeSession: string | undefined,
  presentations: Readonly<Record<string, TerminalPanelPresentation>>,
  sessions: LabRuntimeSnapshotV6["sessions"],
  client: MultiRouterRuntimeClient | undefined): Promise<void> {
  // CLI commits mutate the C++-owned configuration datastore, not React's
  // portable topology projection. A durable save therefore has two mandatory
  // parts: the runtime checkpoint preserves committed CLI intent, while the
  // project head preserves user-owned topology and layout. Writing the
  // checkpoint first makes a torn save recoverable because startup rejects a
  // checkpoint whose object graph does not match the older project head.
  if (client) {
    const checkpoint = await client.exportCheckpoint();
    const recoveryName = await projectCheckpointNameV4(project);
    await saveProjectBinaryV4(project.projectId, recoveryName, checkpoint);
  }

  await saveLabProjectV4({
    ...project, updatedAt: new Date().toISOString()
  });
  await saveProjectPresentation(project.projectId, {
    projectId: project.projectId,
    selectedNodeId,
    terminal: terminalPresentationForSessions(
      activeSession, presentations, sessions)
  });
}

export class DurableProjectSaveQueue {
  // One queue owns publication order for one mounted application. IndexedDB
  // and OPFS make each individual write atomic, but they cannot make four
  // writes from two overlapping saves atomic as a group. Serializing complete
  // transactions prevents an older autosave from publishing its project head
  // after a newer autosave has already stored the matching checkpoint.
  private tail: Promise<void> = Promise.resolve();

  persist(project: LabProjectV4, selectedNodeId: string | undefined,
    activeSession: string | undefined,
    presentations: Readonly<Record<string, TerminalPanelPresentation>>,
    sessions: LabRuntimeSnapshotV6["sessions"],
    client: MultiRouterRuntimeClient | undefined): Promise<void> {
    const transaction = this.tail.catch(() => {
      // A failed save is reported to its own caller. It must not poison the
      // queue because a later autosave may still recover durability.
    }).then(() => persistDurableProject(project, selectedNodeId, activeSession,
      presentations, sessions, client));
    this.tail = transaction;
    return transaction;
  }
}
