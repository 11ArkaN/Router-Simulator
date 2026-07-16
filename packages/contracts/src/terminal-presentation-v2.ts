// Terminal presentation format 2 stores browser-owned view state for many
// router sessions. Runtime-owned candidate data and command execution never
// enter this contract. The browser persistence layer is the state owner.

import { PROFILE_CATALOG } from "./generated-device-catalog";
import type { NodeId, SessionId } from "./lab-project-v3";

export const TERMINAL_PRESENTATION_VERSION = 2 as const;

export interface TerminalEditorPresentationV2 {
  buffer: string;
  cursor: number;
  history: string[];
  historyIndex: number;
}

export interface TerminalSessionPresentationV2 {
  sessionId: SessionId;
  routerId: NodeId;
  engine: "md" | "classic";
  editors: Record<"md-operational" | "md-configuration" | "classic",
    TerminalEditorPresentationV2>;
  queuedInput: string[];
  pager?: { output: string; rows: number; offset: number };
}

export interface TerminalPresentationV2 {
  version: typeof TERMINAL_PRESENTATION_VERSION;
  activeSessionId?: SessionId;
  sessions: TerminalSessionPresentationV2[];
}

const identifierPattern = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i;
const encoder = new TextEncoder();

function assert(condition: unknown, message: string): asserts condition {
  // One fail-closed path keeps malformed renderer state from reaching xterm.
  if (!condition) throw new Error(message);
}

export function parseTerminalPresentationV2(input: unknown): TerminalPresentationV2 {
  // Presentation input can originate in an edited .netsim file, so every
  // nested field is bounded before it can allocate history or pager storage.
  assert(input && typeof input === "object" && !Array.isArray(input),
    "Terminal presentation must be an object");
  const value = input as Partial<TerminalPresentationV2>;
  const maximumSessions = PROFILE_CATALOG.limits.routers *
    PROFILE_CATALOG.limits.sessions_per_router;
  assert(value.version === TERMINAL_PRESENTATION_VERSION &&
    Array.isArray(value.sessions) && value.sessions.length <= maximumSessions,
  "Terminal presentation version or session count is invalid");

  const sessionIds = new Set<string>();
  for (const session of value.sessions) {
    // Stable IDs route the restored tab back to one runtime session. Display
    // names are intentionally absent because renaming a router must not fork
    // terminal history or presentation ownership.
    assert(session && identifierPattern.test(session.sessionId) &&
      identifierPattern.test(session.routerId) && !sessionIds.has(session.sessionId) &&
      (session.engine === "md" || session.engine === "classic"),
    "Terminal session identity is invalid or duplicated");
    const validEditor = (editor: TerminalEditorPresentationV2 | undefined) =>
      editor && typeof editor.buffer === "string" &&
      encoder.encode(editor.buffer).length <= 65536 &&
      Number.isSafeInteger(editor.cursor) && editor.cursor >= 0 &&
      editor.cursor <= editor.buffer.length && Array.isArray(editor.history) &&
      editor.history.length <= 10000 && editor.history.every((entry) =>
        typeof entry === "string" && encoder.encode(entry).length <= 65536) &&
      Number.isSafeInteger(editor.historyIndex) && editor.historyIndex >= 0 &&
      editor.historyIndex <= editor.history.length;
    assert(session.editors && validEditor(session.editors["md-operational"]) &&
      validEditor(session.editors["md-configuration"]) &&
      validEditor(session.editors.classic) && Array.isArray(session.queuedInput) &&
      session.queuedInput.every((chunk) => typeof chunk === "string") &&
      encoder.encode(session.queuedInput.join("")).length <=
        PROFILE_CATALOG.runtime.terminal_result_bytes,
    "Terminal editor presentation is invalid");
    if (session.pager !== undefined) {
      // Pager output is bounded by the shared terminal result limit. It is a
      // renderer snapshot, not an alternative unbounded transcript store.
      assert(typeof session.pager.output === "string" &&
        encoder.encode(session.pager.output).length <=
          PROFILE_CATALOG.runtime.terminal_result_bytes &&
        Number.isSafeInteger(session.pager.rows) && session.pager.rows > 0 &&
        Number.isSafeInteger(session.pager.offset) && session.pager.offset >= 0,
      "Terminal pager presentation is invalid");
    }
    sessionIds.add(session.sessionId);
  }
  assert(value.activeSessionId === undefined ||
    sessionIds.has(value.activeSessionId),
  "Active terminal session is not present");
  return structuredClone(value as TerminalPresentationV2);
}
