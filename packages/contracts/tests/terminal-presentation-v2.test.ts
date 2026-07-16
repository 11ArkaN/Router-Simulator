// Terminal presentation tests protect per-session identity and memory bounds.
// Runtime candidate state is intentionally absent from these renderer records.

import { describe, expect, it } from "vitest";
import { parseTerminalPresentationV2 } from "../src";

describe("terminal presentation format 2", () => {
  it("accepts independent sessions for different routers", () => {
    const blank: { buffer: string; cursor: number; history: string[];
      historyIndex: number } = { buffer: "", cursor: 0, history: [], historyIndex: 0 };
    const presentation = (editor: typeof blank) => ({ editors: {
      "md-operational": editor, "md-configuration": blank, classic: blank
    }, queuedInput: [] });
    const value = { version: 2 as const, activeSessionId: "s2", sessions: [
      { sessionId: "s1", routerId: "r1", engine: "md" as const,
        ...presentation({ buffer: "show router", cursor: 11, history: [], historyIndex: 0 }) },
      { sessionId: "s2", routerId: "r2", engine: "classic" as const,
        ...presentation({ buffer: "", cursor: 0, history: ["show card"], historyIndex: 1 }) }
    ] };
    expect(parseTerminalPresentationV2(value)).toEqual(value);
  });

  it("rejects dangling active and duplicate session identities", () => {
    const editor = { buffer: "", cursor: 0, history: [], historyIndex: 0 };
    const state = { editors: { "md-operational": editor,
      "md-configuration": editor, classic: editor }, queuedInput: [] };
    expect(() => parseTerminalPresentationV2({ version: 2,
      activeSessionId: "missing", sessions: [] })).toThrow("Active terminal");
    expect(() => parseTerminalPresentationV2({ version: 2, sessions: [
      { sessionId: "same", routerId: "r1", engine: "md", ...state },
      { sessionId: "same", routerId: "r2", engine: "md", ...state }
    ] })).toThrow("duplicated");
  });
});
