// Terminal model tests replay byte-level user behavior without xterm or React.
// This keeps editor, pager and bounded-queue semantics deterministic.

import { describe, expect, it } from "vitest";
import { GENERATED_PROFILE } from "@router-simulator/contracts";
import { paginateTerminal, TerminalInputQueue, TerminalLineEditor } from "./terminal-model";

describe("terminal byte editing", () => {
  it("applies printable input, backspace and history navigation in order", () => {
    // Build and repair a command character by character, then verify history
    // keeps submitted lines and exposes the empty editable tail.
    const editor = new TerminalLineEditor();
    editor.insert("show porx");
    expect(editor.backspace()).toBe("show por");
    editor.insert("t");
    expect(editor.submit()).toBe("show port");
    editor.insert("show card");
    editor.submit();
    expect(editor.previous()).toBe("show card");
    expect(editor.previous()).toBe("show port");
    expect(editor.next()).toBe("show card");
    expect(editor.next()).toBe("");
  });

  it("creates stable pager screens without dropping response lines", () => {
    // Four terminal rows reserve two rows for prompt and pager marker, leaving
    // two response lines per page. The final short page must remain present.
    const pages = paginateTerminal("one\ntwo\nthree\nfour\nfive", 4);
    expect(pages).toEqual([["one", "two"], ["three", "four"], ["five"]]);
  });

  it("bounds per-session history at the sourced default size", () => {
    // Insert one more line than the documented limit and walk to the oldest
    // retained entry. Further navigation must remain clamped at that entry.
    const editor = new TerminalLineEditor();
    for (let index = 0; index < GENERATED_PROFILE.cliDefaults.history_entries + 1; ++index) {
      editor.insert(`show command ${index}`);
      editor.submit();
    }
    for (let index = 0; index < GENERATED_PROFILE.cliDefaults.history_entries; ++index) editor.previous();
    expect(editor.value).toBe("show command 1");
    expect(editor.previous()).toBe("show command 1");
  });

  it("buffers terminal bytes in FIFO order and rejects overflow without loss", () => {
    // The non-ASCII character proves capacity counts UTF-8 bytes, not UTF-16
    // code units. Rejected input must leave all already queued chunks intact.
    const queue = new TerminalInputQueue(8);
    expect(queue.push("show")).toBe(true);
    expect(queue.push(" ą")).toBe(true);
    expect(queue.byteLength).toBe(7);
    expect(queue.push("xx")).toBe(false);
    expect(queue.byteLength).toBe(7);
    expect(queue.shift()).toBe("show");
    expect(queue.shift()).toBe(" ą");
    expect(queue.shift()).toBeUndefined();
  });
});
