// Terminal model tests replay byte-level user behavior without xterm or React.
// This keeps editor, pager and bounded-queue semantics deterministic.

import { describe, expect, it } from "vitest";
import { PROFILE_CATALOG } from "@router-simulator/contracts";
import {
  restoreTerminalPresentation,
  TerminalInputQueue,
  TerminalLineEditor,
  TerminalPager
} from "./terminal-model";

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

  it("navigates the sourced 26.7 pager without dropping response lines", () => {
    // Four terminal rows leave three output rows above the less-style status.
    // Screen, line, backward and end motions operate on one immutable result.
    const pager = new TerminalPager("one\ntwo\nthree\nfour\nfive", 4);
    expect(pager.page).toEqual(["one", "two", "three"]);
    expect(pager.status).toBe("--(more)--(60%)--(lines 1-3/5)--");
    expect(pager.handle("\r")).toBe("continue");
    expect(pager.page).toEqual(["two", "three", "four"]);
    expect(pager.handle("k")).toBe("continue");
    expect(pager.page).toEqual(["one", "two", "three"]);
    expect(pager.handle(" ")).toBe("complete");
    expect(pager.page).toEqual(["three", "four", "five"]);
    expect(pager.handle("Q")).toBe("quit");
  });

  it("bounds per-session history at the sourced default size", () => {
    // Insert one more line than the documented limit and walk to the oldest
    // retained entry. Further navigation must remain clamped at that entry.
    const editor = new TerminalLineEditor();
    for (let index = 0; index < 51; ++index) {
      editor.insert(`show command ${index}`);
      editor.submit();
    }
    for (let index = 0; index < 50; ++index) editor.previous();
    expect(editor.value).toBe("show command 1");
    expect(editor.previous()).toBe("show command 1");
  });

  it("implements documented word, case and transpose editing at the cursor", () => {
    // The sequence covers the stateful operations behind Esc-B, Esc-C, Esc-L,
    // Ctrl-T and Ctrl-W instead of checking only final submitted commands.
    const editor = new TerminalLineEditor();
    editor.insert("show prot");
    editor.left();
    editor.left();
    expect(editor.transposeCharacters()).toBe("show port");
    editor.home();
    editor.nextWord();
    expect(editor.changeWordCase(true)).toBe("show PORT");
    editor.previousWord();
    expect(editor.changeWordCase(false)).toBe("show port");
    expect(editor.deletePreviousWord()).toBe("show ");
  });

  it("recalls matching history and the previous command's last element", () => {
    // Ctrl-R and Esc-. are history editing actions, not backend commands. A
    // quoted final element remains intact when it is recalled.
    const editor = new TerminalLineEditor();
    editor.insert("show card");
    editor.submit();
    editor.insert("show port");
    editor.submit();
    editor.insert('description "edge uplink"');
    editor.submit();
    expect(editor.insertLastElement()).toBe('"edge uplink"');
    editor.replace("");
    editor.insert("show");
    expect(editor.reverseSearch()).toBe("show port");
    // A repeated Ctrl-R retains the original "show" query. It must continue
    // farther back instead of searching for the full first result.
    expect(editor.reverseSearch()).toBe("show card");
    editor.submit();
    expect(editor.insertLastElement()).toBe("card");
  });

  it("recognizes a literal question mark inside an open quoted parameter", () => {
    // Quote detection influences only terminal input dispatch. C++ remains the
    // owner of whether the completed string is legal for a specific command.
    const editor = new TerminalLineEditor();
    editor.insert('description "edge?');
    expect(editor.hasOpenQuote()).toBe(true);
    editor.insert('"');
    expect(editor.hasOpenQuote()).toBe(false);
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

  it("round-trips all editor regions, queued bytes and pager position", () => {
    // Structural checkpoints must preserve text that has not yet become a CLI
    // command. The three histories remain distinct because switching with //
    // returns to the same router session but a different history region.
    const editors = {
      "md-operational": new TerminalLineEditor(),
      "md-configuration": new TerminalLineEditor(),
      classic: new TerminalLineEditor()
    };
    editors["md-operational"].insert("show port");
    editors["md-operational"].submit();
    editors["md-configuration"].insert("card 1");
    editors.classic.insert("configure");
    editors.classic.left();
    const queue = new TerminalInputQueue(PROFILE_CATALOG.runtime.terminal_result_bytes);
    queue.push("next");
    const pager = new TerminalPager("one\ntwo\nthree\nfour\nfive", 4);
    pager.handle("\r");
    const state = {
      version: 1 as const,
      editors: {
        "md-operational": editors["md-operational"].snapshot(),
        "md-configuration": editors["md-configuration"].snapshot(),
        classic: editors.classic.snapshot()
      },
      queuedInput: queue.snapshot(),
      pager: pager.snapshot()
    };

    const restoredEditors = {
      "md-operational": new TerminalLineEditor(),
      "md-configuration": new TerminalLineEditor(),
      classic: new TerminalLineEditor()
    };
    const restoredQueue = new TerminalInputQueue(PROFILE_CATALOG.runtime.terminal_result_bytes);
    const restoredPager = restoreTerminalPresentation(state, restoredEditors, restoredQueue);
    expect(restoredEditors["md-operational"].previous()).toBe("show port");
    expect(restoredEditors["md-configuration"].value).toBe("card 1");
    expect(restoredEditors.classic.cursor).toBe("configure".length - 1);
    expect(restoredQueue.shift()).toBe("next");
    expect(restoredPager?.page).toEqual(["two", "three", "four"]);
  });
});
