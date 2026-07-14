import { describe, expect, it } from "vitest";
import { paginateTerminal, TerminalInputQueue, TerminalLineEditor } from "./terminal-model";

describe("terminal byte editing", () => {
  it("applies printable input, backspace and history navigation in order", () => {
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
    const pages = paginateTerminal("one\ntwo\nthree\nfour\nfive", 4);
    expect(pages).toEqual([["one", "two"], ["three", "four"], ["five"]]);
  });

  it("bounds per-session history at the sourced default size", () => {
    const editor = new TerminalLineEditor();
    for (let index = 0; index < 51; ++index) {
      editor.insert(`show command ${index}`);
      editor.submit();
    }
    for (let index = 0; index < 50; ++index) editor.previous();
    expect(editor.value).toBe("show command 1");
    expect(editor.previous()).toBe("show command 1");
  });

  it("buffers terminal bytes in FIFO order and rejects overflow without loss", () => {
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
