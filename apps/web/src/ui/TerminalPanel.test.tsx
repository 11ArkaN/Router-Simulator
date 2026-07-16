// Byte-to-screen integration test for the xterm adapter. The mocked renderer
// records exactly what TerminalPanel writes while real editor, completion,
// engine refresh and submission logic execute unchanged.

// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TerminalPanel } from "./TerminalPanel";
import type { TerminalState } from "./terminal-contract";
import type { TerminalHistoryStorage } from "./terminal-history";

interface RecordedTerminal {
  writes: string[];
  options: Record<string, unknown>;
  rows: number;
  scrolls: number;
  emit(data: string): void;
}

// vi.hoisted creates the shared recorder before the static xterm import is
// evaluated. Tests can therefore inject raw onData bytes without exposing a
// test-only hook in the production component.
const recorder = vi.hoisted(() => ({
  current: undefined as RecordedTerminal | undefined,
  instances: 0
}));

// Component tests exercise terminal byte semantics, not browser persistence.
// This no-I/O store preserves the production archive contract without requiring
// jsdom to pretend that it implements Chromium OPFS handles.
const historyStorage: TerminalHistoryStorage = {
  async list() { return []; },
  async write() {},
  async read() { return ""; }
};

vi.mock("@xterm/xterm", () => ({
  Terminal: class implements RecordedTerminal {
    writes: string[] = [];
    options: Record<string, unknown>;
    rows = 24;
    scrolls = 0;
    private input: ((data: string) => void) | undefined;

    constructor(options: Record<string, unknown>) {
      this.options = options;
      recorder.current = this;
      ++recorder.instances;
    }
    loadAddon() {}
    open() {}
    write(value: string, callback?: () => void) {
      this.writes.push(value);
      callback?.();
    }
    writeln(value: string) { this.writes.push(`${value}\r\n`); }
    onData(callback: (data: string) => void) {
      this.input = callback;
      return { dispose() {} };
    }
    onScroll() { return { dispose() {} }; }
    buffer = { active: { length: 24 } };
    emit(data: string) { this.input?.(data); }
    blur() {}
    focus() {}
    scrollToBottom() { ++this.scrolls; }
    clear() {}
    dispose() {}
  }
}));

vi.mock("@xterm/addon-fit", () => ({ FitAddon: class {
  fit() {}
} }));

class TestResizeObserver implements ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

afterEach(() => {
  cleanup();
  recorder.current = undefined;
  recorder.instances = 0;
  vi.restoreAllMocks();
});

describe("terminal raw-key transcript", () => {
  it("does not repeat an MD context marker while editing one line", async () => {
    const resize = globalThis.ResizeObserver;
    globalThis.ResizeObserver = TestResizeObserver;
    try {
      render(<TerminalPanel ready systemName="R1" historyKey="test:r1"
        historyStorage={historyStorage} execute={vi.fn()}
        complete={async (input) => input} cancel={vi.fn()} state={async () => ({
          engine: "md", historyRegion: "md-operational", banner: "SR OS 26.7.R1",
          prompt: "\n[/]\nA:admin@R1# "
        })} height={360} onHeightChange={vi.fn()} close={vi.fn()} />);
      await waitFor(() => expect(recorder.current?.writes.join("")).toContain("[/]"));

      // Each printable byte redraws only the editable prompt line. The context
      // marker was already rendered once when the terminal state arrived.
      recorder.current!.emit("a");
      recorder.current!.emit("b");
      expect(recorder.current!.writes).toEqual([
        "SR OS 26.7.R1\r\n",
        "[/]\r\nA:admin@R1# ",
        "\r\u001b[2KA:admin@R1# a",
        "\r\u001b[2KA:admin@R1# ab"
      ]);
    } finally {
      globalThis.ResizeObserver = resize;
    }
  });

  it("completes MD input, switches the same router session and executes classic input", async () => {
    // Prompt and engine are always returned by the router owner after a command.
    // The UI test changes this fixture only when execute simulates the router's
    // `//` response; TerminalPanel itself never predicts the transition.
    let terminalState: TerminalState = {
      engine: "md",
      historyRegion: "md-operational",
      banner: "SR OS 26.7.R1",
      prompt: "A:admin@R1# "
    };
    const execute = vi.fn(async (command: string) => {
      if (command === "//") {
        terminalState = { ...terminalState, engine: "classic",
          historyRegion: "classic", prompt: "A:R1# " };
        return "A:R1# ";
      }
      return command === "show" ? `System information\n${terminalState.prompt}`
        : terminalState.prompt;
    });
    const complete = vi.fn(async (input: string) => input === "sho" ? "show" : input);
    const resize = globalThis.ResizeObserver;
    globalThis.ResizeObserver = TestResizeObserver;
    try {
      const view = render(<TerminalPanel ready systemName="R1" historyKey="test:r1"
        historyStorage={historyStorage} execute={execute}
        complete={complete} cancel={vi.fn()} state={async () => terminalState}
        height={360} onHeightChange={vi.fn()}
        close={vi.fn()} />);
      await waitFor(() => expect(recorder.current?.writes.join("")).toContain("A:admin@R1# "));

      // Each value below is a real xterm onData sequence. Tab completes the
      // keyword, Enter submits it, and `//` is ordinary router input rather
      // than an application-level mode button.
      recorder.current!.emit("sho");
      recorder.current!.emit("\t");
      await waitFor(() => expect(complete).toHaveBeenCalledWith("sho", "tab"));
      recorder.current!.emit("\r");
      await waitFor(() => expect(execute).toHaveBeenCalledWith("show"));
      recorder.current!.emit("//");
      recorder.current!.emit("\r");
      await waitFor(() => expect(execute).toHaveBeenCalledWith("//"));
      recorder.current!.emit("show");
      recorder.current!.emit("\r");
      await waitFor(() => expect(execute).toHaveBeenCalledTimes(3));

      // Full history is reached by ordinary scrolling. There is no parallel
      // view toggle, and each completed output write returns the hot viewport
      // to the newest prompt only after xterm has parsed the response.
      expect(screen.queryByRole("button", { name: "Full terminal history" }))
        .toBeNull();
      expect(recorder.current!.scrolls).toBe(3);

      // App publishes a new snapshot and therefore new callback identities
      // after every command. Those callbacks must update through refs without
      // recreating the terminal or erasing the command that was just written.
      view.rerender(<TerminalPanel ready systemName="R1" historyKey="test:r1"
        historyStorage={historyStorage} execute={execute}
        complete={complete} cancel={vi.fn()} state={async () => terminalState}
        registerCheckpointProvider={vi.fn()} height={360}
        onHeightChange={vi.fn()} close={vi.fn()} />);
      expect(recorder.instances).toBe(1);

      // The golden array preserves cursor erasure and CRLF bytes without a
      // snapshot serializer normalizing control characters. A renderer change
      // that drops a prompt or submits different input changes a specific write.
      expect(recorder.current!.writes).toEqual([
        "SR OS 26.7.R1\r\n",
        "A:admin@R1# ",
        "\r\u001b[2KA:admin@R1# sho",
        "\r\u001b[2KA:admin@R1# show",
        "\r\n",
        "System information\r\nA:admin@R1# ",
        "\r\u001b[2KA:admin@R1# //",
        "\r\n",
        "A:R1# ",
        "\r\u001b[2KA:R1# show",
        "\r\n",
        "System information\r\nA:R1# "
      ]);
    } finally {
      globalThis.ResizeObserver = resize;
    }
  });
});
