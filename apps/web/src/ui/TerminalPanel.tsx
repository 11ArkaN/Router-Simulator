// xterm renderer and lossless byte-input adapter for one router CLI session.
// Engine selection and candidate semantics remain in the C++ session owner.

import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { paginateTerminal, TerminalInputQueue, TerminalLineEditor } from "./terminal-model";
import { GENERATED_PROFILE } from "@router-simulator/contracts";
import type { TerminalState } from "../runtime/client";

interface Props {
  ready: boolean;
  systemName: string;
  execute(command: string): Promise<string>;
  complete(input: string): Promise<string>;
  state(): Promise<TerminalState>;
}

export function TerminalPanel({ ready, systemName, execute, complete, state }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const executeRef = useRef(execute);
  const completeRef = useRef(complete);
  const stateRef = useRef(state);
  executeRef.current = execute;
  completeRef.current = complete;
  stateRef.current = state;

  useEffect(() => {
    if (!hostRef.current) return;
    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: '"Cascadia Mono", "IBM Plex Mono", monospace',
      fontSize: 12,
      lineHeight: 1.35,
      scrollback: 3000,
      theme: {
        background: "#090b0c",
        foreground: "#cdd4d2",
        cursor: "#9ef0ba",
        selectionBackground: "#33594688",
        green: "#76d99a",
        brightGreen: "#9ef0ba",
        red: "#ef8b83"
      }
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(hostRef.current);

    // xterm.js owns rendering only. The session owner remains C++, while this
    // adapter translates byte-level editing keys into complete command lines.
    // History is local terminal ergonomics and cannot mutate router state.
    const editor = new TerminalLineEditor();
    let busy = false;
    const queuedInput = new TerminalInputQueue(GENERATED_PROFILE.resources.cli_input_queue_bytes);
    let sessionState: TerminalState | undefined;
    let pages: string[][] = [];
    let pageIndex = 0;

    const prompt = () => sessionState?.prompt.replace(/^\n/, "") ?? "";
    const redraw = () => terminal.write(`\r\x1b[2K${prompt()}${editor.value}`);

    if (ready) {
      void stateRef.current().then((next) => {
        sessionState = next;
        terminal.writeln(next.banner);
        terminal.write(next.prompt.replaceAll("\n", "\r\n").replace(/^\r\n/, ""));
      }).catch((cause) => console.error("Console session startup failed", cause));
    }

    const writePage = () => {
      // Paging is a presentation boundary, not a CLI command retry. The full
      // response has already been produced exactly once by the session owner.
      terminal.write(pages[pageIndex].join("\r\n"));
      if (++pageIndex < pages.length) terminal.write("\r\n--More--");
      else pages = [];
    };

    const writePaged = (output: string) => {
      pages = paginateTerminal(output, terminal.rows);
      pageIndex = 0;
      writePage();
    };

    const showCompletion = async () => {
      busy = true;
      try {
        const result = await completeRef.current(editor.value);
        if (!result) return;
        if (!result.includes("\n")) {
          // A unique result replaces the editable buffer. Redrawing the current
          // line avoids synthesizing key presses or bypassing normal execution.
          editor.replace(result);
          redraw();
        } else {
          terminal.write(`\r\n${result.replaceAll("\n", "\r\n")}\r\n`);
          redraw();
        }
      } finally {
        busy = false;
      }
    };

    const processData = async (data: string): Promise<void> => {
      // While the pager is active, only Space, Enter and q have meaning. Other
      // bytes are ignored so they cannot leak into the next router command.
      if (pages.length) {
        if (data === "q" || data === "Q") {
          pages = [];
          terminal.write(`\r\x1b[2K\r\n${prompt()}`);
        } else if (data === " " || data === "\r") {
          terminal.write("\r\x1b[2K");
          writePage();
        }
        return;
      }
      if (!ready) return;
      if (busy) {
        // The terminal adapter is the producer of the 64 KiB CLI input queue.
        // processData is its only consumer and preserves xterm byte order. A
        // full queue applies visible backpressure by disabling stdin instead of
        // acknowledging and silently discarding later characters.
        if (!queuedInput.push(data)) {
          terminal.options.disableStdin = true;
          terminal.write("\u0007");
        }
        return;
      }
      if (data === "\r") {
        terminal.write("\r\n");
        busy = true;
        const submitted = editor.submit();
        try {
          const output = await executeRef.current(submitted);
          // The backend may change engine, prompt markers or system name while
          // executing. Refreshing state prevents the renderer from predicting
          // any of those router-owned semantics.
          sessionState = await stateRef.current();
          writePaged(output);
        } catch (cause) {
          // Transport diagnostics belong in developer tools. The router
          // console must never expose Worker, Wasm or mailbox implementation.
          console.error("Console command transport failed", cause);
          terminal.write(`Console unavailable.\r\n${prompt()}`);
        } finally {
          busy = false;
          terminal.options.disableStdin = false;
        }
      } else if (data === "\u007f") {
        if (editor.value.length) {
          editor.backspace();
          terminal.write("\b \b");
        }
      } else if (data === "\u001b[A" || data === "\u001b[B") {
        // Arrow navigation never submits a command. It only replaces the local
        // edit buffer and therefore preserves immediate classic CLI semantics.
        if (data === "\u001b[A") editor.previous();
        else editor.next();
        redraw();
      } else if (data === "\t" || data === "?") {
        await showCompletion();
      } else if (data >= " " && data !== "\u007f") {
        editor.insert(data);
        terminal.write(data);
      }
      while (!busy && queuedInput.length) {
        const queued = queuedInput.shift()!;
        await processData(queued);
      }
    };
    const inputDisposable = terminal.onData((data) => { void processData(data); });
    let rendererReady = false;
    let resizeFrame = window.requestAnimationFrame(() => {
      rendererReady = true;
      fit.fit();
    });
    const resize = new ResizeObserver(() => {
      if (!rendererReady) return;
      window.cancelAnimationFrame(resizeFrame);
      resizeFrame = window.requestAnimationFrame(() => fit.fit());
    });
    resize.observe(hostRef.current);
    return () => {
      // Disposing both xterm resources and ResizeObserver prevents a reopened
      // panel from owning duplicate keyboard handlers or animation callbacks.
      rendererReady = false;
      window.cancelAnimationFrame(resizeFrame);
      resize.disconnect();
      inputDisposable.dispose();
      terminal.dispose();
    };
  }, [ready]);

  return (
    <section className="terminal-panel">
      <div className="terminal-head">
        <div>{systemName} console</div>
      </div>
      <div className="terminal-host" ref={hostRef} />
    </section>
  );
}
