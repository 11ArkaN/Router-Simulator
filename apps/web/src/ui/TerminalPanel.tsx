// xterm renderer and lossless byte-input adapter for one router CLI session.
// Engine selection and candidate semantics remain in the C++ session owner.

import { useEffect, useMemo, useRef, useState, type WheelEvent } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import {
  TerminalInputQueue,
  TerminalLineEditor,
  TerminalPager,
  restoreTerminalPresentation,
  type TerminalCheckpointProvider
} from "./terminal-model";
import { PROFILE_CATALOG } from "@router-simulator/contracts";
import type { TerminalHistoryRegion, TerminalPanelPresentation,
  TerminalState } from "./terminal-contract";
import { PanelResizeHandle } from "./PanelResizeHandle";
import { TerminalHistoryArchive, type TerminalHistoryStorage } from "./terminal-history";
import { TerminalHistoryView } from "./TerminalHistoryView";
import { Eraser, Maximize2, Plus, Settings2, X } from "lucide-react";

interface Props {
  ready: boolean;
  systemName: string;
  historyKey: string;
  historyStorage?: TerminalHistoryStorage;
  execute(command: string): Promise<string>;
  complete(input: string, trigger: "tab" | "question" | "space"): Promise<string>;
  cancel(): void;
  state(): Promise<TerminalState>;
  height: number;
  onHeightChange(value: number): void;
  restorePresentation?: TerminalPanelPresentation;
  registerCheckpointProvider?(provider: TerminalCheckpointProvider | undefined): void;
  tabs?: readonly { id: string; label: string }[];
  activeTab?: string;
  selectTab?(id: string): void;
  newTab?(): void;
  closeTab?(id: string): void;
  close(): void;
}

export function TerminalPanel({ ready, systemName, historyKey, historyStorage, execute, complete, cancel, state,
  height, onHeightChange, restorePresentation, registerCheckpointProvider,
  tabs, activeTab, selectTab, newTab, closeTab, close }: Props) {
  const panelRef = useRef<HTMLElement>(null);
  const hostRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const [fontSize, setFontSize] = useState(12);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyBoundaryRows, setHistoryBoundaryRows] = useState(0);
  const historyOpenRef = useRef(false);
  const archive = useMemo(() => new TerminalHistoryArchive(historyKey, historyStorage,
    (cause) => console.error("Terminal history archival failed", cause)), [historyKey, historyStorage]);
  const executeRef = useRef(execute);
  const completeRef = useRef(complete);
  const stateRef = useRef(state);
  const cancelRef = useRef(cancel);
  const checkpointRegistrationRef = useRef(registerCheckpointProvider);
  executeRef.current = execute;
  completeRef.current = complete;
  stateRef.current = state;
  cancelRef.current = cancel;
  checkpointRegistrationRef.current = registerCheckpointProvider;

  useEffect(() => () => { void archive.close(); }, [archive]);

  useEffect(() => {
    // History browsing is read-only. Disabling xterm input while its canvas is
    // covered prevents invisible commands from reaching the router session.
    historyOpenRef.current = historyOpen;
    const terminal = terminalRef.current;
    if (!terminal) return;
    terminal.options.disableStdin = historyOpen;
    if (historyOpen) terminal.blur();
    else {
      // History can open after the user reaches xterm's oldest hot row. Return
      // to the current router prompt instead of leaving the live buffer at top.
      terminal.scrollToBottom();
      terminal.focus();
    }
  }, [historyOpen]);

  useEffect(() => {
    if (!hostRef.current) return;
    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: '"Cascadia Mono", "IBM Plex Mono", monospace',
      fontSize,
      lineHeight: 1.35,
      // xterm keeps only the recent interactive window. Its renderer paints
      // viewport rows rather than one DOM node per historical line. The full
      // transcript is independently chunked into OPFS below, so this bounded
      // cache protects RAM without imposing a user-visible history limit.
      scrollback: 8000,
      scrollOnUserInput: true,
      // A terminal recreated while the disk history overlay is already open
      // must never accept keys during the one frame before effects settle.
      disableStdin: historyOpenRef.current,
      theme: {
        background: "#060507",
        foreground: "#d6d2dc",
        cursor: "#cba6ff",
        selectionBackground: "#4b2f7099",
        green: "#76d99a",
        brightGreen: "#9ef0ba",
        red: "#ef8b83"
      }
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(hostRef.current);
    terminalRef.current = terminal;
    fitRef.current = fit;

    // xterm.js owns rendering only. The session owner remains C++, while this
    // adapter translates byte-level editing keys into complete command lines.
    // History is local terminal ergonomics and cannot mutate router state.
    // SR OS keeps separate MD operational, MD configuration and classic
    // histories. The active region still comes only from C++; the renderer
    // merely selects the corresponding bounded line-editing buffer.
    const editors: Record<TerminalHistoryRegion, TerminalLineEditor> = {
      "md-operational": new TerminalLineEditor(),
      "md-configuration": new TerminalLineEditor(),
      classic: new TerminalLineEditor()
    };
    let busy = false;
    const queuedInput = new TerminalInputQueue(PROFILE_CATALOG.runtime.terminal_result_bytes);
    let sessionState: TerminalState | undefined;
    let pager = restoreTerminalPresentation(restorePresentation, editors, queuedInput);

    // Checkpoint export samples the presentation owner only after the runtime
    // returns its structural bytes. No mutable xterm object crosses this API,
    // and all arrays are detached by the individual snapshot methods.
    const checkpointProvider: TerminalCheckpointProvider = {
      snapshot: () => ({
        editors: {
          "md-operational": editors["md-operational"].snapshot(),
          "md-configuration": editors["md-configuration"].snapshot(),
          classic: editors.classic.snapshot()
        },
        queuedInput: queuedInput.snapshot(),
        ...(pager ? { pager: pager.snapshot() } : {})
      })
    };
    checkpointRegistrationRef.current?.(checkpointProvider);

    const editor = () => editors[sessionState?.historyRegion ?? "md-operational"];
    const prompt = () => sessionState?.prompt.replace(/^\n/, "") ?? "";
    const inputPrompt = () => {
      // MD-CLI state includes a context line such as [/], followed by the
      // editable prompt. Context belongs to command boundaries, not to every
      // cursor redraw. Returning only the final line preserves the router-owned
      // prompt text while preventing one context marker per typed character.
      const lines = prompt().split("\n");
      return lines[lines.length - 1] ?? "";
    };
    const redraw = () => {
      const active = editor();
      const tail = active.value.length - active.cursor;
      terminal.write(`\r\x1b[2K${inputPrompt()}${active.value}${tail ? `\x1b[${tail}D` : ""}`);
    };

    if (ready) {
      void stateRef.current().then((next) => {
        sessionState = next;
        terminal.writeln(next.banner);
        terminal.write(next.prompt.replaceAll("\n", "\r\n").replace(/^\r\n/, ""));
        archive.append(next.banner);
      }).catch((cause) => console.error("Console session startup failed", cause));
    }

    const writePaged = (output: string) => {
      // Paging is a presentation boundary, not a CLI command retry. The full
      // response has already been produced exactly once by the session owner.
      archive.append(output);
      const next = new TerminalPager(output, terminal.rows);
      let rendered = next.renderedPage.join("\r\n");
      if (next.active) {
        pager = next;
        rendered += `\r\n${next.status}`;
      } else {
        pager = undefined;
      }
      // A command may emit more rows than the visible console. Finish the
      // complete xterm write before moving the viewport, otherwise a later
      // parser frame can leave the user above the new prompt.
      terminal.write(rendered, () => terminal.scrollToBottom());
    };

    const showCompletion = async (trigger: "tab" | "question" | "space") => {
      busy = true;
      try {
        const active = editor();
        const result = await completeRef.current(active.value, trigger);
        if (!result) {
          if (trigger === "space") {
            active.insert(" ");
            redraw();
          }
          return;
        }
        if (!result.includes("\n") && trigger !== "question") {
          // A unique result replaces the editable buffer. Redrawing the current
          // line avoids synthesizing key presses or bypassing normal execution.
          //
          // SR OS treats a unique Tab completion as a completed CLI element,
          // just like completion triggered by Spacebar. Keep the separator in
          // the editor rather than in C++ completion output: the result string
          // is the router-owned token replacement, while this adapter owns the
          // physical key and cursor presentation. An already present separator
          // is retained as one byte so a future completion transport can carry
          // the same presentation without producing doubled spaces.
          active.replace(result.endsWith(" ") ? result : `${result} `);
          redraw();
        } else {
          terminal.write(`\r\n${result.replaceAll("\n", "\r\n")}\r\n`);
          archive.append(`${inputPrompt()}${active.value}\n${result}`);
          redraw();
        }
      } finally {
        busy = false;
      }
    };

    const completeEnterKeyword = async () => {
      // With default 26.7 MD settings, Enter completes a unique command
      // keyword before execution. Variable parameters are deliberately left
      // untouched because their completion is Tab-only.
      if (sessionState?.engine !== "md") return;
      const active = editor();
      const result = await completeRef.current(active.value, "space");
      if (result && !result.includes("\n") && result !== active.value) {
        active.replace(result);
        redraw();
      }
    };

    const processData = async (data: string): Promise<void> => {
      // The 26.7 pager accepts line, half-screen, screen and absolute movement
      // keys. Bytes consumed here never leak into the next router command.
      if (pager) {
        const action = pager.handle(data);
        if (action === "quit") {
          pager = undefined;
          terminal.write(`\r\x1b[2K\r\n${prompt()}`);
        } else if (action === "unchanged") {
          terminal.write("\u0007");
        } else {
          // A pager redraw replaces the current screen, which permits backward
          // navigation without duplicating old lines in the visible viewport.
          terminal.write(`\x1b[2J\x1b[H${pager.renderedPage.join("\r\n")}`);
          if (action === "complete") pager = undefined;
          else terminal.write(`\r\n${pager.status}`);
        }
        return;
      }
      if (!ready) return;
      if (busy) {
        if (data === "\u0003") {
          // Ctrl-C is an out-of-band terminal signal. It must not wait behind
          // the active command in the byte queue or the ping could never be
          // interrupted until after its final probe.
          cancelRef.current();
          terminal.write("^C");
          return;
        }
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
      if (data === "\r" || data === "\n") {
        busy = true;
        try {
          await completeEnterKeyword();
          terminal.write("\r\n");
          const submitted = editor().submit();
          archive.append(`${inputPrompt()}${submitted}`);
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
          archive.append("Console unavailable.");
        } finally {
          busy = false;
          terminal.options.disableStdin = historyOpenRef.current;
        }
      } else if (data === "\u007f" || data === "\b") {
        editor().backspace();
        redraw();
      } else if (data === "\u001b[A" || data === "\u001b[B" ||
                 data === "\u0010" || data === "\u000e") {
        // Arrow navigation never submits a command. It only replaces the local
        // edit buffer and therefore preserves immediate classic CLI semantics.
        if (data === "\u001b[A" || data === "\u0010") editor().previous();
        else editor().next();
        redraw();
      } else if (data === "\u001b[D" || data === "\u0002") {
        editor().left();
        redraw();
      } else if (data === "\u001b[C" || data === "\u0006") {
        editor().right();
        redraw();
      } else if (data === "\u001b[H" || data === "\u001b[1~" || data === "\u0001") {
        editor().home();
        redraw();
      } else if (data === "\u001b[F" || data === "\u001b[4~" || data === "\u0005") {
        editor().end();
        redraw();
      } else if (data === "\u001b[3~" || data === "\u0004") {
        editor().deleteCharacter();
        redraw();
      } else if (data === "\u0017") {
        editor().deletePreviousWord();
        redraw();
      } else if (data === "\u001b\u007f" || data === "\u001b\b") {
        editor().deletePreviousWord();
        redraw();
      } else if (data === "\u001b[1;3D" || data === "\u001bb") {
        editor().previousWord();
        redraw();
      } else if (data === "\u001b[1;3C" || data === "\u001bf") {
        editor().nextWord();
        redraw();
      } else if (data === "\u001bd") {
        editor().deleteNextWord();
        redraw();
      } else if (data === "\u001bc" || data === "\u001bC") {
        editor().changeWordCase(true);
        redraw();
      } else if (data === "\u001bl" || data === "\u001bL") {
        editor().changeWordCase(false);
        redraw();
      } else if (data === "\u0015") {
        editor().deleteBeforeCursor();
        redraw();
      } else if (data === "\u000b") {
        editor().deleteAfterCursor();
        redraw();
      } else if (data === "\u0014") {
        editor().transposeCharacters();
        redraw();
      } else if (data === "\u0012") {
        editor().reverseSearch();
        redraw();
      } else if (data === "\u001b.") {
        editor().insertLastElement();
        redraw();
      } else if (data === "\u000c") {
        // MD-CLI defines Ctrl-L as clear-screen, while classic CLI documents a
        // refresh of the input line. Both preserve the router session and edit
        // buffer, differing only in local terminal presentation.
        if (sessionState?.engine === "md") terminal.write("\x1b[2J\x1b[H");
        redraw();
      } else if (data === "\u001a") {
        // Ctrl-Z executes a pending line, then asks the active router engine to
        // return to its operational root. The UI does not mutate CLI context.
        busy = true;
        try {
          await completeEnterKeyword();
          terminal.write("\r\n");
          const submitted = editor().submit();
          archive.append(`${inputPrompt()}${submitted}`);
          let output = "";
          if (submitted) {
            output = await executeRef.current(submitted);
            sessionState = await stateRef.current();
            const intermediatePrompt = sessionState.prompt;
            if (output.endsWith(intermediatePrompt)) {
              output = output.slice(0, -intermediatePrompt.length);
            }
          }
          output += await executeRef.current("exit all");
          sessionState = await stateRef.current();
          writePaged(output);
        } catch (cause) {
          console.error("Console Ctrl-Z transport failed", cause);
          terminal.write(`Console unavailable.\r\n${prompt()}`);
          archive.append("Console unavailable.");
        } finally {
          busy = false;
        }
      } else if (data === "\u0003") {
        // Ctrl-C cancels the editable line without submitting a router command.
        editor().replace("");
        terminal.write(`^C\r\n${inputPrompt()}`);
      } else if (data === "\t" || data === "?") {
        if (data === "?" && editor().hasOpenQuote()) {
          editor().insert(data);
          redraw();
        } else {
          await showCompletion(data === "\t" ? "tab" : "question");
        }
      } else if (data === " ") {
        await showCompletion("space");
      } else if (data >= " " && data !== "\u007f") {
        editor().insert(data);
        redraw();
      }
      while (!busy && queuedInput.length) {
        const queued = queuedInput.shift()!;
        await processData(queued);
      }
    };
    const inputDisposable = terminal.onData((data) => { void processData(data); });
    const scrollDisposable = terminal.onScroll((position) => {
      // Once older disk rows exist, reaching the beginning of xterm's bounded
      // cache continues into the virtual transcript instead of ending history.
      // No React update occurs during ordinary scrolling inside the hot window.
      if (position === 0 && archive.lineCount > terminal.buffer.active.length) {
        setHistoryBoundaryRows(terminal.buffer.active.length);
        setHistoryOpen(true);
      }
    });
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
      scrollDisposable.dispose();
      terminal.dispose();
      terminalRef.current = null;
      fitRef.current = null;
      // Unregister only this disposed owner. App keeps no borrowed closure that
      // could later sample dead editor state after the panel is reopened.
      checkpointRegistrationRef.current?.(undefined);
    };
  // Callback identities change when App publishes a fresh runtime snapshot.
  // Refs above keep those operations current without destroying xterm, its
  // visible command line or its hot scrollback after every router command.
  }, [ready, archive, restorePresentation]);

  useEffect(() => {
    // Font size is a renderer preference, not session state. Updating the live
    // xterm option preserves scrollback, the active edit buffer and the C++
    // session while ResizeObserver recalculates the available row count.
    const terminal = terminalRef.current;
    if (!terminal) return;
    terminal.options.fontSize = fontSize;
    // xterm installs renderer dimensions on its next animation frame. Fitting
    // synchronously during the opening effect can read an uninitialized canvas
    // dimension object, so font changes join the same paint boundary as resize.
    const frame = window.requestAnimationFrame(() => fitRef.current?.fit());
    return () => window.cancelAnimationFrame(frame);
  }, [fontSize]);

  const handleTerminalWheel = (event: WheelEvent<HTMLDivElement>) => {
    if (historyOpenRef.current || !event.deltaY) return;
    const terminal = terminalRef.current;
    const viewport = hostRef.current?.querySelector<HTMLElement>(".xterm-viewport");
    if (!terminal || !viewport) return;
    // xterm renders the visible rows above its scrollable viewport. Browser
    // wheel events can therefore land on renderer layers instead of the native
    // scrollbar owner. Routing every vertical wheel from the terminal body to
    // the viewport makes mouse wheels, touchpads and Browser Use hit the same
    // scrollback without changing the router session or the archived history.
    const unit =
      // DOM_DELTA_LINE is 1 and DOM_DELTA_PAGE is 2. Using the numeric values
      // avoids importing a browser global into the React type namespace.
      event.deltaMode === 1
        ? fontSize * 1.35
        : event.deltaMode === 2
          ? viewport.clientHeight
          : 1;
    const before = viewport.scrollTop;
    viewport.scrollTop += event.deltaY * unit;
    const moved = viewport.scrollTop !== before;
    if (!moved && event.deltaY < 0 &&
        archive.lineCount > terminal.buffer.active.length) {
      // When the hot xterm window reaches its first retained row, one more
      // upward wheel opens the virtualized OPFS transcript. The full-history
      // reader is explicit UI state; the C++ CLI owner never receives a byte.
      setHistoryBoundaryRows(terminal.buffer.active.length);
      setHistoryOpen(true);
    }
    if (moved || event.deltaY < 0) {
      event.preventDefault();
      event.stopPropagation();
    }
  };

  return (
    <section className="terminal-panel" ref={panelRef}>
      <PanelResizeHandle axis="y" className="terminal-resizer"
        defaultValue={360} direction={-1}
        label="Resize console" min={64}
        max={Math.max(64, window.innerHeight - 53)} value={height}
        onChange={onHeightChange} />
      <div className="terminal-head">
        <div className="terminal-tabs">{tabs?.length ? tabs.map((tab) => <div
          className={tab.id === activeTab ? "terminal-tab active" : "terminal-tab"}
          key={tab.id}><button onClick={() => selectTab?.(tab.id)}><i className="dot-good" />{tab.label}</button><button aria-label={`Close ${tab.label}`} onClick={() => closeTab?.(tab.id)}><X size={14} /></button></div>) : <div className="terminal-tab active"><button><i className="dot-good" />{systemName} console</button></div>}{newTab && <button className="terminal-new-tab" title="New router terminal" aria-label="New router terminal" onClick={newTab}><Plus size={16} /></button>}</div>
        <div className="terminal-actions">
          <button title="Clear visible terminal" aria-label="Clear visible terminal" onClick={() => terminalRef.current?.clear()}><Eraser size={16} /></button>
          <button title="Terminal settings" aria-label="Terminal settings" className={settingsOpen ? "active" : ""} onClick={() => setSettingsOpen((value) => !value)}><Settings2 size={16} /></button>
          <button title="Fullscreen console" aria-label="Fullscreen console" onClick={() => void (document.fullscreenElement ? document.exitFullscreen() : panelRef.current?.requestFullscreen())}><Maximize2 size={15} /></button>
          <button title="Close console" aria-label="Close console" onClick={close}><X size={16} /></button>
        </div>
      </div>
      {settingsOpen && <div className="terminal-settings"><label>Font size<input type="range" min="10" max="18" value={fontSize} onChange={(event) => setFontSize(Number(event.target.value))} /><span>{fontSize}px</span></label></div>}
      <div className="terminal-body" onWheelCapture={handleTerminalWheel}>
        <div className="terminal-host" ref={hostRef} />
        {historyOpen && <TerminalHistoryView archive={archive} fontSize={fontSize}
          liveRows={historyBoundaryRows}
          close={() => setHistoryOpen(false)} />}
      </div>
    </section>
  );
}
