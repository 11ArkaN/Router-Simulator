// DOM-independent terminal editor, pager and bounded byte queue. xterm renders
// these values but does not own CLI session semantics or router prompts.

import { parseTerminalPanelPresentation, type TerminalHistoryRegion,
  type TerminalLineEditorState as TerminalLineEditorStateV1,
  type TerminalPagerState as TerminalPagerStateV1,
  type TerminalPanelPresentation } from "./terminal-contract";

export class TerminalLineEditor {
  // This model owns only local keystroke editing. Router session state, current
  // CLI engine and configuration remain in C++. Keeping editing deterministic
  // makes byte sequences testable without depending on xterm's renderer.
  private buffer = "";
  private cursorIndex = 0;
  private readonly history: string[] = [];
  private historyIndex = 0;
  private reverseSearchIndex = 0;
  private reverseSearchQuery: string | undefined;
  // Source: nokia.sros.26_7.md_cli.navigation. The default MD-CLI per-session
  // history size is 50. Bounding the local keystroke projection also prevents
  // an indefinitely open browser tab from retaining every submitted line.
  private static readonly historyLimit = 50;

  get value(): string { return this.buffer; }
  get cursor(): number { return this.cursorIndex; }

  snapshot(): TerminalLineEditorStateV1 {
    // Return copies because the editor remains mutable after a checkpoint
    // request. A manifest must describe one instant, not a live history array.
    return { buffer: this.buffer, cursor: this.cursorIndex,
      history: [...this.history], historyIndex: this.historyIndex };
  }

  restore(state: TerminalLineEditorStateV1): void {
    // Callers validate the enclosing versioned record first. Replacing every
    // field together prevents history navigation from observing old indices
    // paired with a newly restored command list.
    this.buffer = state.buffer;
    this.cursorIndex = state.cursor;
    this.history.splice(0, this.history.length, ...state.history);
    this.historyIndex = state.historyIndex;
    this.endReverseSearch();
  }

  insert(text: string): string {
    // xterm reports printable input as text chunks. Insert at the modeled
    // cursor so pasted text and mid-line edits follow the same path.
    this.buffer = this.buffer.slice(0, this.cursorIndex) + text +
      this.buffer.slice(this.cursorIndex);
    this.cursorIndex += text.length;
    this.endReverseSearch();
    return this.buffer;
  }

  backspace(): string {
    if (this.cursorIndex) {
      this.buffer = this.buffer.slice(0, this.cursorIndex - 1) +
        this.buffer.slice(this.cursorIndex);
      --this.cursorIndex;
      this.endReverseSearch();
    }
    return this.buffer;
  }

  deleteCharacter(): string {
    if (this.cursorIndex < this.buffer.length) {
      this.buffer = this.buffer.slice(0, this.cursorIndex) +
        this.buffer.slice(this.cursorIndex + 1);
      this.endReverseSearch();
    }
    return this.buffer;
  }

  left(): number { return this.cursorIndex = Math.max(0, this.cursorIndex - 1); }
  right(): number { return this.cursorIndex = Math.min(this.buffer.length, this.cursorIndex + 1); }
  home(): number { return this.cursorIndex = 0; }
  end(): number { return this.cursorIndex = this.buffer.length; }

  previousWord(): number {
    while (this.cursorIndex && this.buffer[this.cursorIndex - 1] === " ") --this.cursorIndex;
    while (this.cursorIndex && this.buffer[this.cursorIndex - 1] !== " ") --this.cursorIndex;
    return this.cursorIndex;
  }

  nextWord(): number {
    while (this.cursorIndex < this.buffer.length && this.buffer[this.cursorIndex] !== " ") ++this.cursorIndex;
    while (this.cursorIndex < this.buffer.length && this.buffer[this.cursorIndex] === " ") ++this.cursorIndex;
    return this.cursorIndex;
  }

  deletePreviousWord(): string {
    const end = this.cursorIndex;
    this.previousWord();
    this.buffer = this.buffer.slice(0, this.cursorIndex) + this.buffer.slice(end);
    this.endReverseSearch();
    return this.buffer;
  }

  deleteNextWord(): string {
    const start = this.cursorIndex;
    this.nextWord();
    this.buffer = this.buffer.slice(0, start) + this.buffer.slice(this.cursorIndex);
    this.cursorIndex = start;
    this.endReverseSearch();
    return this.buffer;
  }

  deleteBeforeCursor(): string {
    this.buffer = this.buffer.slice(this.cursorIndex);
    this.cursorIndex = 0;
    this.endReverseSearch();
    return this.buffer;
  }

  deleteAfterCursor(): string {
    this.buffer = this.buffer.slice(0, this.cursorIndex);
    this.endReverseSearch();
    return this.buffer;
  }

  transposeCharacters(): string {
    // Readline-style Ctrl-T exchanges the character before the cursor with the
    // current character. At end of line it exchanges the final pair, while a
    // cursor at column zero or a one-character line cannot change anything.
    if (this.buffer.length < 2 || this.cursorIndex === 0) return this.buffer;
    const right = Math.min(this.cursorIndex, this.buffer.length - 1);
    const left = right - 1;
    this.buffer = this.buffer.slice(0, left) + this.buffer[right] +
      this.buffer[left] + this.buffer.slice(right + 1);
    this.cursorIndex = Math.min(this.buffer.length, this.cursorIndex + 1);
    this.endReverseSearch();
    return this.buffer;
  }

  changeWordCase(upper: boolean): string {
    // Esc-C and Esc-L affect the remainder of the word at the cursor and then
    // leave the cursor at that word's end, matching the documented CLI editor.
    const start = this.cursorIndex;
    while (this.cursorIndex < this.buffer.length && this.buffer[this.cursorIndex] !== " ") {
      ++this.cursorIndex;
    }
    const word = this.buffer.slice(start, this.cursorIndex);
    this.buffer = this.buffer.slice(0, start) +
      (upper ? word.toUpperCase() : word.toLowerCase()) +
      this.buffer.slice(this.cursorIndex);
    this.endReverseSearch();
    return this.buffer;
  }

  hasOpenQuote(): boolean {
    // SR OS permits spaces and special characters inside a quoted parameter.
    // The terminal adapter uses quote parity only to decide whether '?' is
    // literal input; command syntax validation remains entirely in C++.
    let quoted = false;
    for (const character of this.buffer) {
      if (character === '"') quoted = !quoted;
    }
    return quoted;
  }

  replace(text: string): string {
    this.buffer = text;
    this.cursorIndex = text.length;
    this.endReverseSearch();
    return this.buffer;
  }

  submit(): string {
    const submitted = this.buffer;
    if (submitted.trim() && this.history.at(-1) !== submitted) {
      this.history.push(submitted);
      if (this.history.length > TerminalLineEditor.historyLimit) this.history.shift();
    }
    this.historyIndex = this.history.length;
    this.endReverseSearch();
    this.buffer = "";
    this.cursorIndex = 0;
    return submitted;
  }

  previous(): string {
    this.endReverseSearch();
    if (this.historyIndex > 0) --this.historyIndex;
    this.buffer = this.historyIndex < this.history.length ? this.history[this.historyIndex] : "";
    this.cursorIndex = this.buffer.length;
    return this.buffer;
  }

  next(): string {
    this.endReverseSearch();
    if (this.historyIndex < this.history.length) ++this.historyIndex;
    this.buffer = this.historyIndex < this.history.length ? this.history[this.historyIndex] : "";
    this.cursorIndex = this.buffer.length;
    return this.buffer;
  }

  reverseSearch(): string {
    // Ctrl-R searches backward using the text already present on the line.
    // Repeated presses continue before the last match, while ordinary edits
    // naturally start a new search from the current history tail.
    if (this.reverseSearchQuery === undefined) {
      this.reverseSearchQuery = this.buffer;
      this.reverseSearchIndex = this.history.length;
    }
    const query = this.reverseSearchQuery;
    for (let index = this.reverseSearchIndex; index > 0; --index) {
      const candidate = this.history[index - 1];
      if (candidate.includes(query)) {
        this.reverseSearchIndex = index - 1;
        this.buffer = candidate;
        this.cursorIndex = candidate.length;
        return this.buffer;
      }
    }
    return this.buffer;
  }

  insertLastElement(): string {
    // Esc-. recalls the last syntactic element of the previous command. Quote
    // boundaries are honored so a multi-word description remains one element.
    const previous = this.history.at(-1);
    if (!previous) return this.buffer;
    let quoted = false;
    let start = 0;
    for (let index = 0; index < previous.length; ++index) {
      if (previous[index] === '"') quoted = !quoted;
      else if (previous[index] === " " && !quoted) start = index + 1;
    }
    return this.insert(previous.slice(start));
  }

  private endReverseSearch(): void {
    // Editing after a recalled match starts a new search sequence. Cursor-only
    // movement is intentionally excluded because it does not alter the query
    // text or the history ordering used by Ctrl-R.
    this.reverseSearchQuery = undefined;
    this.reverseSearchIndex = this.history.length;
  }
}

export class TerminalInputQueue {
  // xterm onData is the sole producer and processData is the sole consumer.
  // Capacity is measured in UTF-8 bytes because the C ABI receives UTF-8, not
  // JavaScript code units. Overflow returns false without modifying FIFO state;
  // the adapter then disables stdin to apply visible backpressure.
  private readonly chunks: Array<{ text: string; bytes: number }> = [];
  private used = 0;
  // Capacity is supplied by the active generated runtime profile. Requiring it
  // here prevents a second browser-only mailbox limit from drifting.
  constructor(private readonly capacity: number) {}

  push(text: string): boolean {
    const bytes = new TextEncoder().encode(text).byteLength;
    if (this.used + bytes > this.capacity) return false;
    this.chunks.push({ text, bytes });
    this.used += bytes;
    return true;
  }

  shift(): string | undefined {
    const chunk = this.chunks.shift();
    if (!chunk) return undefined;
    this.used -= chunk.bytes;
    return chunk.text;
  }

  get length(): number { return this.chunks.length; }
  get byteLength(): number { return this.used; }

  snapshot(): string[] { return this.chunks.map((chunk) => chunk.text); }

  restore(chunks: string[]): void {
    // Restore through push so UTF-8 accounting and the all-or-nothing capacity
    // rule stay identical to live input admission.
    this.chunks.splice(0);
    this.used = 0;
    for (const chunk of chunks) {
      if (!this.push(chunk)) throw new Error("Restored terminal input exceeds its profile capacity");
    }
  }
}

export type PagerResult = "continue" | "complete" | "quit" | "unchanged";

export class TerminalPager {
  // SR OS 26.7 uses a less-style pager. This model owns only the visible line
  // window; the router command has already executed once and cannot be retried
  // by navigation. One terminal row is reserved for the status line.
  private readonly lines: string[];
  private readonly height: number;
  private offset = 0;

  constructor(output: string, rows: number) {
    this.lines = output.replaceAll("\r", "").split("\n");
    this.height = Math.max(1, rows - 1);
  }

  static restore(state: TerminalPagerStateV1): TerminalPager {
    const pager = new TerminalPager(state.output, state.rows);
    pager.offset = state.offset;
    return pager;
  }

  snapshot(): TerminalPagerStateV1 {
    // Join with LF because pager parsing normalizes CR on construction. This
    // canonical representation avoids platform line-ending drift in .netsim.
    return { output: this.lines.join("\n"), rows: this.height + 1, offset: this.offset };
  }

  get active(): boolean { return this.lines.length > this.height && this.end < this.lines.length; }
  get page(): string[] { return this.lines.slice(this.offset, this.end); }

  get status(): string {
    // Percent and line bounds are recomputed from the current window, matching
    // the information shown by the 26.7 MD-CLI pager without leaking UI state
    // into the C++ CLI session.
    const percent = Math.floor((this.end * 100) / this.lines.length);
    return `--(more)--(${percent}%)--(lines ${this.offset + 1}-${this.end}/${this.lines.length})--`;
  }

  handle(input: string): PagerResult {
    const maximum = Math.max(0, this.lines.length - this.height);
    const previous = this.offset;
    if (input === "q" || input === "Q" || input === "\u0003" || input === "\u001a") return "quit";
    if (input === " " || input === "f" || input === "\u0006" || input === "\u0016" ||
        input === "\u001b[6~" || input === "\u001b[C") this.offset += this.height;
    else if (input === "\r" || input === "\n" || input === "e" || input === "j" ||
             input === "\u0005" || input === "\u000a" || input === "\u000d" ||
             input === "\u000e" || input === "\u001b[B") ++this.offset;
    else if (input === "d" || input === "\u0004" || input === "\t") this.offset += Math.max(1, Math.floor(this.height / 2));
    else if (input === "b" || input === "\u0002" || input === "\u001b[5~" || input === "\u001b[D") this.offset -= this.height;
    else if (input === "u" || input === "\u0015") this.offset -= Math.max(1, Math.floor(this.height / 2));
    else if (input === "k" || input === "y" || input === "-" || input === "\u0010" ||
             input === "\u0019" || input === "\u007f" || input === "\b" ||
             input === "\u001b[A") --this.offset;
    else if (input === "g" || input === "p" || input === "<" || input === "\u0001" ||
             input === "\u001b[H") this.offset = 0;
    else if (input === "G" || input === ">" || input === "\u001b[F") this.offset = maximum;
    else return "unchanged";
    this.offset = Math.max(0, Math.min(maximum, this.offset));
    if (this.offset === maximum) return "complete";
    return this.offset === previous ? "unchanged" : "continue";
  }

  private get end(): number { return Math.min(this.lines.length, this.offset + this.height); }
}

export interface TerminalCheckpointProvider {
  // The provider borrows no renderer objects. Its return value is a detached,
  // versioned snapshot safe to serialize after the function returns.
  snapshot(): TerminalPanelPresentation;
}

export function restoreTerminalPresentation(
  input: TerminalPanelPresentation | undefined,
  editors: Record<TerminalHistoryRegion, TerminalLineEditor>,
  queue: TerminalInputQueue
): TerminalPager | undefined {
  // Undefined is the normal project-only path. A present value crosses the
  // public parser even when it originated locally, keeping tests and imports
  // on exactly the same validation boundary.
  if (!input) return undefined;
  const state = parseTerminalPanelPresentation(input);
  for (const region of Object.keys(editors) as TerminalHistoryRegion[]) {
    editors[region].restore(state.editors[region]);
  }
  queue.restore(state.queuedInput);
  return state.pager ? TerminalPager.restore(state.pager) : undefined;
}
