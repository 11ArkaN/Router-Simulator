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
  private numericPrefix = "";
  private searchDirection: "forward" | "backward" | undefined;
  private searchBuffer = "";
  private lastSearchPattern = "";
  private lastSearchDirection: "forward" | "backward" | undefined;
  private matchLine: number | undefined;
  private searchHighlightVisible = false;
  private helpVisible = false;

  // The help is intentionally a compact view of Nokia's two pager command
  // tables. It fits the documented minimum 24-line terminal and therefore
  // does not need a second pager whose ownership and exit rules would differ
  // from the command output pager.
  private static readonly helpLines = [
    "Pager commands",
    "  h, H                         show this help",
    "  q, Q, Ctrl-C, Ctrl-Z        exit",
    "  (n)e, j, Enter, Down        move line forward",
    "  (n)d, Ctrl-D, Tab           move half screen forward",
    "  (n)f, Space, PageDown       move screen forward",
    "  (n)k, y, -, Up              move line backward",
    "  (n)u, Ctrl-U                move half screen backward",
    "  (n)b, PageUp, Left          move screen backward",
    "  g, p, <, Home               move to beginning",
    "  G, >, End                   move to end",
    "  (n)g, (n)G                  jump to line",
    "  /expression                 search forward",
    "  ?expression                 search backward",
    "  n, N                        repeat forward, backward",
    "  c, Ctrl-L, Esc+U            clear search highlighting"
  ];

  constructor(output: string, rows: number) {
    this.lines = output.replaceAll("\r", "").split("\n");
    this.height = Math.max(1, rows - 1);
  }

  static restore(state: TerminalPagerStateV1): TerminalPager {
    const pager = new TerminalPager(state.output, state.rows);
    pager.offset = Math.min(state.offset,
      Math.max(0, pager.lines.length - pager.height));
    pager.numericPrefix = state.numericPrefix ?? "";
    pager.searchDirection = state.searchDirection;
    pager.searchBuffer = state.searchBuffer ?? "";
    pager.lastSearchPattern = state.lastSearchPattern ?? "";
    pager.lastSearchDirection = state.lastSearchDirection;
    pager.matchLine = state.matchLine !== undefined &&
      state.matchLine < pager.lines.length ? state.matchLine : undefined;
    pager.searchHighlightVisible = state.searchHighlightVisible ?? false;
    pager.helpVisible = state.helpVisible ?? false;
    return pager;
  }

  snapshot(): TerminalPagerStateV1 {
    // Join with LF because pager parsing normalizes CR on construction. This
    // canonical representation avoids platform line-ending drift in .netsim.
    return {
      output: this.lines.join("\n"), rows: this.height + 1, offset: this.offset,
      ...(this.numericPrefix ? { numericPrefix: this.numericPrefix } : {}),
      ...(this.searchDirection ? { searchDirection: this.searchDirection,
        searchBuffer: this.searchBuffer } : {}),
      ...(this.lastSearchDirection ? { lastSearchPattern: this.lastSearchPattern,
        lastSearchDirection: this.lastSearchDirection } : {}),
      ...(this.matchLine !== undefined ? { matchLine: this.matchLine } : {}),
      ...(this.searchHighlightVisible ? { searchHighlightVisible: true } : {}),
      ...(this.helpVisible ? { helpVisible: true } : {})
    };
  }

  get active(): boolean { return this.lines.length > this.height && this.end < this.lines.length; }
  get page(): string[] { return this.lines.slice(this.offset, this.end); }

  get renderedPage(): string[] {
    if (this.helpVisible) return TerminalPager.helpLines.slice(0, this.height);
    // ANSI emphasis belongs to terminal presentation and never contaminates
    // archived output or router response bytes. Every visible match is
    // underlined, and the selected match receives inverse video as the Nokia
    // guide requires.
    return this.page.map((line, visibleIndex) => {
      const lineIndex = this.offset + visibleIndex;
      return this.decorateMatches(line, lineIndex === this.matchLine);
    });
  }

  get status(): string {
    // Percent and line bounds are recomputed from the current window, matching
    // the information shown by the 26.7 MD-CLI pager without leaking UI state
    // into the C++ CLI session.
    if (this.searchDirection) {
      const marker = this.searchDirection === "forward" ? "/" : "?";
      return `${marker}${this.searchBuffer}`;
    }
    if (this.numericPrefix) return this.numericPrefix;
    const percent = Math.floor((this.end * 100) / this.lines.length);
    return `--(more)--(${percent}%)--(lines ${this.offset + 1}-${this.end}/${this.lines.length})--`;
  }

  handle(input: string): PagerResult {
    // Escape sequences must remain atomic, while pasted printable text is
    // consumed as the same ordered bytes the terminal would have delivered
    // interactively. The strongest result wins when one chunk contains more
    // than one key.
    const atomic = ["\u001b[6~", "\u001b[5~", "\u001b[3~", "\u001b[C", "\u001b[D",
      "\u001b[B", "\u001b[A", "\u001b[H", "\u001b[F", "\u001bU"];
    if (atomic.includes(input)) return this.handleToken(input);
    let result: PagerResult = "unchanged";
    for (const token of input) {
      const next = this.handleToken(token);
      if (next === "quit" || next === "complete") result = next;
      else if (next === "continue" && result === "unchanged") result = next;
    }
    return result;
  }

  private handleToken(input: string): PagerResult {
    const maximum = Math.max(0, this.lines.length - this.height);
    const previous = this.offset;
    // Search input owns every printable character, including h and H. Checking
    // this first prevents a regular expression from accidentally opening help.
    if (this.searchDirection) return this.handleSearchInput(input);
    if (input === "h" || input === "H") {
      this.helpVisible = true;
      this.numericPrefix = "";
      return "continue";
    }
    // Any command after help returns to the immutable output and applies that
    // command in one operation. This avoids inventing a second nested session.
    this.helpVisible = false;
    if (/^[0-9]$/.test(input)) {
      // Nine digits exceed every bounded output in this application while
      // keeping Number conversion exact. Extra digits ring the terminal bell
      // through the unchanged result instead of wrapping a movement count.
      if (this.numericPrefix.length === 9) return "unchanged";
      this.numericPrefix += input;
      return "continue";
    }
    if (input === "/" || input === "?") {
      this.searchDirection = input === "/" ? "forward" : "backward";
      this.searchBuffer = this.lastSearchPattern;
      this.numericPrefix = "";
      return "continue";
    }
    if ((input === "n" || input === "N") && this.lastSearchDirection) {
      // SR OS assigns n to forward repetition and N to backward repetition,
      // regardless of the direction used to establish the expression.
      const direction = input === "n" ? "forward" : "backward";
      this.numericPrefix = "";
      return this.search(this.lastSearchPattern, direction);
    }
    if (input === "c" || input === "\u000c" || input === "\u001bU") {
      this.matchLine = undefined;
      this.searchHighlightVisible = false;
      this.numericPrefix = "";
      return "continue";
    }
    if (input === "q" || input === "Q" || input === "\u0003" || input === "\u001a") return "quit";
    const count = this.consumeCount();
    if ((input === "g" || input === "G") && count !== undefined) {
      // Line numbers in the pager are one-based. Both g and G accept the
      // documented numeric jump, while their unprefixed forms retain the
      // beginning and end meanings below.
      this.offset = Math.max(0, Math.min(maximum, count - 1));
    } else if (input === " " || input === "f" || input === "\u0006" || input === "\u0016" ||
        input === "\u001b[6~" || input === "\u001b[C") this.offset += (count ?? 1) * this.height;
    else if (input === "\r" || input === "\n" || input === "e" || input === "j" ||
             input === "\u0005" || input === "\u000a" || input === "\u000d" ||
             input === "\u000e" || input === "\u001b[B") this.offset += count ?? 1;
    else if (input === "d" || input === "\u0004" || input === "\t") this.offset += (count ?? 1) * Math.max(1, Math.floor(this.height / 2));
    else if (input === "b" || input === "\u0002" || input === "\u001b[5~" || input === "\u001b[D") this.offset -= (count ?? 1) * this.height;
    else if (input === "u" || input === "\u0015") this.offset -= (count ?? 1) * Math.max(1, Math.floor(this.height / 2));
    else if (input === "k" || input === "y" || input === "-" || input === "\u0010" ||
             input === "\u0019" || input === "\u000b" || input === "\u007f" ||
             input === "\b" || input === "\u001b[3~" || input === "\u001b[A")
      this.offset -= count ?? 1;
    else if (input === "g" || input === "p" || input === "<" || input === "\u0001" ||
             input === "\u001b[H") this.offset = 0;
    else if (input === "G" || input === ">" || input === "\u001b[F") this.offset = maximum;
    else {
      this.numericPrefix = "";
      return "unchanged";
    }
    this.offset = Math.max(0, Math.min(maximum, this.offset));
    this.matchLine = undefined;
    if (this.offset === maximum) return "complete";
    return this.offset === previous ? "unchanged" : "continue";
  }

  private consumeCount(): number | undefined {
    if (!this.numericPrefix) return undefined;
    const count = Number(this.numericPrefix);
    this.numericPrefix = "";
    return Math.max(1, count);
  }

  private handleSearchInput(input: string): PagerResult {
    if (input === "\u001b") {
      this.searchDirection = undefined;
      this.searchBuffer = "";
      return "continue";
    }
    if (input === "\u007f" || input === "\b") {
      this.searchBuffer = this.searchBuffer.slice(0, -1);
      return "continue";
    }
    if (input === "\r" || input === "\n") {
      const direction = this.searchDirection;
      const pattern = this.searchBuffer;
      this.searchDirection = undefined;
      this.searchBuffer = "";
      if (!direction || !pattern) return "unchanged";
      try {
        // Compile before publishing last-search state. An invalid expression
        // therefore cannot replace the previous repeatable search.
        void new RegExp(pattern);
      } catch {
        return "unchanged";
      }
      this.lastSearchPattern = pattern;
      this.lastSearchDirection = direction;
      return this.search(pattern, direction);
    }
    if (input >= " " && input !== "\u007f") {
      this.searchBuffer += input;
      return "continue";
    }
    return "unchanged";
  }

  private search(pattern: string,
    direction: "forward" | "backward"): PagerResult {
    let expression: RegExp;
    try { expression = new RegExp(pattern); } catch { return "unchanged"; }
    const origin = this.matchLine ??
      (direction === "forward" ? this.offset - 1 : this.end);
    for (let line = origin + (direction === "forward" ? 1 : -1);
         line >= 0 && line < this.lines.length;
         line += direction === "forward" ? 1 : -1) {
      expression.lastIndex = 0;
      if (!expression.test(this.lines[line] ?? "")) continue;
      this.matchLine = line;
      this.searchHighlightVisible = true;
      this.offset = Math.max(0, Math.min(
        Math.max(0, this.lines.length - this.height), line));
      // A search remains interactive even when its match is on the final
      // screen. The user must still be able to repeat backward or clear the
      // highlight before explicitly leaving the pager.
      return "continue";
    }
    return "unchanged";
  }

  private decorateMatches(line: string, selectedLine: boolean): string {
    if (!this.searchHighlightVisible || !this.lastSearchPattern) return line;
    let expression: RegExp;
    try { expression = new RegExp(this.lastSearchPattern, "g"); }
    catch { return line; }

    let rendered = "";
    let cursor = 0;
    for (const match of line.matchAll(expression)) {
      const start = match.index;
      const text = match[0] ?? "";
      // JavaScript advances a global zero-width match internally. There are no
      // bytes to underline, so leaving that assertion undecorated is safer
      // than modifying an adjacent character that did not match.
      if (!text) continue;
      rendered += line.slice(cursor, start);
      const emphasis = selectedLine ? "\x1b[7m\x1b[4m" : "\x1b[4m";
      const reset = selectedLine ? "\x1b[24m\x1b[27m" : "\x1b[24m";
      rendered += `${emphasis}${text}${reset}`;
      cursor = start + text.length;
    }
    return cursor === 0 ? line : rendered + line.slice(cursor);
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
