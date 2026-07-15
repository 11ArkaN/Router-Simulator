// DOM-independent terminal editor, pager and bounded byte queue. xterm renders
// these values but does not own CLI session semantics or router prompts.

import { GENERATED_PROFILE } from "@router-simulator/contracts";

export class TerminalLineEditor {
  // This model owns only local keystroke editing. Router session state, current
  // CLI engine and configuration remain in C++. Keeping editing deterministic
  // makes byte sequences testable without depending on xterm's renderer.
  private buffer = "";
  private readonly history: string[] = [];
  private historyIndex = 0;
  // Source: nokia.sros.26_7.md_cli.navigation. The default MD-CLI per-session
  // history size is 50. Bounding the local keystroke projection also prevents
  // an indefinitely open browser tab from retaining every submitted line.
  private static readonly historyLimit = GENERATED_PROFILE.cliDefaults.history_entries;

  get value(): string { return this.buffer; }

  insert(text: string): string {
    this.buffer += text;
    return this.buffer;
  }

  backspace(): string {
    if (this.buffer.length) this.buffer = this.buffer.slice(0, -1);
    return this.buffer;
  }

  replace(text: string): string {
    this.buffer = text;
    return this.buffer;
  }

  submit(): string {
    const submitted = this.buffer;
    if (submitted.trim() && this.history.at(-1) !== submitted) {
      this.history.push(submitted);
      if (this.history.length > TerminalLineEditor.historyLimit) this.history.shift();
    }
    this.historyIndex = this.history.length;
    this.buffer = "";
    return submitted;
  }

  previous(): string {
    if (this.historyIndex > 0) --this.historyIndex;
    this.buffer = this.historyIndex < this.history.length ? this.history[this.historyIndex] : "";
    return this.buffer;
  }

  next(): string {
    if (this.historyIndex < this.history.length) ++this.historyIndex;
    this.buffer = this.historyIndex < this.history.length ? this.history[this.historyIndex] : "";
    return this.buffer;
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
}

export function paginateTerminal(output: string, rows: number): string[][] {
  // Two rows remain available for --More-- and the current prompt. Pagination
  // changes only rendering slices and never re-executes a command to get data.
  const height = Math.max(1, rows - 2);
  const lines = output.replaceAll("\r", "").split("\n");
  const pages: string[][] = [];
  for (let index = 0; index < lines.length; index += height) {
    pages.push(lines.slice(index, index + height));
  }
  return pages;
}
