// Storage-independent tests for transcript batching, indexing and range reads.
// The fake persists immutable chunks exactly like OPFS without browser globals.

import { describe, expect, it } from "vitest";
import { TerminalHistoryArchive, type TerminalHistoryStorage } from "./terminal-history";

class MemoryHistoryStorage implements TerminalHistoryStorage {
  readonly files = new Map<string, string>();

  async list(): Promise<Array<{ name: string; lineCount: number }>> {
    return Array.from(this.files.keys()).sort().map((name) => ({
      name,
      lineCount: Number(name.match(/^\d{13}-\d{6}-(\d+)-/)?.[1] ?? 0)
    }));
  }

  async write(_key: string, name: string, text: string): Promise<void> {
    this.files.set(name, text);
  }

  async read(_key: string, name: string): Promise<string> {
    const value = this.files.get(name);
    if (value === undefined) throw new Error("Missing transcript chunk");
    return value;
  }
}

describe("terminal history archive", () => {
  it("normalizes records and reads only a requested logical range", async () => {
    const storage = new MemoryHistoryStorage();
    const archive = new TerminalHistoryArchive("router:r1", storage);
    archive.append("banner\r\n");
    archive.append("A:R1# show\routput\nA:R1# ");

    const snapshot = await archive.snapshot();
    expect(snapshot.totalLines).toBe(4);
    expect(storage.files.size).toBe(1);
    expect(await archive.readRange(snapshot, 1, 2)).toEqual([
      "A:R1# show", "output"
    ]);
  });

  it("rebuilds line offsets from immutable chunk filenames", async () => {
    const storage = new MemoryHistoryStorage();
    const first = new TerminalHistoryArchive("router:r1", storage);
    first.append("one\ntwo");
    await first.close();

    const reopened = new TerminalHistoryArchive("router:r1", storage);
    reopened.append("three");
    const snapshot = await reopened.snapshot();
    expect(snapshot.totalLines).toBe(3);
    expect(await reopened.readRange(snapshot, 0, 3)).toEqual(["one", "two", "three"]);
  });
});
