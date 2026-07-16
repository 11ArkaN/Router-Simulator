// Disk-backed terminal transcript split into independently readable OPFS chunks.
// The archive owns transcript ordering; xterm owns only the bounded live screen.

const CHUNK_CHARACTERS = 64 * 1024;
const CHUNK_FILE = /^(\d{13})-(\d{6})-(\d+)-[0-9a-f-]+\.log$/;

export interface TerminalHistoryChunk {
  name: string;
  startLine: number;
  lineCount: number;
}

export interface TerminalHistorySnapshot {
  chunks: readonly TerminalHistoryChunk[];
  totalLines: number;
}

export interface TerminalHistoryStorage {
  list(key: string): Promise<Array<{ name: string; lineCount: number }>>;
  write(key: string, name: string, text: string): Promise<void>;
  read(key: string, name: string): Promise<string>;
}

function countLines(value: string): number {
  // Records always end with LF. Counting without split avoids allocating one
  // short-lived string per line while a large command result is being archived.
  let lines = 0;
  for (let index = 0; index < value.length; ++index) {
    if (value.charCodeAt(index) === 10) ++lines;
  }
  return lines;
}

function normalizeRecord(value: string): string {
  // OPFS stores a renderer-independent transcript. CRLF and bare CR are screen
  // transport details; canonical LF keeps chunk indexing stable across hosts.
  const normalized = value.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
  return normalized.endsWith("\n") ? normalized : `${normalized}\n`;
}

async function directoryName(key: string): Promise<string> {
  // User-controlled project and system names never become path components.
  // A deterministic digest reopens the same transcript without path escaping.
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(digest).subarray(0, 16),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export class OpfsTerminalHistoryStorage implements TerminalHistoryStorage {
  private readonly directories = new Map<string, Promise<FileSystemDirectoryHandle>>();

  private directory(key: string): Promise<FileSystemDirectoryHandle> {
    // One promise per logical console serializes directory creation and avoids
    // repeatedly hashing the key or traversing OPFS for every transcript chunk.
    const existing = this.directories.get(key);
    if (existing) return existing;
    const created = (async () => {
      if (!navigator.storage?.getDirectory) throw new Error("OPFS is not available");
      const root = await navigator.storage.getDirectory();
      const history = await root.getDirectoryHandle("terminal-history", { create: true });
      return history.getDirectoryHandle(await directoryName(key), { create: true });
    })();
    this.directories.set(key, created);
    return created;
  }

  async list(key: string): Promise<Array<{ name: string; lineCount: number }>> {
    // Only filenames are read during startup. The encoded line count lets a
    // long-lived console rebuild its index without loading historical text.
    const result: Array<{ name: string; lineCount: number }> = [];
    // TypeScript's File System Access declarations still omit the iterable
    // members implemented by Chromium's OPFS directory handle.
    const directory = await this.directory(key) as FileSystemDirectoryHandle & {
      entries(): AsyncIterableIterator<[string, FileSystemHandle]>;
    };
    for await (const [name, handle] of directory.entries()) {
      if (handle.kind !== "file") continue;
      const match = CHUNK_FILE.exec(name);
      if (match) result.push({ name, lineCount: Number(match[3]) });
    }
    result.sort((left, right) => left.name.localeCompare(right.name));
    return result;
  }

  async write(key: string, name: string, text: string): Promise<void> {
    // createWritable commits atomically on close. A torn browser process leaves
    // either the previous directory state or the complete new immutable chunk.
    const handle = await (await this.directory(key)).getFileHandle(name, { create: true });
    const writer = await handle.createWritable();
    try {
      await writer.write(text);
      await writer.close();
    } catch (cause) {
      await writer.abort();
      throw cause;
    }
  }

  async read(key: string, name: string): Promise<string> {
    const handle = await (await this.directory(key)).getFileHandle(name);
    return (await handle.getFile()).text();
  }
}

export class TerminalHistoryArchive {
  private readonly chunks: TerminalHistoryChunk[] = [];
  private readonly cache = new Map<string, string[]>();
  private readonly initialized: Promise<void>;
  private pending: string[] = [];
  private pendingCharacters = 0;
  private pendingLines = 0;
  private totalLines = 0;
  private lastTimestamp = 0;
  private sequence = 0;
  private writeTail = Promise.resolve();
  private failed = false;

  constructor(private readonly key: string,
    private readonly storage: TerminalHistoryStorage = new OpfsTerminalHistoryStorage(),
    private readonly onError: (cause: unknown) => void = () => {}) {
    // Initialization owns ordering between old chunks and new appends. New text
    // may enter pending immediately, but no write starts before the old index is
    // known, so startLine remains monotonic after reopening the console.
    this.initialized = storage.list(key).then((stored) => {
      for (const chunk of stored) {
        this.chunks.push({ ...chunk, startLine: this.totalLines });
        this.totalLines += chunk.lineCount;
        this.lastTimestamp = Math.max(this.lastTimestamp, Number(chunk.name.slice(0, 13)) || 0);
      }
    }).catch((cause) => this.fail(cause));
  }

  get lineCount(): number {
    // This synchronous estimate is used only to decide whether xterm has older
    // disk-backed rows beyond its hot buffer. Exact range reads await flush.
    return this.totalLines + this.pendingLines;
  }

  append(value: string): void {
    if (!value || this.failed) return;
    const record = normalizeRecord(value);
    this.pending.push(record);
    this.pendingCharacters += record.length;
    this.pendingLines += countLines(record);
    if (this.pendingCharacters >= CHUNK_CHARACTERS) {
      // The CLI path never awaits OPFS. Immutable batches are handed to the
      // existing write chain, keeping command latency independent of disk I/O.
      void this.flush().catch((cause) => this.fail(cause));
    }
  }

  async flush(): Promise<void> {
    if (!this.pending.length || this.failed) {
      await this.writeTail;
      return;
    }
    const text = this.pending.join("");
    const lineCount = this.pendingLines;
    this.pending = [];
    this.pendingCharacters = 0;
    this.pendingLines = 0;
    const write = this.writeTail.then(async () => {
      await this.initialized;
      // Date.now can repeat and may even move backward after a host clock
      // adjustment. A local monotonic filename keeps reopened chunks ordered.
      this.lastTimestamp = Math.max(Date.now(), this.lastTimestamp + 1);
      const timestamp = this.lastTimestamp.toString().padStart(13, "0");
      const sequence = (this.sequence++).toString().padStart(6, "0");
      const name = `${timestamp}-${sequence}-${lineCount}-${crypto.randomUUID()}.log`;
      await this.storage.write(this.key, name, text);
      this.chunks.push({ name, startLine: this.totalLines, lineCount });
      this.totalLines += lineCount;
    });
    // A rejected operation is observed by the caller, while the private tail
    // remains awaitable during cleanup instead of becoming an unhandled promise.
    this.writeTail = write.catch(() => {});
    await write;
  }

  async snapshot(): Promise<TerminalHistorySnapshot> {
    await this.flush();
    await this.initialized;
    return { chunks: this.chunks.map((chunk) => ({ ...chunk })), totalLines: this.totalLines };
  }

  async readRange(snapshot: TerminalHistorySnapshot, start: number,
    count: number): Promise<string[]> {
    // Range reads touch only chunks intersecting the virtual viewport. At most
    // four decoded chunks stay hot, making RAM independent of transcript age.
    const end = Math.min(snapshot.totalLines, Math.max(0, start) + Math.max(0, count));
    const lines: string[] = [];
    for (const chunk of snapshot.chunks) {
      const chunkEnd = chunk.startLine + chunk.lineCount;
      if (chunkEnd <= start || chunk.startLine >= end) continue;
      const decoded = await this.readChunk(chunk.name);
      const from = Math.max(0, start - chunk.startLine);
      const to = Math.min(decoded.length, end - chunk.startLine);
      lines.push(...decoded.slice(from, to));
    }
    return lines;
  }

  async close(): Promise<void> {
    // Closing drains the last partial chunk but does not delete history. The
    // owning project can reopen it later through the same deterministic key.
    try {
      await this.flush();
    } catch (cause) {
      this.fail(cause);
    }
  }

  private async readChunk(name: string): Promise<string[]> {
    const cached = this.cache.get(name);
    if (cached) {
      // Reinsertion implements a tiny LRU without another allocation-heavy
      // bookkeeping structure on the history scroll path.
      this.cache.delete(name);
      this.cache.set(name, cached);
      return cached;
    }
    const text = await this.storage.read(this.key, name);
    const lines = text.endsWith("\n") ? text.slice(0, -1).split("\n") : text.split("\n");
    this.cache.set(name, lines);
    if (this.cache.size > 4) this.cache.delete(this.cache.keys().next().value!);
    return lines;
  }

  private fail(cause: unknown): void {
    // Repeated OPFS failures would otherwise enqueue unbounded text in RAM.
    // Disable this archive instance after the first failure and report once.
    if (this.failed) return;
    this.failed = true;
    this.pending = [];
    this.pendingCharacters = 0;
    this.pendingLines = 0;
    this.onError(cause);
  }
}
