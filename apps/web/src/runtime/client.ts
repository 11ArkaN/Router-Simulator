// Main-thread runtime bridge and SharedArrayBuffer telemetry reader. This is
// the only browser module allowed to encode the versioned runtime protocol.

import { GENERATED_PROFILE, RUNTIME_PROTOCOL, parseRuntimeSnapshot,
  type HostConfig, type LinkConfig, type RunningConfig,
  type RuntimeSnapshot } from "@router-simulator/contracts";

type Pending = { resolve(value: string): void; reject(error: Error): void };
type BinaryPending = { resolve(value: Uint8Array): void; reject(error: Error): void };
interface TelemetryLayout {
  abi: number; size: number; sequence: number; abiVersion: number;
  workerCount: number; portBitmap: number; controlThreadId: number;
  forwardingThreadId: number; capturedFrames: number; captureDropped: number;
  droppedPackets: number; cliCancelRequested: number;
}
export interface TerminalState {
  engine: "md" | "classic";
  historyRegion: "md-operational" | "md-configuration" | "classic";
  banner: string;
  prompt: string;
}
export type HardwareAction =
  { kind: "insert-card"; slot: number; type: string } |
  { kind: "remove-card"; slot: number } |
  { kind: "insert-mda"; cardSlot: number; mdaSlot: number; type: string } |
  { kind: "remove-mda"; cardSlot: number; mdaSlot: number };

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder();

function netstrings(values: string[]): string {
  // Length framing prevents user-entered names and descriptions from changing
  // field boundaries in the control protocol.
  return values.map((value) => `${utf8.encode(value).byteLength}:${value},`).join("");
}

// Decodes C++ terminal state without interpreting its contents. Parsing bytes
// rather than JavaScript code units preserves non-ASCII configured names.
function parseNetstrings(input: string): string[] {
  const values: string[] = [];
  const bytes = utf8.encode(input);
  let offset = 0;
  while (offset < bytes.length) {
    let colon = offset;
    while (colon < bytes.length && bytes[colon] !== 0x3a) ++colon;
    const length = Number(utf8Decoder.decode(bytes.subarray(offset, colon)));
    const start = colon + 1;
    const end = start + length;
    if (colon === bytes.length || !Number.isSafeInteger(length) || length < 0 ||
        bytes[end] !== 0x2c) {
      throw new Error("Runtime returned an invalid length-framed value");
    }
    values.push(utf8Decoder.decode(bytes.subarray(start, end)));
    offset = end + 1;
  }
  return values;
}

export class RuntimeClient {
  // The Worker owns Wasm and its pthreads. React receives only bounded control
  // replies and low-frequency state projections.
  private readonly worker: Worker;
  private readonly pending = new Map<number, Pending>();
  private readonly binaryPending = new Map<number, BinaryPending>();
  private nextId = 1;
  private closed = false;
  private telemetryPage?: {
    buffer: SharedArrayBuffer; offset: number; size: number; layout: TelemetryLayout
  };

  constructor() {
    // Shared memory is a semantic requirement, so deployment isolation is
    // checked before starting a Worker instead of selecting a fallback runtime.
    if (!crossOriginIsolated || typeof SharedArrayBuffer === "undefined") {
      throw new Error("WebAssembly threads require cross-origin isolation. Check COOP and COEP headers.");
    }
    this.worker = new Worker(new URL("./runtime.worker.ts", import.meta.url), { type: "module" });
    this.worker.onmessage = ({ data }: MessageEvent<{ id?: number; ok?: boolean; value?: string;
      error?: string; kind?: string; buffer?: SharedArrayBuffer; offset?: number;
      size?: number; layout?: TelemetryLayout; bytes?: ArrayBuffer }>) => {
      if (data.kind === "telemetry-page" && data.buffer && data.offset !== undefined &&
          data.size && data.layout) {
        this.telemetryPage = {
          buffer: data.buffer, offset: data.offset, size: data.size, layout: data.layout
        };
        return;
      }
      if (data.ok === false && data.id !== undefined && this.binaryPending.has(data.id)) {
        const binary = this.binaryPending.get(data.id)!;
        this.binaryPending.delete(data.id);
        binary.reject(new Error(data.error ?? "Runtime binary request failed"));
        return;
      }
      if (data.bytes && data.id !== undefined) {
        const binary = this.binaryPending.get(data.id);
        if (!binary) return;
        this.binaryPending.delete(data.id);
        binary.resolve(new Uint8Array(data.bytes));
        return;
      }
      const pending = this.pending.get(data.id ?? -1);
      if (!pending) return;
      this.pending.delete(data.id ?? -1);
      if (data.ok) pending.resolve(data.value ?? "");
      else pending.reject(new Error(data.error ?? "Runtime request failed"));
    };
    this.worker.onerror = (event) => {
      for (const pending of this.pending.values()) pending.reject(new Error(event.message));
      this.pending.clear();
    };
  }

  private command(command: string): Promise<string> {
    // Correlation IDs detach request ordering from Worker response scheduling.
    // Only control text crosses postMessage; packet buffers never do.
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      if (this.closed) return reject(new Error("Runtime client is closed"));
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, command });
    });
  }

  private binary(action: "capture-export" | "checkpoint-export", bytes?: Uint8Array): Promise<Uint8Array> {
    // Binary exports are copied once in the Worker and transferred. Imports
    // clone caller bytes so later mutation cannot change the in-flight request.
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      if (this.closed) return reject(new Error("Runtime client is closed"));
      this.binaryPending.set(id, { resolve, reject });
      const buffer = bytes?.slice().buffer;
      this.worker.postMessage({ id, action, bytes: buffer }, buffer ? [buffer] : []);
    });
  }

  // Requests an immutable PCAPNG projection after the forwarding barrier.
  exportCapture(): Promise<Uint8Array> { return this.binary("capture-export"); }
  // Requests a structural checkpoint rather than a raw shared-memory dump.
  exportCheckpoint(): Promise<Uint8Array> { return this.binary("checkpoint-export"); }

  importCheckpoint(bytes: Uint8Array): Promise<string> {
    // The C++ decoder validates ABI, profile, schema and every field before it
    // atomically replaces live control-owned state.
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const buffer = bytes.slice().buffer;
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, action: "checkpoint-import", bytes: buffer }, [buffer]);
    });
  }

  async snapshot(): Promise<RuntimeSnapshot> {
    // JSON is parsed and structurally validated at the Worker trust boundary.
    return parseRuntimeSnapshot(JSON.parse(await this.command(RUNTIME_PROTOCOL.snapshot)));
  }

  telemetry(base: RuntimeSnapshot): RuntimeSnapshot {
    // C++ publishes offsetof values compiled for the current Wasm binary. The
    // reader does not reproduce alignment rules or assume a struct byte size.
    const page = this.telemetryPage;
    if (!page || page.size !== page.layout.size ||
        page.layout.abi !== GENERATED_PROFILE.abi.telemetry) return base;
    const sequence = new Int32Array(page.buffer, page.offset + page.layout.sequence, 1);
    const view = new DataView(page.buffer, page.offset, page.size);
    for (let attempt = 0; attempt < GENERATED_PROFILE.timing.telemetry_read_attempts; ++attempt) {
      const before = Atomics.load(sequence, 0) >>> 0;
      if (before & 1) continue;
      const abi = view.getUint32(page.layout.abiVersion, true);
      const bitmap = view.getUint32(page.layout.portBitmap, true);
      const captured = Number(view.getBigUint64(page.layout.capturedFrames, true));
      const captureDropped = Number(view.getBigUint64(page.layout.captureDropped, true));
      const dropped = Number(view.getBigUint64(page.layout.droppedPackets, true));
      const after = Atomics.load(sequence, 0) >>> 0;
      if (before !== after || (after & 1) || abi !== GENERATED_PROFILE.abi.telemetry) continue;
      return {
        ...base,
        ports: base.ports.map((port, index) => ({
          ...port, oper: (bitmap & (1 << index)) ? "up" : "down"
        })),
        captureCount: captured,
        captureDropped,
        droppedPackets: dropped
      };
    }
    return base;
  }

  async configureHosts(hosts: HostConfig[]): Promise<RuntimeSnapshot> {
    // Every endpoint crosses in one ordered transaction, permitting identity
    // swaps without exposing a transient duplicate to forwarding.
    const response = await this.command(RUNTIME_PROTOCOL.project_hosts +
      hosts.flatMap((host) => [host.mac, host.address, host.gateway]).join("|"));
    if (response.startsWith("ERROR:")) throw new Error(response);
    return parseRuntimeSnapshot(JSON.parse(response));
  }

  async configureLinks(links: LinkConfig[]): Promise<RuntimeSnapshot> {
    // Link delays preserve generated topology order and are applied by one
    // forwarding job, so no packet observes half a project edit.
    const response = await this.command(RUNTIME_PROTOCOL.project_links +
      links.map((link) => link.propagationDelayNs).join("|"));
    if (response.startsWith("ERROR:")) throw new Error(response);
    return parseRuntimeSnapshot(JSON.parse(response));
  }

  async configureRunning(config: RunningConfig): Promise<void> {
    // Length framing protects free-form descriptions from delimiter injection.
    // C++ stages the complete datastore before publishing it.
    const fields = [
      config.systemName,
      String(config.ports.length),
      ...config.ports.flatMap((port) => [port.id, port.admin, String(port.mtu), port.description]),
      String(config.interfaces.length),
      // Interface port and prefix are control-plane configuration, not UI
      // topology hints. They cross the same atomic netstring transaction as
      // admin state so forwarding never observes a half-rebound interface.
      ...config.interfaces.flatMap((item) => [item.name, item.admin, item.port, item.address]),
      String(config.staticRoutes.length),
      ...config.staticRoutes.flatMap((route) => [route.prefix, route.nextHop])
    ];
    const output = await this.command(RUNTIME_PROTOCOL.project_running + netstrings(fields));
    if (output.startsWith("ERROR:")) throw new Error(output);
  }

  async configureProvisioning(cardType: string | null, mdaType: string | null): Promise<RuntimeSnapshot> {
    // Parent and child provisioning form one validated pair. Null is encoded by
    // the versioned protocol token rather than a hardware-type sentinel.
    const output = await this.command(RUNTIME_PROTOCOL.project_provisioning +
      `${cardType ?? RUNTIME_PROTOCOL.provisioning_absent}|${mdaType ?? RUNTIME_PROTOCOL.provisioning_absent}`);
    if (output.startsWith("ERROR:")) throw new Error(output);
    return parseRuntimeSnapshot(JSON.parse(output));
  }

  async changeHardware(action: HardwareAction): Promise<RuntimeSnapshot> {
    // Structured UI intent is converted to protocol text only here. Explicit
    // slot numbers keep physical inventory independent from component layout.
    let command: string;
    switch (action.kind) {
      case "insert-card":
        command = RUNTIME_PROTOCOL.hardware_insert_card + `${action.slot}:${action.type}`;
        break;
      case "remove-card":
        command = RUNTIME_PROTOCOL.hardware_remove_card + action.slot;
        break;
      case "insert-mda":
        command = RUNTIME_PROTOCOL.hardware_insert_mda +
          `${action.cardSlot}:${action.mdaSlot}:${action.type}`;
        break;
      case "remove-mda":
        command = RUNTIME_PROTOCOL.hardware_remove_mda + `${action.cardSlot}:${action.mdaSlot}`;
        break;
    }
    const output = await this.command(command);
    if (output.startsWith("ERROR:")) throw new Error(output);
    return parseRuntimeSnapshot(JSON.parse(output));
  }

  async setLink(portId: string, up: boolean): Promise<RuntimeSnapshot> {
    // The core validates the generated physical port ID and clears only that
    // port's adjacency when carrier is removed.
    const output = await this.command((up ? RUNTIME_PROTOCOL.link_up : RUNTIME_PROTOCOL.link_down) + portId);
    if (output.startsWith("ERROR:")) throw new Error(output);
    return parseRuntimeSnapshot(JSON.parse(output));
  }

  executeTerminal(input: string): Promise<string> {
    // Terminal input remains opaque to React and is parsed only by the active
    // router-owned CLI engine.
    return this.command(RUNTIME_PROTOCOL.terminal_execute + input);
  }

  completeTerminal(input: string, trigger: "tab" | "question" | "space"): Promise<string> {
    // Completion is read-only and cannot submit the completed command.
    return this.command(RUNTIME_PROTOCOL.terminal_complete + `${trigger}|${input}`);
  }

  cancelTerminal(): void {
    // The control owner is synchronously waiting for the active ping result, so
    // another mailbox command could not overtake it. One documented atomic
    // word reaches both C++ shards directly without exposing packet memory.
    const page = this.telemetryPage;
    if (!page || page.layout.cliCancelRequested + 4 > page.size) return;
    const cancellation = new Int32Array(
      page.buffer, page.offset + page.layout.cliCancelRequested, 1
    );
    Atomics.store(cancellation, 0, 1);
    Atomics.notify(cancellation, 0);
  }

  async terminalState(): Promise<TerminalState> {
    // Prompt and engine state are returned by the same C++ session that executes
    // commands, eliminating duplicated frontend state transitions.
    const fields = parseNetstrings(await this.command(RUNTIME_PROTOCOL.terminal_state));
    const regions = ["md-operational", "md-configuration", "classic"] as const;
    if (fields.length !== 4 || !["md", "classic"].includes(fields[0]) ||
        !regions.includes(fields[1] as typeof regions[number])) {
      throw new Error("Runtime returned an incompatible terminal state");
    }
    return {
      engine: fields[0] as "md" | "classic",
      historyRegion: fields[1] as typeof regions[number],
      banner: fields[2],
      prompt: fields[3]
    };
  }

  hostPing(sourceId: string, destinationId: string): Promise<string> {
    // IDs are resolved against generated topology in C++ before encoded frames
    // enter the selected endpoint's physical link.
    return this.command(RUNTIME_PROTOCOL.host_ping + `${sourceId}:${destinationId}`);
  }

  setCapture(active: boolean): Promise<string> {
    // Capture toggling controls observation only and never pauses forwarding.
    return this.command(active ? RUNTIME_PROTOCOL.capture_start : RUNTIME_PROTOCOL.capture_stop);
  }

  close(): void {
    // All pending callers fail immediately. C++ receives a graceful shutdown
    // request, with Worker termination retained as a bounded trap fallback.
    if (this.closed) return;
    this.closed = true;
    for (const pending of this.pending.values()) pending.reject(new Error("Runtime client is closing"));
    this.pending.clear();
    for (const pending of this.binaryPending.values()) pending.reject(new Error("Runtime client is closing"));
    this.binaryPending.clear();
    this.worker.postMessage({ id: 0, shutdown: true });
    window.setTimeout(() => this.worker.terminate(),
      GENERATED_PROFILE.timing.worker_shutdown_milliseconds);
  }
}
