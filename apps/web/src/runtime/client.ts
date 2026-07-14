// Main-thread runtime bridge and SharedArrayBuffer telemetry reader. This module
// owns request correlation but never sees packet buffers or C++ class layouts.

import { parseRuntimeSnapshot, type HostConfig, type LinkConfig, type RunningConfig, type RuntimeSnapshot } from "@router-simulator/contracts";

type Pending = { resolve(value: string): void; reject(error: Error): void };
type BinaryPending = { resolve(value: Uint8Array): void; reject(error: Error): void };
const utf8 = new TextEncoder();

function netstrings(values: string[]): string {
  // Length framing keeps user text separate from the control protocol. Names
  // and descriptions may contain separators without becoming commands.
  return values.map((value) => `${utf8.encode(value).byteLength}:${value}`).join("");
}

export class RuntimeClient {
  // The browser Worker owns the Emscripten module. React sees only request IDs
  // and low-frequency string projections, never shared packet memory.
  private readonly worker: Worker;
  private readonly pending = new Map<number, Pending>();
  private readonly binaryPending = new Map<number, BinaryPending>();
  private nextId = 1;
  private closed = false;
  private telemetryPage?: { buffer: SharedArrayBuffer; offset: number; size: number };

  constructor() {
    // A single-thread fallback would violate runtime semantics. Fail before
    // loading Wasm when deployment headers do not enable SharedArrayBuffer.
    if (!crossOriginIsolated || typeof SharedArrayBuffer === "undefined") {
      throw new Error("WebAssembly threads require cross-origin isolation. Check COOP and COEP headers.");
    }
    this.worker = new Worker(new URL("./runtime.worker.ts", import.meta.url), { type: "module" });
    this.worker.onmessage = ({ data }: MessageEvent<{ id?: number; ok?: boolean; value?: string; error?: string;
      kind?: string; buffer?: SharedArrayBuffer; offset?: number; size?: number; bytes?: ArrayBuffer }>) => {
      if (data.kind === "telemetry-page" && data.buffer && data.offset !== undefined && data.size) {
        this.telemetryPage = { buffer: data.buffer, offset: data.offset, size: data.size };
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
      // IDs allow responses to complete independently without binding the UI to
      // Worker scheduling order.
      const pending = this.pending.get(data.id ?? -1);
      if (!pending) return;
      this.pending.delete(data.id ?? -1);
      if (data.ok) pending.resolve(data.value ?? "");
      else pending.reject(new Error(data.error ?? "Runtime request failed"));
    };
    this.worker.onerror = (event) => {
      // A Worker crash invalidates every outstanding request. Rejecting all of
      // them prevents UI operations from remaining pending indefinitely.
      for (const pending of this.pending.values()) pending.reject(new Error(event.message));
      this.pending.clear();
    };
  }

  command(command: string): Promise<string> {
    // postMessage carries control text only. Packet traffic stays in shared Wasm
    // memory and bounded C++ queues.
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      if (this.closed) {
        reject(new Error("Runtime client is closed"));
        return;
      }
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, command });
    });
  }

  private binary(action: "capture-export" | "checkpoint-export", bytes?: Uint8Array): Promise<Uint8Array> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      if (this.closed) return reject(new Error("Runtime client is closed"));
      this.binaryPending.set(id, { resolve, reject });
      const buffer = bytes?.slice().buffer;
      this.worker.postMessage({ id, action, bytes: buffer }, buffer ? [buffer] : []);
    });
  }

  exportCapture(): Promise<Uint8Array> { return this.binary("capture-export"); }
  exportCheckpoint(): Promise<Uint8Array> { return this.binary("checkpoint-export"); }

  importCheckpoint(bytes: Uint8Array): Promise<string> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const buffer = bytes.slice().buffer;
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, action: "checkpoint-import", bytes: buffer }, [buffer]);
    });
  }

  async snapshot(): Promise<RuntimeSnapshot> {
    // RuntimeSnapshot is a read-only UI projection, not a state object that can
    // be edited and sent back to the device.
    return parseRuntimeSnapshot(JSON.parse(await this.command("snapshot")));
  }

  telemetry(base: RuntimeSnapshot): RuntimeSnapshot {
    // Shared page layout is an ABI, not a C++ class layout. Atomics on sequence
    // implement the reader half of the seqlock documented in telemetry.hpp.
    // At most four retries bound UI work if control publishes concurrently.
    const page = this.telemetryPage;
    if (!page || page.size < 104) return base;
    const sequence = new Int32Array(page.buffer, page.offset, 1);
    const view = new DataView(page.buffer, page.offset, page.size);
    for (let attempt = 0; attempt < 4; ++attempt) {
      const before = Atomics.load(sequence, 0) >>> 0;
      if (before & 1) continue;
      const abi = view.getUint32(4, true);
      const bitmap = view.getUint32(28, true);
      const captured = Number(view.getBigUint64(80, true));
      const captureDropped = Number(view.getBigUint64(88, true));
      const dropped = Number(view.getBigUint64(96, true));
      const after = Atomics.load(sequence, 0) >>> 0;
      if (before !== after || (after & 1) || abi !== 3) continue;
      return {
        ...base,
        ports: base.ports.map((port, index) => ({ ...port, oper: (bitmap & (1 << index)) ? "up" : "down" })),
        captureCount: captured,
        captureDropped,
        droppedPackets: dropped
      };
    }
    return base;
  }

  async configureHosts(hosts: [HostConfig, HostConfig]): Promise<RuntimeSnapshot> {
    // The pair crosses the Worker boundary as one project transaction. C++
    // validates both endpoints again and publishes one forwarding job, so a
    // valid address swap cannot fail on a transient duplicate identity.
    const response = await this.command(
      `project:hosts|${hosts[0].mac}|${hosts[0].address}|${hosts[0].gateway}|` +
      `${hosts[1].mac}|${hosts[1].address}|${hosts[1].gateway}`
    );
    if (response.startsWith("ERROR")) throw new Error(response);
    return parseRuntimeSnapshot(JSON.parse(response));
  }

  async configureLinks(links: [LinkConfig, LinkConfig]): Promise<RuntimeSnapshot> {
    // IDs are validated while loading the project, so this compact runtime
    // message carries the ordered pair of nanosecond values without JSON or
    // floating point conversion in C++.
    const response = await this.command(
      `project:links|${links[0].propagationDelayNs}|${links[1].propagationDelayNs}`
    );
    if (response.startsWith("ERROR")) throw new Error(response);
    return parseRuntimeSnapshot(JSON.parse(response));
  }

  async configureRunning(config: RunningConfig): Promise<void> {
    // Project restoration is a structured atomic operation. The browser does
    // not know CLI grammar and cannot accidentally expose a partial candidate.
    const fields = [
      config.systemName,
      String(config.ports.length),
      ...config.ports.flatMap((port) => [port.id, port.admin, String(port.mtu), port.description]),
      String(config.interfaces.length),
      ...config.interfaces.flatMap((item) => [item.name, item.admin]),
      String(config.staticRoutes.length),
      ...config.staticRoutes.flatMap((route) => [route.prefix, route.nextHop])
    ];
    const output = await this.command(`project:running|${netstrings(fields)}`);
    if (output.startsWith("ERROR:")) throw new Error(output);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    // Let C++ set its stop flag, wake both pthread domains and join them before
    // the Web Worker exits. terminate() remains a bounded fallback for a worker
    // that has already trapped and can no longer process its shutdown message.
    for (const pending of this.pending.values()) {
      pending.reject(new Error("Runtime client is closing"));
    }
    this.pending.clear();
    for (const pending of this.binaryPending.values()) pending.reject(new Error("Runtime client is closing"));
    this.binaryPending.clear();
    this.worker.postMessage({ id: 0, shutdown: true });
    window.setTimeout(() => this.worker.terminate(), 250);
  }
}
