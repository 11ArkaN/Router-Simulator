/// <reference lib="webworker" />

// Emscripten Worker owner, pthread smoke gate and binary ABI adapter. All Wasm
// calls stay off the React thread and binary exports are copied before transfer.

import { LAB_RUNTIME_PROTOCOL, PROFILE_CATALOG } from "@router-simulator/contracts";
import type { TelemetryLayout } from "./telemetry-contract";

interface WasmModule {
  // ccall owns UTF-8 marshalling for pointer-based C exports. Calling raw
  // _rs_command with a JavaScript string would pass an invalid numeric pointer.
  _runtime_initialize(): number;
  _lab_close(): void;
  _telemetry_get_page(): number;
  _telemetry_get_page_size(): number;
  _telemetry_publish(): void;
  _capture_export_pcapng(): number;
  _capture_export_size(): number;
  _checkpoint_export(): number;
  _checkpoint_export_size(): number;
  _checkpoint_import(pointer: number, size: number): number;
  _malloc(size: number): number;
  _free(pointer: number): void;
  HEAPU8: Uint8Array;
  ccall(name: string, returnType: "number" | "string" | null,
        argumentTypes: Array<"string">, arguments_: string[]): number | string | null;
}

type RuntimeRequest = { id: number; command?: string; action?: "capture-export" | "checkpoint-export" | "checkpoint-import";
  bytes?: ArrayBuffer; shutdown?: true };
type RuntimeResponse = { id: number; ok: boolean; value?: string; bytes?: ArrayBuffer; error?: string };

let modulePromise: Promise<WasmModule> | undefined;
let telemetryTimer: number | undefined;

function netstrings(values: readonly string[]): string {
  // Startup uses the same protocol encoder as ordinary client commands. Text
  // byte length, not UTF-16 code units, defines each field on the C++ side.
  const encoder = new TextEncoder();
  return values.map((value) => `${encoder.encode(value).byteLength}:${value},`).join("");
}

async function loadRuntime(): Promise<WasmModule> {
  // Memoization guarantees one Emscripten module, one shared memory, and one C++
  // Runtime per browser Worker even when requests arrive during startup.
  if (!modulePromise) {
    // The Emscripten module is a final build artifact in public/wasm. Building
    // the absolute URL at runtime keeps Vite from transforming its pthread
    // self-import into an application chunk.
    const moduleUrl = new URL("wasm/simulator.js", self.location.origin + "/").href;
    modulePromise = import(/* @vite-ignore */ moduleUrl)
      .then(({ default: createRuntime }) => createRuntime({ locateFile: (path: string) => `/wasm/${path}` }))
      .then(async (module: WasmModule) => {
        // C++ construction starts the fixed pthread domains before any command
        // is accepted by the UI bridge.
        if (!module._runtime_initialize()) throw new Error("Multi-router runtime initialization failed");
        const buffer = module.HEAPU8.buffer;
        if (!(buffer instanceof SharedArrayBuffer)) {
          throw new Error("Emscripten runtime did not create shared WebAssembly memory");
        }
        const offset = module._telemetry_get_page();
        const size = module._telemetry_get_page_size();
        const layoutText = module.ccall("telemetry_get_layout", "string", [], []);
        if (typeof layoutText !== "string") throw new Error("Telemetry layout ABI is unavailable");
        const layout = JSON.parse(layoutText) as TelemetryLayout;
        if (layout.abi !== 5 || layout.size !== size) {
          throw new Error("Telemetry layout ABI does not match the active profile");
        }
        const health = new DataView(buffer, offset, size);
        // pthread creation is asynchronous in Emscripten. Polling the shared
        // health page for at most two seconds distinguishes a genuine startup
        // failure from the short interval before both C++ entry points publish
        // their owner IDs. Each snapshot asks the control owner to republish;
        // no packet state or device timer is advanced by this startup gate.
        let ownersReady = false;
        for (let attempt = 0; attempt < PROFILE_CATALOG.runtime.worker_startup_attempts; ++attempt) {
          module.ccall("lab_submit_command", "string", ["string"],
            [netstrings([LAB_RUNTIME_PROTOCOL.snapshot])]);
          const workerCount = health.getUint32(layout.workerCount, true);
          const ownerIds = new Set<bigint>();
          let complete = workerCount >= 2 &&
            workerCount <= PROFILE_CATALOG.runtime.maximum_worker_domains;
          for (let index = 0; complete && index < workerCount; ++index) {
            const record = offset + layout.workerDirectory + index * layout.workerBlockSize;
            const running = new Uint8Array(buffer, record + layout.workerRunning, 1)[0];
            const ownerId = Atomics.load(
              new BigUint64Array(buffer, record + layout.workerThreadId, 1), 0);
            complete = running === 1 && ownerId !== 0n && !ownerIds.has(ownerId);
            ownerIds.add(ownerId);
          }
          if (complete) {
            ownersReady = true;
            break;
          }
          await new Promise((resolve) => setTimeout(
            resolve, PROFILE_CATALOG.runtime.worker_startup_poll_milliseconds));
        }
        // This smoke test executes before the lab is announced ready. It proves
        // that both worker domains published distinct owners into shared memory
        // and prevents a silently linked single-thread runtime from opening.
        if (!ownersReady) {
          throw new Error("pthread smoke test did not observe distinct control and forwarding owners");
        }
        self.postMessage({ kind: "telemetry-page", buffer, offset, size, layout });
        // The Worker event loop is the only LabRuntime caller. A bounded timer
        // therefore preserves control affinity while refreshing shared data
        // independently from UI commands and packet frequency.
        telemetryTimer = self.setInterval(() => module._telemetry_publish(),
          PROFILE_CATALOG.runtime.telemetry_publish_interval_milliseconds);
        return module;
      });
  }
  return modulePromise;
}

self.onmessage = async ({ data }: MessageEvent<RuntimeRequest>) => {
  // Requests are deliberately handled by the Worker event loop. The C++ bridge
  // then serializes access to its SPSC control mailbox.
  try {
    if (data.shutdown) {
      // Do not initialize Wasm merely to shut down a Worker that never finished
      // booting. If construction completed, rs_shutdown performs the required
      // pthread joins before the Worker closes its own event loop.
      if (telemetryTimer !== undefined) self.clearInterval(telemetryTimer);
      if (modulePromise) (await modulePromise)._lab_close();
      self.close();
      return;
    }
    const module = await loadRuntime();
    if (data.action === "capture-export") {
      const pointer = module._capture_export_pcapng();
      const size = module._capture_export_size();
      if (!pointer || !size) throw new Error("PCAPNG export failed");
      const bytes = module.HEAPU8.slice(pointer, pointer + size).buffer;
      self.postMessage({ id: data.id, ok: true, bytes } satisfies RuntimeResponse, [bytes]);
      return;
    }
    if (data.action === "checkpoint-export") {
      const pointer = module._checkpoint_export();
      const size = module._checkpoint_export_size();
      if (!pointer || !size) throw new Error("Checkpoint export failed");
      const bytes = module.HEAPU8.slice(pointer, pointer + size).buffer;
      self.postMessage({ id: data.id, ok: true, bytes } satisfies RuntimeResponse, [bytes]);
      return;
    }
    if (data.action === "checkpoint-import") {
      if (!data.bytes?.byteLength) throw new Error("Checkpoint is empty");
      const pointer = module._malloc(data.bytes.byteLength);
      try {
        module.HEAPU8.set(new Uint8Array(data.bytes), pointer);
        if (!module._checkpoint_import(pointer, data.bytes.byteLength)) {
          throw new Error("Checkpoint ABI, build or profile is incompatible");
        }
      } finally {
        module._free(pointer);
      }
      self.postMessage({ id: data.id, ok: true, value: "checkpoint imported" } satisfies RuntimeResponse);
      return;
    }
    const value = module.ccall("lab_submit_command", "string", ["string"], [data.command ?? ""]);
    if (typeof value !== "string") throw new Error("Runtime returned an invalid command response");
    self.postMessage({ id: data.id, ok: true, value } satisfies RuntimeResponse);
  } catch (cause) {
    // Errors cross the Worker boundary as plain data so no Error prototype or
    // implementation-specific stack is required by the UI thread.
    const error = cause instanceof Error ? cause.message : String(cause);
    self.postMessage({ id: data.id, ok: false, error } satisfies RuntimeResponse);
  }
};
