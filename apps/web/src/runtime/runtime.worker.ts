/// <reference lib="webworker" />

// Emscripten Worker owner, pthread smoke gate and binary ABI adapter. All Wasm
// calls stay off the React thread and binary exports are copied before transfer.

import { GENERATED_PROFILE, RUNTIME_PROTOCOL } from "@router-simulator/contracts";

interface TelemetryLayout {
  abi: number; size: number; sequence: number; abiVersion: number;
  workerCount: number; portBitmap: number; controlThreadId: number;
  forwardingThreadId: number; capturedFrames: number; captureDropped: number;
  droppedPackets: number;
}

interface WasmModule {
  // ccall owns UTF-8 marshalling for pointer-based C exports. Calling raw
  // _rs_command with a JavaScript string would pass an invalid numeric pointer.
  _rs_create(): number;
  _rs_shutdown(): void;
  _telemetry_get_page(): number;
  _telemetry_get_page_size(): number;
  _rs_capture_prepare(): number;
  _rs_capture_data(): number;
  _rs_capture_size(): number;
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
        if (!module._rs_create()) throw new Error("Runtime instance already exists");
        const buffer = module.HEAPU8.buffer;
        if (!(buffer instanceof SharedArrayBuffer)) {
          throw new Error("Emscripten runtime did not create shared WebAssembly memory");
        }
        const offset = module._telemetry_get_page();
        const size = module._telemetry_get_page_size();
        const layoutText = module.ccall("telemetry_get_layout", "string", [], []);
        if (typeof layoutText !== "string") throw new Error("Telemetry layout ABI is unavailable");
        const layout = JSON.parse(layoutText) as TelemetryLayout;
        if (layout.abi !== GENERATED_PROFILE.abi.telemetry || layout.size !== size) {
          throw new Error("Telemetry layout ABI does not match the active profile");
        }
        const health = new DataView(buffer, offset, size);
        const controlOwner = new BigUint64Array(buffer, offset + layout.controlThreadId, 1);
        const forwardingOwner = new BigUint64Array(buffer, offset + layout.forwardingThreadId, 1);
        // pthread creation is asynchronous in Emscripten. Polling the shared
        // health page for at most two seconds distinguishes a genuine startup
        // failure from the short interval before both C++ entry points publish
        // their owner IDs. Each snapshot asks the control owner to republish;
        // no packet state or device timer is advanced by this startup gate.
        let ownersReady = false;
        for (let attempt = 0; attempt < GENERATED_PROFILE.timing.worker_startup_attempts; ++attempt) {
          module.ccall("rs_command", "string", ["string"], [RUNTIME_PROTOCOL.snapshot]);
          const control = Atomics.load(controlOwner, 0);
          const forwarding = Atomics.load(forwardingOwner, 0);
          if (health.getUint32(layout.workerCount, true) >=
                GENERATED_PROFILE.resources.runtime_worker_count && control !== 0n &&
              forwarding !== 0n && control !== forwarding) {
            ownersReady = true;
            break;
          }
          await new Promise((resolve) => setTimeout(
            resolve, GENERATED_PROFILE.timing.worker_startup_poll_milliseconds));
        }
        // This smoke test executes before the lab is announced ready. It proves
        // that both worker domains published distinct owners into shared memory
        // and prevents a silently linked single-thread runtime from opening.
        if (!ownersReady) {
          throw new Error("pthread smoke test did not observe distinct control and forwarding owners");
        }
        self.postMessage({ kind: "telemetry-page", buffer, offset, size, layout });
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
      if (modulePromise) (await modulePromise)._rs_shutdown();
      self.close();
      return;
    }
    const module = await loadRuntime();
    if (data.action === "capture-export") {
      if (!module._rs_capture_prepare()) throw new Error("PCAPNG export failed");
      const pointer = module._rs_capture_data();
      const size = module._rs_capture_size();
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
    const value = module.ccall("rs_command", "string", ["string"], [data.command ?? ""]);
    if (typeof value !== "string") throw new Error("Runtime returned an invalid command response");
    self.postMessage({ id: data.id, ok: true, value } satisfies RuntimeResponse);
  } catch (cause) {
    // Errors cross the Worker boundary as plain data so no Error prototype or
    // implementation-specific stack is required by the UI thread.
    const error = cause instanceof Error ? cause.message : String(cause);
    self.postMessage({ id: data.id, ok: false, error } satisfies RuntimeResponse);
  }
};
