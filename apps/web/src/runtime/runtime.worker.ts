/// <reference lib="webworker" />

// Emscripten Worker owner, pthread smoke gate and binary ABI adapter. All Wasm
// calls stay off the React thread and binary exports are copied before transfer.

import { LAB_RUNTIME_PROTOCOL, PROFILE_CATALOG } from "@router-simulator/contracts";
import type { TelemetryLayout } from "./telemetry-contract";
import { RuntimeContinuityGuard,
  RuntimeRecoveryController } from "./runtime-continuity";

interface WasmModule {
  // ccall owns UTF-8 marshalling for pointer-based C exports. Calling raw
  // _rs_command with a JavaScript string would pass an invalid numeric pointer.
  _runtime_initialize(): number;
  _memory_epoch(): number;
  _memory_size(): number;
  _memory_reserve(minimumTotalSize: number): number;
  _lab_close(): void;
  _telemetry_get_page(): number;
  _telemetry_get_page_size(): number;
  _telemetry_publish(): void;
  _capture_export_pcapng(): number;
  _capture_export_size(): number;
  _capture_clear(): number;
  _checkpoint_export(): number;
  _checkpoint_export_size(): number;
  _checkpoint_import(pointer: number, size: number): number;
  _secret_vault_initialize(keyPointer: number, keySize: number,
    contextPointer: number, contextSize: number): number;
  _malloc(size: number): number;
  _free(pointer: number): void;
  HEAPU8: Uint8Array;
  wasmMemory: WebAssembly.Memory;
  ccall(name: string, returnType: "number" | "string" | null,
        argumentTypes: Array<"string">, arguments_: string[]): number | string | null;
}

type RuntimeRequest = { id: number; command?: string; action?: "capture-export" |
  "capture-clear" | "capture-import" | "capture-storage-activate" |
  "capture-storage-release" | "checkpoint-export" | "checkpoint-import" |
  "secret-vault-initialize"; bytes?: ArrayBuffer; storageId?: string;
  shutdown?: true };
type RuntimeResponse = { id: number; ok: boolean; value?: string; bytes?: ArrayBuffer; error?: string };
type RuntimeContinuityNotice = { kind: "continuity-recovered" |
  "continuity-unrecoverable"; elapsedMilliseconds: number;
  checkpointAgeMilliseconds: number; error?: string };

let modulePromise: Promise<WasmModule> | undefined;
let telemetryTimer: number | undefined;
let observedMemoryBuffer: SharedArrayBuffer | undefined;
let observedMemoryEpoch = 0;
let telemetryProjection: { offset: number; size: number;
  layout: TelemetryLayout } | undefined;
let continuityRecovery: RuntimeRecoveryController | undefined;
let continuityBridgeUnavailable = false;
let captureFileHandle: FileSystemFileHandle | undefined;
let captureAccess: FileSystemSyncAccessHandle | undefined;
let captureOffset = 0;
let capturePending: Uint8Array | undefined;
let capturePendingWritten = 0;
let captureProjectId: string | undefined;
const continuity = new RuntimeContinuityGuard(
  PROFILE_CATALOG.runtime.recovery_checkpoint_interval_milliseconds,
  PROFILE_CATALOG.runtime.continuity_loss_threshold_milliseconds,
  performance.now());

function refreshMemoryViews(module: WasmModule): {
  buffer: SharedArrayBuffer; epoch: number; changed: boolean
} {
  // Emscripten keeps Wasm-internal views current, but external Module.HEAPU8
  // and telemetry DataViews can retain the old extent after pthread growth.
  // Comparing both the allocator epoch and buffer identity also handles hosts
  // that implement growable SharedArrayBuffer without replacing the object.
  const epoch = module._memory_epoch();
  // TypeScript's WebAssembly lib still declares Memory.buffer as ArrayBuffer
  // even when the memory descriptor is shared. Widen before the runtime gate.
  const rawBuffer = module.wasmMemory.buffer as ArrayBufferLike;
  if (!(rawBuffer instanceof SharedArrayBuffer)) {
    throw new Error("Emscripten runtime did not create shared WebAssembly memory");
  }
  const buffer: SharedArrayBuffer = rawBuffer;
  const changed = epoch !== observedMemoryEpoch ||
    buffer !== observedMemoryBuffer;
  const heapBuffer = module.HEAPU8.buffer as ArrayBufferLike;
  if (heapBuffer !== buffer ||
      module.HEAPU8.byteLength !== buffer.byteLength) {
    module.HEAPU8 = new Uint8Array(buffer);
  }
  observedMemoryBuffer = buffer;
  observedMemoryEpoch = epoch;
  return { buffer, epoch, changed };
}

function publishTelemetryMemory(module: WasmModule, force = false): void {
  const memory = refreshMemoryViews(module);
  if (!telemetryProjection || (!force && !memory.changed)) return;
  self.postMessage({ kind: "telemetry-page", buffer: memory.buffer,
    offset: telemetryProjection.offset, size: telemetryProjection.size,
    layout: telemetryProjection.layout, memoryEpoch: memory.epoch });
}

function exportRecoveryCheckpoint(module: WasmModule): Uint8Array | undefined {
  // checkpoint_export prepares one immutable runtime-owned generation. Copying
  // it immediately is essential because the next ABI call may reuse the C++
  // vector and because a later memory grow may replace external typed views.
  const pointer = module._checkpoint_export();
  const size = module._checkpoint_export_size();
  if (!pointer || !size) return undefined;
  refreshMemoryViews(module);
  return module.HEAPU8.slice(pointer, pointer + size);
}

function importCheckpointBytes(module: WasmModule,
  bytes: Uint8Array): void {
  // Reserve through the Worker-affine allocator owner before malloc. The
  // conservative extent includes the entire incoming image, so allocation
  // cannot initiate memory.grow from a forwarding pthread or publish a prefix.
  const requiredExtent = module._memory_size() + bytes.byteLength;
  if (!Number.isSafeInteger(requiredExtent) ||
      requiredExtent > PROFILE_CATALOG.runtime.wasm_maximum_memory_bytes ||
      !module._memory_reserve(requiredExtent)) {
    throw new Error("Checkpoint allocation exceeded the 1 GiB memory limit");
  }
  refreshMemoryViews(module);
  const pointer = module._malloc(bytes.byteLength);
  try {
    if (!pointer)
      throw new Error("Checkpoint allocation exceeded the 1 GiB memory limit");
    refreshMemoryViews(module);
    module.HEAPU8.set(bytes, pointer);
    if (!module._checkpoint_import(pointer, bytes.byteLength))
      throw new Error("Checkpoint ABI, build or profile is incompatible");
  } finally {
    if (pointer) module._free(pointer);
  }
}

function maintainRuntimeContinuity(module: WasmModule): boolean {
  if (!continuityRecovery || continuityBridgeUnavailable) return false;
  const result = continuityRecovery.maintain(performance.now());
  if (result.state === "stable" || result.state === "checkpointed") return true;
  if (result.state === "unrecoverable") {
    continuityBridgeUnavailable = true;
    self.postMessage({ kind: "continuity-unrecoverable",
      elapsedMilliseconds: result.elapsedMilliseconds,
      checkpointAgeMilliseconds: result.checkpointAgeMilliseconds,
      error: result.error } satisfies RuntimeContinuityNotice);
    return false;
  }
  try {
    // Import is a transactional replacement inside the existing LabRuntime.
    // The project vault remains initialized, every pthread owner receives the
    // restored state through its normal checkpoint boundary, and no absolute
    // steady-clock value from before suspension crosses the operation.
    const offset = module._telemetry_get_page();
    const size = module._telemetry_get_page_size();
    if (!telemetryProjection || !offset || size !== telemetryProjection.size)
      throw new Error("Recovered telemetry layout is incompatible");
    telemetryProjection = { ...telemetryProjection, offset, size };
    module._telemetry_publish();
    publishTelemetryMemory(module, true);
    self.postMessage({ kind: "continuity-recovered",
      elapsedMilliseconds: result.elapsedMilliseconds,
      checkpointAgeMilliseconds: result.checkpointAgeMilliseconds
    } satisfies RuntimeContinuityNotice);
  } catch (cause) {
    continuityBridgeUnavailable = true;
    self.postMessage({ kind: "continuity-unrecoverable",
      elapsedMilliseconds: result.elapsedMilliseconds,
      checkpointAgeMilliseconds: result.checkpointAgeMilliseconds,
      error: cause instanceof Error ? cause.message : String(cause)
    } satisfies RuntimeContinuityNotice);
    return false;
  }
  return true;
}

function netstrings(values: readonly string[]): string {
  // Startup uses the same protocol encoder as ordinary client commands. Text
  // byte length, not UTF-16 code units, defines each field on the C++ side.
  const encoder = new TextEncoder();
  return values.map((value) => `${encoder.encode(value).byteLength}:${value},`).join("");
}

async function bindCaptureStorage(projectId: string): Promise<void> {
  // Project IDs are directory names, not paths. Applying the same grammar as
  // the main-thread persistence owner prevents traversal through a crafted
  // imported identity before asking OPFS to create any handle.
  if (!/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i.test(projectId))
    throw new Error("Capture storage identity is invalid");
  if (!navigator.storage?.getDirectory)
    throw new Error("OPFS is not available for packet capture");
  const root = await navigator.storage.getDirectory();
  const projects = await root.getDirectoryHandle("projects", { create: true });
  const directory = await projects.getDirectoryHandle(projectId, { create: true });
  captureFileHandle = await directory.getFileHandle("capture.pcapng", { create: true });
  // A dedicated Worker may use the synchronous OPFS handle. It gives the
  // capture bridge positional writes and flush without blocking React or
  // opening one atomic replacement stream for every short capture chunk.
  captureAccess = await captureFileHandle.createSyncAccessHandle();
  captureOffset = captureAccess.getSize();
}

async function ensureCaptureStorage(): Promise<void> {
  if (!captureAccess) {
    if (!captureProjectId)
      throw new Error("Capture project identity is not initialized");
    await bindCaptureStorage(captureProjectId);
  }
}

function drainCaptureToStorage(module: WasmModule): void {
  if (!captureAccess) return;
  if (!capturePending) {
    const pointer = module._capture_export_pcapng();
    const size = module._capture_export_size();
    if (!pointer || !size) return;
    refreshMemoryViews(module);
    // Keep one retryable private chunk. The next C++ drain may reuse prepared_
    // after this call, and an OPFS quota or device error must not turn that
    // reuse into silent packet loss.
    capturePending = module.HEAPU8.slice(pointer, pointer + size);
    capturePendingWritten = 0;
  }
  while (capturePendingWritten < capturePending.byteLength) {
    const count = captureAccess.write(capturePending.subarray(capturePendingWritten),
      { at: captureOffset + capturePendingWritten });
    if (!count) throw new Error("OPFS capture write made no progress");
    capturePendingWritten += count;
  }
  captureOffset += capturePending.byteLength;
  capturePending = undefined;
  capturePendingWritten = 0;
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
        const initialMemory = refreshMemoryViews(module);
        const offset = module._telemetry_get_page();
        const size = module._telemetry_get_page_size();
        const layoutText = module.ccall("telemetry_get_layout", "string", [], []);
        if (typeof layoutText !== "string") throw new Error("Telemetry layout ABI is unavailable");
        const layout = JSON.parse(layoutText) as TelemetryLayout;
        // The telemetry page intentionally shares the snapshot ABI revision.
        // Reading the generated contract prevents a C++ ABI bump from leaving
        // this startup gate on a stale literal and rejecting every valid lab.
        if (layout.abi !== LAB_RUNTIME_PROTOCOL.snapshotAbi ||
            layout.size !== size) {
          throw new Error("Telemetry layout ABI does not match the active profile");
        }
        telemetryProjection = { offset, size, layout };
        // pthread creation is asynchronous in Emscripten. Polling the shared
        // health page for at most two seconds distinguishes a genuine startup
        // failure from the short interval before both C++ entry points publish
        // their owner IDs. Each snapshot asks the control owner to republish;
        // no packet state or device timer is advanced by this startup gate.
        let ownersReady = false;
        for (let attempt = 0; attempt < PROFILE_CATALOG.runtime.worker_startup_attempts; ++attempt) {
          module.ccall("lab_submit_command", "string", ["string"],
            [netstrings([LAB_RUNTIME_PROTOCOL.snapshot])]);
          const memory = refreshMemoryViews(module);
          const health = new DataView(memory.buffer, offset, size);
          const workerCount = health.getUint32(layout.workerCount, true);
          const ownerIds = new Set<bigint>();
          let complete = workerCount >= 2 &&
            workerCount <= PROFILE_CATALOG.runtime.maximum_worker_domains;
          for (let index = 0; complete && index < workerCount; ++index) {
            const record = offset + layout.workerDirectory + index * layout.workerBlockSize;
            const running = new Uint8Array(memory.buffer,
              record + layout.workerRunning, 1)[0];
            const ownerId = Atomics.load(
              new BigUint64Array(memory.buffer,
                record + layout.workerThreadId, 1), 0);
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
        // initialMemory is intentionally observed before startup allocations;
        // the forced publish below always sends the latest memory generation.
        void initialMemory;
        publishTelemetryMemory(module, true);
        // Dependency download, Wasm compilation and pthread startup happen
        // before the live laboratory is announced. Establish the first
        // continuity baseline only after those one-time costs have completed.
        const runtimeReadyNow = performance.now();
        continuityRecovery = new RuntimeRecoveryController(continuity, {
          exportCheckpoint: () => {
            // Persist packet bytes before publishing the matching structural
            // recovery point. A later continuity rollback can then restore
            // capture counters without losing a chunk that existed only in
            // the old runtime's transient encoder vector.
            drainCaptureToStorage(module);
            return exportRecoveryCheckpoint(module);
          },
          importCheckpoint: (bytes) => importCheckpointBytes(module, bytes)
        });
        if (!continuityRecovery.initialize(runtimeReadyNow))
          throw new Error("Initial runtime recovery checkpoint failed");
        // The Worker event loop is the only LabRuntime caller. A bounded timer
        // therefore preserves control affinity while refreshing shared data,
        // supervising browser continuity and preparing bounded recovery images
        // independently from UI commands and packet frequency.
        telemetryTimer = self.setInterval(() => {
          if (!maintainRuntimeContinuity(module)) return;
          module._telemetry_publish();
          publishTelemetryMemory(module);
          // One drain per telemetry interval bounds transient Wasm bytes by
          // traffic produced during that interval, not by capture duration.
          // OPFS capacity is the persistent session limit and any write error
          // is surfaced rather than silently discarding the prepared chunk.
          try {
            drainCaptureToStorage(module);
          } catch (cause) {
            self.postMessage({ kind: "capture-storage-error",
              error: cause instanceof Error ? cause.message : String(cause) });
          }
        }, PROFILE_CATALOG.runtime.telemetry_publish_interval_milliseconds);
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
      if (modulePromise) {
        const module = await modulePromise;
        drainCaptureToStorage(module);
        captureAccess?.flush();
        captureAccess?.close();
        module._lab_close();
      }
      self.close();
      return;
    }
    const module = await loadRuntime();
    if (!maintainRuntimeContinuity(module))
      throw new Error("Runtime continuity recovery failed");
    refreshMemoryViews(module);
    if (data.action === "capture-export") {
      await ensureCaptureStorage();
      drainCaptureToStorage(module);
      if (!captureAccess || !captureFileHandle)
        throw new Error("Capture storage is not initialized");
      captureAccess.flush();
      // Export may transiently allocate the complete file for browser download,
      // but the live runtime never retains it and has no 32 MiB session cap.
      // Chromium can indefinitely defer getFile() while this Worker owns the
      // synchronous handle, and releasing then immediately reacquiring the
      // handle is not an atomic snapshot. Read the flushed extent through the
      // existing exclusive owner instead. Positional reads also let us reject
      // a zero-progress storage failure rather than exporting truncated data.
      const size = captureAccess.getSize();
      const snapshot = new Uint8Array(size);
      let read = 0;
      while (read < size) {
        const count = captureAccess.read(snapshot.subarray(read), { at: read });
        if (!count) throw new Error("OPFS capture read made no progress");
        read += count;
      }
      const bytes = snapshot.buffer;
      self.postMessage({ id: data.id, ok: true, bytes } satisfies RuntimeResponse,
        [bytes]);
      return;
    }
    if (data.action === "capture-clear") {
      await ensureCaptureStorage();
      if (!captureAccess || !module._capture_clear())
        throw new Error("Capture session could not be cleared");
      captureAccess.truncate(0);
      captureOffset = 0;
      capturePending = undefined;
      capturePendingWritten = 0;
      drainCaptureToStorage(module);
      captureAccess.flush();
      self.postMessage({ id: data.id, ok: true,
        value: "capture cleared" } satisfies RuntimeResponse);
      return;
    }
    if (data.action === "capture-import") {
      await ensureCaptureStorage();
      if (!captureAccess || !data.bytes || data.bytes.byteLength < 28)
        throw new Error("Imported capture is empty or storage is unavailable");
      const imported = new Uint8Array(data.bytes);
      if (imported[0] !== 0x0a || imported[1] !== 0x0d ||
          imported[2] !== 0x0d || imported[3] !== 0x0a)
        throw new Error("Imported capture is not a PCAPNG section");
      captureAccess.truncate(0);
      captureOffset = 0;
      capturePending = imported;
      capturePendingWritten = 0;
      drainCaptureToStorage(module);
      // The live runtime already owns a fresh section header and active IDBs.
      // Append them after the imported section so new traffic never refers to
      // an interface table from the external artifact.
      drainCaptureToStorage(module);
      captureAccess.flush();
      self.postMessage({ id: data.id, ok: true,
        value: "capture imported" } satisfies RuntimeResponse);
      return;
    }
    if (data.action === "capture-storage-activate") {
      await ensureCaptureStorage();
      drainCaptureToStorage(module);
      self.postMessage({ id: data.id, ok: true,
        value: "capture storage active" } satisfies RuntimeResponse);
      return;
    }
    if (data.action === "capture-storage-release") {
      if (captureAccess) {
        drainCaptureToStorage(module);
        captureAccess.flush();
        captureAccess.close();
      }
      captureAccess = undefined;
      captureFileHandle = undefined;
      self.postMessage({ id: data.id, ok: true,
        value: "capture storage released" } satisfies RuntimeResponse);
      return;
    }
    if (data.action === "checkpoint-export") {
      const pointer = module._checkpoint_export();
      const size = module._checkpoint_export_size();
      if (!pointer || !size) throw new Error("Checkpoint export failed");
      refreshMemoryViews(module);
      const bytes = module.HEAPU8.slice(pointer, pointer + size).buffer;
      self.postMessage({ id: data.id, ok: true, bytes } satisfies RuntimeResponse, [bytes]);
      return;
    }
    if (data.action === "checkpoint-import") {
      if (!data.bytes?.byteLength) throw new Error("Checkpoint is empty");
      importCheckpointBytes(module, new Uint8Array(data.bytes));
      if (!continuityRecovery?.refreshRecoveryPoint(performance.now()))
        throw new Error("Imported runtime could not publish a recovery point");
      self.postMessage({ id: data.id, ok: true, value: "checkpoint imported" } satisfies RuntimeResponse);
      return;
    }
    if (data.action === "secret-vault-initialize") {
      if (!data.bytes || data.bytes.byteLength !== 32 || !data.command ||
          !data.storageId)
        throw new Error("Project vault material is invalid");
      const key = new Uint8Array(data.bytes);
      const context = new TextEncoder().encode(data.command);
      const keyPointer = module._malloc(key.byteLength);
      const contextPointer = module._malloc(context.byteLength);
      try {
        if (!keyPointer || !contextPointer)
          throw new Error("Project vault initialization allocation failed");
        refreshMemoryViews(module);
        module.HEAPU8.set(key, keyPointer);
        module.HEAPU8.set(context, contextPointer);
        if (!module._secret_vault_initialize(keyPointer, key.byteLength,
          contextPointer, context.byteLength))
          throw new Error("Project vault initialization was rejected");
      } finally {
        // Key bytes are transient in both heaps. They are erased before either
        // allocation is returned to a general-purpose allocator.
        key.fill(0);
        refreshMemoryViews(module);
        if (keyPointer) module.HEAPU8.fill(0, keyPointer, keyPointer + 32);
        if (contextPointer) module.HEAPU8.fill(
          0, contextPointer, contextPointer + context.byteLength);
        context.fill(0);
        if (keyPointer) module._free(keyPointer);
        if (contextPointer) module._free(contextPointer);
      }
      if (!continuityRecovery?.refreshRecoveryPoint(performance.now()))
        throw new Error("Vault initialization recovery checkpoint failed");
      // Storage ownership is activated separately. Transactional runtime
      // replacement can therefore build and validate a new Worker while the
      // visible predecessor still owns the same project capture file.
      captureProjectId = data.storageId;
      self.postMessage({ id: data.id, ok: true,
        value: "project vault initialized" } satisfies RuntimeResponse);
      return;
    }
    const value = module.ccall("lab_submit_command", "string", ["string"], [data.command ?? ""]);
    publishTelemetryMemory(module);
    if (typeof value !== "string") throw new Error("Runtime returned an invalid command response");
    self.postMessage({ id: data.id, ok: true, value } satisfies RuntimeResponse);
  } catch (cause) {
    // Errors cross the Worker boundary as plain data so no Error prototype or
    // implementation-specific stack is required by the UI thread.
    const error = cause instanceof Error ? cause.message : String(cause);
    self.postMessage({ id: data.id, ok: false, error } satisfies RuntimeResponse);
  }
};
