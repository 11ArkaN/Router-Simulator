// Shared telemetry ABI reader. C++ owns every projected byte and publishes
// through sequence locks. JavaScript performs bounded read-only observations
// and returns an immutable React projection only when visible values changed.

import { LAB_RUNTIME_PROTOCOL, PROFILE_CATALOG_COMPILED,
  type LabRuntimeSnapshotV6, type RuntimeRouterV6
} from "@router-simulator/contracts";

export interface TelemetryLayout {
  abi: number; size: number; sequence: number; abiVersion: number;
  workerCount: number; workerDirectory: number; workerBlockSize: number;
  workerRole: number; workerRunning: number; workerThreadId: number;
  workerTurns: number; capturedFrames: number; captureDropped: number;
  droppedPackets: number;
  deviceCount: number; sessionCount: number; deviceDirectory: number;
  deviceBlockSize: number; deviceSequence: number; deviceIndex: number;
  deviceGeneration: number; deviceOperationalPorts: number;
  deviceFibGeneration: number; deviceReceivedPackets: number;
  deviceTransmittedPackets: number; deviceDroppedPackets: number;
  sessionDirectory: number; sessionBlockSize: number;
  portBitsets: number; portBitsetBytes: number;
}

export interface TelemetryPage {
  buffer: SharedArrayBuffer;
  offset: number;
  size: number;
  layout: TelemetryLayout;
  // The worker replaces this generation whenever Wasm memory grows. Readers
  // never retain a typed array outside one readTelemetrySnapshot invocation.
  memoryEpoch?: number;
}

function safeCounter(value: bigint): number {
  // JavaScript UI counters saturate rather than round. The full uint64 remains
  // in shared memory and checkpoint state; only presentation is constrained by
  // Number's exact integer range.
  return value > BigInt(Number.MAX_SAFE_INTEGER)
    ? Number.MAX_SAFE_INTEGER : Number(value);
}

function portOrdinal(id: string): number | undefined {
  const values = id.split("/").map(Number);
  if (values.length !== 3 || values.some((value) =>
    !Number.isInteger(value) || value < 1)) return undefined;
  const ordinal = (values[0] - 1) *
    PROFILE_CATALOG_COMPILED.maximumMdaSlotsPerCard *
    PROFILE_CATALOG_COMPILED.maximumPortsPerMda +
    (values[1] - 1) * PROFILE_CATALOG_COMPILED.maximumPortsPerMda +
    values[2] - 1;
  return ordinal < PROFILE_CATALOG_COMPILED.maximumPortsPerRouter
    ? ordinal : undefined;
}

export function readTelemetrySnapshot(page: TelemetryPage,
  base: LabRuntimeSnapshotV6): LabRuntimeSnapshotV6 {
  const layout = page.layout;
  // The telemetry page and JSON snapshot are independent wire contracts.
  // Comparing the telemetry ABI with the snapshot ABI silently disabled every
  // shared-memory projection as soon as either contract advanced alone.
  if (layout.abi !== LAB_RUNTIME_PROTOCOL.telemetryAbi ||
      layout.size !== page.size) return base;
  const globalSequence = new Uint32Array(page.buffer,
    page.offset + layout.sequence, 1);
  const before = Atomics.load(globalSequence, 0);
  if (before & 1) return base;
  const view = new DataView(page.buffer, page.offset, page.size);
  const count = view.getUint32(layout.deviceCount, true);
  if (count > base.routers.length) return base;

  let routersChanged = false;
  const routers = base.routers.map((router): RuntimeRouterV6 => {
    const record = layout.deviceDirectory + router.handle.index *
      layout.deviceBlockSize;
    if (record + layout.deviceBlockSize > page.size) return router;
    const localSequence = new Uint32Array(page.buffer,
      page.offset + record + layout.deviceSequence, 1);
    const localBefore = Atomics.load(localSequence, 0);
    if (localBefore & 1 ||
        view.getUint16(record + layout.deviceIndex, true) !== router.handle.index ||
        view.getUint16(record + layout.deviceGeneration, true) !==
          router.handle.generation) return router;

    let changed = false;
    const ports = router.ports.map((port) => {
      const ordinal = portOrdinal(port.id);
      if (ordinal === undefined) return port;
      const byte = new Uint8Array(page.buffer, page.offset + layout.portBitsets +
        router.handle.index * layout.portBitsetBytes + Math.floor(ordinal / 8), 1)[0];
      const oper = (byte & (1 << (ordinal % 8))) !== 0;
      // For an administratively down port, the operational bitmap cannot
      // distinguish retained physical signal from no signal. Preserve carrier
      // in that state and update it only where admin permits operation.
      const carrier = port.admin ? oper : port.carrier;
      if (oper === port.oper && carrier === port.carrier) return port;
      changed = true;
      return { ...port, oper, carrier };
    });
    const localAfter = Atomics.load(localSequence, 0);
    if (localBefore !== localAfter || (localAfter & 1)) return router;
    if (!changed) return router;
    routersChanged = true;
    return { ...router, ports };
  });

  const capturedFrames = safeCounter(view.getBigUint64(layout.capturedFrames, true));
  const captureDropped = safeCounter(view.getBigUint64(layout.captureDropped, true));
  const droppedPackets = safeCounter(view.getBigUint64(layout.droppedPackets, true));
  const after = Atomics.load(globalSequence, 0);
  if (before !== after || (after & 1)) return base;
  if (!routersChanged && capturedFrames === base.capturedFrames &&
      captureDropped === base.captureDropped &&
      droppedPackets === base.droppedPackets) return base;
  return { ...base, routers, capturedFrames, captureDropped, droppedPackets };
}
