// Seqlock reader tests use a synthetic SharedArrayBuffer with compiler-like
// offsets. They verify consistency and stale-generation rejection without
// starting a second Wasm runtime inside the DOM test process.

import type { LabRuntimeSnapshotV6 } from "@router-simulator/contracts";
import { describe, expect, it } from "vitest";
import { readTelemetrySnapshot, type TelemetryLayout,
  type TelemetryPage } from "./telemetry-contract";

const layout: TelemetryLayout = {
  abi: 6, size: 512, sequence: 0, abiVersion: 4,
  workerCount: 0, workerDirectory: 0, workerBlockSize: 0, workerRole: 0,
  workerRunning: 0, workerThreadId: 0, workerTurns: 0,
  capturedFrames: 8, captureDropped: 16, droppedPackets: 24,
  deviceCount: 32, sessionCount: 36, deviceDirectory: 64,
  deviceBlockSize: 64, deviceSequence: 0, deviceIndex: 4,
  deviceGeneration: 6, deviceOperationalPorts: 8, deviceFibGeneration: 12,
  deviceReceivedPackets: 16, deviceTransmittedPackets: 24,
  deviceDroppedPackets: 32, sessionDirectory: 0, sessionBlockSize: 0,
  portBitsets: 256, portBitsetBytes: 8
};

function snapshot(): LabRuntimeSnapshotV6 {
  return { abiVersion: 6, protocolVersion: 4, status: "ready",
    routers: [{ id: "r1", profileId: "7750-sr-1", chassis: "7750 SR-1",
      systemName: "R1", handle: { index: 0, generation: 1 }, cards: [],
      ports: [{ id: "1/1/1", admin: true, carrier: false, oper: false,
        mtu: 9212, speedMbps: 100000, description: "" }], interfaces: [],
      staticRoutes: [], ipv6StaticRoutes: [] }], hosts: [], links: [], sessions: [], capturePoints: [],
    activeLinks: 0, capturedFrames: 0, captureDropped: 0, droppedPackets: 0 };
}

function page(generation = 1): TelemetryPage {
  const buffer = new SharedArrayBuffer(layout.size);
  const view = new DataView(buffer);
  // Even global and device sequences publish one stable observation.
  view.setUint32(layout.sequence, 2, true);
  view.setUint32(layout.deviceCount, 1, true);
  view.setBigUint64(layout.capturedFrames, 9n, true);
  view.setBigUint64(layout.captureDropped, 2n, true);
  view.setBigUint64(layout.droppedPackets, 3n, true);
  view.setUint32(layout.deviceDirectory + layout.deviceSequence, 2, true);
  view.setUint16(layout.deviceDirectory + layout.deviceIndex, 0, true);
  view.setUint16(layout.deviceDirectory + layout.deviceGeneration,
    generation, true);
  new Uint8Array(buffer, layout.portBitsets, 1)[0] = 1;
  return { buffer, offset: 0, size: layout.size, layout };
}

describe("shared telemetry projection", () => {
  it("publishes stable counters and operational port bits", () => {
    const projected = readTelemetrySnapshot(page(), snapshot());
    expect(projected.capturedFrames).toBe(9);
    expect(projected.captureDropped).toBe(2);
    expect(projected.droppedPackets).toBe(3);
    expect(projected.routers[0].ports[0]).toMatchObject({
      carrier: true, oper: true
    });
  });

  it("rejects stale device generations and an in-progress global write", () => {
    const base = snapshot();
    const stale = readTelemetrySnapshot(page(2), base);
    expect(stale.routers[0]).toBe(base.routers[0]);

    const busy = page();
    new DataView(busy.buffer).setUint32(layout.sequence, 3, true);
    expect(readTelemetrySnapshot(busy, base)).toBe(base);
  });
});
