// Runtime snapshot validation tests exercise the browser trust boundary with
// legal state combinations produced by the C++ hardware owner. The validator
// owns structural safety only; it must not reconstruct private operational
// gates that are intentionally absent from the public snapshot contract.

import { describe, expect, it } from "vitest";
import { parseLabRuntimeSnapshotV6 } from "../src/lab-runtime-v6";

function snapshotWithPort(port: {
  admin: boolean;
  carrier: boolean;
  oper: boolean;
}) {
  return {
    abiVersion: 8,
    protocolVersion: 4,
    status: "ready",
    routers: [{
      id: "r1",
      profileId: "7750-sr-1",
      chassis: "7750 SR-1",
      systemName: "R1",
      maximumEcmpPaths: 1,
      handle: { index: 0, generation: 1 },
      // The SR-1 profile is fixed hardware, so its projection has exactly one
      // immutable card. Empty MDA details are valid because the runtime port
      // list below is the authoritative faceplate projection.
      cards: [{
        slot: 1,
        admin: true,
        provisionedType: "imm-2pac-fp3",
        equippedType: "imm-2pac-fp3",
        mdas: []
      }],
      ports: [{
        id: "1/1/1",
        ...port,
        mtu: 9212,
        speedMbps: 100000,
        description: ""
      }],
      interfaces: [],
      staticRoutes: [],
      ipv6StaticRoutes: [],
      policyOptions: { prefixLists: [], statements: [] },
      ospf: { instances: [] }
    }],
    hosts: [],
    switches: [],
    links: [],
    sessions: [],
    capturePoints: [],
    activeLinks: 0,
    capturedFrames: 0,
    captureDropped: 0,
    droppedPackets: 0
  } as const;
}

describe("runtime port projection", () => {
  it("accepts a hierarchy-blocked port with carrier and admin present", () => {
    // Card or MDA shutdown and retained-speed mismatch are real reasons for
    // oper=false even while the local port leaf and remote medium remain up.
    expect(parseLabRuntimeSnapshotV6(snapshotWithPort({
      admin: true,
      carrier: true,
      oper: false
    })).routers[0].ports[0].oper).toBe(false);
  });

  it("rejects an operational port without both necessary lower gates", () => {
    expect(() => parseLabRuntimeSnapshotV6(snapshotWithPort({
      admin: true,
      carrier: false,
      oper: true
    }))).toThrow("Runtime port projection is invalid");
  });
});
