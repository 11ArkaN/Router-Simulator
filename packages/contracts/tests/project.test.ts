import { describe, expect, it } from "vitest";
import { ABI_VERSION, DEFAULT_PROJECT, parseProject, parseRuntimeSnapshot } from "../src";

describe("project format", () => {
  it("accepts the pinned default profile", () => {
    expect(parseProject(DEFAULT_PROJECT).hardware.card1).toBe("absent");
    expect(parseProject(DEFAULT_PROJECT).links[0].propagationDelayNs).toBe(100);
  });

  it("migrates only the absent legacy link field", () => {
    const legacy = structuredClone(DEFAULT_PROJECT) as Partial<typeof DEFAULT_PROJECT>;
    delete legacy.links;
    expect(parseProject(legacy).links).toEqual(DEFAULT_PROJECT.links);
  });

  it("validates link identity and exactly representable nanoseconds", () => {
    const malformed = structuredClone(DEFAULT_PROJECT);
    malformed.links[0].propagationDelayNs = -1;
    expect(() => parseProject(malformed)).toThrow("invalid link propagation");

    malformed.links[0].propagationDelayNs = 1.5;
    expect(() => parseProject(malformed)).toThrow("invalid link propagation");

    // Source: ecma.number.max_safe_integer. A larger JSON number could round to
    // a different integer before it reaches the runtime command.
    malformed.links[0].propagationDelayNs = Number.MAX_SAFE_INTEGER + 1;
    expect(() => parseProject(malformed)).toThrow("invalid link propagation");
  });

  it("rejects a future ABI instead of guessing a migration", () => {
    expect(() => parseProject({ ...DEFAULT_PROJECT, version: 2 })).toThrow("Unsupported project");
  });

  it("rejects malformed endpoint data before runtime configuration", () => {
    const malformed = structuredClone(DEFAULT_PROJECT);
    malformed.hosts[0].mac = "not-a-mac";
    expect(() => parseProject(malformed)).toThrow("invalid host");
  });

  it("rejects a child provisioned without its parent", () => {
    const malformed = structuredClone(DEFAULT_PROJECT);
    malformed.hardware.card1Provisioned = "absent";
    malformed.hardware.mda11Provisioned = "me10-10gb-sfp+";
    // The structural validator accepts only supported values. Dependency
    // validation remains explicit here so invalid persisted hardware cannot be
    // normalized silently while restoring the project.
    expect(() => parseProject(malformed)).toThrow("unsupported hardware");
  });

  it("rejects a gateway outside the host prefix", () => {
    const malformed = structuredClone(DEFAULT_PROJECT);
    malformed.hosts[0].gateway = "198.51.100.1";
    expect(() => parseProject(malformed)).toThrow("local prefix");
  });

  it("rejects reversed endpoint order and duplicate identities", () => {
    const reversed = structuredClone(DEFAULT_PROJECT);
    reversed.hosts.reverse();
    expect(() => parseProject(reversed)).toThrow("invalid host");

    const duplicate = structuredClone(DEFAULT_PROJECT);
    duplicate.hosts[1].mac = duplicate.hosts[0].mac.toLowerCase();
    expect(() => parseProject(duplicate)).toThrow("duplicate endpoint");
  });

  it("rejects group MAC and IPv4 broadcast endpoint values", () => {
    const groupMac = structuredClone(DEFAULT_PROJECT);
    groupMac.hosts[0].mac = "01:00:5E:00:00:01";
    expect(() => parseProject(groupMac)).toThrow("duplicate endpoint");

    const broadcastIp = structuredClone(DEFAULT_PROJECT);
    broadcastIp.hosts[0].address = "192.0.2.3/30";
    expect(() => parseProject(broadcastIp)).toThrow("local prefix");
  });

  it("rejects an incompatible runtime snapshot ABI", () => {
    const snapshot = {
      abiVersion: ABI_VERSION,
      status: "ready",
      nowMs: 1,
      hardware: DEFAULT_PROJECT.hardware,
      ports: [
        { id: "1/1/1", admin: "up", oper: "up", speedMbps: 10000, mtu: 1500, description: "", rxPackets: 0, txPackets: 0 },
        { id: "1/1/2", admin: "up", oper: "up", speedMbps: 10000, mtu: 1500, description: "", rxPackets: 0, txPackets: 0 }
      ],
      arp: [], routes: [], alarms: [], runningConfig: DEFAULT_PROJECT.runningConfig,
      captureCount: 0, captureDropped: 0, droppedPackets: 0
    };
    expect(parseRuntimeSnapshot(snapshot).abiVersion).toBe(ABI_VERSION);
    expect(() => parseRuntimeSnapshot({ ...snapshot, abiVersion: 999 })).toThrow("incompatible ABI");
  });

  it("rejects non-canonical and duplicate static route keys", () => {
    const hostBits = structuredClone(DEFAULT_PROJECT);
    hostBits.runningConfig.staticRoutes = [{ prefix: "203.0.113.7/24", nextHop: "192.0.2.2" }];
    expect(() => parseProject(hostBits)).toThrow("canonical and unique");

    const duplicate = structuredClone(DEFAULT_PROJECT);
    duplicate.runningConfig.staticRoutes = [
      { prefix: "203.0.113.0/24", nextHop: "192.0.2.2" },
      { prefix: "203.0.113.0/24", nextHop: "198.51.100.2" }
    ];
    // Route identity is prefix-based. Allowing a second entry with a different
    // next hop would make restore order an undocumented route-selection rule.
    expect(() => parseProject(duplicate)).toThrow("canonical and unique");
  });

  it("mutation-fuzzes the portable netsim project boundary", () => {
    const original = JSON.stringify(DEFAULT_PROJECT);
    let random = 0x9e3779b9;
    for (let iteration = 0; iteration < 1000; ++iteration) {
      random ^= random << 13; random ^= random >>> 17; random ^= random << 5;
      const index = (random >>> 0) % original.length;
      const code = 32 + ((random >>> 8) % 95);
      const candidate = original.slice(0, index) + String.fromCharCode(code) + original.slice(index + 1);
      try {
        const decoded = JSON.parse(candidate) as unknown;
        const parsed = parseProject(decoded);
        expect(parseProject(parsed)).toEqual(parsed);
      } catch (cause) {
        expect(cause).toBeInstanceOf(Error);
      }
    }
  });
});
