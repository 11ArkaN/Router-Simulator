// Portable project and runtime projection tests exercise the browser trust
// boundary. Every accepted object must remain safe to send into C++.

import { describe, expect, it } from "vitest";
import { ABI_VERSION, DEFAULT_PROJECT, GENERATED_PROFILE, PROJECT_VERSION,
  parseProject, parseRuntimeSnapshot } from "../src";

describe("project format", () => {
  it("accepts the pinned default profile", () => {
    // Defaults are compiled from the active profile and must already satisfy
    // the same parser used for IndexedDB and imported files.
    expect(parseProject(DEFAULT_PROJECT).hardware.cards.every((card) =>
      card.equippedType === null)).toBe(true);
    expect(parseProject(DEFAULT_PROJECT).links[0].propagationDelayNs)
      .toBe(GENERATED_PROFILE.defaultPropagationDelayNs);
    expect(parseProject(DEFAULT_PROJECT).notes).toBe("");
    expect(DEFAULT_PROJECT.runningConfig.ports.filter((port) => port.admin === "up")
      .map((port) => port.id)).toEqual([...GENERATED_PROFILE.ports.initiallyEnabled]);
  });

  it("migrates absent additive project fields", () => {
    // The sole migration is lossless because links are deterministic profile
    // defaults. No unknown version or malformed provided value is repaired.
    const legacy = structuredClone(DEFAULT_PROJECT) as Partial<typeof DEFAULT_PROJECT>;
    delete legacy.links;
    delete legacy.notes;
    delete (legacy.layout as Partial<typeof DEFAULT_PROJECT.layout>).sidebarWidth;
    expect(parseProject(legacy).links).toEqual(DEFAULT_PROJECT.links);
    expect(parseProject(legacy).notes).toBe("");
    expect(parseProject(legacy).layout.sidebarWidth)
      .toBe(GENERATED_PROFILE.uiDefaults.sidebar_width);
  });

  it("bounds portable project notes", () => {
    // Notes travel with the .netsim project but never enter C++ runtime state.
    // The bound prevents a text field from bypassing binary-storage policy.
    const project = structuredClone(DEFAULT_PROJECT);
    project.notes = "Link maintenance window: 02:00 UTC";
    expect(parseProject(project).notes).toBe(project.notes);
    project.notes = "x".repeat(GENERATED_PROFILE.limits.project_notes_bytes + 1);
    expect(() => parseProject(project)).toThrow("invalid metadata");
  });

  it("bounds portable workspace dimensions", () => {
    // Import validation uses the same generated limits as range inputs. A
    // hand-edited .netsim file cannot make a sidebar, inspector or terminal
    // control permanently unreachable outside the responsive application grid.
    const project = structuredClone(DEFAULT_PROJECT);
    project.layout.sidebarWidth = GENERATED_PROFILE.uiDefaults.sidebar_width_max + 1;
    expect(() => parseProject(project)).toThrow("UI layout");
    project.layout.sidebarWidth = GENERATED_PROFILE.uiDefaults.sidebar_width;
    project.layout.inspectorWidth = GENERATED_PROFILE.uiDefaults.inspector_width_max + 1;
    expect(() => parseProject(project)).toThrow("UI layout");
    project.layout.inspectorWidth = GENERATED_PROFILE.uiDefaults.inspector_width;
    project.layout.terminalHeight = GENERATED_PROFILE.uiDefaults.terminal_height_min - 1;
    expect(() => parseProject(project)).toThrow("UI layout");
  });

  it("validates link identity and exactly representable nanoseconds", () => {
    const malformed = structuredClone(DEFAULT_PROJECT);
    malformed.links[0].propagationDelayNs = -1;
    expect(() => parseProject(malformed)).toThrow("invalid link configuration");

    malformed.links[0].propagationDelayNs = 1.5;
    expect(() => parseProject(malformed)).toThrow("invalid link configuration");

    // Source: ecma.number.max_safe_integer. A larger JSON number could round to
    // a different integer before it reaches the runtime command.
    malformed.links[0].propagationDelayNs = Number.MAX_SAFE_INTEGER + 1;
    expect(() => parseProject(malformed)).toThrow("invalid link configuration");
  });

  it("rejects a future ABI instead of guessing a migration", () => {
    // A future writer may change semantics even when fields look familiar.
    expect(() => parseProject({ ...DEFAULT_PROJECT, version: 3 })).toThrow("Unsupported project");
  });

  it("rejects malformed endpoint data before runtime configuration", () => {
    // Invalid text must remain an editable UI draft and never cross to C++.
    const malformed = structuredClone(DEFAULT_PROJECT);
    malformed.hosts[0].mac = "not-a-mac";
    expect(() => parseProject(malformed)).toThrow("invalid host");
  });

  it("rejects a child provisioned without its parent", () => {
    const malformed = structuredClone(DEFAULT_PROJECT);
    const card = malformed.hardware.cards[GENERATED_PROFILE.lineCard.slot - 1];
    card.provisionedType = null;
    card.mdas[GENERATED_PROFILE.mda.slot - 1].provisionedType =
      GENERATED_PROFILE.mda.modeledType;
    // The structural validator accepts only supported values. Dependency
    // validation remains explicit here so invalid persisted hardware cannot be
    // normalized silently while restoring the project.
    expect(() => parseProject(malformed)).toThrow("hardware state");
  });

  it("migrates version 1 live hardware into portable intent", () => {
    // Runtime-owned lifecycle is accepted only through the exact legacy shape
    // and discarded before the current project reaches restoration.
    const malformed = structuredClone(DEFAULT_PROJECT) as unknown as {
      version: number;
      hardware: {
        chassis?: string;
        control?: unknown;
        cards: Array<Record<string, unknown> & { mdas: Array<Record<string, unknown>> }>
      }
    };
    malformed.version = 1;
    malformed.hardware.chassis = GENERATED_PROFILE.chassis;
    malformed.hardware.control = {
      slot: GENERATED_PROFILE.control.slot,
      type: GENERATED_PROFILE.control.card,
      state: GENERATED_PROFILE.control.initial_state
    };
    for (const card of malformed.hardware.cards) {
      Object.assign(card, { compatible: true, lifecycle: "absent", reason: "not-equipped" });
      for (const mda of card.mdas) {
        Object.assign(mda, { compatible: true, lifecycle: "absent", reason: "not-equipped" });
      }
    }
    const migrated = parseProject(malformed);
    expect(migrated.version).toBe(PROJECT_VERSION);
    expect("lifecycle" in migrated.hardware.cards[0]).toBe(false);
  });

  it("rejects live lifecycle fields in a current project", () => {
    // Version 2 files cannot claim the legacy migration path merely by adding
    // operational fields to otherwise valid portable hardware.
    const malformed = structuredClone(DEFAULT_PROJECT) as unknown as {
      hardware: { cards: Array<Record<string, unknown>> }
    };
    malformed.hardware.cards[0].lifecycle = "ready";
    expect(() => parseProject(malformed)).toThrow("hardware state");
  });

  it("rejects a gateway outside the host prefix", () => {
    // Endpoint next-hop selection assumes gateway reachability on the local
    // medium, so a remote gateway would make ARP behavior undefined.
    const malformed = structuredClone(DEFAULT_PROJECT);
    malformed.hosts[0].gateway = "198.51.100.1";
    expect(() => parseProject(malformed)).toThrow("local prefix");
  });

  it("rejects reversed endpoint order and duplicate identities", () => {
    // Profile order is the compact endpoint index shared with C++. Reordering
    // would silently attach identities to different links without this check.
    const reversed = structuredClone(DEFAULT_PROJECT);
    reversed.hosts.reverse();
    expect(() => parseProject(reversed)).toThrow("invalid host");

    const duplicate = structuredClone(DEFAULT_PROJECT);
    duplicate.hosts[1].mac = duplicate.hosts[0].mac.toLowerCase();
    expect(() => parseProject(duplicate)).toThrow("duplicate endpoint");
  });

  it("rejects group MAC and IPv4 broadcast endpoint values", () => {
    // Hosts require unicast identities. Multicast MAC and subnet broadcast
    // values cannot participate in the modeled ARP and ICMP endpoint stack.
    const groupMac = structuredClone(DEFAULT_PROJECT);
    groupMac.hosts[0].mac = "01:00:5E:00:00:01";
    expect(() => parseProject(groupMac)).toThrow("duplicate endpoint");

    const broadcastIp = structuredClone(DEFAULT_PROJECT);
    broadcastIp.hosts[0].address = "192.0.2.3/30";
    expect(() => parseProject(broadcastIp)).toThrow("local prefix");
  });

  it("rejects an incompatible runtime snapshot ABI", () => {
    // Runtime projections deliberately include reconciler-owned fields that
    // portable project hardware excludes. Build that live shape explicitly.
    const runtimeHardware = {
      chassis: GENERATED_PROFILE.chassis,
      control: {
        slot: GENERATED_PROFILE.control.slot,
        type: GENERATED_PROFILE.control.card,
        state: GENERATED_PROFILE.control.initial_state
      },
      cards: DEFAULT_PROJECT.hardware.cards.map((card) => ({
        ...card, compatible: true, lifecycle: "absent", reason: "not-equipped",
        mdas: card.mdas.map((mda) => ({
          ...mda, compatible: true, lifecycle: "absent", reason: "not-equipped"
        }))
      }))
    };
    const snapshot = {
      abiVersion: ABI_VERSION,
      status: "ready",
      nowMs: 1,
      hardware: runtimeHardware,
      ports: GENERATED_PROFILE.links.map((link) => ({ id: link.router_port,
        admin: "up", oper: "up", physicalLink: true,
        speedMbps: GENERATED_PROFILE.ports.speedMbps,
        mtu: GENERATED_PROFILE.ports.defaultMtu, description: "", rxPackets: 0,
        txPackets: 0 })),
      arp: [], routes: [], alarms: [], runningConfig: DEFAULT_PROJECT.runningConfig,
      captureCount: 0, captureDropped: 0, droppedPackets: 0
    };
    expect(parseRuntimeSnapshot(snapshot).abiVersion).toBe(ABI_VERSION);
    // Physical media is not inferred from ifOperStatus. The versioned snapshot
    // rejects older projections that omit the independent carrier observation.
    expect(() => parseRuntimeSnapshot({ ...snapshot, ports: snapshot.ports.map(
      ({ physicalLink: _physicalLink, ...port }) => port) })).toThrow("operational data");
    expect(() => parseRuntimeSnapshot({ ...snapshot, abiVersion: 999 })).toThrow("incompatible ABI");
  });

  it("rejects non-canonical and duplicate static route keys", () => {
    // Canonical network keys keep route identity independent of host bits and
    // serialization order.
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
    // Deterministic xorshift mutation gives broad parser coverage without
    // introducing a flaky random seed into CI.
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
        // Rejection is expected for most mutations, but the boundary must fail
        // through a controlled Error rather than an unchecked type exception.
        expect(cause).toBeInstanceOf(Error);
      }
    }
  });
});
