// Project format 3 tests protect resource limits, profile compatibility and
// point-to-point ownership before a project can reach a runtime shard.

import { describe, expect, it } from "vitest";
import { createEmptyProjectV3, createRouterProjectV3, equippedRouterPorts,
  createFourRouterReferenceLabV3, parseLabProjectV3, PROFILE_CATALOG, type HostProjectV3,
  type LabProjectV3 } from "../src";

function host(id: string, octet: number): HostProjectV3 {
  // Tests vary only the final octet so every fixture remains in one subnet
  // while preserving globally unique IPv4 and MAC identities.
  return { id, kind: "host", name: id.toUpperCase(), eth0: {
    mac: `02:00:00:00:00:${octet.toString(16).padStart(2, "0")}`,
    address: `192.0.2.${octet}/24`, gateway: "192.0.2.1", mtu: 1500,
    mode: "ethernet"
  } };
}

describe("multi-router project format", () => {
  it("ships the four-router reference topology as ordinary project intent", () => {
    const project = createFourRouterReferenceLabV3();
    expect(project.routers.map((router) => router.profileId)).toEqual([
      "7750-sr-1", "7750-sr-7", "7750-sr-12", "7750-sr-7"
    ]);
    expect(project.hosts).toHaveLength(4);
    expect(project.links.map((link) => link.id)).toEqual(expect.arrayContaining([
      "r1-r2", "r2-r3", "r3-r4", "r1-r4"
    ]));
    expect(project.routers.every((router) =>
      router.running.staticRoutes.length === 3)).toBe(true);
    expect(parseLabProjectV3(project)).toEqual(project);
  });

  it("accepts canonical static prefixes with the IPv4 high bit set", () => {
    const project = createEmptyProjectV3();
    const router = createRouterProjectV3("r1", "7750-sr-1", "R1");
    router.running.staticRoutes.push({ prefix: "192.0.2.4/30",
      nextHop: "192.0.2.1" });
    project.routers.push(router);
    project.layout.nodes.r1 = { x: 0, y: 0 };
    expect(parseLabProjectV3(project).routers[0].running.staticRoutes)
      .toEqual(router.running.staticRoutes);
  });

  it("opens as an empty version 3 laboratory", () => {
    // Empty is a valid product state. A hidden default router would couple UI
    // startup to one topology and violate user-owned node creation.
    const project = createEmptyProjectV3(new Date("2026-07-16T10:00:00Z"));
    expect(parseLabProjectV3(project).version).toBe(3);
    expect(project.routers).toEqual([]);
    expect(project.hosts).toEqual([]);
    expect(project.links).toEqual([]);
  });

  it("constructs fixed SR-1 inventory without user-provisioned cards", () => {
    // The fixed profile exposes integrated hardware immediately because users
    // cannot insert a card into a chassis without modular card slots.
    const router = createRouterProjectV3("r1", "7750-sr-1", "R1");
    expect(router.hardware.cards[0].equippedType).toBe("cpm-1");
    expect(equippedRouterPorts(router)).toHaveLength(18);
    const project = createEmptyProjectV3();
    project.routers.push(router);
    project.layout.nodes.r1 = { x: 100, y: 100 };
    expect(parseLabProjectV3(project).routers[0].profileId).toBe("7750-sr-1");
  });

  it("keeps modular chassis empty until compatible hardware is equipped", () => {
    // An empty slot must stay operationally absent. Auto-equipping a default
    // card would create ports that the user never added.
    for (const profileId of ["7750-sr-7", "7750-sr-12"] as const) {
      const router = createRouterProjectV3("r1", profileId, "R1");
      expect(equippedRouterPorts(router)).toEqual([]);
      expect(router.hardware.cards).toHaveLength(
        PROFILE_CATALOG.profiles.find((profile) => profile.id === profileId)!.card_slots);
    }
  });

  it("accepts arbitrary point-to-point links and preserves links after hardware removal", () => {
    // The second router intentionally has no equipped card. Topology stores
    // cable intent independently, while runtime carrier remains down.
    const project = createEmptyProjectV3();
    const left = createRouterProjectV3("r1", "7750-sr-1", "R1");
    const right = createRouterProjectV3("r2", "7750-sr-7", "R2");
    project.routers.push(left, right);
    project.hosts.push(host("h1", 2));
    project.links.push(
      { id: "r1-r2", endpoints: [{ nodeId: "r1", portId: "1/1/1" },
        { nodeId: "r2", portId: "1/1/1" }], admin: "up", propagationDelayNs: 100 },
      { id: "r1-h1", endpoints: [{ nodeId: "r1", portId: "1/1/2" },
        { nodeId: "h1", portId: "eth0" }], admin: "up", propagationDelayNs: 100 }
    );
    project.layout.nodes = { r1: { x: 0, y: 0 }, r2: { x: 300, y: 0 }, h1: { x: 0, y: 200 } };
    expect(parseLabProjectV3(project).links).toHaveLength(2);
  });

  it("rejects resource overflow, duplicate bindings and stale formats", () => {
    // Fill the exact supported boundary before testing overflow so an off-by-
    // one error cannot pass merely because the fixture was already invalid.
    const project = createEmptyProjectV3();
    for (let index = 1; index <= 16; ++index) {
      const id = `r${index}`;
      project.routers.push(createRouterProjectV3(id, "7750-sr-1", id.toUpperCase()));
      project.layout.nodes[id] = { x: index * 10, y: 0 };
    }
    expect(parseLabProjectV3(project).routers).toHaveLength(16);
    const overflow = structuredClone(project);
    overflow.routers.push(createRouterProjectV3("r17", "7750-sr-1", "R17"));
    expect(() => parseLabProjectV3(overflow)).toThrow("router limit");
    expect(() => parseLabProjectV3({ ...project, version: 2 })).toThrow("not supported");

    const duplicate = createEmptyProjectV3() as LabProjectV3;
    // Both links claim the same physical router port. Validation must reject
    // the whole project instead of keeping the first link implicitly.
    duplicate.routers.push(createRouterProjectV3("r1", "7750-sr-1", "R1"));
    duplicate.hosts.push(host("h1", 2), host("h2", 3));
    duplicate.links.push(
      { id: "one", endpoints: [{ nodeId: "r1", portId: "1/1/1" },
        { nodeId: "h1", portId: "eth0" }], admin: "up", propagationDelayNs: 0 },
      { id: "two", endpoints: [{ nodeId: "r1", portId: "1/1/1" },
        { nodeId: "h2", portId: "eth0" }], admin: "up", propagationDelayNs: 0 }
    );
    duplicate.layout.nodes = { r1: { x: 0, y: 0 }, h1: { x: 1, y: 1 }, h2: { x: 2, y: 2 } };
    expect(() => parseLabProjectV3(duplicate)).toThrow("already connected");
  });

  it("rejects host and link overflow at the complete product boundary", () => {
    const hostOverflow = createEmptyProjectV3();
    for (let index = 1; index <= PROFILE_CATALOG.limits.hosts + 1; ++index) {
      const id = `h${index}`;
      hostOverflow.hosts.push(host(id, index));
      hostOverflow.layout.nodes[id] = { x: index, y: 0 };
    }
    expect(() => parseLabProjectV3(hostOverflow)).toThrow("host limit");

    const linkOverflow = createEmptyProjectV3();
    const freePorts: Array<{ nodeId: string; portId: string }> = [];
    for (let index = 1; index <= PROFILE_CATALOG.limits.routers; ++index) {
      const id = `r${index}`;
      const router = createRouterProjectV3(id, "7750-sr-1", id.toUpperCase());
      linkOverflow.routers.push(router);
      linkOverflow.layout.nodes[id] = { x: index, y: 0 };
      for (const port of equippedRouterPorts(router))
        freePorts.push({ nodeId: id, portId: port.id });
    }
    for (let index = 0; index <= PROFILE_CATALOG.limits.links; ++index) {
      linkOverflow.links.push({ id: `link-${index}`,
        endpoints: [freePorts[index * 2], freePorts[index * 2 + 1]],
        admin: "up", propagationDelayNs: 0 });
    }
    expect(() => parseLabProjectV3(linkOverflow)).toThrow("link limit");
  });

  it("atomically rejects varied malformed object graphs", () => {
    const valid = createFourRouterReferenceLabV3();
    const corruptions: Array<(value: LabProjectV3, seed: number) => void> = [
      (value, seed) => { value.links[seed % value.links.length].endpoints[0].nodeId = "missing"; },
      (value, seed) => { value.links[seed % value.links.length].id = value.links[(seed + 1) % value.links.length].id; },
      (value, seed) => { value.routers[seed % value.routers.length].id = "bad id with spaces"; },
      (value, seed) => { value.layout.nodes[value.routers[seed % value.routers.length].id].x = Number.NaN; }
    ];
    // Repeating each corruption across different graph positions catches
    // validators that accidentally inspect only the first node or first link.
    for (let seed = 0; seed < 32; ++seed) {
      const malformed = structuredClone(valid);
      corruptions[seed % corruptions.length](malformed, seed);
      expect(() => parseLabProjectV3(malformed)).toThrow();
      expect(parseLabProjectV3(valid)).toEqual(valid);
    }
  });
});
