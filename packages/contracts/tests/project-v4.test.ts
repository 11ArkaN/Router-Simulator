// Project format 4 tests protect resource limits, profile compatibility and
// point-to-point ownership before a project can reach a runtime shard.

import { describe, expect, it } from "vitest";
import { createEmptyProjectV4, createRouterProjectV4, equippedRouterPorts,
  createFourRouterReferenceLabV4, hostInterfaceId, parseLabProjectV4, PROFILE_CATALOG, type HostProjectV4,
  type LabProjectV4 } from "../src";

function host(id: string, octet: number): HostProjectV4 {
  // Tests vary only the final octet so every fixture remains in one subnet
  // while preserving globally unique IPv4 and MAC identities.
  return { id, kind: "host", name: id.toUpperCase(), eth0: {
    mac: `02:00:00:00:00:${octet.toString(16).padStart(2, "0")}`,
    address: `192.0.2.${octet}/24`, gateway: "192.0.2.1", mtu: 1500,
    mode: "ethernet",
    transportSecretHex: octet.toString(16).padStart(2, "0").repeat(32),
    dns: { resolver: null, authoritative: null },
    ipv6: { autoconfiguration: true, interfaceId: hostInterfaceId(id),
      interfaceIdentifierMode: "modified-eui64", stableIidSecret: null,
      networkId: "", dhcpv6: { client: null, server: null } }
  } };
}

describe("multi-router project format", () => {
  it("ships the four-router reference topology as ordinary project intent", () => {
    const project = createFourRouterReferenceLabV4();
    expect(project.routers.map((router) => router.profileId)).toEqual([
      "7750-sr-1", "7750-sr-7", "7750-sr-12", "7750-sr-7"
    ]);
    expect(project.hosts).toHaveLength(4);
    expect(project.links.map((link) => link.id)).toEqual(expect.arrayContaining([
      "r1-r2", "r2-r3", "r3-r4", "r1-r4"
    ]));
    expect(project.routers.every((router) =>
      router.running.staticRoutes.length === 3)).toBe(true);
    expect(parseLabProjectV4(project)).toEqual(project);
  });

  it("accepts canonical static prefixes with the IPv4 high bit set", () => {
    const project = createEmptyProjectV4();
    const router = createRouterProjectV4("r1", "7750-sr-1", "R1");
    router.running.staticRoutes.push({ prefix: "192.0.2.4/30",
      nextHop: "192.0.2.1" });
    project.routers.push(router);
    project.layout.nodes.r1 = { x: 0, y: 0 };
    expect(parseLabProjectV4(project).routers[0].running.staticRoutes)
      .toEqual(router.running.staticRoutes);
  });

  it("persists the reserved IPv4 system interface without a physical port", () => {
    const project = createEmptyProjectV4();
    const router = createRouterProjectV4("r1", "7750-sr-1", "R1");
    router.running.interfaces.push({ name: "system", admin: "up",
      portId: "", address: "10.255.0.1/32", arpTimeoutSeconds: null,
      arpRetryTimerDeciseconds: null, ipv6Addresses: [] });
    project.routers.push(router);
    project.layout.nodes.r1 = { x: 0, y: 0 };
    expect(parseLabProjectV4(project).routers[0].running.interfaces[0])
      .toEqual(router.running.interfaces[0]);

    const physical = structuredClone(project);
    physical.routers[0].running.interfaces[0].portId = "1/1/1";
    expect(() => parseLabProjectV4(physical)).toThrow("interface configuration");
    const subnet = structuredClone(project);
    subnet.routers[0].running.interfaces[0].address = "10.255.0.0/31";
    expect(() => parseLabProjectV4(subnet)).toThrow("interface configuration");
  });

  it("persists router IPv6 interfaces and scoped static routes", () => {
    const project = createEmptyProjectV4();
    const router = createRouterProjectV4("r1", "7750-sr-1", "R1");

    // A global next hop is unambiguous without a scope, while a link-local
    // next hop must carry its physical egress port. Keeping that scope in the
    // project prevents restore from guessing an interface from current links.
    router.running.interfaces.push({ name: "edge", admin: "up",
      portId: "1/1/1", address: "", arpTimeoutSeconds: 0,
      arpRetryTimerDeciseconds: 25, ipv6Addresses: [{
        address: "2001:db8:1::1/64", duplicateAddressDetection: true, eui64: false,
        eui64SourceMac: null,
        primaryPreference: 10, tag: null
      }, {
        address: "2001:db8:3::1/64", duplicateAddressDetection: false, eui64: false,
        eui64SourceMac: null,
        primaryPreference: 20, tag: 700
      }, {
        // This is the configured prefix key. The captured source MAC preserves
        // the effective IID if the routed interface is detached and later
        // attached to a different Ethernet port.
        address: "2001:db8:4::/64", duplicateAddressDetection: true, eui64: true,
        eui64SourceMac: "02:00:00:00:01:01",
        primaryPreference: 30, tag: null
      }] });
    router.running.ipv6StaticRoutes.push({ prefix: "2001:db8:2::/64",
      nextHop: "fe80::2", outgoingPortId: "1/1/1" });
    project.routers.push(router);
    project.layout.nodes.r1 = { x: 0, y: 0 };
    const restored = parseLabProjectV4(project).routers[0].running;
    expect(restored.interfaces[0].ipv6Addresses).toEqual(
      router.running.interfaces[0].ipv6Addresses);
    expect(restored.ipv6StaticRoutes).toEqual(router.running.ipv6StaticRoutes);

    const unscoped = structuredClone(project);
    unscoped.routers[0].running.ipv6StaticRoutes[0].outgoingPortId = "";
    expect(() => parseLabProjectV4(unscoped)).toThrow("static route");

    const hostBits = structuredClone(project);
    hostBits.routers[0].running.ipv6StaticRoutes[0].prefix =
      "2001:db8:2::1/64";
    expect(() => parseLabProjectV4(hostBits)).toThrow("static route");
  });

  it("opens as an empty version 3 laboratory", () => {
    // Empty is a valid product state. A hidden default router would couple UI
    // startup to one topology and violate user-owned node creation.
    const project = createEmptyProjectV4(new Date("2026-07-16T10:00:00Z"));
    expect(parseLabProjectV4(project).version).toBe(4);
    expect(project.routers).toEqual([]);
    expect(project.hosts).toEqual([]);
    expect(project.links).toEqual([]);
  });

  it("constructs fixed SR-1 inventory without user-provisioned cards", () => {
    // The fixed profile exposes integrated hardware immediately because users
    // cannot insert a card into a chassis without modular card slots.
    const router = createRouterProjectV4("r1", "7750-sr-1", "R1");
    expect(router.hardware.cards[0].equippedType).toBe("cpm-1");
    expect(equippedRouterPorts(router)).toHaveLength(18);
    const project = createEmptyProjectV4();
    project.routers.push(router);
    project.layout.nodes.r1 = { x: 100, y: 100 };
    expect(parseLabProjectV4(project).routers[0].profileId).toBe("7750-sr-1");
  });

  it("keeps modular chassis empty until compatible hardware is equipped", () => {
    // An empty slot must stay operationally absent. Auto-equipping a default
    // card would create ports that the user never added.
    for (const profileId of ["7750-sr-7", "7750-sr-12"] as const) {
      const router = createRouterProjectV4("r1", profileId, "R1");
      expect(equippedRouterPorts(router)).toEqual([]);
      expect(router.hardware.cards).toHaveLength(
        PROFILE_CATALOG.profiles.find((profile) => profile.id === profileId)!.card_slots);
    }
  });

  it("accepts arbitrary point-to-point links and preserves links after hardware removal", () => {
    // The second router intentionally has no equipped card. Topology stores
    // cable intent independently, while runtime carrier remains down.
    const project = createEmptyProjectV4();
    const left = createRouterProjectV4("r1", "7750-sr-1", "R1");
    const right = createRouterProjectV4("r2", "7750-sr-7", "R2");
    project.routers.push(left, right);
    project.hosts.push(host("h1", 2));
    project.links.push(
      { id: "r1-r2", endpoints: [{ nodeId: "r1", portId: "1/1/1" },
        { nodeId: "r2", portId: "1/1/1" }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 },
      { id: "r1-h1", endpoints: [{ nodeId: "r1", portId: "1/1/2" },
        { nodeId: "h1", portId: "eth0" }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 }
    );
    project.layout.nodes = { r1: { x: 0, y: 0 }, r2: { x: 300, y: 0 }, h1: { x: 0, y: 200 } };
    expect(parseLabProjectV4(project).links).toHaveLength(2);
  });

  it("rejects resource overflow, duplicate bindings and stale formats", () => {
    // Fill the exact supported boundary before testing overflow so an off-by-
    // one error cannot pass merely because the fixture was already invalid.
    const project = createEmptyProjectV4();
    for (let index = 1; index <= 16; ++index) {
      const id = `r${index}`;
      project.routers.push(createRouterProjectV4(id, "7750-sr-1", id.toUpperCase()));
      project.layout.nodes[id] = { x: index * 10, y: 0 };
    }
    expect(parseLabProjectV4(project).routers).toHaveLength(16);
    const overflow = structuredClone(project);
    overflow.routers.push(createRouterProjectV4("r17", "7750-sr-1", "R17"));
    expect(() => parseLabProjectV4(overflow)).toThrow("router limit");
    expect(() => parseLabProjectV4({ ...project, version: 2 })).toThrow("not supported");

    const duplicate = createEmptyProjectV4() as LabProjectV4;
    // Both links claim the same physical router port. Validation must reject
    // the whole project instead of keeping the first link implicitly.
    duplicate.routers.push(createRouterProjectV4("r1", "7750-sr-1", "R1"));
    duplicate.hosts.push(host("h1", 2), host("h2", 3));
    duplicate.links.push(
      { id: "one", endpoints: [{ nodeId: "r1", portId: "1/1/1" },
        { nodeId: "h1", portId: "eth0" }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 0 },
      { id: "two", endpoints: [{ nodeId: "r1", portId: "1/1/1" },
        { nodeId: "h2", portId: "eth0" }], admin: "up", configuredSpeedMbps: 10000, propagationDelayNs: 0 }
    );
    duplicate.layout.nodes = { r1: { x: 0, y: 0 }, h1: { x: 1, y: 1 }, h2: { x: 2, y: 2 } };
    expect(() => parseLabProjectV4(duplicate)).toThrow("already connected");
  });

  it("rejects host and link overflow at the complete product boundary", () => {
    const hostOverflow = createEmptyProjectV4();
    for (let index = 1; index <= PROFILE_CATALOG.limits.hosts + 1; ++index) {
      const id = `h${index}`;
      hostOverflow.hosts.push(host(id, index));
      hostOverflow.layout.nodes[id] = { x: index, y: 0 };
    }
    expect(() => parseLabProjectV4(hostOverflow)).toThrow("host limit");

    const linkOverflow = createEmptyProjectV4();
    const freePorts: Array<{ nodeId: string; portId: string }> = [];
    for (let index = 1; index <= PROFILE_CATALOG.limits.routers; ++index) {
      const id = `r${index}`;
      const router = createRouterProjectV4(id, "7750-sr-1", id.toUpperCase());
      linkOverflow.routers.push(router);
      linkOverflow.layout.nodes[id] = { x: index, y: 0 };
      for (const port of equippedRouterPorts(router))
        freePorts.push({ nodeId: id, portId: port.id });
    }
    for (let index = 0; index <= PROFILE_CATALOG.limits.links; ++index) {
      linkOverflow.links.push({ id: `link-${index}`,
        endpoints: [freePorts[index * 2], freePorts[index * 2 + 1]],
        admin: "up", configuredSpeedMbps: null, propagationDelayNs: 0 });
    }
    expect(() => parseLabProjectV4(linkOverflow)).toThrow("link limit");
  });

  it("validates every input needed to reproduce a stable opaque IPv6 interface identifier", () => {
    const project = createEmptyProjectV4();
    const stableHost = host("h1", 2);

    // RFC 7217 stability depends on both a secret unknown outside the node and
    // a link-specific Network_ID. Accepting either as an implicit default
    // would make two independently created hosts derive predictable or
    // accidentally identical identifiers, so the portable format carries
    // both values explicitly.
    stableHost.eth0.ipv6.interfaceIdentifierMode = "stable-opaque";
    stableHost.eth0.ipv6.stableIidSecret =
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    stableHost.eth0.ipv6.networkId = "access-link-17";
    project.hosts.push(stableHost);
    project.layout.nodes.h1 = { x: 0, y: 0 };
    expect(parseLabProjectV4(project).hosts[0].eth0.ipv6).toEqual(stableHost.eth0.ipv6);

    // A syntactically correct all-zero secret still has no entropy. Reject it
    // at the project boundary instead of allowing a deterministic privacy
    // identifier to reach the owner running in the forwarding shard.
    const zeroSecret = structuredClone(project);
    zeroSecret.hosts[0].eth0.ipv6.stableIidSecret = "0".repeat(64);
    expect(() => parseLabProjectV4(zeroSecret)).toThrow("Ethernet configuration is invalid");

    const missingNetwork = structuredClone(project);
    missingNetwork.hosts[0].eth0.ipv6.networkId = "";
    expect(() => parseLabProjectV4(missingNetwork)).toThrow("Ethernet configuration is invalid");

    const malformedSecret = structuredClone(project);
    malformedSecret.hosts[0].eth0.ipv6.stableIidSecret = "not-a-256-bit-secret";
    expect(() => parseLabProjectV4(malformedSecret)).toThrow("Ethernet configuration is invalid");
  });

  it("validates portable stateful DHCPv6 client and server intent", () => {
    const project = createEmptyProjectV4();
    const endpoint = host("h1", 2);
    const secret = "01".repeat(32);
    endpoint.eth0.ipv6.dhcpv6 = {
      client: {
        duidHex: "00030001020000000002",
        transactionSecretHex: "02".repeat(32), rapidCommit: true,
        informationOnly: false,
        identityAssociations: [{ iaid: 1, kind: "ia-na" },
          { iaid: 2, kind: "ia-pd" }], requestedOptions: [23, 32]
      },
      server: {
        duidHex: "00030001020000000003", preference: 127,
        rapidCommit: true, dnsRecursiveServers: ["2001:db8::53"],
        informationRefreshTimeSeconds: 86400,
        solicitMaximumRetransmissionSeconds: 3600,
        informationMaximumRetransmissionSeconds: null,
        declineHoldTimeSeconds: 3600, addressPoolIndex: 0,
        prefixPoolIndex: 0,
        addressPools: [{ prefix: "2001:db8:1::/64",
          allocationSecretHex: secret, preferredLifetimeSeconds: 1800,
          validLifetimeSeconds: 3600, t1Seconds: 900, t2Seconds: 1440,
          delegatedLength: null }],
        prefixPools: [{ prefix: "2001:db8:100::/56",
          allocationSecretHex: secret, preferredLifetimeSeconds: 1800,
          validLifetimeSeconds: 3600, t1Seconds: 900, t2Seconds: 1440,
          delegatedLength: 64 }]
      }
    };
    project.hosts.push(endpoint);
    project.layout.nodes.h1 = { x: 0, y: 0 };
    expect(parseLabProjectV4(project).hosts[0].eth0.ipv6.dhcpv6.client
      ?.identityAssociations).toHaveLength(2);

    const duplicateIa = structuredClone(project);
    duplicateIa.hosts[0].eth0.ipv6.dhcpv6.client!
      .identityAssociations.push({ iaid: 1, kind: "ia-na" });
    expect(() => parseLabProjectV4(duplicateIa)).toThrow("identity association");
    const hostBits = structuredClone(project);
    hostBits.hosts[0].eth0.ipv6.dhcpv6.server!.addressPools[0].prefix =
      "2001:db8:1::1/64";
    expect(() => parseLabProjectV4(hostBits)).toThrow("lease pool");
  });

  it("validates portable DNS and managed DNSSEC intent", () => {
    const project = createEmptyProjectV4();
    const endpoint = host("dns", 53);
    endpoint.eth0.dns = {
      resolver: {
        identifierSecretHex: "53".repeat(32), maximumNsec3Iterations: 0,
        serveClients: false,
        rootHints: [{ serverName: "ns.example.test.",
          addresses: [{ family: "ipv4", address: "192.0.2.53" },
            { family: "ipv6", address: "2001:db8::53" }] }],
        trustAnchors: []
      },
      authoritative: {
        zones: [{ origin: "example.test.", masterFile:
          "$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns hostmaster " +
          "(1 3600 600 86400 60)\n@ IN NS ns\nns IN A 192.0.2.53\n" }],
        signing: {
          dnskeyTtl: 300, denialTtl: 60, denialMode: "nsec",
          validitySeconds: 3600, refreshSeconds: 1200,
          resignSeconds: 600, inceptionOffsetSeconds: 60,
          keys: [{ role: "ksk", algorithm: 15, rsaBits: 2048,
            publishAt: 100, readyAt: 100, activateAt: 100, retireAt: 5000,
            deadAt: 5100, removeAt: 5200 },
          { role: "zsk", algorithm: 15, rsaBits: 2048,
            publishAt: 100, readyAt: 100, activateAt: 100, retireAt: 5000,
            deadAt: 5100, removeAt: 5200 }]
        }
      }
    };
    project.hosts.push(endpoint);
    project.layout.nodes.dns = { x: 0, y: 0 };
    expect(parseLabProjectV4(project).hosts[0].eth0.dns)
      .toEqual(endpoint.eth0.dns);

    const unsupported = structuredClone(project);
    unsupported.hosts[0].eth0.dns.authoritative!.signing!
      .keys[0].algorithm = 16;
    expect(() => parseLabProjectV4(unsupported)).toThrow("signing key");
    const incompleteRoles = structuredClone(project);
    incompleteRoles.hosts[0].eth0.dns.authoritative!.signing!
      .keys[0].role = "zsk";
    expect(() => parseLabProjectV4(incompleteRoles)).toThrow("KSK and ZSK");
  });

  it("atomically rejects varied malformed object graphs", () => {
    const valid = createFourRouterReferenceLabV4();
    const corruptions: Array<(value: LabProjectV4, seed: number) => void> = [
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
      expect(() => parseLabProjectV4(malformed)).toThrow();
      expect(parseLabProjectV4(valid)).toEqual(valid);
    }
  });
});
