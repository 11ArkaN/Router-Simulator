// Project format 3 stores portable multi-device intent. This module owns all
// structural validation and has no browser, persistence or runtime dependency.

import { PROFILE_CATALOG } from "./generated-device-catalog";

export const LAB_PROJECT_VERSION = 3 as const;
export const LAB_MANIFEST_VERSION = 2 as const;
export const LAB_RELEASE = PROFILE_CATALOG.release;

export type NodeId = string;
export type LinkId = string;
export type SessionId = string;
export type DeviceProfileId = typeof PROFILE_CATALOG.profiles[number]["id"];
type MdaProfileId = keyof typeof PROFILE_CATALOG.mdas;

export interface RouterPortIntent {
  id: string;
  admin: "up" | "down";
  mtu: number;
  description: string;
  speedMbps: number;
}

export interface RouterInterfaceIntent {
  name: string;
  admin: "up" | "down";
  portId: string;
  address: string;
}

export interface RouterRunningIntent {
  systemName: string;
  ports: RouterPortIntent[];
  interfaces: RouterInterfaceIntent[];
  staticRoutes: Array<{ prefix: string; nextHop: string }>;
}

export interface RouterMdaIntent {
  slot: number;
  admin: "up" | "down";
  provisionedType: string | null;
  equippedType: string | null;
}

export interface RouterCardIntent {
  slot: number;
  admin: "up" | "down";
  provisionedType: string | null;
  equippedType: string | null;
  mdas: RouterMdaIntent[];
}

export interface RouterProjectV3 {
  id: NodeId;
  kind: "router";
  profileId: DeviceProfileId;
  release: typeof LAB_RELEASE;
  systemName: string;
  hardware: { cards: RouterCardIntent[] };
  running: RouterRunningIntent;
}

export interface HostProjectV3 {
  id: NodeId;
  kind: "host";
  name: string;
  eth0: {
    mac: string;
    address: string;
    gateway: string;
    mtu: number;
    mode: "ethernet";
  };
}

export interface PortRefV3 {
  nodeId: NodeId;
  portId: string;
}

export interface LinkProjectV3 {
  id: LinkId;
  endpoints: readonly [PortRefV3, PortRefV3];
  admin: "up" | "down";
  propagationDelayNs: number;
}

export interface LabProjectV3 {
  format: "router-simulator-project";
  version: typeof LAB_PROJECT_VERSION;
  projectId: string;
  name: string;
  routers: RouterProjectV3[];
  hosts: HostProjectV3[];
  links: LinkProjectV3[];
  notes: string;
  layout: {
    nodes: Record<NodeId, { x: number; y: number }>;
    sidebarWidth: number;
    inspectorWidth: number;
    terminalHeight: number;
  };
  updatedAt: string;
}

export interface ProjectManifestV2 {
  formatVersion: typeof LAB_MANIFEST_VERSION;
  mode: "project" | "checkpoint";
  project: LabProjectV3;
  checkpointAbi: 5;
  checkpointBase64?: string;
  captureBase64?: string;
  terminalPresentation?: import("./terminal-presentation-v2").TerminalPresentationV2;
}

const encoder = new TextEncoder();
const identifierPattern = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i;
const portPattern = /^\d{1,2}\/\d{1,2}\/\d{1,3}$/;
const macPattern = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

function assert(condition: unknown, message: string): asserts condition {
  // All project failures use one exception path so callers cannot accidentally
  // continue with an object that passed only part of structural validation.
  if (!condition) throw new Error(message);
}

function profileById(id: string) {
  // Three profiles make a generated array scan cheaper and less error-prone
  // than maintaining a second hand-written lookup table.
  return PROFILE_CATALOG.profiles.find((profile) => profile.id === id);
}

function cardByType(profile: typeof PROFILE_CATALOG.profiles[number], type: string) {
  // Compatibility is scoped to the chassis profile. Finding the same card text
  // in another profile must not make it legal on this router.
  return profile.cards.find((card) => card.type === type);
}

function mdaByType(type: string) {
  // Object.hasOwn blocks prototype names from becoming catalog records when a
  // hand-edited project supplies untrusted text such as "constructor".
  return Object.hasOwn(PROFILE_CATALOG.mdas, type)
    ? PROFILE_CATALOG.mdas[type as MdaProfileId]
    : undefined;
}

function parseIpv4(text: string): number | undefined {
  // Canonical decimal parsing is implemented explicitly because URL and number
  // parsers accept hexadecimal, signs or truncated input on different hosts.
  const octets = text.split(".");
  if (octets.length !== 4) return undefined;
  let result = 0;
  for (const octet of octets) {
    // Requiring one to three decimal digits rejects empty components and keeps
    // native and browser project validation aligned.
    if (!/^\d{1,3}$/.test(octet)) return undefined;
    const value = Number(octet);
    if (value > 255) return undefined;
    result = (result * 256 + value) >>> 0;
  }
  return result;
}

function parsePrefix(text: string): { address: number; length: number } | undefined {
  // A single slash separates the address and prefix. parseIpv4 rejects any
  // additional slash because it becomes part of the final octet text.
  const slash = text.indexOf("/");
  if (slash < 1) return undefined;
  const address = parseIpv4(text.slice(0, slash));
  const lengthText = text.slice(slash + 1);
  if (address === undefined || !/^\d{1,2}$/.test(lengthText)) return undefined;
  const length = Number(lengthText);
  return length <= 32 ? { address, length } : undefined;
}

function canonicalPrefix(text: string): boolean {
  // Static route keys contain no host bits. Rejecting rather than normalizing
  // protects round trips and matches the route manager's exact key semantics.
  const prefix = parsePrefix(text);
  if (!prefix) return false;
  const mask = prefix.length === 0 ? 0 : (0xffffffff << (32 - prefix.length)) >>> 0;
  // JavaScript bitwise operators return a signed int32. Converting the masked
  // result back to uint32 keeps valid prefixes such as 192.0.2.4/30 from being
  // rejected only because their high address bit is set.
  return ((prefix.address & mask) >>> 0) === prefix.address;
}

function isUnicastMac(text: string): boolean {
  // IEEE individual addresses have the low bit of the first octet clear. The
  // all-zero value is reserved as unresolved adjacency state in the core.
  if (!macPattern.test(text)) return false;
  const first = Number.parseInt(text.slice(0, 2), 16);
  return (first & 1) === 0 && !/^00:00:00:00:00:00$/i.test(text);
}

function maximumPortForProfile(profile: typeof PROFILE_CATALOG.profiles[number]): number {
  // Removed hardware may leave a cable in project intent. Validation therefore
  // checks the largest compatible MDA position, not only current inventory.
  let maximum = 0;
  for (const card of profile.cards) {
    for (const mdaType of card.mdas) {
      const mda = PROFILE_CATALOG.mdas[mdaType];
      maximum = Math.max(maximum, mda.ports.reduce((sum, group) => sum + group.count, 0));
    }
  }
  return maximum;
}

export function isPossibleRouterPort(profileId: DeviceProfileId, portId: string): boolean {
  // This test proves that a port can exist on the selected chassis. Carrier and
  // inventory are separate live-state questions evaluated by the runtime.
  const profile = profileById(profileId);
  if (!profile || !portPattern.test(portId)) return false;
  const [card, mda, port] = portId.split("/").map(Number);
  const maximumCard = profile.fixed ? 1 : profile.card_slots;
  const maximumMda = Math.max(...profile.cards.map((item) => item.mda_slots));
  return card >= 1 && card <= maximumCard && mda >= 1 && mda <= maximumMda &&
    port >= 1 && port <= maximumPortForProfile(profile);
}

export function equippedRouterPorts(router: RouterProjectV3): RouterPortIntent[] {
  // Port inventory is derived from matching provisioned and equipped hardware.
  // A mismatch exposes no operational ports and never fabricates a fallback.
  const profile = profileById(router.profileId);
  if (!profile) return [];
  const result: RouterPortIntent[] = [];
  for (const card of router.hardware.cards) {
    // Provisioned type selects compatibility. Equipped type selects physical
    // presence. Both must match before an MDA can contribute ports.
    const cardType = card.equippedType ?? card.provisionedType;
    const cardProfile = cardType ? cardByType(profile, cardType) : undefined;
    if (!cardProfile || card.equippedType !== card.provisionedType) continue;
    for (const mda of card.mdas) {
      // Resource modules such as ISA records have no Ethernet groups and add no
      // linkable ports even though they remain valid hardware inventory.
      if (!mda.equippedType || mda.equippedType !== mda.provisionedType ||
          !cardProfile.mdas.includes(mda.equippedType as never)) continue;
      const mdaProfile = mdaByType(mda.equippedType);
      if (!mdaProfile) continue;
      let portNumber = 1;
      for (const group of mdaProfile.ports) {
        // Mixed-rate MDAs retain one physical sequence across groups. The
        // highest supported speed is the initial selected port speed.
        for (let index = 0; index < group.count; ++index, ++portNumber) {
          const id = `${card.slot}/${mda.slot}/${portNumber}`;
          const saved = router.running.ports.find((port) => port.id === id);
          result.push(saved ?? { id, admin: "down",
            mtu: PROFILE_CATALOG.ethernet.default_network_mtu, description: "",
            speedMbps: group.speeds_mbps[group.speeds_mbps.length - 1] });
        }
      }
    }
  }
  return result;
}

function emptyHardware(profile: typeof PROFILE_CATALOG.profiles[number]): RouterProjectV3["hardware"] {
  // Modular chassis start physically empty. This preserves the hardware
  // dependency of port inventory instead of giving every new router magic
  // ports merely because its profile supports a card.
  if (!profile.fixed) {
    return { cards: Array.from({ length: profile.card_slots }, (_, index) => ({
      slot: index + 1, admin: "down" as const,
      provisionedType: null, equippedType: null,
      mdas: Array.from({ length: Math.max(...profile.cards.map((card) => card.mda_slots)) },
        (_, mda) => ({ slot: mda + 1, admin: "down" as const,
          provisionedType: null, equippedType: null }))
    })) };
  }
  // SR-1 is fixed form factor. Its integrated card and default MDA identities
  // cannot be removed through card-slot configuration.
  const card = profile.cards[0];
  return { cards: [{ slot: 1, admin: "up", provisionedType: card.type, equippedType: card.type,
    mdas: profile.default_hardware.mdas.map((type, index) => ({
      slot: index + 1, admin: "up", provisionedType: type, equippedType: type
    })) }] };
}

export function createRouterProjectV3(id: NodeId, profileId: DeviceProfileId,
  systemName = id.toUpperCase()): RouterProjectV3 {
  // Validate identity before allocating nested hardware arrays. A failed add
  // operation therefore has no partially constructed project node to clean up.
  assert(identifierPattern.test(id), "Router ID is invalid");
  const profile = profileById(profileId);
  assert(profile, "Router profile is not supported");
  const router: RouterProjectV3 = {
    id, kind: "router", profileId, release: LAB_RELEASE, systemName,
    hardware: emptyHardware(profile),
    running: { systemName, ports: [], interfaces: [], staticRoutes: [] }
  };
  // Fixed platforms receive their real derived inventory now. Modular routers
  // remain at zero ports until the user provisions and equips hardware.
  router.running.ports = equippedRouterPorts(router);
  return router;
}

export function createEmptyProjectV3(now = new Date()): LabProjectV3 {
  // UUID identity survives project rename and prevents OPFS transcript paths
  // from colliding when two projects use the same display name.
  const timestamp = now.toISOString();
  const random = globalThis.crypto?.randomUUID?.() ??
    `lab-${now.getTime().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  return {
    format: "router-simulator-project", version: LAB_PROJECT_VERSION,
    projectId: random, name: "Untitled lab", routers: [], hosts: [], links: [],
    notes: "", layout: { nodes: {}, sidebarWidth: 194, inspectorWidth: 324,
      terminalHeight: 360 }, updatedAt: timestamp
  };
}

function validateHardware(router: RouterProjectV3,
  profile: typeof PROFILE_CATALOG.profiles[number]): void {
  // Slot arrays are canonical and dense. A sparse or reordered array could
  // otherwise map configuration for one slot onto another during C++ import.
  const expectedCards = profile.fixed ? 1 : profile.card_slots;
  assert(router.hardware.cards.length === expectedCards, `${router.id} has an invalid card slot count`);
  for (let index = 0; index < router.hardware.cards.length; ++index) {
    const card = router.hardware.cards[index];
    assert(card.slot === index + 1 && (card.admin === "up" || card.admin === "down"),
      `${router.id} card slots are not canonical`);
    if (profile.fixed) {
      // Fixed hardware is inventory, not user choice. Project files cannot
      // remove or replace the integrated CPM through desired configuration.
      assert(card.provisionedType === profile.cards[0].type &&
        card.equippedType === profile.cards[0].type && card.admin === "up",
      `${router.id} fixed card cannot be changed`);
    }
    for (const type of [card.provisionedType, card.equippedType]) {
      // Provisioned and equipped identities are checked independently so a
      // valid mismatch remains representable and can produce a live alarm.
      assert(type === null || Boolean(cardByType(profile, type)), `${router.id} has an incompatible card`);
    }
    assert(card.provisionedType !== null || card.admin === "down",
      `${router.id} cannot enable an unprovisioned card`);
    const selectedCard = card.provisionedType ? cardByType(profile, card.provisionedType) : undefined;
    const maximumMdas = Math.max(...profile.cards.map((item) => item.mda_slots));
    assert(card.mdas.length === maximumMdas || profile.fixed && card.mdas.length === selectedCard?.mda_slots,
      `${router.id} has an invalid MDA slot count`);
    for (let mdaIndex = 0; mdaIndex < card.mdas.length; ++mdaIndex) {
      const mda = card.mdas[mdaIndex];
      assert(mda.slot === mdaIndex + 1 && (mda.admin === "up" || mda.admin === "down"),
        `${router.id} MDA slots are not canonical`);
      for (const type of [mda.provisionedType, mda.equippedType]) {
        // MDA compatibility follows the provisioned parent card. An unprovided
        // parent cannot acquire a child type through a hand-edited project.
        assert(type === null || Boolean(selectedCard?.mdas.includes(type as never)),
          `${router.id} has an incompatible MDA`);
      }
      assert(mda.provisionedType !== null || mda.admin === "down",
        `${router.id} cannot enable an unprovisioned MDA`);
      if (profile.fixed) assert(mda.admin === "up",
        `${router.id} fixed MDA cannot be disabled`);
    }
  }
}

export function parseLabProjectV3(input: unknown): LabProjectV3 {
  // Validation is fail-closed and non-mutating. The final structuredClone is
  // the first value returned to persistence or the runtime bridge.
  assert(input && typeof input === "object" && !Array.isArray(input), "Project must be an object");
  const project = input as Partial<LabProjectV3>;
  assert(project.format === "router-simulator-project" && project.version === LAB_PROJECT_VERSION,
    "Project format is not supported");
  assert(typeof project.projectId === "string" && identifierPattern.test(project.projectId),
    "Project ID is invalid");
  assert(typeof project.name === "string" && encoder.encode(project.name).length <= 128,
    "Project name is invalid");
  assert(Array.isArray(project.routers) && project.routers.length <= PROFILE_CATALOG.limits.routers,
    "Project exceeds the router limit");
  assert(Array.isArray(project.hosts) && project.hosts.length <= PROFILE_CATALOG.limits.hosts,
    "Project exceeds the host limit");
  assert(Array.isArray(project.links) && project.links.length <= PROFILE_CATALOG.limits.links,
    "Project exceeds the link limit");
  assert(typeof project.notes === "string" && encoder.encode(project.notes).length <= 65536,
    "Project notes are invalid");
  assert(typeof project.updatedAt === "string" && Number.isFinite(Date.parse(project.updatedAt)),
    "Project update time is invalid");

  const nodes = new Map<NodeId, "router" | "host">();
  // MAC and IPv4 uniqueness spans router interfaces and hosts. Separate local
  // validators would miss conflicts between those two node classes.
  const macs = new Set<string>();
  const addresses = new Set<number>();
  for (const router of project.routers) {
    // Stable node IDs are registered before links are examined, but only after
    // the complete router record passes profile and configuration validation.
    assert(router?.kind === "router" && identifierPattern.test(router.id) && !nodes.has(router.id),
      "Router identity is invalid or duplicated");
    const profile = profileById(router.profileId);
    assert(profile && router.release === LAB_RELEASE, `${router.id} profile or release is not supported`);
    assert(typeof router.systemName === "string" && encoder.encode(router.systemName).length <= 64,
      `${router.id} system name is invalid`);
    validateHardware(router, profile);
    assert(router.running?.systemName === router.systemName && Array.isArray(router.running.ports) &&
      Array.isArray(router.running.interfaces) && Array.isArray(router.running.staticRoutes),
      `${router.id} running configuration is invalid`);
    const portIds = new Set<string>();
    for (const port of router.running.ports) {
      // Persisted port configuration may outlive equipped inventory. It still
      // must name a physical position possible for this chassis profile.
      assert(isPossibleRouterPort(router.profileId, port.id) && !portIds.has(port.id) &&
        (port.admin === "up" || port.admin === "down") && Number.isSafeInteger(port.mtu) &&
        port.mtu >= PROFILE_CATALOG.ethernet.minimum_network_mtu &&
        port.mtu <= PROFILE_CATALOG.ethernet.maximum_network_mtu &&
        Number.isSafeInteger(port.speedMbps) &&
        port.speedMbps > 0 && typeof port.description === "string" &&
        encoder.encode(port.description).length <= 80, `${router.id} port configuration is invalid`);
      portIds.add(port.id);
    }
    const interfaceNames = new Set<string>();
    for (const item of router.running.interfaces) {
      // Interface MAC identity is derived from the physical router port by the
      // hardware owner. It is not a user-configurable routed-interface leaf.
      assert(typeof item.name === "string" && item.name.length > 0 && !interfaceNames.has(item.name) &&
        (item.portId === "" || isPossibleRouterPort(router.profileId, item.portId)) &&
        (item.address === "" || parsePrefix(item.address)) &&
        (item.admin === "up" || item.admin === "down"),
        `${router.id} interface configuration is invalid`);
      if (item.address) {
        const address = parsePrefix(item.address)!.address;
        assert(!addresses.has(address),
          "Router interface addresses must be unique in a laboratory");
        addresses.add(address);
      }
      interfaceNames.add(item.name);
    }
    const routePrefixes = new Set<string>();
    for (const route of router.running.staticRoutes) {
      // Duplicate prefixes would make restore order select a winner. Rejecting
      // them preserves one unambiguous route candidate per project key.
      assert(canonicalPrefix(route.prefix) && parseIpv4(route.nextHop) !== undefined &&
        !routePrefixes.has(route.prefix), `${router.id} static route is invalid`);
      routePrefixes.add(route.prefix);
    }
    nodes.set(router.id, "router");
  }

  for (const host of project.hosts) {
    // One host owns exactly eth0 in this format. Additional interfaces require
    // a later version instead of being silently ignored.
    assert(host?.kind === "host" && identifierPattern.test(host.id) && !nodes.has(host.id),
      "Host identity is invalid or duplicated");
    const address = parsePrefix(host.eth0?.address);
    const gateway = parseIpv4(host.eth0?.gateway);
    assert(typeof host.name === "string" && host.name.length > 0 && host.name.length <= 64 &&
      host.eth0?.mode === "ethernet" && isUnicastMac(host.eth0.mac) && address &&
      gateway !== undefined && Number.isSafeInteger(host.eth0.mtu) &&
      host.eth0.mtu >= PROFILE_CATALOG.ethernet.minimum_host_ipv4_mtu &&
      host.eth0.mtu <= PROFILE_CATALOG.ethernet.maximum_network_mtu,
      `${host.id} Ethernet configuration is invalid`);
    const mask = address.length === 0 ? 0 : (0xffffffff << (32 - address.length)) >>> 0;
    // The gateway must share the configured prefix and cannot equal the host.
    // Reachability beyond that link remains a packet-path result.
    assert(address.address !== gateway && (address.address & mask) === (gateway & mask) &&
      !macs.has(host.eth0.mac.toLowerCase()) && !addresses.has(address.address),
      `${host.id} address, gateway or MAC conflicts with the laboratory`);
    macs.add(host.eth0.mac.toLowerCase());
    addresses.add(address.address);
    nodes.set(host.id, "host");
  }

  const linkIds = new Set<string>();
  const boundPorts = new Set<string>();
  for (const link of project.links) {
    // Validate the complete link header before reserving either endpoint in the
    // local bound-port set. A malformed link cannot poison following checks.
    assert(identifierPattern.test(link?.id) && !linkIds.has(link.id) &&
      Array.isArray(link.endpoints) && link.endpoints.length === 2 &&
      (link.admin === "up" || link.admin === "down") &&
      Number.isSafeInteger(link.propagationDelayNs) && link.propagationDelayNs >= 0,
      "Link configuration is invalid");
    assert(link.endpoints[0].nodeId !== link.endpoints[1].nodeId,
      `${link.id} cannot connect a node to itself`);
    for (const endpoint of link.endpoints) {
      // Topology validation checks only possible physical identity. Missing
      // equipped hardware leaves carrier down but does not delete the cable.
      const kind = nodes.get(endpoint.nodeId);
      assert(kind, `${link.id} contains a dangling endpoint`);
      const router = kind === "router" ? project.routers.find((item) => item.id === endpoint.nodeId) : undefined;
      assert(kind === "host" ? endpoint.portId === "eth0" :
        Boolean(router && isPossibleRouterPort(router.profileId, endpoint.portId)),
        `${link.id} references an invalid port`);
      const key = `${endpoint.nodeId}\u0000${endpoint.portId}`;
      // NUL cannot occur in either validated identifier, so this compound key
      // has no ambiguous concatenations such as ab+c versus a+bc.
      assert(!boundPorts.has(key), `${endpoint.nodeId} ${endpoint.portId} is already connected`);
      boundPorts.add(key);
    }
    linkIds.add(link.id);
  }

  assert(project.layout && typeof project.layout === "object" && project.layout.nodes &&
    Number.isFinite(project.layout.sidebarWidth) && project.layout.sidebarWidth >= 64 &&
    Number.isFinite(project.layout.inspectorWidth) && project.layout.inspectorWidth >= 120 &&
    Number.isFinite(project.layout.terminalHeight) && project.layout.terminalHeight >= 64,
    "Project layout is invalid");
  for (const [id, point] of Object.entries(project.layout.nodes)) {
    // Layout may omit a node and let the UI choose a position. It may not name
    // a nonexistent node or inject NaN and infinity into React Flow.
    assert(nodes.has(id) && Number.isFinite(point?.x) && Number.isFinite(point?.y),
      "Project layout contains an invalid node position");
  }
  // Detach the accepted value from the caller's mutable object graph. Later
  // edits cannot change the project while a runtime transaction is in flight.
  return structuredClone(project as LabProjectV3);
}

export { PROFILE_CATALOG };
