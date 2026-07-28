// Runtime snapshot ABI 8 for protocol 4. This validator is the browser trust
// boundary for C++ JSON and contains no UI defaults or selected-router state.

import { PROFILE_CATALOG, PROFILE_CATALOG_COMPILED } from "./generated-device-catalog";
import { LAB_RUNTIME_PROTOCOL } from "./generated-lab-runtime-protocol";
import { isCanonicalIpv6PrefixText, isIpv6AddressText,
  isIpv6InterfacePrefixText, type RouterIpv6AddressIntent,
  type RouterOspfIntent, type RouterPolicyOptionsIntent } from "./lab-project-v4";

export interface RuntimeHandleV6 {
  index: number;
  generation: number;
}

export interface RuntimeMdaV6 {
  slot: number;
  admin: boolean;
  provisionedType: string | null;
  equippedType: string | null;
}

export interface RuntimeCardV6 {
  slot: number;
  admin: boolean;
  provisionedType: string | null;
  equippedType: string | null;
  mdas: RuntimeMdaV6[];
}

export interface RuntimePortV6 {
  id: string;
  admin: boolean;
  carrier: boolean;
  oper: boolean;
  mtu: number;
  speedMbps: number;
  description: string;
}

export interface RuntimeRouterV6 {
  id: string;
  profileId: string;
  chassis: string;
  systemName: string;
  maximumEcmpPaths: number;
  handle: RuntimeHandleV6;
  cards: RuntimeCardV6[];
  ports: RuntimePortV6[];
  interfaces: Array<{ name: string; portId: string; address: string;
    arpTimeoutSeconds: number | null; arpRetryTimerDeciseconds: number | null;
    ipv6Addresses: RouterIpv6AddressIntent[]; admin: boolean }>;
  staticRoutes: Array<{ prefix: string; nextHop: string; indirect: boolean }>;
  ipv6StaticRoutes: Array<{ prefix: string; nextHop: string;
    outgoingPortId: string; indirect: boolean }>;
  policyOptions: RouterPolicyOptionsIntent;
  ospf: RouterOspfIntent;
}

export interface RuntimeHostV6 {
  id: string;
  name: string;
  handle: RuntimeHandleV6;
  mac: string;
  address: string;
  gateway: string;
  mtu: number;
  interfaceId: string;
  dhcpv4: {
    configured: boolean;
    state: "stopped" | "init" | "selecting" | "requesting" | "checking" |
      "declining" | "bound" | "renewing" | "rebinding" | "init-reboot" |
      "rebooting" | "releasing" | "informing" | "failed";
    leasePresent: boolean;
    address: string;
    subnetMask: string;
    router: string;
    serverIdentifier: string;
    renewRemainingMs: number;
    rebindRemainingMs: number;
    validRemainingMs: number;
  };
  ipv6Autoconfiguration: boolean;
  ipv6InterfaceIdentifierMode: "modified-eui64" | "stable-opaque";
}

export interface RuntimeSwitchV6 {
  id: string;
  name: string;
  profileId: string;
  handle: RuntimeHandleV6;
  ports: Array<{
    id: string;
    admin: boolean;
    mtu: number;
    speedMbps: number;
  }>;
}

export interface RuntimeLinkV6 {
  id: string;
  admin: boolean;
  carrier: boolean;
  speedMbps: number;
  propagationDelayNs: number;
  endpoints: readonly [
    { nodeId: string; portId: string },
    { nodeId: string; portId: string }
  ];
}

export interface RuntimeSessionV6 {
  id: string;
  routerId: string;
  mode: number;
  engine: "md" | "classic";
}

export interface RuntimeCapturePointV6 {
  id: number;
  kind: "link-direction" | "router-ingress" | "router-egress" | "cpm-punt";
  objectId: string;
  portId: string;
  direction: 0 | 1;
}

export interface LabRuntimeSnapshotV6 {
  // The public type follows the generated schemas. Changing either YAML
  // contract therefore changes the compiler-visible snapshot type instead of
  // leaving a second handwritten version constant behind.
  abiVersion: typeof LAB_RUNTIME_PROTOCOL.snapshotAbi;
  protocolVersion: typeof LAB_RUNTIME_PROTOCOL.version;
  status: "ready";
  routers: RuntimeRouterV6[];
  // Dedicated servers use the same multiport projection fields. Their
  // generated profile role, not a browser-provided discriminator, separates
  // them from SR OS routers at this trust boundary.
  dhcpServers: RuntimeRouterV6[];
  hosts: RuntimeHostV6[];
  switches: RuntimeSwitchV6[];
  links: RuntimeLinkV6[];
  sessions: RuntimeSessionV6[];
  capturePoints: RuntimeCapturePointV6[];
  activeLinks: number;
  capturedFrames: number;
  captureDropped: number;
  droppedPackets: number;
}

const identifier = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i;
// The integrated BOF connector has a catalog identity rather than fabricated
// card coordinates. Snapshot validation accepts that one explicit name while
// project validation still checks whether the selected chassis owns it.
const portId = /^(?:\d{1,2}\/\d{1,2}\/\d{1,3}|management)$/;
const prefix = /^(?:\d{1,3}\.){3}\d{1,3}\/([0-9]|[12]\d|3[0-2])$/;
const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const uint64 = /^(?:0|[1-9]\d{0,19})$/;
const maximumUint64 = (1n << 64n) - 1n;
const finiteCounter = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

function assert(condition: unknown, reason: string): asserts condition {
  if (!condition) throw new Error(reason);
}

function validHandle(value: unknown): value is RuntimeHandleV6 {
  if (!value || typeof value !== "object") return false;
  const handle = value as Partial<RuntimeHandleV6>;
  return Number.isInteger(handle.index) && handle.index! >= 0 &&
    handle.index! < 0xffff && Number.isInteger(handle.generation) &&
    handle.generation! > 0 && handle.generation! <= 0xffff;
}

export function parseLabRuntimeSnapshotV6(input: unknown): LabRuntimeSnapshotV6 {
  assert(input && typeof input === "object", "Runtime snapshot must be an object");
  // The native ABI stores both roles in its bounded network-device array.
  // Parsing normalizes that compact representation into separate product
  // collections without weakening validation of either role.
  const value = input as Partial<Omit<LabRuntimeSnapshotV6, "dhcpServers">>;
  assert(value.abiVersion === LAB_RUNTIME_PROTOCOL.snapshotAbi &&
    value.protocolVersion === LAB_RUNTIME_PROTOCOL.version && value.status === "ready",
    "Runtime snapshot ABI is incompatible");
  assert(Array.isArray(value.routers) && value.routers.length <= PROFILE_CATALOG.limits.routers &&
    Array.isArray(value.hosts) && value.hosts.length <= PROFILE_CATALOG.limits.hosts &&
    Array.isArray(value.switches) &&
      value.switches.length <= PROFILE_CATALOG.limits.switches &&
    Array.isArray(value.links) && value.links.length <= PROFILE_CATALOG.limits.links &&
    Array.isArray(value.sessions) && value.sessions.length <=
      PROFILE_CATALOG.limits.routers * PROFILE_CATALOG.limits.sessions_per_router &&
    Array.isArray(value.capturePoints) && value.capturePoints.length <=
      PROFILE_CATALOG.runtime.maximum_active_capture_points &&
    finiteCounter(value.activeLinks) && value.activeLinks <= value.links.length &&
    finiteCounter(value.capturedFrames) && finiteCounter(value.captureDropped) &&
    finiteCounter(value.droppedPackets),
  "Runtime snapshot exceeds resource bounds");

  const nodes = new Set<string>();
  const handles = new Set<string>();
  for (const router of value.routers) {
    const profile = PROFILE_CATALOG.profiles.find((item) => item.id === router?.profileId);
    assert(router && identifier.test(router.id) && !nodes.has(router.id) &&
      profile &&
      router.chassis === profile.chassis && typeof router.systemName === "string" &&
      Number.isSafeInteger(router.maximumEcmpPaths) &&
      router.maximumEcmpPaths >= 1 &&
      router.maximumEcmpPaths <= PROFILE_CATALOG.runtime.maximum_ecmp_paths &&
      validHandle(router.handle) && Array.isArray(router.cards) &&
      Array.isArray(router.ports) && router.ports.length <=
        PROFILE_CATALOG_COMPILED.maximumPortsPerRouter &&
      Array.isArray(router.interfaces) && Array.isArray(router.staticRoutes) &&
      Array.isArray(router.ipv6StaticRoutes) &&
      router.policyOptions &&
      Array.isArray(router.policyOptions.prefixLists) &&
      Array.isArray(router.policyOptions.statements) &&
      router.ospf && Array.isArray(router.ospf.instances),
    "Runtime router projection is invalid");
    const handleKey = `r:${router.handle.index}:${router.handle.generation}`;
    assert(!handles.has(handleKey), "Runtime router handle is duplicated");
    handles.add(handleKey);
    nodes.add(router.id);
    const expectedCards = profile.fixed ? 1 : profile.card_slots;
    assert(router.cards.length === expectedCards && router.cards.every((card, index) =>
      card && card.slot === index + 1 && typeof card.admin === "boolean" &&
      (card.provisionedType === null || typeof card.provisionedType === "string") &&
      (card.equippedType === null || typeof card.equippedType === "string") &&
      Array.isArray(card.mdas) && card.mdas.every((mda, mdaIndex) =>
        mda && mda.slot === mdaIndex + 1 && typeof mda.admin === "boolean" &&
        (mda.provisionedType === null || typeof mda.provisionedType === "string") &&
        (mda.equippedType === null || typeof mda.equippedType === "string"))),
    "Runtime hardware projection is invalid");
    const ports = new Set<string>();
    for (const port of router.ports) {
      assert(port && portId.test(port.id) && !ports.has(port.id) &&
        typeof port.admin === "boolean" && typeof port.carrier === "boolean" &&
        typeof port.oper === "boolean" &&
        // Administration and carrier are necessary, but they are not the
        // complete SR OS operational-state equation. The C++ hardware owner
        // also gates a port on the card and MDA hierarchy plus retained-speed
        // compatibility with the installed MDA. A card transition can
        // therefore truthfully publish admin=true, carrier=true, oper=false.
        // The browser does not receive those private hardware flags, so its
        // trust boundary can enforce only the implication that is observable:
        // an operational port must have both administration and carrier.
        (!port.oper || (port.admin && port.carrier)) &&
        Number.isInteger(port.mtu) && port.mtu >= PROFILE_CATALOG.ethernet.minimum_network_mtu &&
        port.mtu <= PROFILE_CATALOG.ethernet.maximum_network_mtu &&
        Number.isSafeInteger(port.speedMbps) && port.speedMbps > 0 &&
        typeof port.description === "string", "Runtime port projection is invalid");
      ports.add(port.id);
    }
    assert(router.interfaces.every((item) => item && typeof item.name === "string" &&
      (item.portId === "" || portId.test(item.portId)) &&
      (item.address === "" || prefix.test(item.address)) &&
      (item.arpTimeoutSeconds === null ||
        (Number.isSafeInteger(item.arpTimeoutSeconds) &&
         item.arpTimeoutSeconds >=
           PROFILE_CATALOG.protocol_defaults.arp_timeout_minimum_seconds &&
         item.arpTimeoutSeconds <=
           PROFILE_CATALOG.protocol_defaults.arp_timeout_maximum_seconds)) &&
      (item.arpRetryTimerDeciseconds === null ||
        (Number.isSafeInteger(item.arpRetryTimerDeciseconds) &&
         item.arpRetryTimerDeciseconds >=
           PROFILE_CATALOG.protocol_defaults.arp_retry_minimum_deciseconds &&
         item.arpRetryTimerDeciseconds <=
           PROFILE_CATALOG.protocol_defaults.arp_retry_maximum_deciseconds)) &&
      Array.isArray(item.ipv6Addresses) &&
      item.ipv6Addresses.length + (item.address ? 1 : 0) <=
        PROFILE_CATALOG.runtime.network_interface_ip_addresses &&
      item.ipv6Addresses.every((address) => address &&
        isIpv6InterfacePrefixText(address.address) &&
        typeof address.duplicateAddressDetection === "boolean" &&
        typeof address.eui64 === "boolean" &&
        (address.eui64SourceMac === null ||
          /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(address.eui64SourceMac)) &&
        (address.eui64 === (address.eui64SourceMac !== null)) &&
        Number.isSafeInteger(address.primaryPreference) &&
        address.primaryPreference >= 0 && address.primaryPreference <= 0xffffffff &&
        (address.tag === null ||
          (Number.isSafeInteger(address.tag) && address.tag >= 0 &&
           address.tag <= 0xffffffff))) &&
      typeof item.admin === "boolean") &&
      router.staticRoutes.every((item) => item && prefix.test(item.prefix) &&
        ipv4.test(item.nextHop) && typeof item.indirect === "boolean") &&
      router.ipv6StaticRoutes.every((item) => item &&
        isCanonicalIpv6PrefixText(item.prefix) &&
        isIpv6AddressText(item.nextHop) &&
        typeof item.indirect === "boolean" &&
        (item.outgoingPortId === "" || portId.test(item.outgoingPortId))),
    "Runtime routing projection is invalid");
  }
  const runtimeRouters = value.routers.filter((device) =>
    PROFILE_CATALOG.profiles.find((profile) => profile.id === device.profileId)
      ?.role === "router");
  const runtimeDhcpServers = value.routers.filter((device) =>
    PROFILE_CATALOG.profiles.find((profile) => profile.id === device.profileId)
      ?.role === "dhcp-server");
  for (const host of value.hosts) {
    const dhcpState = host?.dhcpv4?.state;
    assert(host && identifier.test(host.id) && !nodes.has(host.id) &&
      typeof host.name === "string" && validHandle(host.handle) &&
      /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(host.mac) &&
      prefix.test(host.address) && ipv4.test(host.gateway) &&
      Number.isInteger(host.mtu) &&
      host.mtu >= PROFILE_CATALOG.ethernet.minimum_host_ipv4_mtu &&
      host.mtu <= PROFILE_CATALOG.ethernet.maximum_network_mtu &&
      uint64.test(host.interfaceId) &&
      BigInt(host.interfaceId) <= maximumUint64 &&
      host.dhcpv4 && typeof host.dhcpv4.configured === "boolean" &&
      ["stopped", "init", "selecting", "requesting", "checking",
       "declining", "bound", "renewing", "rebinding", "init-reboot",
       "rebooting", "releasing", "informing", "failed"].includes(
        dhcpState ?? "") &&
      typeof host.dhcpv4.leasePresent === "boolean" &&
      (!host.dhcpv4.address || ipv4.test(host.dhcpv4.address)) &&
      (!host.dhcpv4.subnetMask || ipv4.test(host.dhcpv4.subnetMask)) &&
      (!host.dhcpv4.router || ipv4.test(host.dhcpv4.router)) &&
      (!host.dhcpv4.serverIdentifier ||
       ipv4.test(host.dhcpv4.serverIdentifier)) &&
      finiteCounter(host.dhcpv4.renewRemainingMs) &&
      finiteCounter(host.dhcpv4.rebindRemainingMs) &&
      finiteCounter(host.dhcpv4.validRemainingMs) &&
      (host.dhcpv4.leasePresent
        ? Boolean(host.dhcpv4.address && host.dhcpv4.subnetMask &&
            host.dhcpv4.serverIdentifier)
        : !host.dhcpv4.address && !host.dhcpv4.subnetMask &&
          !host.dhcpv4.router && !host.dhcpv4.serverIdentifier) &&
      typeof host.ipv6Autoconfiguration === "boolean" &&
      (host.ipv6InterfaceIdentifierMode === "modified-eui64" ||
       host.ipv6InterfaceIdentifierMode === "stable-opaque") &&
      (!host.ipv6Autoconfiguration ||
       (BigInt(host.interfaceId) > 0n &&
        host.mtu >= PROFILE_CATALOG.ethernet.minimum_host_ipv6_mtu)),
    "Runtime host projection is invalid");
    const handleKey = `h:${host.handle.index}:${host.handle.generation}`;
    assert(!handles.has(handleKey), "Runtime host handle is duplicated");
    handles.add(handleKey);
    nodes.add(host.id);
  }
  for (const ethernetSwitch of value.switches) {
    const profile = PROFILE_CATALOG.switch_profiles.find(
      (item) => item.id === ethernetSwitch?.profileId);
    assert(ethernetSwitch && identifier.test(ethernetSwitch.id) &&
      !nodes.has(ethernetSwitch.id) && typeof ethernetSwitch.name === "string" &&
      profile && validHandle(ethernetSwitch.handle) &&
      Array.isArray(ethernetSwitch.ports) &&
      ethernetSwitch.ports.length === profile.port_count,
    "Runtime switch projection is invalid");
    const handleKey =
      `s:${ethernetSwitch.handle.index}:${ethernetSwitch.handle.generation}`;
    assert(!handles.has(handleKey) &&
      ethernetSwitch.ports.every((port, index) => port &&
        port.id === String(index + 1) && typeof port.admin === "boolean" &&
        Number.isInteger(port.mtu) && port.mtu >= profile.minimum_mtu &&
        port.mtu <= profile.maximum_mtu &&
        Number.isSafeInteger(port.speedMbps) &&
        profile.supported_speeds_mbps.some(
          (speed) => speed === port.speedMbps)),
    "Runtime switch port projection is invalid");
    handles.add(handleKey);
    nodes.add(ethernetSwitch.id);
  }
  const links = new Set<string>();
  for (const link of value.links) {
    assert(link && identifier.test(link.id) && !links.has(link.id) &&
      typeof link.admin === "boolean" && typeof link.carrier === "boolean" &&
      finiteCounter(link.speedMbps) && finiteCounter(link.propagationDelayNs) &&
      Array.isArray(link.endpoints) && link.endpoints.length === 2 &&
      link.endpoints.every((endpoint) => endpoint && nodes.has(endpoint.nodeId) &&
        (endpoint.portId === "eth0" || portId.test(endpoint.portId) ||
         /^\d+$/.test(endpoint.portId))),
    "Runtime link projection is invalid");
    links.add(link.id);
  }
  const sessionIds = new Set<string>();
  const counts = new Map<string, number>();
  for (const session of value.sessions) {
    assert(session && identifier.test(session.id) && !sessionIds.has(session.id) &&
      runtimeRouters.some((router) => router.id === session.routerId) &&
      Number.isInteger(session.mode) && session.mode >= 0 && session.mode <= 4 &&
      (session.engine === "md" || session.engine === "classic"),
    "Runtime terminal session projection is invalid");
    const count = (counts.get(session.routerId) ?? 0) + 1;
    assert(count <= PROFILE_CATALOG.limits.sessions_per_router,
      "Runtime router exceeds its terminal session limit");
    counts.set(session.routerId, count);
    sessionIds.add(session.id);
  }
  const captureIds = new Set<number>();
  for (const point of value.capturePoints) {
    const routerPoint = point?.kind === "router-ingress" ||
      point?.kind === "router-egress" || point?.kind === "cpm-punt";
    const linkPoint = point?.kind === "link-direction";
    // A location must still exist when projected. Retained PCAPNG records for
    // deleted locations remain in the capture store but are not active points.
    assert(point && Number.isInteger(point.id) && point.id >= 0 &&
      point.id <= 0xffff_ffff &&
      !captureIds.has(point.id) && (routerPoint || linkPoint) &&
      (point.direction === 0 || point.direction === 1) &&
      (linkPoint ? links.has(point.objectId) : value.routers.some((router) =>
        router.id === point.objectId)) &&
      (point.kind === "cpm-punt" ? point.portId === "" :
        linkPoint ? point.portId === "" : portId.test(point.portId)),
    "Runtime capture point projection is invalid");
    captureIds.add(point.id);
  }
  const clone = structuredClone(value);
  return {
    ...clone,
    routers: runtimeRouters.map((router) => structuredClone(router)),
    dhcpServers: runtimeDhcpServers.map((server) => structuredClone(server))
  } as LabRuntimeSnapshotV6;
}
