// Runtime snapshot ABI 5 for protocol 3. This validator is the browser trust
// boundary for C++ JSON and contains no UI defaults or selected-router state.

import { PROFILE_CATALOG, PROFILE_CATALOG_COMPILED } from "./generated-device-catalog";
import { LAB_RUNTIME_PROTOCOL } from "./generated-lab-runtime-protocol";

export interface RuntimeHandleV5 {
  index: number;
  generation: number;
}

export interface RuntimeMdaV5 {
  slot: number;
  admin: boolean;
  provisionedType: string | null;
  equippedType: string | null;
}

export interface RuntimeCardV5 {
  slot: number;
  admin: boolean;
  provisionedType: string | null;
  equippedType: string | null;
  mdas: RuntimeMdaV5[];
}

export interface RuntimePortV5 {
  id: string;
  admin: boolean;
  carrier: boolean;
  oper: boolean;
  mtu: number;
  speedMbps: number;
  description: string;
}

export interface RuntimeRouterV5 {
  id: string;
  profileId: string;
  chassis: string;
  systemName: string;
  handle: RuntimeHandleV5;
  cards: RuntimeCardV5[];
  ports: RuntimePortV5[];
  interfaces: Array<{ name: string; portId: string; address: string; admin: boolean }>;
  staticRoutes: Array<{ prefix: string; nextHop: string }>;
}

export interface RuntimeHostV5 {
  id: string;
  name: string;
  handle: RuntimeHandleV5;
  mac: string;
  address: string;
  gateway: string;
  mtu: number;
}

export interface RuntimeLinkV5 {
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

export interface RuntimeSessionV5 {
  id: string;
  routerId: string;
  mode: number;
  engine: "md" | "classic";
}

export interface RuntimeCapturePointV5 {
  id: number;
  kind: "link-direction" | "router-ingress" | "router-egress" | "cpm-punt";
  objectId: string;
  portId: string;
  direction: 0 | 1;
}

export interface LabRuntimeSnapshotV5 {
  // The public type follows the generated schemas. Changing either YAML
  // contract therefore changes the compiler-visible snapshot type instead of
  // leaving a second handwritten version constant behind.
  abiVersion: typeof LAB_RUNTIME_PROTOCOL.snapshotAbi;
  protocolVersion: typeof LAB_RUNTIME_PROTOCOL.version;
  status: "ready";
  routers: RuntimeRouterV5[];
  hosts: RuntimeHostV5[];
  links: RuntimeLinkV5[];
  sessions: RuntimeSessionV5[];
  capturePoints: RuntimeCapturePointV5[];
  activeLinks: number;
  capturedFrames: number;
  captureDropped: number;
  droppedPackets: number;
}

const identifier = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i;
const portId = /^\d{1,2}\/\d{1,2}\/\d{1,3}$/;
const prefix = /^(?:\d{1,3}\.){3}\d{1,3}\/([0-9]|[12]\d|3[0-2])$/;
const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const finiteCounter = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

function assert(condition: unknown, reason: string): asserts condition {
  if (!condition) throw new Error(reason);
}

function validHandle(value: unknown): value is RuntimeHandleV5 {
  if (!value || typeof value !== "object") return false;
  const handle = value as Partial<RuntimeHandleV5>;
  return Number.isInteger(handle.index) && handle.index! >= 0 &&
    handle.index! < 0xffff && Number.isInteger(handle.generation) &&
    handle.generation! > 0 && handle.generation! <= 0xffff;
}

export function parseLabRuntimeSnapshotV5(input: unknown): LabRuntimeSnapshotV5 {
  assert(input && typeof input === "object", "Runtime snapshot must be an object");
  const value = input as Partial<LabRuntimeSnapshotV5>;
  assert(value.abiVersion === LAB_RUNTIME_PROTOCOL.snapshotAbi &&
    value.protocolVersion === LAB_RUNTIME_PROTOCOL.version && value.status === "ready",
    "Runtime snapshot ABI is incompatible");
  assert(Array.isArray(value.routers) && value.routers.length <= PROFILE_CATALOG.limits.routers &&
    Array.isArray(value.hosts) && value.hosts.length <= PROFILE_CATALOG.limits.hosts &&
    Array.isArray(value.links) && value.links.length <= PROFILE_CATALOG.limits.links &&
    Array.isArray(value.sessions) && value.sessions.length <=
      PROFILE_CATALOG.limits.routers * PROFILE_CATALOG.limits.sessions_per_router &&
    Array.isArray(value.capturePoints) && value.capturePoints.length <=
      PROFILE_CATALOG.runtime.selected_capture_points &&
    finiteCounter(value.activeLinks) && value.activeLinks <= value.links.length &&
    finiteCounter(value.capturedFrames) && finiteCounter(value.captureDropped) &&
    finiteCounter(value.droppedPackets),
  "Runtime snapshot exceeds resource bounds");

  const nodes = new Set<string>();
  const handles = new Set<string>();
  for (const router of value.routers) {
    const profile = PROFILE_CATALOG.profiles.find((item) => item.id === router?.profileId);
    assert(router && identifier.test(router.id) && !nodes.has(router.id) && profile &&
      router.chassis === profile.chassis && typeof router.systemName === "string" &&
      validHandle(router.handle) && Array.isArray(router.cards) &&
      Array.isArray(router.ports) && router.ports.length <=
        PROFILE_CATALOG_COMPILED.maximumPortsPerRouter &&
      Array.isArray(router.interfaces) && Array.isArray(router.staticRoutes),
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
        typeof port.oper === "boolean" && port.oper === (port.admin && port.carrier) &&
        Number.isInteger(port.mtu) && port.mtu >= PROFILE_CATALOG.ethernet.minimum_network_mtu &&
        port.mtu <= PROFILE_CATALOG.ethernet.maximum_network_mtu &&
        Number.isSafeInteger(port.speedMbps) && port.speedMbps > 0 &&
        typeof port.description === "string", "Runtime port projection is invalid");
      ports.add(port.id);
    }
    assert(router.interfaces.every((item) => item && typeof item.name === "string" &&
      (item.portId === "" || portId.test(item.portId)) &&
      (item.address === "" || prefix.test(item.address)) &&
      typeof item.admin === "boolean") &&
      router.staticRoutes.every((item) => item && prefix.test(item.prefix) && ipv4.test(item.nextHop)),
    "Runtime routing projection is invalid");
  }
  for (const host of value.hosts) {
    assert(host && identifier.test(host.id) && !nodes.has(host.id) &&
      typeof host.name === "string" && validHandle(host.handle) &&
      /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(host.mac) &&
      prefix.test(host.address) && ipv4.test(host.gateway) &&
      Number.isInteger(host.mtu) &&
      host.mtu >= PROFILE_CATALOG.ethernet.minimum_host_ipv4_mtu &&
      host.mtu <= PROFILE_CATALOG.ethernet.maximum_network_mtu,
    "Runtime host projection is invalid");
    const handleKey = `h:${host.handle.index}:${host.handle.generation}`;
    assert(!handles.has(handleKey), "Runtime host handle is duplicated");
    handles.add(handleKey);
    nodes.add(host.id);
  }
  const links = new Set<string>();
  for (const link of value.links) {
    assert(link && identifier.test(link.id) && !links.has(link.id) &&
      typeof link.admin === "boolean" && typeof link.carrier === "boolean" &&
      finiteCounter(link.speedMbps) && finiteCounter(link.propagationDelayNs) &&
      Array.isArray(link.endpoints) && link.endpoints.length === 2 &&
      link.endpoints.every((endpoint) => endpoint && nodes.has(endpoint.nodeId) &&
        (endpoint.portId === "eth0" || portId.test(endpoint.portId))),
    "Runtime link projection is invalid");
    links.add(link.id);
  }
  const sessionIds = new Set<string>();
  const counts = new Map<string, number>();
  for (const session of value.sessions) {
    assert(session && identifier.test(session.id) && !sessionIds.has(session.id) &&
      value.routers.some((router) => router.id === session.routerId) &&
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
      point.id < PROFILE_CATALOG.runtime.selected_capture_points &&
      !captureIds.has(point.id) && (routerPoint || linkPoint) &&
      (point.direction === 0 || point.direction === 1) &&
      (linkPoint ? links.has(point.objectId) : value.routers.some((router) =>
        router.id === point.objectId)) &&
      (point.kind === "cpm-punt" ? point.portId === "" :
        linkPoint ? point.portId === "" : portId.test(point.portId)),
    "Runtime capture point projection is invalid");
    captureIds.add(point.id);
  }
  return structuredClone(value as LabRuntimeSnapshotV5);
}
