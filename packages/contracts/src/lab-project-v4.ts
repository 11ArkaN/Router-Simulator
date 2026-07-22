// Project format 4 stores portable dual-stack multi-device intent. This module owns all
// structural validation and has no browser, persistence or runtime dependency.

import { PROFILE_CATALOG, PROFILE_CATALOG_COMPILED } from "./generated-device-catalog";
import { dnssecAlgorithms } from "./generated-dnssec-policy";

export const LAB_PROJECT_VERSION = 4 as const;
export const LAB_MANIFEST_VERSION = 3 as const;
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
  // null means that the interface inherits the 26.7.R1 release default. Zero
  // remains a configured ARP timeout and disables dynamic entry aging.
  arpTimeoutSeconds: number | null;
  arpRetryTimerDeciseconds: number | null;
  ipv6Addresses: RouterIpv6AddressIntent[];
}

export interface RouterIpv6AddressIntent {
  address: string;
  duplicateAddressDetection: boolean;
  // When enabled, address is the configured /64 prefix and the runtime owns
  // formation of the lower 64 bits from the attached port MAC.
  eui64: boolean;
  // Captured source identity keeps a chassis-derived IID stable when a port is
  // attached later. It is runtime-owned and not presented as an editable UI
  // field.
  eui64SourceMac: string | null;
  primaryPreference: number;
  // null means that the optional policy tag leaf is absent. Numeric zero is a
  // configured value and must survive save, reload and CLI `info` separately.
  tag: number | null;
}

export interface RouterRunningIntent {
  systemName: string;
  // One is the documented disabled ECMP state. Higher values cap the number
  // of equal protocol, preference and metric paths installed per prefix.
  maximumEcmpPaths: number;
  ports: RouterPortIntent[];
  interfaces: RouterInterfaceIntent[];
  staticRoutes: Array<{ prefix: string; nextHop: string; indirect: boolean }>;
  ipv6StaticRoutes: Array<{
    prefix: string;
    nextHop: string;
    outgoingPortId: string;
    indirect: boolean;
  }>;
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

export interface RouterProjectV4 {
  id: NodeId;
  kind: "router";
  profileId: DeviceProfileId;
  release: typeof LAB_RELEASE;
  systemName: string;
  hardware: { cards: RouterCardIntent[] };
  running: RouterRunningIntent;
}

export interface HostProjectV4 {
  id: NodeId;
  kind: "host";
  name: string;
  eth0: {
    mac: string;
    address: string;
    gateway: string;
    mtu: number;
    mode: "ethernet";
    // TCP ISN and timestamp entropy is portable private endpoint intent. It is
    // never rendered in telemetry and is domain-separated from SLAAC secrets.
    transportSecretHex: string;
    dns: HostDnsIntent;
    ipv6: {
      autoconfiguration: boolean;
      interfaceId: string;
      interfaceIdentifierMode: "modified-eui64" | "stable-opaque";
      // RFC 7217 secrets are project intent and never appear in runtime
      // snapshots or UI telemetry. Modified EUI-64 needs no secret.
      stableIidSecret: string | null;
      networkId: string;
      dhcpv6: HostDhcpv6Intent;
    };
  };
}

export interface HostDhcpv6ClientIntent {
  // DUID and transaction secret are portable endpoint identity. Hexadecimal
  // avoids text encodings whose normalization could change wire bytes.
  duidHex: string;
  transactionSecretHex: string;
  rapidCommit: boolean;
  informationOnly: boolean;
  identityAssociations: Array<{
    iaid: number;
    kind: "ia-na" | "ia-pd";
  }>;
  requestedOptions: number[];
}

export interface HostDhcpv6PoolIntent {
  prefix: string;
  allocationSecretHex: string;
  preferredLifetimeSeconds: number;
  validLifetimeSeconds: number;
  t1Seconds: number;
  t2Seconds: number;
  // Address pools use null. Prefix pools carry the delegated child length.
  delegatedLength: number | null;
}

export interface HostDhcpv6ServerIntent {
  duidHex: string;
  preference: number;
  rapidCommit: boolean;
  dnsRecursiveServers: string[];
  informationRefreshTimeSeconds: number;
  solicitMaximumRetransmissionSeconds: number | null;
  informationMaximumRetransmissionSeconds: number | null;
  declineHoldTimeSeconds: number;
  addressPoolIndex: number;
  prefixPoolIndex: number;
  addressPools: HostDhcpv6PoolIntent[];
  prefixPools: HostDhcpv6PoolIntent[];
}

export interface HostDhcpv6Intent {
  client: HostDhcpv6ClientIntent | null;
  server: HostDhcpv6ServerIntent | null;
}

export interface HostDnsRootHintIntent {
  serverName: string;
  addresses: Array<{ family: "ipv4" | "ipv6"; address: string }>;
}

export interface HostDnsTrustAnchorIntent {
  owner: string;
  ttl: number;
  // Exact DNSKEY RDATA. The owner and TTL remain separate DNS fields and are
  // not inferred from a presentation-format parser in the browser.
  rdataHex: string;
}

export interface HostDnsResolverIntent {
  identifierSecretHex: string;
  maximumNsec3Iterations: number;
  serveClients: boolean;
  rootHints: HostDnsRootHintIntent[];
  trustAnchors: HostDnsTrustAnchorIntent[];
}

export interface HostDnsSigningKeyIntent {
  role: "ksk" | "zsk";
  algorithm: number;
  rsaBits: number;
  publishAt: number;
  readyAt: number;
  activateAt: number;
  retireAt: number;
  deadAt: number;
  removeAt: number;
}

export interface HostDnsSigningIntent {
  dnskeyTtl: number;
  denialTtl: number;
  denialMode: "nsec" | "nsec3";
  validitySeconds: number;
  refreshSeconds: number;
  resignSeconds: number;
  inceptionOffsetSeconds: number;
  keys: HostDnsSigningKeyIntent[];
}

export interface HostDnsAuthoritativeIntent {
  zones: Array<{
    origin: string;
    // RFC 1035 master-file text is portable project configuration. $INCLUDE
    // is unavailable because a browser project has no ambient filesystem.
    masterFile: string;
  }>;
  signing: HostDnsSigningIntent | null;
}

export interface HostDnsIntent {
  resolver: HostDnsResolverIntent | null;
  authoritative: HostDnsAuthoritativeIntent | null;
}

export interface PortRefV4 {
  nodeId: NodeId;
  portId: string;
}

export interface LinkProjectV4 {
  id: LinkId;
  endpoints: readonly [PortRefV4, PortRefV4];
  admin: "up" | "down";
  // null delegates rate selection to catalog-backed router ports. A cable
  // between two generic hosts has no such equipment owner, so it remains
  // carrier-down until this field contains explicit project intent.
  configuredSpeedMbps: number | null;
  propagationDelayNs: number;
}

// A free-form canvas annotation. It is pure presentation intent owned by the
// browser, never sent to the runtime: the C++ owner receives routers, hosts
// and links only, exactly like node positions and panel geometry. It carries
// enough styling to document addressing, areas and intent directly on the
// topology rather than only in the separate project notes document.
export interface TopologyAnnotationV4 {
  id: string;
  text: string;
  x: number;
  y: number;
  // Box width in flow units. Height is content-driven, so text wraps at this
  // width and a label never clips its own content.
  width: number;
  fontSize: number;
  bold: boolean;
  italic: boolean;
  align: "left" | "center" | "right";
  // #rgb or #rrggbb foreground. Background accepts an optional alpha pair so a
  // translucent region can group devices without hiding them; null is a plain
  // label with no fill.
  color: string;
  background: string | null;
  border: boolean;
}

export const ANNOTATION_LIMITS = {
  count: 240,
  minWidth: 80,
  maxWidth: 1600,
  minFontSize: 9,
  maxFontSize: 96,
  maxTextBytes: 4000
} as const;

export interface LabProjectV4 {
  format: "router-simulator-project";
  version: typeof LAB_PROJECT_VERSION;
  projectId: string;
  name: string;
  routers: RouterProjectV4[];
  hosts: HostProjectV4[];
  links: LinkProjectV4[];
  annotations: TopologyAnnotationV4[];
  notes: string;
  layout: {
    nodes: Record<NodeId, { x: number; y: number }>;
    sidebarWidth: number;
    inspectorWidth: number;
    terminalHeight: number;
  };
  updatedAt: string;
}

export interface ProjectManifestV3 {
  formatVersion: typeof LAB_MANIFEST_VERSION;
  mode: "project" | "checkpoint";
  project: LabProjectV4;
  checkpointAbi: 6;
  checkpointBase64?: string;
  captureBase64?: string;
  terminalPresentation?: import("./terminal-presentation-v2").TerminalPresentationV2;
}

const encoder = new TextEncoder();
const identifierPattern = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i;
const portPattern = /^\d{1,2}\/\d{1,2}\/\d{1,3}$/;
const macPattern = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const uint64Pattern = /^(?:0|[1-9]\d{0,19})$/;
const stableIidSecretPattern = /^[0-9a-f]{64}$/i;
const hexadecimalPattern = /^[0-9a-f]+$/i;
// Annotation foreground is an opaque CSS hex triple or sextet. The optional
// fill additionally admits a four or eight digit form so the alpha channel of
// a grouping region survives save and reload unchanged.
const annotationColorPattern = /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i;
const annotationFillPattern = /^#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;
const maximumUint64 = (1n << 64n) - 1n;
const maximumUint32 = 0xffffffff;

export function hostInterfaceId(nodeId: NodeId): string {
  // FNV-1a is used only to create a stable nonzero local interface identity,
  // never as the RFC 7217 secret or cryptographic PRF. The resulting value is
  // stored in project format 4, so later renames do not change timer ownership.
  const offsetBasis = 14_695_981_039_346_656_037n;
  const prime = 1_099_511_628_211n;
  let value = offsetBasis;
  for (const byte of encoder.encode(nodeId)) {
    value ^= BigInt(byte);
    value = (value * prime) & maximumUint64;
  }
  return (value || 1n).toString();
}

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

function parseIpv6(text: string): bigint | undefined {
  // The project accepts every RFC 4291 text form, including one embedded IPv4
  // tail. Zone identifiers are excluded because project pool and DNS values
  // are not scoped socket addresses.
  if (!text || text.includes("%") || text.split("::").length > 2)
    return undefined;
  const compressed = text.includes("::");
  const halves = text.split("::");
  const parseHalf = (value: string, final: boolean): number[] | undefined => {
    if (!value) return [];
    const tokens = value.split(":");
    const words: number[] = [];
    for (let index = 0; index < tokens.length; ++index) {
      const token = tokens[index];
      if (token.includes(".")) {
        if (!final || index + 1 !== tokens.length) return undefined;
        const address = parseIpv4(token);
        if (address === undefined) return undefined;
        words.push(address >>> 16, address & 0xffff);
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(token)) return undefined;
        words.push(Number.parseInt(token, 16));
      }
    }
    return words;
  };
  const left = parseHalf(halves[0], halves.length === 1);
  const right = parseHalf(halves[1] ?? "", true);
  if (!left || !right) return undefined;
  const present = left.length + right.length;
  if (compressed ? present >= 8 : present !== 8) return undefined;
  const words = [...left,
    ...Array.from({ length: compressed ? 8 - present : 0 }, () => 0),
    ...right];
  let result = 0n;
  for (const word of words) result = result << 16n | BigInt(word);
  return result;
}

function parseIpv6Prefix(text: string): { address: bigint; length: number } | undefined {
  // Pools are route-style canonical prefixes. Rejecting host bits keeps the
  // server allocator and portable project hash independent from normalization.
  const slash = text.lastIndexOf("/");
  if (slash <= 0 || !/^\d{1,3}$/.test(text.slice(slash + 1))) return undefined;
  const address = parseIpv6(text.slice(0, slash));
  const length = Number(text.slice(slash + 1));
  if (address === undefined || length > 128) return undefined;
  const hostBits = 128n - BigInt(length);
  const mask = length === 0 ? 0n :
    ((1n << BigInt(length)) - 1n) << hostBits;
  return (address & mask) === address ? { address, length } : undefined;
}

function parseIpv6InterfacePrefix(text: string):
  { address: bigint; length: number } | undefined {
  // Interface prefixes retain host bits and cannot use /0. This is separate
  // from the canonical route and allocation-pool parser above.
  const slash = text.lastIndexOf("/");
  if (slash <= 0 || !/^\d{1,3}$/.test(text.slice(slash + 1))) return undefined;
  const address = parseIpv6(text.slice(0, slash));
  const length = Number(text.slice(slash + 1));
  return address !== undefined && length > 0 && length <= 128
    ? { address, length } : undefined;
}

export function isIpv6AddressText(text: string): boolean {
  return parseIpv6(text) !== undefined;
}

export function isIpv6InterfacePrefixText(text: string): boolean {
  return parseIpv6InterfacePrefix(text) !== undefined;
}

export function isCanonicalIpv6PrefixText(text: string): boolean {
  return parseIpv6Prefix(text) !== undefined;
}

function validHexOctets(text: string, minimumOctets: number,
  maximumOctets: number): boolean {
  // Even length is part of the wire contract. Odd nibble input is rejected
  // instead of being padded on one side by an implementation detail.
  return text.length % 2 === 0 && hexadecimalPattern.test(text) &&
    text.length >= minimumOctets * 2 && text.length <= maximumOctets * 2;
}

function validateDhcpv6(hostId: string, intent: HostDhcpv6Intent): void {
  // RFC 9915 option-length is an unsigned 16-bit octet count. OPTION_DNS_SERVERS
  // contains only complete 16-octet IPv6 addresses, so this is the exact wire
  // representability ceiling rather than an application policy limit.
  const maximumDnsAddressesPerOption = Math.floor(0xffff / 16);
  assert(intent && typeof intent === "object" &&
    (intent.client === null || typeof intent.client === "object") &&
    (intent.server === null || typeof intent.server === "object"),
  `${hostId} DHCPv6 intent is invalid`);
  const client = intent.client;
  if (client) {
    assert(validHexOctets(client.duidHex, 3, 130) &&
      stableIidSecretPattern.test(client.transactionSecretHex) &&
      !/^0{64}$/.test(client.transactionSecretHex) &&
      typeof client.rapidCommit === "boolean" &&
      typeof client.informationOnly === "boolean" &&
      Array.isArray(client.identityAssociations) &&
      Array.isArray(client.requestedOptions),
    `${hostId} DHCPv6 client identity is invalid`);
    const associations = new Set<string>();
    for (const association of client.identityAssociations) {
      assert(Number.isSafeInteger(association?.iaid) && association.iaid >= 0 &&
        association.iaid <= maximumUint32 &&
        (association.kind === "ia-na" || association.kind === "ia-pd") &&
        !associations.has(`${association.kind}:${association.iaid}`),
      `${hostId} DHCPv6 identity association is invalid`);
      associations.add(`${association.kind}:${association.iaid}`);
    }
    const options = new Set<number>();
    for (const option of client.requestedOptions) {
      assert(Number.isSafeInteger(option) && option > 0 && option <= 0xffff &&
        !options.has(option), `${hostId} DHCPv6 requested option is invalid`);
      options.add(option);
    }
    assert(!client.informationOnly || client.identityAssociations.length === 0,
      `${hostId} information-only DHCPv6 client cannot request leases`);
  }
  const server = intent.server;
  if (!server) return;
  assert(validHexOctets(server.duidHex, 3, 130) &&
    Number.isSafeInteger(server.preference) && server.preference >= 0 &&
    server.preference <= 255 && typeof server.rapidCommit === "boolean" &&
    Array.isArray(server.dnsRecursiveServers) &&
    server.dnsRecursiveServers.length <= maximumDnsAddressesPerOption &&
    server.dnsRecursiveServers.every((address) =>
      typeof address === "string" && parseIpv6(address) !== undefined) &&
    Number.isSafeInteger(server.informationRefreshTimeSeconds) &&
    server.informationRefreshTimeSeconds >= 600 &&
    Number.isSafeInteger(server.declineHoldTimeSeconds) &&
    server.declineHoldTimeSeconds > 0 &&
    server.declineHoldTimeSeconds <= maximumUint32 &&
    Number.isSafeInteger(server.addressPoolIndex) &&
    Number.isSafeInteger(server.prefixPoolIndex) &&
    Array.isArray(server.addressPools) && server.addressPools.length <=
      PROFILE_CATALOG.runtime.dhcpv6_address_pools_per_server &&
    Array.isArray(server.prefixPools) && server.prefixPools.length <=
      PROFILE_CATALOG.runtime.dhcpv6_prefix_pools_per_server,
  `${hostId} DHCPv6 server configuration is invalid`);
  for (const value of [server.solicitMaximumRetransmissionSeconds,
    server.informationMaximumRetransmissionSeconds]) {
    assert(value === null || Number.isSafeInteger(value) && value >= 60 &&
      value <= 86400, `${hostId} DHCPv6 retransmission option is invalid`);
  }
  const validatePool = (pool: HostDhcpv6PoolIntent, delegated: boolean) => {
    const prefix = parseIpv6Prefix(pool?.prefix);
    assert(prefix && stableIidSecretPattern.test(pool.allocationSecretHex) &&
      !/^0{64}$/.test(pool.allocationSecretHex) &&
      Number.isSafeInteger(pool.preferredLifetimeSeconds) &&
      Number.isSafeInteger(pool.validLifetimeSeconds) &&
      Number.isSafeInteger(pool.t1Seconds) && Number.isSafeInteger(pool.t2Seconds) &&
      pool.preferredLifetimeSeconds >= 0 &&
      pool.preferredLifetimeSeconds <= pool.validLifetimeSeconds &&
      pool.t1Seconds >= 0 && pool.t1Seconds <= pool.t2Seconds &&
      pool.t2Seconds <= pool.validLifetimeSeconds &&
      pool.validLifetimeSeconds > 0 && pool.validLifetimeSeconds <= maximumUint32 &&
      (delegated ? Number.isInteger(pool.delegatedLength) &&
        pool.delegatedLength! >= prefix.length && pool.delegatedLength! <= 128 &&
        pool.delegatedLength! - prefix.length <= 64 :
        pool.delegatedLength === null),
    `${hostId} DHCPv6 lease pool is invalid`);
  };
  server.addressPools.forEach((pool) => validatePool(pool, false));
  server.prefixPools.forEach((pool) => validatePool(pool, true));
  assert((server.addressPools.length === 0 ? server.addressPoolIndex === 0 :
    server.addressPoolIndex < server.addressPools.length) &&
    (server.prefixPools.length === 0 ? server.prefixPoolIndex === 0 :
      server.prefixPoolIndex < server.prefixPools.length),
  `${hostId} DHCPv6 selected pool is invalid`);
}

function validDnsName(text: unknown): text is string {
  if (typeof text !== "string" || text === "." || !text.endsWith(".") ||
      new TextEncoder().encode(text).length > 255) return text === ".";
  const labels = text.slice(0, -1).split(".");
  // Project names use the ordinary ASCII presentation form. Master-file
  // escaped owner names remain inside masterFile and are parsed by the C++
  // RFC 1035 implementation instead of being approximated here.
  return labels.every((label) => label.length > 0 && label.length <= 63 &&
    /^[A-Za-z0-9_*-]+$/.test(label));
}

function validateDns(hostId: string, intent: HostDnsIntent): void {
  assert(intent && typeof intent === "object" &&
    (intent.resolver === null || typeof intent.resolver === "object") &&
    (intent.authoritative === null ||
      typeof intent.authoritative === "object"),
  `${hostId} DNS intent is invalid`);
  const resolver = intent.resolver;
  if (resolver) {
    assert(stableIidSecretPattern.test(resolver.identifierSecretHex) &&
      !/^0{64}$/.test(resolver.identifierSecretHex) &&
      Number.isSafeInteger(resolver.maximumNsec3Iterations) &&
      resolver.maximumNsec3Iterations >= 0 &&
      resolver.maximumNsec3Iterations <= 0xffff &&
      typeof resolver.serveClients === "boolean" &&
      Array.isArray(resolver.rootHints) && resolver.rootHints.length > 0 &&
      Array.isArray(resolver.trustAnchors),
    `${hostId} DNS resolver configuration is invalid`);
    const roots = new Set<string>();
    for (const root of resolver.rootHints) {
      assert(validDnsName(root?.serverName) &&
        Array.isArray(root.addresses) && root.addresses.length > 0 &&
        !roots.has(root.serverName.toLowerCase()),
      `${hostId} DNS root hint is invalid`);
      roots.add(root.serverName.toLowerCase());
      const addresses = new Set<string>();
      for (const address of root.addresses) {
        const valid = address?.family === "ipv4"
          ? parseIpv4(address.address) !== undefined
          : address?.family === "ipv6"
            ? parseIpv6(address.address) !== undefined : false;
        assert(valid && !addresses.has(`${address.family}:${address.address}`),
          `${hostId} DNS root address is invalid`);
        addresses.add(`${address.family}:${address.address}`);
      }
    }
    const anchors = new Set<string>();
    for (const anchor of resolver.trustAnchors) {
      assert(validDnsName(anchor?.owner) &&
        Number.isSafeInteger(anchor.ttl) && anchor.ttl >= 0 &&
        anchor.ttl <= maximumUint32 &&
        validHexOctets(anchor.rdataHex, 4, 0xffff) &&
        !anchors.has(`${anchor.owner.toLowerCase()}:${anchor.rdataHex}`),
      `${hostId} DNS trust anchor is invalid`);
      anchors.add(`${anchor.owner.toLowerCase()}:${anchor.rdataHex}`);
    }
  }

  const authoritative = intent.authoritative;
  if (!authoritative) return;
  assert(Array.isArray(authoritative.zones) && authoritative.zones.length > 0 &&
    (authoritative.signing === null ||
      typeof authoritative.signing === "object"),
  `${hostId} authoritative DNS configuration is invalid`);
  const origins = new Set<string>();
  for (const zone of authoritative.zones) {
    assert(validDnsName(zone?.origin) && typeof zone.masterFile === "string" &&
      zone.masterFile.length > 0 &&
      !origins.has(zone.origin.toLowerCase()),
    `${hostId} authoritative DNS zone is invalid`);
    origins.add(zone.origin.toLowerCase());
  }
  const signing = authoritative.signing;
  if (!signing) return;
  assert(Number.isSafeInteger(signing.dnskeyTtl) && signing.dnskeyTtl > 0 &&
    signing.dnskeyTtl <= maximumUint32 &&
    Number.isSafeInteger(signing.denialTtl) && signing.denialTtl > 0 &&
    signing.denialTtl <= maximumUint32 &&
    (signing.denialMode === "nsec" || signing.denialMode === "nsec3") &&
    Number.isSafeInteger(signing.validitySeconds) &&
    Number.isSafeInteger(signing.refreshSeconds) &&
    Number.isSafeInteger(signing.resignSeconds) &&
    Number.isSafeInteger(signing.inceptionOffsetSeconds) &&
    signing.resignSeconds > 0 &&
    signing.resignSeconds < signing.refreshSeconds &&
    signing.refreshSeconds < signing.validitySeconds &&
    signing.validitySeconds <= maximumUint32 &&
    signing.inceptionOffsetSeconds >= 0 &&
    signing.inceptionOffsetSeconds < signing.validitySeconds &&
    Array.isArray(signing.keys) && signing.keys.length >= 2,
  `${hostId} DNSSEC signing policy is invalid`);
  const supportedAlgorithms = new Set<number>(dnssecAlgorithms
    .filter((algorithm) => algorithm.backend !== null)
    .map((algorithm) => algorithm.number));
  let ksk = false;
  let zsk = false;
  for (const key of signing.keys) {
    assert((key?.role === "ksk" || key?.role === "zsk") &&
      supportedAlgorithms.has(key.algorithm) &&
      Number.isSafeInteger(key.rsaBits) && key.rsaBits >= 512 &&
      key.rsaBits <= 4096 &&
      [key.publishAt, key.readyAt, key.activateAt, key.retireAt, key.deadAt,
        key.removeAt].every((time) => Number.isSafeInteger(time) && time >= 0) &&
      key.publishAt <= key.readyAt && key.readyAt <= key.activateAt &&
      key.activateAt <= key.retireAt && key.retireAt <= key.deadAt &&
      key.deadAt <= key.removeAt,
    `${hostId} DNSSEC signing key is invalid`);
    ksk ||= key.role === "ksk";
    zsk ||= key.role === "zsk";
  }
  assert(ksk && zsk, `${hostId} DNSSEC requires KSK and ZSK roles`);
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

export function equippedRouterPorts(router: RouterProjectV4): RouterPortIntent[] {
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

function emptyHardware(profile: typeof PROFILE_CATALOG.profiles[number]): RouterProjectV4["hardware"] {
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

export function createRouterProjectV4(id: NodeId, profileId: DeviceProfileId,
  systemName = id.toUpperCase()): RouterProjectV4 {
  // Validate identity before allocating nested hardware arrays. A failed add
  // operation therefore has no partially constructed project node to clean up.
  assert(identifierPattern.test(id), "Router ID is invalid");
  const profile = profileById(profileId);
  assert(profile, "Router profile is not supported");
  const router: RouterProjectV4 = {
    id, kind: "router", profileId, release: LAB_RELEASE, systemName,
    hardware: emptyHardware(profile),
    running: { systemName, maximumEcmpPaths: 1, ports: [], interfaces: [], staticRoutes: [],
      ipv6StaticRoutes: [] }
  };
  // Fixed platforms receive their real derived inventory now. Modular routers
  // remain at zero ports until the user provisions and equips hardware.
  router.running.ports = equippedRouterPorts(router);
  return router;
}

export function createEmptyProjectV4(now = new Date()): LabProjectV4 {
  // UUID identity survives project rename and prevents OPFS transcript paths
  // from colliding when two projects use the same display name.
  const timestamp = now.toISOString();
  const random = globalThis.crypto?.randomUUID?.() ??
    `lab-${now.getTime().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  return {
    format: "router-simulator-project", version: LAB_PROJECT_VERSION,
    projectId: random, name: "Untitled lab", routers: [], hosts: [], links: [],
    annotations: [], notes: "",
    layout: { nodes: {}, sidebarWidth: 194, inspectorWidth: 324,
      terminalHeight: 360 }, updatedAt: timestamp
  };
}

export function createAnnotationV4(id: string, x: number,
  y: number): TopologyAnnotationV4 {
  // Identity is validated before the record is handed to callers so a rejected
  // placement never leaves a half-built annotation on the canvas. The default
  // is a plain readable label; fill, border and emphasis are opt-in styling.
  assert(identifierPattern.test(id), "Annotation ID is invalid");
  return { id, text: "", x, y, width: 240, fontSize: 14, bold: false,
    italic: false, align: "left", color: "#f3f0f7", background: null,
    border: false };
}

function validateHardware(router: RouterProjectV4,
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

export function parseLabProjectV4(input: unknown): LabProjectV4 {
  // Validation is fail-closed and non-mutating. The final structuredClone is
  // the first value returned to persistence or the runtime bridge.
  assert(input && typeof input === "object" && !Array.isArray(input), "Project must be an object");
  const project = input as Partial<LabProjectV4>;
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
  // Address uniqueness spans router interfaces and hosts. Separate local
  // validators would miss conflicts between those two node classes.
  const macs = new Set<string>();
  const addresses = new Set<number>();
  const ipv6Addresses = new Set<bigint>();
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
      Array.isArray(router.running.interfaces) && Array.isArray(router.running.staticRoutes) &&
      Array.isArray(router.running.ipv6StaticRoutes),
      `${router.id} running configuration is invalid`);
    // Physical inventory bounds ports, while the Base router also owns one
    // portless system interface. Keep the portable validator aligned with the
    // native RIB capacity instead of silently treating that loopback as a port.
    assert(router.running.interfaces.length <=
      PROFILE_CATALOG_COMPILED.maximumPortsPerRouter + 1,
    `${router.id} exceeds the routed interface limit`);
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
      const parsedIpv4 = item.address ? parsePrefix(item.address) : undefined;
      const systemInterface = item.name === "system";
      // Interface MAC identity is derived from the physical router port by the
      // hardware owner. It is not a user-configurable routed-interface leaf.
      assert(typeof item.name === "string" && item.name.length > 0 && !interfaceNames.has(item.name) &&
        (item.portId === "" || isPossibleRouterPort(router.profileId, item.portId)) &&
        (item.address === "" || parsedIpv4) &&
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
        // The reserved Base-router loopback has neither a physical connector
        // nor an Ethernet neighbor zone. Until its IPv6 owner is implemented,
        // reject those leaves instead of restoring configuration as a no-op.
        (!systemInterface || (item.portId === "" &&
          (!parsedIpv4 || parsedIpv4.length === 32) &&
          item.ipv6Addresses.length === 0 && item.arpTimeoutSeconds === null &&
          item.arpRetryTimerDeciseconds === null)) &&
        (item.admin === "up" || item.admin === "down"),
        `${router.id} interface configuration is invalid`);
      if (item.address) {
        const address = parsePrefix(item.address)!.address;
        assert(!addresses.has(address),
          "Router interface addresses must be unique in a laboratory");
        addresses.add(address);
      }
      const interfaceAddresses = new Set<bigint>();
      for (const configured of item.ipv6Addresses) {
        const parsed = configured &&
          parseIpv6InterfacePrefix(configured.address);
        assert(parsed && typeof configured.duplicateAddressDetection === "boolean" &&
          typeof configured.eui64 === "boolean" &&
          (configured.eui64SourceMac === null ||
            /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(
              configured.eui64SourceMac)) &&
          (configured.eui64 === (configured.eui64SourceMac !== null)) &&
          (!configured.eui64 ||
            (parsed.length === 64 && parsed.address ===
              (parsed.address >> 64n << 64n))) &&
          Number.isSafeInteger(configured.primaryPreference) &&
          configured.primaryPreference >= 0 &&
          configured.primaryPreference <= maximumUint32 &&
          (configured.tag === null ||
            (Number.isSafeInteger(configured.tag) && configured.tag >= 0 &&
             configured.tag <= maximumUint32)),
        `${router.id} IPv6 interface address attributes are invalid`);
        const address = parsed.address;
        assert((configured.eui64 || address !== 0n) &&
          address >> 120n !== 0xffn && !interfaceAddresses.has(address) &&
          (configured.eui64 || !ipv6Addresses.has(address)),
        "Router IPv6 interface addresses must be unique unicast values");
        interfaceAddresses.add(address);
        // An EUI-64 row stores a prefix, not the effective address. Treating
        // that prefix as a global address would reject the normal case where
        // multiple routers share one link prefix but derive distinct IIDs.
        if (!configured.eui64) ipv6Addresses.add(address);
      }
      interfaceNames.add(item.name);
    }
    assert(Number.isSafeInteger(router.running.maximumEcmpPaths) &&
      router.running.maximumEcmpPaths >= 1 &&
      router.running.maximumEcmpPaths <= PROFILE_CATALOG.runtime.maximum_ecmp_paths,
    `${router.id} maximumEcmpPaths is invalid`);
    const routeKeys = new Set<string>();
    for (const route of router.running.staticRoutes) {
      // A static candidate is keyed by prefix, next hop and resolution kind.
      // Repeating only the prefix is intentional and forms an ECMP candidate
      // set when the router-wide maximum permits more than one member.
      const key = `${route.prefix}|${route.nextHop}|${route.indirect}`;
      assert(canonicalPrefix(route.prefix) && parseIpv4(route.nextHop) !== undefined &&
        typeof route.indirect === "boolean",
      `${router.id} static route is invalid`);
      assert(!routeKeys.has(key), `${router.id} duplicate static route`);
      routeKeys.add(key);
    }
    const ipv6RouteKeys = new Set<string>();
    for (const route of router.running.ipv6StaticRoutes) {
      const nextHop = parseIpv6(route.nextHop);
      const linkLocal = nextHop !== undefined &&
        nextHop >> 118n === 0x3fan;
      assert(parseIpv6Prefix(route.prefix) && nextHop !== undefined &&
        nextHop !== 0n && nextHop >> 120n !== 0xffn &&
        typeof route.indirect === "boolean" &&
        (route.outgoingPortId === "" ||
          isPossibleRouterPort(router.profileId, route.outgoingPortId)) &&
        (route.indirect
          ? !linkLocal && route.outgoingPortId === ""
          : !linkLocal || route.outgoingPortId !== ""),
      `${router.id} IPv6 static route is invalid`);
      assert(!ipv6RouteKeys.has(
        `${route.prefix}|${route.nextHop}|${route.indirect}`),
      `${router.id} duplicate IPv6 static route`);
      ipv6RouteKeys.add(`${route.prefix}|${route.nextHop}|${route.indirect}`);
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
      stableIidSecretPattern.test(host.eth0.transportSecretHex) &&
      !/^0{64}$/.test(host.eth0.transportSecretHex) &&
      gateway !== undefined && Number.isSafeInteger(host.eth0.mtu) &&
      host.eth0.mtu >= PROFILE_CATALOG.ethernet.minimum_host_ipv4_mtu &&
      host.eth0.mtu <= PROFILE_CATALOG.ethernet.maximum_network_mtu &&
      typeof host.eth0.ipv6?.autoconfiguration === "boolean" &&
      (host.eth0.ipv6.interfaceIdentifierMode === "modified-eui64" ||
       host.eth0.ipv6.interfaceIdentifierMode === "stable-opaque") &&
      (host.eth0.ipv6.stableIidSecret === null ||
       stableIidSecretPattern.test(host.eth0.ipv6.stableIidSecret)) &&
      typeof host.eth0.ipv6.networkId === "string" &&
      new TextEncoder().encode(host.eth0.ipv6.networkId).length <=
        PROFILE_CATALOG.runtime.ipv6_stable_iid_network_id_octets &&
      (host.eth0.ipv6.interfaceIdentifierMode !== "stable-opaque" ||
       (host.eth0.ipv6.stableIidSecret !== null &&
        !/^0{64}$/.test(host.eth0.ipv6.stableIidSecret) &&
        host.eth0.ipv6.networkId.length > 0)) &&
      uint64Pattern.test(host.eth0.ipv6.interfaceId) &&
      BigInt(host.eth0.ipv6.interfaceId) > 0n &&
      BigInt(host.eth0.ipv6.interfaceId) <= maximumUint64 &&
      (!host.eth0.ipv6.autoconfiguration ||
        host.eth0.mtu >= PROFILE_CATALOG.ethernet.minimum_host_ipv6_mtu),
      `${host.id} Ethernet configuration is invalid`);
    validateDhcpv6(host.id, host.eth0.ipv6.dhcpv6);
    validateDns(host.id, host.eth0.dns);
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
      (link.configuredSpeedMbps === null ||
       Number.isSafeInteger(link.configuredSpeedMbps) &&
       link.configuredSpeedMbps > 0) &&
      Number.isSafeInteger(link.propagationDelayNs) && link.propagationDelayNs >= 0,
      "Link configuration is invalid");
    assert(link.endpoints[0].nodeId !== link.endpoints[1].nodeId,
      `${link.id} cannot connect a node to itself`);
    // A host-only cable may retain null intent while the user is editing it.
    // Runtime reconciliation deliberately withholds carrier in that state, so
    // accepting the portable graph does not invent serialization timing.
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

  // Annotations are optional so a project written before this feature still
  // loads. When present each record is validated as strictly as operational
  // intent, including that its identity cannot shadow a node or link id, since
  // selection shares one identifier namespace across the canvas.
  const annotations = project.annotations ?? [];
  assert(Array.isArray(annotations) &&
    annotations.length <= ANNOTATION_LIMITS.count,
    "Project exceeds the annotation limit");
  const annotationIds = new Set<string>();
  for (const annotation of annotations) {
    assert(annotation && typeof annotation === "object" &&
      identifierPattern.test(annotation.id) &&
      !annotationIds.has(annotation.id) && !nodes.has(annotation.id) &&
      !linkIds.has(annotation.id) && typeof annotation.text === "string" &&
      encoder.encode(annotation.text).length <= ANNOTATION_LIMITS.maxTextBytes &&
      Number.isFinite(annotation.x) && Number.isFinite(annotation.y) &&
      Number.isFinite(annotation.width) &&
      annotation.width >= ANNOTATION_LIMITS.minWidth &&
      annotation.width <= ANNOTATION_LIMITS.maxWidth &&
      Number.isSafeInteger(annotation.fontSize) &&
      annotation.fontSize >= ANNOTATION_LIMITS.minFontSize &&
      annotation.fontSize <= ANNOTATION_LIMITS.maxFontSize &&
      typeof annotation.bold === "boolean" &&
      typeof annotation.italic === "boolean" &&
      (annotation.align === "left" || annotation.align === "center" ||
        annotation.align === "right") &&
      annotationColorPattern.test(annotation.color) &&
      (annotation.background === null ||
        annotationFillPattern.test(annotation.background)) &&
      typeof annotation.border === "boolean",
      "Annotation configuration is invalid");
    annotationIds.add(annotation.id);
  }

  // Detach the accepted value from the caller's mutable object graph. Later
  // edits cannot change the project while a runtime transaction is in flight.
  // A legacy project without an annotations array is normalized to an empty
  // one so every accepted value has the same shape.
  const result = structuredClone(project as LabProjectV4);
  result.annotations = structuredClone(annotations) as TopologyAnnotationV4[];
  return result;
}

export { PROFILE_CATALOG };
