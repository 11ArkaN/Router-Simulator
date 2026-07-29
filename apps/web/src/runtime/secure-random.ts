// Browser-owned creation of opaque 256-bit project secrets. This module owns
// no persistent state and depends only on Web Crypto. Callers decide whether a
// secret belongs to transport, RFC 7217 identity generation or another owner.

import { hostInterfaceId, PROFILE_CATALOG,
  type HostProjectV4 } from "@router-simulator/contracts";

export interface RandomValuesSource {
  getRandomValues<T extends ArrayBufferView | null>(array: T): T;
}

export function secureRandomSecretHex(
  source: RandomValuesSource = crypto): string {
  const bytes = new Uint8Array(32);
  // Project validation reserves the all-zero value as "not configured". A
  // compliant CSPRNG can theoretically return it, so retry instead of changing
  // one byte and biasing the distribution. Browser failure is allowed to throw
  // and abort the surrounding project transaction.
  do source.getRandomValues(bytes);
  while (bytes.every((value) => value === 0));
  return Array.from(bytes, (value) =>
    value.toString(16).padStart(2, "0")).join("");
}

export function secureRandomHostMac(usedMacs: ReadonlySet<string>,
  source: RandomValuesSource = crypto): string {
  const octets = new Uint8Array(6);
  // Project imports preserve canonical lowercase today, but this public
  // creation boundary remains case-insensitive so callers cannot accidentally
  // bypass collision detection with an uppercase representation.
  const occupied = new Set(Array.from(usedMacs,
    (value) => value.toLowerCase()));
  for (let attempt = 0; attempt < 128; ++attempt) {
    source.getRandomValues(octets);
    // IEEE 802 distinguishes individual/group addresses with bit 0 and
    // universal/local administration with bit 1 of the first octet. A
    // generated endpoint identity must be unicast and must not claim an OUI
    // assigned to a hardware vendor, so force the canonical x2 bit pattern.
    octets[0] = (octets[0]! & 0xfc) | 0x02;
    const candidate = Array.from(octets, (value) =>
      value.toString(16).padStart(2, "0")).join(":");
    if (!occupied.has(candidate)) return candidate;
  }
  // A permanently colliding or broken entropy source must fail host creation
  // instead of looping on the UI thread or publishing a duplicate identity.
  throw new Error("Could not allocate a unique host MAC address");
}

export function createUnconfiguredHost(id: string, name: string,
  usedMacs: ReadonlySet<string>,
  source: RandomValuesSource = crypto): HostProjectV4 {
  // An unconfigured IPv4 endpoint uses the runtime's explicit unspecified
  // tuple. It owns a real L2 identity and Ethernet MTU immediately, but owns
  // no IPv4 address, default route or DHCP socket until the user selects one.
  return { id, kind: "host", name, eth0: {
    mac: secureRandomHostMac(usedMacs, source),
    address: "0.0.0.0/0",
    gateway: "0.0.0.0",
    mtu: PROFILE_CATALOG.ethernet.default_host_ipv4_mtu,
    mode: "ethernet",
    transportSecretHex: secureRandomSecretHex(source),
    dhcpv4: { client: null, server: null },
    dns: { resolver: null, authoritative: null },
    ipv6: {
      autoconfiguration: true,
      interfaceId: hostInterfaceId(id),
      interfaceIdentifierMode: "modified-eui64",
      stableIidSecret: null,
      networkId: "",
      dhcpv6: { client: null, server: null }
    }
  } };
}

export function materializeStableIidSecret(host: HostProjectV4,
  source: RandomValuesSource = crypto): HostProjectV4 {
  // Existing secrets are stable project identity and must never rotate during
  // an unrelated host edit. Modified EUI-64 does not consume secret material.
  if (host.eth0.ipv6.interfaceIdentifierMode !== "stable-opaque" ||
      host.eth0.ipv6.stableIidSecret)
    return host;
  return { ...host, eth0: { ...host.eth0, ipv6: { ...host.eth0.ipv6,
    stableIidSecret: secureRandomSecretHex(source) } } };
}
