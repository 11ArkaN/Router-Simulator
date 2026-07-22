// Browser-owned creation of opaque 256-bit project secrets. This module owns
// no persistent state and depends only on Web Crypto. Callers decide whether a
// secret belongs to transport, RFC 7217 identity generation or another owner.

import type { HostProjectV4 } from "@router-simulator/contracts";

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
