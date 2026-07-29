// Secure project-secret tests use a deterministic random source. They verify
// representation and the reserved-zero retry without weakening production by
// replacing Web Crypto with a fallback PRNG.

import { describe, expect, it } from "vitest";
import { createEmptyProjectV4, createFourRouterReferenceLabV4, parseLabProjectV4,
  PROFILE_CATALOG } from "@router-simulator/contracts";
import { createUnconfiguredHost, materializeStableIidSecret,
  secureRandomHostMac, secureRandomSecretHex,
  type RandomValuesSource } from "./secure-random";

describe("secure project secret generation", () => {
  it("encodes all 256 random bits as canonical lowercase hexadecimal", () => {
    const source: RandomValuesSource = { getRandomValues(array) {
      const bytes = array as Uint8Array;
      for (let index = 0; index < bytes.length; ++index)
        bytes[index] = index;
      return array;
    } };
    expect(secureRandomSecretHex(source)).toBe(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  });

  it("retries the project-reserved all-zero value", () => {
    let calls = 0;
    const source: RandomValuesSource = { getRandomValues(array) {
      const bytes = array as Uint8Array;
      bytes.fill(calls++ === 0 ? 0 : 0xa5);
      return array;
    } };
    expect(secureRandomSecretHex(source)).toBe("a5".repeat(32));
    expect(calls).toBe(2);
  });

  it("creates a missing RFC 7217 secret once and preserves it", () => {
    const host = structuredClone(createFourRouterReferenceLabV4().hosts[0]);
    host.eth0.ipv6.interfaceIdentifierMode = "stable-opaque";
    host.eth0.ipv6.networkId = "access-a";
    const source: RandomValuesSource = { getRandomValues(array) {
      (array as Uint8Array).fill(0x3c);
      return array;
    } };
    const generated = materializeStableIidSecret(host, source);
    const retained = materializeStableIidSecret(generated, {
      getRandomValues() { throw new Error("stable secret was regenerated"); }
    });
    expect(generated.eth0.ipv6.stableIidSecret).toBe("3c".repeat(32));
    expect(retained).toBe(generated);
    expect(host.eth0.ipv6.stableIidSecret).toBeNull();
  });

  it("creates a locally administered unicast MAC and retries collisions", () => {
    let calls = 0;
    const source: RandomValuesSource = { getRandomValues(array) {
      const bytes = array as Uint8Array;
      bytes.fill(calls++ === 0 ? 0xaa : 0xbb);
      return array;
    } };
    expect(secureRandomHostMac(new Set(["AA:AA:AA:AA:AA:AA"]), source))
      .toBe("ba:bb:bb:bb:bb:bb");
    expect(calls).toBe(2);
  });

  it("creates a valid unconfigured endpoint with the catalog host MTU", () => {
    let fill = 1;
    const source: RandomValuesSource = { getRandomValues(array) {
      (array as Uint8Array).fill(fill++);
      return array;
    } };
    const host = createUnconfiguredHost("h1", "H1", new Set(), source);
    const project = createEmptyProjectV4();
    project.hosts.push(host);
    project.layout.nodes.h1 = { x: 0, y: 0 };
    expect(host.eth0).toMatchObject({
      mac: "02:01:01:01:01:01",
      address: "0.0.0.0/0",
      gateway: "0.0.0.0",
      mtu: PROFILE_CATALOG.ethernet.default_host_ipv4_mtu,
      dhcpv4: { client: null, server: null }
    });
    expect(parseLabProjectV4(project).hosts[0]).toEqual(host);
  });
});
