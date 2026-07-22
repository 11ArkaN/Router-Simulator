// Generated from profiles/dnssec/iana-2026-01-13.yaml. Do not edit.
// Registry policy and compiled crypto support share this single wire-number map.

export type DnssecRecommendation = "must-not" | "not-recommended" | "may" | "recommended" | "must";
export type DnssecCryptoBackend = "rsa-sha256" | "ecdsa-p256-sha256" | "ed25519";
export type DnssecDigestBackend = "sha1" | "sha256" | "sha384";
export const dnssecRegistryDate = "2026-01-13" as const;
export const dnssecAlgorithmRegistryUrl = "https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml" as const;
export const dnssecDigestRegistryUrl = "https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml" as const;
export const dnssecAlgorithms = [
  { number: 1, name: "RSAMD5", use_signing: "must-not", use_validation: "must-not", implement_signing: "must-not", implement_validation: "must-not", backend: null },
  { number: 3, name: "DSA", use_signing: "must-not", use_validation: "must-not", implement_signing: "must-not", implement_validation: "must-not", backend: null },
  { number: 5, name: "RSASHA1", use_signing: "not-recommended", use_validation: "recommended", implement_signing: "not-recommended", implement_validation: "must", backend: null },
  { number: 6, name: "DSA-NSEC3-SHA1", use_signing: "must-not", use_validation: "must-not", implement_signing: "must-not", implement_validation: "must-not", backend: null },
  { number: 7, name: "RSASHA1-NSEC3-SHA1", use_signing: "not-recommended", use_validation: "recommended", implement_signing: "not-recommended", implement_validation: "must", backend: null },
  { number: 8, name: "RSASHA256", use_signing: "recommended", use_validation: "recommended", implement_signing: "must", implement_validation: "must", backend: "rsa-sha256" },
  { number: 10, name: "RSASHA512", use_signing: "not-recommended", use_validation: "recommended", implement_signing: "not-recommended", implement_validation: "must", backend: null },
  { number: 12, name: "ECC-GOST", use_signing: "must-not", use_validation: "must-not", implement_signing: "must-not", implement_validation: "must-not", backend: null },
  { number: 13, name: "ECDSAP256SHA256", use_signing: "recommended", use_validation: "recommended", implement_signing: "must", implement_validation: "must", backend: "ecdsa-p256-sha256" },
  { number: 14, name: "ECDSAP384SHA384", use_signing: "may", use_validation: "recommended", implement_signing: "may", implement_validation: "recommended", backend: null },
  { number: 15, name: "ED25519", use_signing: "recommended", use_validation: "recommended", implement_signing: "recommended", implement_validation: "recommended", backend: "ed25519" },
  { number: 16, name: "ED448", use_signing: "may", use_validation: "recommended", implement_signing: "may", implement_validation: "recommended", backend: null },
  { number: 17, name: "SM2SM3", use_signing: "may", use_validation: "may", implement_signing: "may", implement_validation: "may", backend: null },
  { number: 23, name: "ECC-GOST12", use_signing: "may", use_validation: "may", implement_signing: "may", implement_validation: "may", backend: null },
  { number: 253, name: "PRIVATEDNS", use_signing: "may", use_validation: "may", implement_signing: "may", implement_validation: "may", backend: null },
  { number: 254, name: "PRIVATEOID", use_signing: "may", use_validation: "may", implement_signing: "may", implement_validation: "may", backend: null },
] as const;
export const dnssecDigests = [
  { number: 0, name: "Reserved", use_delegation: "must-not", use_validation: "must-not", implement_delegation: "must-not", implement_validation: "must-not", backend: null },
  { number: 1, name: "SHA-1", use_delegation: "must-not", use_validation: "recommended", implement_delegation: "must-not", implement_validation: "must", backend: "sha1" },
  { number: 2, name: "SHA-256", use_delegation: "recommended", use_validation: "recommended", implement_delegation: "must", implement_validation: "must", backend: "sha256" },
  { number: 3, name: "GOST-R-34.11-94", use_delegation: "must-not", use_validation: "must-not", implement_delegation: "must-not", implement_validation: "must-not", backend: null },
  { number: 4, name: "SHA-384", use_delegation: "may", use_validation: "recommended", implement_delegation: "may", implement_validation: "recommended", backend: "sha384" },
  { number: 5, name: "GOST-R-34.11-2012", use_delegation: "may", use_validation: "may", implement_delegation: "may", implement_validation: "may", backend: null },
  { number: 6, name: "SM3", use_delegation: "may", use_validation: "may", implement_delegation: "may", implement_validation: "may", backend: null },
] as const;
