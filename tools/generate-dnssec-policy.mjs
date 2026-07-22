// Converts the pinned IANA DNSSEC registries into identical C++ and TypeScript
// tables. Runtime policy reads generated values and never duplicates an
// algorithm number or recommendation in executable source.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";

const root = resolve(import.meta.dirname, "..");
const inputPath = resolve(root, "profiles/dnssec/iana-2026-01-13.yaml");
const cppPath = resolve(root, "core/include/router/generated_dnssec_policy.hpp");
const tsPath = resolve(root, "packages/contracts/src/generated-dnssec-policy.ts");
const check = process.argv.includes("--check");
const profile = parse(readFileSync(inputPath, "utf8"));
const recommendations = ["must-not", "not-recommended", "may", "recommended", "must"];
const cryptoBackends = [undefined, "rsa-sha256", "ecdsa-p256-sha256", "ed25519"];
const digestBackends = [undefined, "sha1", "sha256", "sha384"];

function validateRows(rows, kind, fields) {
  if (!Array.isArray(rows) || rows.length === 0)
    throw new Error(`${kind} registry is empty`);
  let previous = -1;
  for (const row of rows) {
    // Increasing octets make duplicate numbers impossible and permit a compact
    // constexpr lookup without constructing a mutable map at runtime.
    if (!Number.isInteger(row.number) || row.number < 0 ||
        row.number > 255 || row.number <= previous)
      throw new Error(`${kind} numbers must be unique, increasing octets`);
    previous = row.number;
    for (const field of fields)
      if (!recommendations.includes(row[field]))
        throw new Error(`${kind} ${row.number} has invalid ${field}`);
  }
}

validateRows(profile.algorithms, "algorithm",
  ["use_signing", "use_validation", "implement_signing", "implement_validation"]);
for (const row of profile.algorithms)
  if (!cryptoBackends.includes(row.backend))
    throw new Error(`algorithm ${row.number} has unknown crypto backend`);
validateRows(profile.digests, "digest",
  ["use_delegation", "use_validation", "implement_delegation", "implement_validation"]);
for (const row of profile.digests)
  if (!digestBackends.includes(row.backend))
    throw new Error(`digest ${row.number} has unknown crypto backend`);
if (!/^\d{4}-\d{2}-\d{2}$/.test(profile.registry_date) ||
    !profile.algorithm_registry_url?.startsWith("https://www.iana.org/") ||
    !profile.digest_registry_url?.startsWith("https://www.iana.org/"))
  throw new Error("DNSSEC registry metadata must pin a date and official IANA URLs");

const cppRecommendation = value => ({
  "must-not": "Recommendation::must_not",
  "not-recommended": "Recommendation::not_recommended",
  may: "Recommendation::may",
  recommended: "Recommendation::recommended",
  must: "Recommendation::must",
})[value];
const cppBackend = value => ({
  undefined: "CryptoBackend::none",
  "rsa-sha256": "CryptoBackend::rsa_sha256",
  "ecdsa-p256-sha256": "CryptoBackend::ecdsa_p256_sha256",
  ed25519: "CryptoBackend::ed25519",
})[value];
const cppDigestBackend = value => ({
  undefined: "DigestBackend::none",
  sha1: "DigestBackend::sha1",
  sha256: "DigestBackend::sha256",
  sha384: "DigestBackend::sha384",
})[value];
const cppRows = (rows, nameField, fields, withBackend = false) => rows.map(row => {
  const backend = withBackend ? `, ${cppBackend(row.backend)}` : "";
  return `    {${row.number}U, "${row[nameField]}", ${fields.map(field => cppRecommendation(row[field])).join(", ")}${backend}}`;
}).join(",\n");
const tsRows = (rows, nameField, fields, withBackend = false) => rows.map(row => {
  const backend = withBackend ? `, backend: ${JSON.stringify(row.backend ?? null)}` : "";
  return `  { number: ${row.number}, name: ${JSON.stringify(row[nameField])}, ${fields.map(field => `${field}: ${JSON.stringify(row[field])}`).join(", ")}${backend} },`;
}).join("\n");
const cppDigestRows = (rows, fields) => rows.map(row =>
  `    {${row.number}U, "${row.name}", ${fields.map(field => cppRecommendation(row[field])).join(", ")}, ${cppDigestBackend(row.backend)}}`).join(",\n");
const tsDigestRows = (rows, fields) => rows.map(row =>
  `  { number: ${row.number}, name: ${JSON.stringify(row.name)}, ${fields.map(field => `${field}: ${JSON.stringify(row[field])}`).join(", ")}, backend: ${JSON.stringify(row.backend ?? null)} },`).join("\n");

const cpp = `// Generated from profiles/dnssec/iana-2026-01-13.yaml. Do not edit.\n// Registry policy and compiled crypto support share this single wire-number map.\n\n#pragma once\n\n#include <array>\n#include <cstdint>\n#include <optional>\n#include <string_view>\n\nnamespace router::dnssec::policy {\n\nenum class Recommendation : std::uint8_t { must_not, not_recommended, may, recommended, must };\nenum class CryptoBackend : std::uint8_t { none, rsa_sha256, ecdsa_p256_sha256, ed25519 };\nenum class DigestBackend : std::uint8_t { none, sha1, sha256, sha384 };\n\nstruct Algorithm {\n  std::uint8_t number;\n  std::string_view mnemonic;\n  Recommendation use_signing;\n  Recommendation use_validation;\n  Recommendation implement_signing;\n  Recommendation implement_validation;\n  CryptoBackend backend;\n};\n\nstruct Digest {\n  std::uint8_t number;\n  std::string_view name;\n  Recommendation use_delegation;\n  Recommendation use_validation;\n  Recommendation implement_delegation;\n  Recommendation implement_validation;\n  DigestBackend backend;\n};\n\ninline constexpr std::string_view registry_date = "${profile.registry_date}";\ninline constexpr std::string_view algorithm_registry_url = "${profile.algorithm_registry_url}";\ninline constexpr std::string_view digest_registry_url = "${profile.digest_registry_url}";\ninline constexpr std::array<Algorithm, ${profile.algorithms.length}> algorithms{{\n${cppRows(profile.algorithms, "mnemonic", ["use_signing", "use_validation", "implement_signing", "implement_validation"], true)}\n}};\ninline constexpr std::array<Digest, ${profile.digests.length}> digests{{\n${cppDigestRows(profile.digests, ["use_delegation", "use_validation", "implement_delegation", "implement_validation"])}\n}};\n\n[[nodiscard]] constexpr std::optional<Algorithm> algorithm(std::uint8_t number) noexcept {\n  for (const auto &entry : algorithms) if (entry.number == number) return entry;\n  return std::nullopt;\n}\n\n[[nodiscard]] constexpr std::optional<Digest> digest(std::uint8_t number) noexcept {\n  for (const auto &entry : digests) if (entry.number == number) return entry;\n  return std::nullopt;\n}\n\n} // namespace router::dnssec::policy\n`;

const ts = `// Generated from profiles/dnssec/iana-2026-01-13.yaml. Do not edit.\n// Registry policy and compiled crypto support share this single wire-number map.\n\nexport type DnssecRecommendation = "must-not" | "not-recommended" | "may" | "recommended" | "must";\nexport type DnssecCryptoBackend = "rsa-sha256" | "ecdsa-p256-sha256" | "ed25519";\nexport type DnssecDigestBackend = "sha1" | "sha256" | "sha384";\nexport const dnssecRegistryDate = ${JSON.stringify(profile.registry_date)} as const;\nexport const dnssecAlgorithmRegistryUrl = ${JSON.stringify(profile.algorithm_registry_url)} as const;\nexport const dnssecDigestRegistryUrl = ${JSON.stringify(profile.digest_registry_url)} as const;\nexport const dnssecAlgorithms = [\n${tsRows(profile.algorithms, "mnemonic", ["use_signing", "use_validation", "implement_signing", "implement_validation"], true)}\n] as const;\nexport const dnssecDigests = [\n${tsDigestRows(profile.digests, ["use_delegation", "use_validation", "implement_delegation", "implement_validation"])}\n] as const;\n`;

function publish(path, content) {
  if (check) {
    if (readFileSync(path, "utf8") !== content)
      throw new Error(`${path} is stale`);
  } else {
    writeFileSync(path, content);
  }
}

publish(cppPath, cpp);
publish(tsPath, ts);
