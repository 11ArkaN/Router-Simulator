import { existsSync, readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";

const root = resolve(import.meta.dirname, "..");
const catalog = parse(readFileSync(resolve(root, "sources/catalog.yaml"), "utf8"));
const capabilities = parse(readFileSync(resolve(root, "sources/capabilities.yaml"), "utf8"));
const profile = parse(readFileSync(resolve(root, "profiles/7750-sr-7-iom4-e.yaml"), "utf8"));
const cliSchema = parse(readFileSync(resolve(root, "schemas/cli/26.7.R1.yaml"), "utf8"));
const required = [
  "id", "kind", "release", "platforms", "source_type", "source_url", "section",
  "rfc_refs", "yang_path", "last_verified_at", "implementation", "tests", "status", "notes"
];
const statuses = new Set([
  "planned", "researched", "schema-only", "partially-implemented", "implemented",
  "verified-srsim", "verified-hardware", "unsupported", "experimental"
]);
const ids = new Set();
const errors = [];

for (const [index, record] of (catalog.records ?? []).entries()) {
  const label = record?.id ?? `record ${index + 1}`;
  for (const field of required) {
    if (!(field in (record ?? {}))) errors.push(`${label}: missing ${field}`);
  }
  if (ids.has(record.id)) errors.push(`${label}: duplicate id`);
  ids.add(record.id);
  if (!statuses.has(record.status)) errors.push(`${label}: invalid status ${record.status}`);
  if (!String(record.source_url ?? "").startsWith("https://")) errors.push(`${label}: source_url must use HTTPS`);

  if (["partially-implemented", "implemented", "verified-srsim", "verified-hardware"].includes(record.status)) {
    if (!record.implementation?.length) errors.push(`${label}: implemented feature has no implementation path`);
    if (!record.tests?.length) errors.push(`${label}: implemented feature has no test path`);
  }
  for (const path of [...(record.implementation ?? []), ...(record.tests ?? [])]) {
    if (!existsSync(resolve(root, path))) errors.push(`${label}: missing referenced file ${path}`);
  }
}

// A capability is a public claim. Every non-planned claim must resolve to at
// least one catalog record, and an implemented claim cannot cite only research,
// unsupported, experimental, or schema-only records.
for (const [feature, capability] of Object.entries(capabilities.features ?? {})) {
  if (!capability || typeof capability !== "object" || !statuses.has(capability.status)) {
    errors.push(`${feature}: capability must contain a valid status`);
    continue;
  }
  if (!Array.isArray(capability.source_ids)) {
    errors.push(`${feature}: source_ids must be an array`);
    continue;
  }
  if (capability.status !== "planned" && !capability.source_ids.length) {
    errors.push(`${feature}: non-planned capability has no source`);
  }
  const records = capability.source_ids.map((id) => catalog.records.find((record) => record.id === id));
  for (let index = 0; index < records.length; ++index) {
    if (!records[index]) errors.push(`${feature}: unknown source id ${capability.source_ids[index]}`);
  }
  if (capability.status === "implemented" && records.filter(Boolean).every((record) =>
    !["implemented", "verified-srsim", "verified-hardware"].includes(record.status))) {
    errors.push(`${feature}: implemented capability has no implemented source record`);
  }
}

// Profile dependencies use the same catalog namespace as feature claims. This
// prevents a timing or hardware value from carrying a plausible but dead source
// label that CI never resolves.
for (const id of [...(profile.source_ids ?? []), profile.link_defaults?.source_id].filter(Boolean)) {
  if (!ids.has(id)) errors.push(`profile ${profile.id}: unknown source id ${id}`);
}

// Every executable grammar row carries its normative source. This prevents a
// generated command from becoming visible merely because a handler exists.
for (const command of cliSchema.commands ?? []) {
  if (!ids.has(command.source_id))
    errors.push(`CLI command ${command.id}: unknown source id ${command.source_id}`);
}

// Source IDs in code comments are machine checked. A misspelling would make a
// reviewer search for a nonexistent catalog entry and therefore fails the same
// validation as a broken URL record.
const sourceFiles = ["core/include/router", "core/src", "apps/web/src"]
  .flatMap((directory) => readdirSync(resolve(root, directory), { recursive: true })
    .filter((entry) => /\.(?:hpp|cpp|ts|tsx)$/.test(entry))
    .map((entry) => resolve(root, directory, entry)));
for (const path of sourceFiles) {
  const contents = readFileSync(path, "utf8");
  for (const match of contents.matchAll(/Source:\s*([a-z0-9_]+(?:\.[a-z0-9_]+)*)/g)) {
    if (!ids.has(match[1])) errors.push(`${path}: unknown source comment ${match[1]}`);
  }
}

// Every production C++ translation unit must be reachable from the catalog.
// Header-only helpers are covered through the records of their consumers.
const referencedImplementation = new Set(catalog.records.flatMap((record) => record.implementation ?? []));
for (const name of readdirSync(resolve(root, "core/src")).filter((name) => name.endsWith(".cpp"))) {
  const path = `core/src/${name}`;
  if (!referencedImplementation.has(path)) errors.push(`${path}: production source has no catalog record`);
}

if (!catalog.schema_version || !catalog.records?.length) errors.push("Catalog is empty or has no schema version");
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
console.log(`source catalog valid: ${catalog.records.length} records`);
