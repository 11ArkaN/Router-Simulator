// Contextual info coverage validator. The release command schema is the source
// of every reachable configuration family. The renderer catalog must assign
// each family independently to MD-CLI and classic CLI before tests or a
// production build may continue.

import fs from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import YAML from "yaml";

const root = resolve(import.meta.dirname, "..");
const schemaPath = resolve(root, "schemas/cli/26.7.R1.yaml");
const coveragePath = resolve(root, "schemas/cli/info-renderers.yaml");
const runtimePath = resolve(root, "core/src/runtime/lab_runtime.cpp");

const schema = YAML.parse(fs.readFileSync(schemaPath, "utf8"));
const coverage = YAML.parse(fs.readFileSync(coveragePath, "utf8"));
const runtime = fs.readFileSync(runtimePath, "utf8");
const errors = [];

if (coverage.release !== schema.release) {
  errors.push(
    `info renderer release ${coverage.release} does not match CLI schema ${schema.release}`,
  );
}

const owners = new Map();
for (const renderer of coverage.renderers ?? []) {
  if (!renderer?.id || !renderer.runtime_function ||
      !Array.isArray(renderer.engines) ||
      !Array.isArray(renderer.source_ids)) {
    errors.push(
      "every info renderer requires id, runtime_function, engines and source_ids",
    );
    continue;
  }
  const escapedFunction = renderer.runtime_function.replace(
    /[.*+?^${}()|[\]\\]/gu,
    "\\$&",
  );
  const runtimeReferences =
    runtime.match(new RegExp(`\\b${escapedFunction}\\s*\\(`, "gu"))?.length ??
    0;
  // One occurrence is the implementation. Each declared engine must also
  // dispatch through that implementation. This prevents a source family from
  // passing the catalog gate merely because its name was assigned to a
  // renderer record, which previously hid the system-keychain gap.
  const requiredReferences = 1 + new Set(renderer.engines).size;
  if (runtimeReferences < requiredReferences) {
    errors.push(
      `${renderer.id}: ${renderer.runtime_function} has ${runtimeReferences} runtime references, expected at least ${requiredReferences}`,
    );
  }
  for (const engine of renderer.engines) {
    if (engine !== "md" && engine !== "classic") {
      errors.push(`${renderer.id}: unsupported engine ${engine}`);
      continue;
    }
    for (const sourceId of renderer.source_ids) {
      const key = `${engine}:${sourceId}`;
      if (owners.has(key)) {
        errors.push(
          `${key}: assigned to both ${owners.get(key)} and ${renderer.id}`,
        );
      } else {
        owners.set(key, renderer.id);
      }
    }
  }
}

const required = new Set();
for (const command of schema.commands ?? []) {
  const first = command.tokens?.[0];
  if (first !== "configure" && first !== "bof") continue;
  // Workflow commands enter an editor but do not represent configuration
  // datastore nodes. Their source therefore has no contextual output owner.
  if (command.source_id === "nokia.sros.26_7.md_cli.configuration_workflow") {
    continue;
  }
  for (const engine of command.engines ?? []) {
    if (engine === "md" || engine === "classic") {
      required.add(`${engine}:${command.source_id}`);
    }
  }
}

for (const key of [...required].sort()) {
  if (!owners.has(key)) errors.push(`${key}: no contextual info renderer`);
}
for (const [key, owner] of owners) {
  if (!required.has(key)) {
    errors.push(`${key}: renderer ${owner} does not own any schema command`);
  }
}

// These fragments were the two silent-success defects that motivated this
// gate. Keeping the check structural makes an accidental reintroduction fail
// before the slower native and Wasm builds begin.
if (/rendered\s*=\s*std::string\{\s*\}/u.test(runtime)) {
  errors.push("classic info dispatcher contains an empty-render fallback");
}
if (/valid configured context with no present children returns an empty body/u
    .test(runtime)) {
  errors.push("MD info dispatcher contains an empty-render fallback");
}

if (errors.length) {
  console.error(errors.map((error) => `info coverage: ${error}`).join("\n"));
  process.exit(1);
}

console.log(
  `Validated ${required.size} engine-specific contextual info ownership records.`,
);
