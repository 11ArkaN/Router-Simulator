// Repository dependency-cycle guard. It scans local C++ headers and relative
// TypeScript modules only. Package and standard-library imports are leaves, so
// an external dependency cannot create a false repository cycle.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, normalize, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const roots = [resolve(root, "core"), resolve(root, "apps"), resolve(root, "packages")];
const files = [];

// Architecture checks inspect executable literals, not explanatory prose.
// Full-line and block comments are removed centrally so every literal guard
// can coexist with the repository's required design and invariant comments.
const withoutComments = (source) => source
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/^\s*\/\/.*$/gm, "");
const walk = (directory) => {
  for (const name of readdirSync(directory)) {
    const path = resolve(directory, name);
    if (statSync(path).isDirectory()) {
      if (!name.startsWith(".") && name !== "node_modules" && name !== "public") walk(path);
    } else if ([".hpp", ".cpp", ".ts", ".tsx"].includes(extname(path))) files.push(path);
  }
};
roots.forEach(walk);

const nodes = new Set(files.map(normalize));
const graph = new Map();
for (const file of files) {
  const source = readFileSync(file, "utf8");
  const dependencies = [];
  for (const match of source.matchAll(/^#include\s+"router\/(.+)"/gm)) {
    dependencies.push(resolve(root, "core/include/router", match[1]));
  }
  for (const match of source.matchAll(/(?:from\s+|import\s*)["'](\.[^"']+)["']/g)) {
    const base = resolve(dirname(file), match[1]);
    const candidate = [base, `${base}.ts`, `${base}.tsx`, resolve(base, "index.ts")].find((item) => nodes.has(normalize(item)));
    if (candidate) dependencies.push(candidate);
  }
  graph.set(normalize(file), dependencies.map(normalize).filter((item) => nodes.has(item)));
}

// C++ layer numbers increase toward orchestration. A source may include its own
// or a lower layer only. CMake target links enforce symbol dependencies, while
// this check also catches header-only inversions that a linker cannot observe.
const cppLayers = new Map([
  ["bounded_queue.hpp", 0], ["generated_profile.hpp", 0], ["generated_cli_schema.hpp", 0],
  ["generated_runtime_protocol.hpp", 0], ["link_direction.hpp", 0],
  ["packet.hpp", 0], ["packet_pool.hpp", 0], ["spsc_ring.hpp", 0], ["telemetry.hpp", 0],
  ["packet.cpp", 0],
  ["device.hpp", 1], ["device_routing.hpp", 1], ["hardware.hpp", 1], ["routing.hpp", 1],
  ["device_routing.cpp", 1], ["hardware.cpp", 1], ["routing.cpp", 1],
  ["network.hpp", 2], ["network.cpp", 2], ["network_adjacency.hpp", 2],
  ["network_adjacency.cpp", 2], ["network_endpoint.hpp", 2], ["network_endpoint.cpp", 2],
  ["network_link_fabric.hpp", 2], ["network_link_fabric.cpp", 2],
  ["capture_store.hpp", 3], ["checkpoint.hpp", 3], ["cli.hpp", 3],
  ["project_configuration.hpp", 3], ["cli_internal.hpp", 3], ["cli_parser.hpp", 3],
  ["capture_store.cpp", 3], ["checkpoint.cpp", 3], ["cli.cpp", 3],
  ["cli_classic.cpp", 3], ["cli_md.cpp", 3], ["cli_parser.cpp", 3], ["project_configuration.cpp", 3],
  ["runtime_messages.hpp", 4], ["runtime.hpp", 4], ["runtime.cpp", 4],
  ["runtime_checkpoint.cpp", 4], ["runtime_project.cpp", 4], ["runtime_projection.cpp", 4],
  ["wasm_api.cpp", 5]
]);
const cppLayer = (file) => {
  const relativePath = relative(root, file).replaceAll("\\", "/");
  if (relativePath.startsWith("core/tests/") || relativePath.startsWith("core/tools/")) return 99;
  return cppLayers.get(relativePath.split("/").at(-1));
};
for (const [source, dependencies] of graph) {
  const sourceLayer = cppLayer(source);
  if (sourceLayer === undefined) continue;
  for (const dependency of dependencies) {
    const dependencyLayer = cppLayer(dependency);
    if (dependencyLayer !== undefined && sourceLayer < dependencyLayer) {
      throw new Error(
        `Dependency layer violation: ${relative(root, source)} (${sourceLayer}) -> ` +
        `${relative(root, dependency)} (${dependencyLayer})`
      );
    }
  }
}

// Command syntax belongs only to the generated release schema. A whole-line
// literal in a handler would silently recreate a second command catalog and
// make completion, source status and execution drift independently again.
for (const name of ["cli.cpp", "cli_md.cpp", "cli_classic.cpp"]) {
  const source = readFileSync(resolve(root, "core/src/cli", name), "utf8");
  // Documentation is intentionally dense in the CLI implementation and may
  // quote a user-visible example while explaining a parser invariant. Remove
  // comments before checking string literals so the guard detects executable
  // shadow grammars without pressuring maintainers to delete useful rationale.
  const executable = withoutComments(source);
  // Schema command tokens are lowercase. Case-sensitive matching avoids
  // confusing prose such as "Delete current character" in help output with a
  // submitted `delete ...` command line.
  if (/"(?:show|configure|delete|ping)\s+[a-z0-9]/.test(executable))
    throw new Error(`${name}: whole CLI command literal must be defined in schemas/cli`);
}

// The browser controls projects through structured runtime operations. It must
// not become a second CLI client with release-specific command text hidden in
// React callbacks, project restoration or demo initialization.
for (const file of files) {
  const path = relative(root, file).replaceAll("\\", "/");
  if (!path.startsWith("apps/web/src/") || /\.test\.[^.]+$/.test(path)) continue;
  const source = withoutComments(readFileSync(file, "utf8"));
  if (/["'`](?:show|configure|delete|ping)\s+[a-z0-9]/i.test(source))
    throw new Error(`${path}: frontend must use structured runtime operations, not CLI command lines`);
}

// Profile identities may occur only in generated projections, schemas, profile
// inputs and focused tests. Production modules must use the generated symbols
// so a profile change cannot leave a hidden second hardware catalog behind.
const profileLiteral = /(?:iom4-e|me10-10gb-sfp\+|me1-100gb-cfp2|host-a|host-b|1\/1\/[0-9]+|7750-sr-7-iom4-e)/i;
for (const file of files) {
  const path = relative(root, file).replaceAll("\\", "/");
  if (/generated[_-]/.test(path) || path.includes("/tests/") ||
      path.includes("/tools/") || path.includes(".test.")) continue;
  const source = withoutComments(readFileSync(file, "utf8"));
  if (profileLiteral.test(source))
    throw new Error(`${path}: profile identity must come from generated data`);
}

// Raw management commands are encoded only by RuntimeClient or the C++
// dispatcher. React components operate on typed methods and cannot assemble a
// private protocol dialect.
for (const file of files) {
  const path = relative(root, file).replaceAll("\\", "/");
  if (!path.startsWith("apps/web/src/ui/") || path.includes(".test.")) continue;
  const source = readFileSync(file, "utf8");
  if (/\.command\s*\(/.test(source) ||
      /["'`](?:hardware|project|terminal|host|capture|link):/.test(source))
    throw new Error(`${path}: UI must use typed RuntimeClient operations`);
}

// Shared-memory field offsets are produced by C++ offsetof. Numeric DataView
// offsets outside tests would silently reinterpret a newer telemetry layout.
for (const file of files) {
  const path = relative(root, file).replaceAll("\\", "/");
  if (!path.startsWith("apps/web/src/") || path.includes(".test.")) continue;
  const source = readFileSync(file, "utf8");
  if (/get(?:Uint32|BigUint64)\(\s*\d+/.test(source) ||
      /new BigUint64Array\([^\n]+\+\s*\d+/.test(source)) {
    throw new Error(`${path}: telemetry offsets must come from the compiled layout ABI`);
  }
}

// Runtime diagnostics belong in developer logs. These exact labels previously
// exposed implementation state as unexplained product UI and are prohibited
// from returning as visible JSX strings.
const forbiddenUiLabels = ["Workers", "Shared memory", "LIVE CAPTURE", "type // to switch engine"];
for (const file of files.filter((item) => relative(root, item).replaceAll("\\", "/").startsWith("apps/web/src/ui/"))) {
  const source = readFileSync(file, "utf8");
  for (const label of forbiddenUiLabels) {
    if (source.includes(`>${label}<`) || source.includes(`\"${label}\"`))
      throw new Error(`${relative(root, file)}: forbidden runtime diagnostic label ${label}`);
  }
}

const active = new Set();
const complete = new Set();
const visit = (node, stack) => {
  if (active.has(node)) throw new Error(`Dependency cycle: ${[...stack, node].map((item) => relative(root, item)).join(" -> ")}`);
  if (complete.has(node)) return;
  active.add(node);
  for (const dependency of graph.get(node) ?? []) visit(dependency, [...stack, node]);
  active.delete(node);
  complete.add(node);
};
for (const node of graph.keys()) visit(node, []);
console.log(`dependency graph and C++ layers valid: ${graph.size} modules`);
