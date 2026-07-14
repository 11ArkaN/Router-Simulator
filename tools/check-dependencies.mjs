// Repository dependency-cycle guard. It scans local C++ headers and relative
// TypeScript modules only. Package and standard-library imports are leaves, so
// an external dependency cannot create a false repository cycle.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, normalize, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const roots = [resolve(root, "core"), resolve(root, "apps"), resolve(root, "packages")];
const files = [];
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
  ["bounded_queue.hpp", 0], ["generated_profile.hpp", 0], ["link_direction.hpp", 0],
  ["packet.hpp", 0], ["packet_pool.hpp", 0], ["spsc_ring.hpp", 0], ["telemetry.hpp", 0],
  ["packet.cpp", 0],
  ["device.hpp", 1], ["device_routing.hpp", 1], ["hardware.hpp", 1], ["routing.hpp", 1],
  ["device_routing.cpp", 1], ["hardware.cpp", 1], ["routing.cpp", 1],
  ["network.hpp", 2], ["network.cpp", 2], ["network_adjacency.hpp", 2],
  ["network_adjacency.cpp", 2], ["network_endpoint.hpp", 2], ["network_endpoint.cpp", 2],
  ["network_link_fabric.hpp", 2], ["network_link_fabric.cpp", 2],
  ["capture_store.hpp", 3], ["checkpoint.hpp", 3], ["cli.hpp", 3],
  ["project_configuration.hpp", 3], ["cli_internal.hpp", 3],
  ["capture_store.cpp", 3], ["checkpoint.cpp", 3], ["cli.cpp", 3],
  ["cli_classic.cpp", 3], ["cli_md.cpp", 3], ["project_configuration.cpp", 3],
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
