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
console.log(`dependency graph valid: ${graph.size} modules`);
