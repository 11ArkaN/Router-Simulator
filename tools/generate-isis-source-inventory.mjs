// Offline exact-release inventory generator. This process owns temporary ASTs
// and writes only project-authored hashes and schema metadata. Vendor bytes
// remain in the ignored Git cache. No production module depends on this tool.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { basename, resolve } from "node:path";
import { parse, stringify } from "yaml";
import { parseStatements } from "./yang/statements.mjs";
import { dependencyClosure, groupingInventory, statementInventory } from "./yang/inventory.mjs";
import { typeResolver } from "./yang/types.mjs";

const root = resolve(import.meta.dirname, "..");
const lockPath = resolve(root, "sources/yang/26.7.R1.lock.yaml");
const lock = parse(readFileSync(lockPath, "utf8"));
const cache = resolve(root, ".tools/nokia-yang-26.7");
if (process.argv.includes("--bootstrap") && !existsSync(resolve(cache, ".git"))) {
  mkdirSync(resolve(root, ".tools"), { recursive: true });
  execFileSync("git", ["clone", "--depth", "1", "--no-checkout", "--branch", lock.tag,
    lock.repository, cache], { stdio: "inherit" });
}
if (!existsSync(resolve(cache, ".git"))) throw new Error("Missing exact-release source cache. Run pnpm yang:bootstrap.");
const git = (...args) => execFileSync("git", ["-C", cache, ...args], { maxBuffer: 32 * 1024 * 1024 });
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const commit = git("rev-parse", `${lock.tag}^{commit}`).toString().trim();
if (commit !== lock.commit || git("rev-parse", lock.tag).toString().trim() !== lock.tag_object)
  throw new Error("YANG release tag does not match the pinned commit and tag object");

const entries = git("ls-tree", "-r", "-z", lock.commit, "--", "YANG").toString().split("\0")
  .filter(Boolean).map((entry) => {
    const [header, path] = entry.split("\t");
    return { path, blob: header.split(" ")[2] };
  }).filter(({ path }) => path.endsWith(".yang") && !path.includes("/nokia-combined/"));
const files = new Map(entries.map((entry) => [basename(entry.path, ".yang"), entry]));
if (files.size !== entries.length) throw new Error("Ambiguous module filenames in pinned YANG tree");
// Git's Windows checkout can convert LF to CRLF. Hashing the checkout would
// reject an unmodified source or require weakening byte identity. Batch-read
// the immutable blob objects instead, preserving their exact original bytes.
const batch = execFileSync("git", ["-C", cache, "cat-file", "--batch"], {
  input: entries.map((entry) => entry.blob).join("\n") + "\n", maxBuffer: 256 * 1024 * 1024 });
const blobs = new Map();
let cursor = 0;
for (const entry of entries) {
  const end = batch.indexOf(10, cursor);
  const [id, kind, length] = batch.subarray(cursor, end).toString().split(" ");
  const size = Number(length);
  if (end < cursor || id !== entry.blob || kind !== "blob" || !Number.isSafeInteger(size) || size < 0)
    throw new Error(`Invalid Git blob response for ${entry.path}`);
  cursor = end + 1;
  if (cursor + size >= batch.length || batch[cursor + size] !== 10)
    throw new Error(`Truncated Git blob response for ${entry.path}`);
  blobs.set(id, batch.subarray(cursor, cursor + size));
  cursor += size + 1;
}
if (cursor !== batch.length) throw new Error("Unexpected trailing Git blob response");
const modules = new Map();
const evidence = new Map();
const load = (name) => {
  if (modules.has(name)) return;
  const entry = files.get(name);
  if (!entry) throw new Error(`Missing source for dependency ${name}`);
  const bytes = blobs.get(entry.blob);
  const blob = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
  if (blob !== entry.blob) throw new Error(`Modified YANG source ${entry.path}`);
  const module = parseStatements(bytes.toString("utf8"), entry.path);
  if (module.argument !== name) throw new Error(`${entry.path}: declared module name mismatch`);
  modules.set(name, module);
  evidence.set(name, { path: entry.path,
    revision: module.children.find((child) => child.keyword === "revision")?.argument ?? null,
    bytes: bytes.length, sha256: digest(bytes) });
  for (const node of module.children)
    if (["import", "include", "belongs-to"].includes(node.keyword)) load(node.argument);
};
const roots = ["nokia-conf-router-isis", "nokia-state-router-isis", "nokia-oper-reset",
  "nokia-oper-perform", "nokia-oper-global", "nokia-debug-conf", "nokia-debug-state"];
roots.forEach(load);
const names = dependencyClosure(modules, roots);
for (const expected of lock.files) {
  const actual = evidence.get(basename(expected.path, ".yang"));
  if (!actual || actual.path !== expected.path || actual.sha256 !== expected.sha256 ||
      actual.bytes !== expected.bytes || actual.revision !== expected.revision)
    throw new Error(`Pinned source evidence changed: ${expected.path}`);
}
const expandedLock = { ...lock, scope: "isis_schema_and_management_dependency_closure",
  dependency_closure: "complete", roots,
  files: names.map((name) => evidence.get(name)).sort((a, b) => a.path.localeCompare(b.path, "en")) };
const resolveType = typeResolver(modules);
const inventory = { schema_version: 2, release: lock.release, source_commit: lock.commit,
  configuration: groupingInventory(modules.get("nokia-conf-router-isis"), "conf-router-isis", "/configure/router", resolveType),
  state: groupingInventory(modules.get("nokia-state-router-isis"), "state-router-isis", "/state/router", resolveType),
  management: ["nokia-oper-reset", "nokia-oper-perform", "nokia-oper-global", "nokia-debug-conf"]
    .flatMap((name) => statementInventory(modules.get(name), '', name, resolveType).filter((row) =>
      /\/(?:isis|is-is|sr-isis)(?:\/|$)/.test(row.data_path)).map((row) => ({ source_module: name, ...row }))) };
const output = resolve(root, "schemas/cli/isis-26.7.R1-inventory.json");
const products = [[lockPath, stringify(expandedLock, { lineWidth: 0 })],
  [output, JSON.stringify(inventory, null, 2) + "\n"]];
for (const [path, contents] of products) {
  if (process.argv.includes("--check")) {
    if (!existsSync(path) || readFileSync(path, "utf8").replaceAll("\r\n", "\n") !== contents)
      throw new Error(`Generated YANG source inventory drift: ${path}`);
  } else writeFileSync(path, contents);
}
console.log(`IS-IS source inventory: ${names.length} dependencies, ${inventory.configuration.length} configuration nodes, ${inventory.state.length} state nodes, ${inventory.management.length} management nodes`);
