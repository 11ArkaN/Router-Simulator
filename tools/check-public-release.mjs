/**
 * Public redistribution gate.
 *
 * The source tree may cite vendor names and documentation because compatibility
 * work needs precise identifiers. Binary vendor payloads and brand artwork have
 * different redistribution risks, so this gate reviews paths and file classes
 * instead of banning legitimate plain-text references.
 */

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];

/** Read a repository file as UTF-8 so policy checks do not depend on the shell locale. */
function read(relativePath) {
  return readFileSync(resolve(root, relativePath), "utf8");
}

/** Record all violations and report them together to keep CI feedback actionable. */
function requireCondition(condition, message) {
  if (!condition) errors.push(message);
}

const requiredFiles = [
  "README.md",
  "LICENSE",
  "NOTICE",
  "TRADEMARKS.md",
  "THIRD_PARTY_NOTICES.md",
  "CONTRIBUTING.md",
  "assets/ui/README.md",
  "policies/redistribution-allowlist.json",
];
const requiredContent = new Map();

for (const path of requiredFiles) {
  try {
    requiredContent.set(path, read(path));
  } catch {
    errors.push(`Missing public-release file: ${path}`);
  }
}

// Normalize line endings before hashing because Git may check out CRLF on
// Windows. The digest is the official Apache-2.0 text fetched from apache.org,
// excluding only trailing line breaks.
if (requiredContent.has("LICENSE")) {
  const licenseDigest = createHash("sha256")
    .update(requiredContent.get("LICENSE").replaceAll("\r\n", "\n").replace(/\n+$/, ""))
    .digest("hex");
  requireCondition(
    licenseDigest === "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd",
    "LICENSE must remain the unmodified official Apache-2.0 text",
  );
}

// Machine-readable license fields prevent package registries and scanners from
// treating private workspace packages as having an unknown license.
for (const path of [
  "package.json",
  "apps/web/package.json",
  "packages/contracts/package.json",
]) {
  const manifest = JSON.parse(read(path));
  requireCondition(
    manifest.license === "Apache-2.0",
    `${path} must declare license Apache-2.0`,
  );
}

if (requiredContent.has("README.md")) {
  const readme = requiredContent.get("README.md");
  requireCondition(
    readme.includes("independent, unofficial educational project"),
    "README.md must retain the independent-project disclaimer",
  );
  requireCondition(
    readme.includes("not affiliated with, sponsored by, endorsed by or produced by Nokia"),
    "README.md must retain the Nokia non-affiliation statement",
  );
}

// Include non-ignored untracked files so the gate catches a prohibited payload
// before it is staged, not only after it becomes part of a commit.
const git = spawnSync(
  "git",
  ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
  {
    cwd: root,
    encoding: "utf8",
  },
);
const gitError = git.stderr?.trim() || git.error?.message || "unknown process error";
requireCondition(git.status === 0, `git ls-files failed: ${gitError}`);

const repositoryFiles = git.status === 0 ? git.stdout.split("\0").filter(Boolean) : [];
const allowlist = new Set(
  requiredContent.has("policies/redistribution-allowlist.json")
    ? JSON.parse(requiredContent.get("policies/redistribution-allowlist.json")).files
    : [],
);

// These extensions commonly carry redistributable copies of vendor software or
// documentation. An exact path allowlist forces a deliberate license review
// without blocking ordinary compatibility metadata and source citations.
const reviewedExtensions = new Set([
  ".bin",
  ".img",
  ".iso",
  ".ova",
  ".ovf",
  ".pdf",
  ".qcow2",
  ".vmdk",
  ".yang",
]);
const vendorLogoPattern = /(?:nokia[-_. ]*(?:logo|brand|wordmark)|(?:logo|brand|wordmark)[-_. ]*nokia)/i;

for (const path of repositoryFiles) {
  const normalized = path.replaceAll("\\", "/");
  const dot = normalized.lastIndexOf(".");
  const extension = dot >= 0 ? normalized.slice(dot).toLowerCase() : "";

  requireCondition(
    !vendorLogoPattern.test(normalized),
    `Vendor brand asset filename is prohibited: ${normalized}`,
  );

  requireCondition(
    !reviewedExtensions.has(extension) || allowlist.has(normalized),
    `Redistribution-sensitive file requires allowlist review: ${normalized}`,
  );
}

for (const allowed of allowlist) {
  requireCondition(
    repositoryFiles.includes(allowed),
    `Redistribution allowlist entry does not name a repository file: ${allowed}`,
  );
}

if (errors.length > 0) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exit(1);
}

console.log(`Public-release policy passed for ${repositoryFiles.length} repository files.`);
