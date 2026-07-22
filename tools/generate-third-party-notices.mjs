/**
 * Production dependency notice generator.
 *
 * Vite bundles third-party JavaScript into application assets. Package manager
 * directories are not deployed, so their license files must be copied into one
 * static notice document that travels with every production build.
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const checkOnly = process.argv.includes("--check");
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const licenseArguments = ["licenses", "list", "--prod", "--json"];
const lifecycleEntrypoint = process.env.npm_execpath;
// A pnpm lifecycle exposes the exact JavaScript entrypoint that launched this
// build. Executing it with the current Node binary avoids PATH and shell-shim
// differences on hosted builders while guaranteeing the lockfile-selected
// package-manager version performs the license inspection.
const command = lifecycleEntrypoint ? process.execPath : pnpm;
const commandArguments = lifecycleEntrypoint
  ? [lifecycleEntrypoint, ...licenseArguments]
  : licenseArguments;
const result = spawnSync(command, commandArguments, {
  cwd: root,
  encoding: "utf8",
  // Direct development invocations do not have lifecycle metadata. Only that
  // fallback needs a shell on Windows to resolve pnpm.cmd; Unix pnpm binaries
  // remain directly executable. Lifecycle builds never invoke a shell.
  shell: !lifecycleEntrypoint && process.platform === "win32",
  // License reports contain package paths and may grow with the production
  // graph. An explicit bound avoids Node-version-dependent spawnSync defaults;
  // the parsed records remain independently bounded by the installed graph.
  maxBuffer: 16 * 1024 * 1024,
});

if (result.status !== 0) {
  // A terminating signal can leave both stderr and result.error empty. Include
  // status and signal so a hosted build never hides the actionable failure.
  const detail = result.stderr?.trim() || result.stdout?.trim() ||
    result.error?.message ||
    `status=${String(result.status)} signal=${String(result.signal)}`;
  throw new Error(`Unable to inspect production licenses: ${detail}`);
}

const report = JSON.parse(result.stdout);
const dependencies = [];

// pnpm groups packages by license expression. A package can be installed in
// multiple versions, so paths and versions are expanded into individual notice
// records before sorting. This keeps the generated file stable across machines.
for (const [license, packages] of Object.entries(report)) {
  for (const packageRecord of packages) {
    for (let index = 0; index < packageRecord.paths.length; index += 1) {
      const packagePath = packageRecord.paths[index];
      const names = readdirSync(packagePath);
      const licenseName = names.find((name) =>
        /^(?:licen[cs]e|copying|unlicense)(?:$|[._-])/i.test(name),
      );

      if (!licenseName) {
        throw new Error(`No license text found for ${packageRecord.name} at ${packagePath}`);
      }

      dependencies.push({
        name: packageRecord.name,
        version: packageRecord.versions[index] ?? packageRecord.versions[0] ?? "unknown",
        license,
        homepage: packageRecord.homepage ?? "",
        text: readFileSync(resolve(packagePath, licenseName), "utf8").trim(),
      });
    }
  }
}

dependencies.sort((left, right) =>
  `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`),
);

const divider = "=".repeat(78);
const sections = dependencies.map((dependency) => {
  const homepage = dependency.homepage ? `\nHomepage: ${dependency.homepage}` : "";
  return [
    divider,
    `${dependency.name}@${dependency.version}`,
    `License: ${dependency.license}${homepage}`,
    divider,
    dependency.text,
  ].join("\n");
});

const output = [
  "Router Simulator third-party notices",
  "",
  "This file contains notices and license terms supplied with production dependencies.",
  "",
  ...sections,
  "",
].join("\n");

const publicDirectory = resolve(root, "apps/web/public");
const artifacts = new Map([
  ["THIRD_PARTY_NOTICES.txt", output],
  // A static deployment distributes the project's compiled object form. Keep
  // the project license, required NOTICE attribution and trademark disclaimer
  // beside the bundle instead of relying on access to the source repository.
  ["LICENSE.txt", readFileSync(resolve(root, "LICENSE"), "utf8")],
  ["NOTICE.txt", readFileSync(resolve(root, "NOTICE"), "utf8")],
  ["TRADEMARKS.txt", readFileSync(resolve(root, "TRADEMARKS.md"), "utf8")],
]);

for (const [destination, expected] of artifacts) {
  const destinationPath = resolve(publicDirectory, destination);
  if (checkOnly) {
    // Hosted builders are allowed to consume only the committed result. pnpm's
    // license command depends on installation-store index files that Vercel may
    // legally omit from its cache even though every package required by Vite is
    // present. Local verification still recomputes the complete dependency
    // closure and rejects a stale notice before a commit can be accepted.
    if (!existsSync(destinationPath) || readFileSync(destinationPath, "utf8") !== expected) {
      throw new Error(`${destination} is stale; run pnpm notices:generate`);
    }
    continue;
  }
  writeFileSync(destinationPath, expected, "utf8");
}

const operation = checkOnly ? "Verified" : "Generated";
console.log(`${operation} notices for ${dependencies.length} production dependency installations.`);
