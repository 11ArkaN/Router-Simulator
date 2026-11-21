// This offline publisher owns the immutable IS-IS configuration projection.
// Runtime code reads only generated constants, never YANG or source documents.

import { readFile, writeFile } from "node:fs/promises";
import { renderConfigurationProfile } from "./isis/configuration-profile.mjs";

const source = new URL("../schemas/cli/isis-26.7.R1-inventory.json", import.meta.url);
const inventory = JSON.parse(await readFile(source, "utf8"));
for (const [path, format] of [
  ["../core/include/router/generated_isis_configuration_profile.hpp", "cpp"],
  ["../packages/contracts/src/generated-isis-configuration-profile.ts", "typescript"]
]) {
  const output = new URL(path, import.meta.url);
  const expected = renderConfigurationProfile(inventory, format);
  if (process.argv.includes("--check")) {
    if (await readFile(output, "utf8") !== expected) throw new Error(`IS-IS configuration projection drifted: ${path}`);
  } else await writeFile(output, expected);
}
