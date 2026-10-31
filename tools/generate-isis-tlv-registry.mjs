// Locked public registry facts own the immutable C++ membership projection.
// This command alone publishes that projection; core code never reads sources.

import { readFile, writeFile } from "node:fs/promises";
import { parse } from "yaml";
import { renderTlvRegistry } from "./isis/tlv-registry.mjs";

const lock = new URL("../sources/normative/isis-tlv-codepoints.lock.yaml", import.meta.url);
const output = new URL("../core/include/router/generated_isis_tlv_registry.hpp", import.meta.url);
const expected = renderTlvRegistry(parse(await readFile(lock, "utf8")));
if (process.argv.includes("--check")) {
  if (await readFile(output, "utf8") !== expected) throw new Error("IS-IS TLV registry projection drifted");
} else await writeFile(output, expected);
