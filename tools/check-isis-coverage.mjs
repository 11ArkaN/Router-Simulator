// The source audit reads immutable inventory, explicit scope and acceptance
// evidence. It owns no runtime state and never updates a classification.
import {readFileSync, existsSync} from "node:fs";
import {resolve} from "node:path";
import {parse} from "yaml";
import {validateIsisCoverage} from "./isis/coverage.mjs";
const root = resolve(import.meta.dirname, "..");
const args = process.argv.slice(2);
if (args.some((value) => value !== "--complete")) throw new Error("Unknown IS-IS coverage argument");
const inventory = JSON.parse(readFileSync(resolve(root, "schemas/cli/isis-26.7.R1-inventory.json"), "utf8"));
const matrix = parse(readFileSync(resolve(root, "schemas/cli/isis-26.7.R1-coverage.yaml"), "utf8"));
const capabilities = parse(readFileSync(resolve(root, "sources/capabilities.yaml"), "utf8"));
const result = validateIsisCoverage(inventory, matrix, {complete: args.includes("--complete"),
  testExists: (path) => existsSync(resolve(root, path)),
  capabilityImplemented: (name) => capabilities.features?.[name]?.status === "implemented"});
console.log(`IS-IS coverage: ${result.configuration} configuration, ${result.state} state, ${result.management} management; ${result.incomplete} acceptance items remain`);
