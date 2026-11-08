// Release coverage joins every pinned schema identity to an explicit scope and
// acceptance state. The caller owns records and evidence; this module has no I/O.
const pin = "6656cbb0905c7b952afaa1d7c2b63aa4da6cc5f7";
const domains = ["configuration", "state", "management"];
const scopes = new Set(["base", "excluded", "review"]);
const statuses = new Set(["pending", "intent-only", "implemented", "verified-exclusion"]);
const fail = (message) => { throw new Error(`IS-IS coverage: ${message}`); };
export function validateIsisCoverage(inventory, matrix, {complete = false, testExists, capabilityImplemented} = {}) {
  if (inventory?.schema_version !== 2 || matrix?.schema_version !== 1 ||
      inventory.source_commit !== pin || matrix.source_commit !== pin ||
      inventory.release !== "26.7.R1" || matrix.release !== inventory.release || !Array.isArray(matrix.nodes))
    fail("unrecognized source pin");
  const expected = new Map();
  for (const domain of domains) {
    if (!Array.isArray(inventory[domain])) fail(`missing inventory domain ${domain}`);
    for (const node of inventory[domain]) {
      const key = `${domain}:${node.schema_id}`;
      if (typeof node.schema_id !== "string" || expected.has(key)) fail(`invalid inventory identity ${key}`);
      expected.set(key, node);
    }
  }
  const seen = new Set();
  const totals = {configuration: 0, state: 0, management: 0, base: 0, excluded: 0, review: 0, incomplete: 0};
  for (const row of matrix.nodes) {
    const key = `${row?.domain}:${row?.schema_id}`;
    if (!expected.has(key) || seen.has(key)) fail(`unknown or duplicate identity ${key}`);
    seen.add(key);
    if (!scopes.has(row.scope) || !statuses.has(row.status)) fail(`invalid classification ${key}`);
    if (row.scope !== "base" && (typeof row.dependency !== "string" || !row.dependency.trim()))
      fail(`missing dependency or review question ${key}`);
    if (row.status !== "pending" && (!Array.isArray(row.tests) || !row.tests.length ||
        row.tests.some((path) => typeof path !== "string" || !path.endsWith(".cpp") && !path.endsWith(".mjs") && !path.endsWith(".ts") && !path.endsWith(".tsx"))))
      fail(`missing test evidence ${key}`);
    if (row.status === "implemented" && (row.scope !== "base" || typeof row.capability !== "string" || !row.capability))
      fail(`implementation lacks a Base capability ${key}`);
    if (row.status === "verified-exclusion" && row.scope !== "excluded") fail(`exclusion has a different scope ${key}`);
    if (row.status === "intent-only" && (row.domain !== "configuration" || row.scope !== "base"))
      fail(`intent status outside Base configuration ${key}`);
    if (testExists && (row.tests ?? []).some((path) => !testExists(path))) fail(`test file does not exist ${key}`);
    if (row.status === "implemented" && capabilityImplemented && !capabilityImplemented(row.capability))
      fail(`capability is not implemented ${key}`);
    const accepted = row.status === "implemented" || row.status === "verified-exclusion";
    if (!accepted) ++totals.incomplete;
    if (complete && !accepted) fail(`unfinished acceptance ${key}`);
    ++totals[row.domain]; ++totals[row.scope];
  }
  for (const key of expected.keys()) if (!seen.has(key)) fail(`missing identity ${key}`);
  return totals;
}
