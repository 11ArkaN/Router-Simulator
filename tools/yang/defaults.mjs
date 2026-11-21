// Build-time YANG default projection under RFC 7950 7.6.1, 7.7.2 and 7.8.2.
// Callers own inventory rows and the returned map; no datastore is mutated.
// Ancestor presence, choice, when and feature activation remain caller-owned.

// Requires a fully expanded inventory with resolved typedef defaults. Returns
// lexical values to preserve uint64 precision and enum/boolean type identity.
// Key leaves require explicit values and ignore defaults. Invalid direct
// default cardinality or mandatory/min-elements combinations throw before any
// projection escapes. This function performs no CLI removal-policy inference.
export function nodeDefaults(rows) {
  const keys = new Set();
  for (const row of rows) if (row.kind === "list") {
    const key = row.constraints.find((item) => item.keyword === "key")?.argument;
    for (const name of key?.trim().split(/\s+/).filter(Boolean) ?? [])
      keys.add(`${row.schema_id}/${name.split(":").at(-1)}`);
  }
  const result = new Map();
  for (const row of rows) {
    if (row.kind !== "leaf" && row.kind !== "leaf-list") continue;
    const argument = (keyword) => row.constraints.find((item) => item.keyword === keyword)?.argument;
    const direct = row.constraints.filter((item) => item.keyword === "default").map((item) => item.argument);
    const key = keys.has(row.schema_id);
    const mandatory = row.kind === "leaf" && argument("mandatory") === "true";
    const minimum = row.kind === "leaf-list" ? BigInt(argument("min-elements") ?? "0") : 0n;
    if (!key && ((row.kind === "leaf" && (direct.length > 1 || (mandatory && direct.length))) ||
        (minimum > 0n && direct.length))) throw new Error(`${row.schema_id}: invalid default constraint`);
    const required = key || mandatory || minimum > 0n;
    const inherited = row.resolved_type?.default;
    const values = required ? [] : direct.length ? direct : inherited !== undefined ? [inherited] : [];
    result.set(row.schema_id, { required, values, origin: values.length ? direct.length ? "node" : "type" : null });
  }
  return result;
}
