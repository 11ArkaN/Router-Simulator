// Source-only YANG inventory projection. Callers own module ASTs and returned
// rows. This module preserves choice/case identity and direct constraints; it
// never treats edit operators, scalar values or schema choices as CLI contexts.

const dataKinds = new Set(["container", "list", "leaf", "leaf-list", "choice", "case",
  "action", "rpc", "notification", "anyxml", "anydata", "input", "output"]);
const structuralKinds = new Set(["container", "list", "action", "rpc", "notification", "input", "output"]);
const constraints = new Set(["type", "range", "length", "pattern", "modifier", "enum", "value",
  "bit", "position", "fraction-digits", "require-instance", "base", "path", "default", "key",
  "unique", "min-elements", "max-elements", "ordered-by", "mandatory", "config", "status",
  "when", "must", "if-feature", "units"]);

const constraint = (node) => ({ keyword: node.keyword, argument: node.argument,
  children: node.children.filter((child) => constraints.has(child.keyword)).map(constraint) });

// Preconditions: modules is a Map of parsed modules keyed by declared name.
// Returns sorted dependency names after validating imports, includes and parent
// modules, including revision-date and module/submodule kind. A missing source
// throws before any closed dependency set is returned. No filesystem access.
export function dependencyClosure(modules, roots) {
  const visited = new Set();
  const visit = (name, relation) => {
    const module = modules.get(name);
    if (!module) throw new Error(`Missing YANG dependency ${name}`);
    if (relation) {
      const expected = relation.keyword === "include" ? "submodule" : "module";
      if (module.keyword !== expected) throw new Error(`${name}: expected ${expected}`);
      const revision = relation.children.find((child) => child.keyword === "revision-date")?.argument;
      if (revision && !module.children.some((child) => child.keyword === "revision" && child.argument === revision))
        throw new Error(`${name}: missing required revision ${revision}`);
    }
    if (visited.has(name)) return;
    visited.add(name);
    for (const child of module.children)
      if (["import", "include", "belongs-to"].includes(child.keyword)) visit(child.argument, child);
  };
  roots.forEach((name) => visit(name));
  return [...visited].sort();
}

// Preconditions: grouping is an existing direct grouping in module. Returns
// every declared data/choice/case row with stable schema identity and its data
// path. Uses/augment/refine are rejected rather than silently dropping nodes.
// Returned metadata is source evidence, not an executable CLI capability.
export function groupingInventory(module, grouping, basePath, resolveType) {
  const owner = module.children.find((node) => node.keyword === "grouping" && node.argument === grouping);
  if (!owner) throw new Error(`${module.argument}: missing grouping ${grouping}`);
  return statementInventory(owner, basePath, module.argument, resolveType);
}

// Returns the same source projection for direct module data or a selected
// statement subtree. Schema expansion remains a separate required phase.
export function statementInventory(owner, basePath = "", sourceName = owner.argument, resolveType) {
  const rows = [];
  const seen = new Set();
  const walk = (parent, schemaPath, dataPath, alternatives) => {
    for (const node of parent.children) {
      if (["uses", "augment", "refine"].includes(node.keyword))
        throw new Error(`${sourceName}:${node.line}: unexpanded ${node.keyword}`);
      if (!dataKinds.has(node.keyword)) continue;
      const isAlternative = ["choice", "case"].includes(node.keyword);
      const id = `${schemaPath}/${isAlternative ? `${node.keyword}:` : ""}${node.argument ?? node.keyword}`;
      if (seen.has(id)) throw new Error(`${sourceName}: duplicate schema identity ${id}`);
      seen.add(id);
      const path = isAlternative ? dataPath : `${dataPath}/${node.argument ?? node.keyword}`;
      const branches = isAlternative ? [...alternatives, { kind: node.keyword, name: node.argument }] : alternatives;
      const type = node.children.find((child) => child.keyword === 'type');
      rows.push({ schema_id: id, data_path: path, kind: node.keyword, name: node.argument,
        source_line: node.line, alternatives: branches, structural_context: structuralKinds.has(node.keyword),
        presence: node.children.some((child) => child.keyword === "presence"),
        ...(type && resolveType ? { resolved_type: resolveType(type) } : {}),
        constraints: node.children.filter((child) => constraints.has(child.keyword)).map(constraint),
        extensions: node.children.filter((child) => child.keyword.includes(":"))
          .map((child) => ({ keyword: child.keyword, argument: child.argument })) });
      walk(node, id, path, branches);
    }
  };
  walk(owner, basePath, basePath, []);
  return rows;
}
