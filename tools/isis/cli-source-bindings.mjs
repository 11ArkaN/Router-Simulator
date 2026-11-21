// Release bindings join YANG nodes, exact engine references and executable
// grammar rows. The caller owns all inputs; validation cannot publish files.
const root = "/configure/router/isis";
const commit = "6656cbb0905c7b952afaa1d7c2b63aa4da6cc5f7";
const literal = (token) => typeof token === "string" ? token : token?.literal;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const fail = (message) => { throw new Error(`IS-IS CLI binding: ${message}`); };
const reference = (value) => typeof value === "string" &&
  /^https:\/\/documentation\.nokia\.com\/sr\/26-7\/[^#]+#[^#]+$/.test(value);

export function validateIsisCliBindings(commands, inventory, bindings, parameters = {}) {
  if (inventory?.source_commit !== commit || inventory.release !== "26.7.R1" ||
      bindings?.schema_version !== 1 || bindings.source_commit !== commit || bindings.release !== inventory.release)
    fail("unrecognized source pin");
  const nodes = new Map();
  for (const node of inventory.configuration) {
    const values = nodes.get(node.data_path) ?? [];
    values.push(node);
    nodes.set(node.data_path, values);
  }
  const selected = new Map();
  for (const binding of bindings.bindings) {
    const candidates = nodes.get(binding.yang_path);
    if (!binding.yang_path.startsWith(root) || candidates?.length !== 1 || selected.has(binding.yang_path) ||
        !reference(binding.md_source) || !reference(binding.classic_source) ||
        typeof binding.md_remove !== "boolean" || typeof binding.classic_no !== "boolean")
      fail(`invalid or ambiguous node ${binding.yang_path}`);
    const node = candidates[0];
    const parent = nodes.get(binding.yang_path.slice(0, binding.yang_path.lastIndexOf("/")))?.[0];
    const key = parent?.constraints?.find((item) => item.keyword === "key")?.argument?.split(/\s+/);
    if (key?.includes(node.name)) fail(`${binding.yang_path} is a key, not an independent command`);
    selected.set(binding.yang_path, {binding, node, rows: []});
  }
  for (const [path, {binding, node}] of selected) {
    if (binding.classic_parameters !== undefined) {
      if (node.kind !== "container" || !binding.classic_parameters || Array.isArray(binding.classic_parameters) ||
          typeof binding.classic_parameters !== "object" || !Object.keys(binding.classic_parameters).length)
        fail(`${path} has an invalid composite parameter map`);
      for (const [parameter, child] of Object.entries(binding.classic_parameters)) {
        const leaf = selected.get(child);
        if (!child.startsWith(path + "/") || child.slice(path.length + 1).includes("/") ||
            leaf?.node.kind !== "leaf" || leaf.binding.classic_via_parent !== path ||
            parameters[parameter]?.yang_path !== child)
          fail(`${path} composite parameter ${parameter} lacks its exact child binding`);
      }
    }
    if (binding.classic_via_parent !== undefined) {
      const parent = selected.get(binding.classic_via_parent);
      if (node.kind !== "leaf" || binding.classic_no || !parent?.binding.classic_no ||
          parent.binding.classic_source !== binding.classic_source ||
          !Object.values(parent.binding.classic_parameters ?? {}).includes(path))
        fail(`${path} has no source-bound composite parent removal`);
    }
  }
  const keys = {"isis-instance": "isis_instance", "interface-name": "interface_name", "level-number": "isis_level"};
  const mdPath = (path) => {
    const tokens = ["router", '"Base"', "isis", {parameter: "isis_instance"}];
    let current = root;
    for (const name of path.slice(root.length + 1).split("/").filter(Boolean)) {
      tokens.push(name);
      current += "/" + name;
      const node = nodes.get(current)?.[0];
      if (!node) fail(`missing ancestor ${current}`);
      if (node.kind !== "list") continue;
      const key = node.constraints.find((item) => item.keyword === "key")?.argument;
      if (!keys[key]) fail(`unmapped list key ${current}`);
      tokens.push({parameter: keys[key]});
    }
    return tokens;
  };
  for (const row of commands) {
    const words = row.tokens.map(literal);
    if (!["configure", "delete"].includes(words[0]) || words[1] !== "router" ||
        !words.slice(2, 5).includes("isis")) continue;
    const match = selected.get(row.yang_path);
    if (!match || row.engines.length !== 1 || !reference(row.source_ref)) fail(`${row.id} has no exact node binding`);
    const engine = row.engines[0];
    const typeShape = (node) => ({
      builtin: node.resolved_type?.builtin,
      restrictions: (node.resolved_type?.layers ?? []).flatMap((layer) => layer.restrictions ?? [])
        .filter((item) => ["range", "length", "pattern", "enum"].includes(item.keyword))
        .map((item) => ({keyword: item.keyword, argument: item.argument}))
    });
    for (const token of row.tokens) {
      if (!token.parameter || ["isis_instance", "interface_name", "isis_level"].includes(token.parameter)) continue;
      const parameter = parameters[token.parameter];
      if (engine === "classic" && match.binding.classic_parameters &&
          !Object.hasOwn(match.binding.classic_parameters, token.parameter))
        fail(`${row.id} has an undeclared compound value parameter`);
      if (!parameter?.yang_path) continue;
      const source = nodes.get(parameter.yang_path);
      const composite = engine === "classic" && match.binding.classic_parameters?.[token.parameter] === parameter.yang_path;
      if (source?.length !== 1 || (!composite && !same(typeShape(source[0]), typeShape(match.node))))
        fail(`${row.id} value parameter differs from the bound YANG type`);
    }
    if (row.source_ref !== match.binding[engine + "_source"]) fail(`${row.id} uses a different engine reference`);
    if (row.enters_context && !["list", "container"].includes(match.node.kind)) fail(`${row.id} navigates into a leaf`);
    if (row.enters_context && words.some((word) => ["delete", "no", "~"].includes(word))) fail(`${row.id} navigates into an edit operator`);
    if (engine === "md") {
      const expected = mdPath(row.yang_path);
      if (!same(row.tokens.slice(1, expected.length + 1), expected)) fail(`${row.id} differs from its YANG path`);
      const tail = row.tokens.slice(expected.length + 1);
      if (words[0] === "configure" && match.node.kind === "leaf" && tail.length !== 1)
        fail(`${row.id} has an invalid scalar value shape`);
      if (words[0] === "delete" && match.node.kind !== "leaf-list" && tail.length)
        fail(`${row.id} adds a value to scalar/list removal`);
    }
    match.rows.push(row);
  }
  for (const [path, {binding, rows}] of selected) {
    const classicRows = binding.classic_via_parent ? selected.get(binding.classic_via_parent).rows : rows;
    if (!rows.some((row) => row.engines.includes("md") && literal(row.tokens[0]) === "configure") ||
        !classicRows.some((row) => row.engines.includes("classic") && !row.tokens.map(literal).includes("no") &&
          (!binding.classic_via_parent || row.tokens.some((token) =>
            binding.classic_via_parent && selected.get(binding.classic_via_parent).binding.classic_parameters?.[token.parameter] === path))))
      fail(`${path} lacks an engine setter/context`);
    if (binding.md_remove && !rows.some((row) => row.engines.includes("md") && literal(row.tokens[0]) === "delete"))
      fail(`${path} lacks its MD removal form`);
    if (binding.classic_no && !rows.some((row) => row.engines.includes("classic") && row.tokens.map(literal).includes("no")))
      fail(`${path} lacks its classic removal/inverse form`);
  }
  return selected.size;
}
