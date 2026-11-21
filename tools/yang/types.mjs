// Source type resolution for pinned YANG metadata. Each resolver owns lexical
// indexes over caller-owned immutable ASTs. Output retains restriction layers
// and provenance; production validators must still enforce their intersection.

const builtins = new Set(['binary', 'bits', 'boolean', 'decimal64', 'empty', 'enumeration',
  'identityref', 'instance-identifier', 'int8', 'int16', 'int32', 'int64', 'leafref',
  'string', 'uint8', 'uint16', 'uint32', 'uint64', 'union']);
const restrictions = new Set(['range', 'length', 'pattern', 'modifier', 'enum', 'value',
  'bit', 'position', 'fraction-digits', 'require-instance', 'base', 'path']);
const project = (node) => ({ keyword: node.keyword, argument: node.argument,
  children: node.children.filter((child) => restrictions.has(child.keyword)).map(project) });

// Preconditions: modules contains the complete import/include closure. Resolves
// lexical typedefs, imported prefixes, parent-module declarations and included
// submodules. Missing references, ambiguous declarations and cycles throw.
// Defaults retain their YANG lexical representation, without CLI conversion.
export function typeResolver(modules) {
  const parents = new WeakMap();
  const owners = new WeakMap();
  for (const module of modules.values()) {
    const index = (node, parent) => {
      parents.set(node, parent);
      owners.set(node, module);
      node.children.forEach((child) => index(child, node));
    };
    index(module, undefined);
  }
  const required = (name) => {
    const module = modules.get(name);
    if (!module) throw new Error(`Missing type module ${name}`);
    return module;
  };
  const family = (module) => {
    const root = module.keyword === 'submodule'
      ? required(module.children.find((node) => node.keyword === 'belongs-to').argument) : module;
    const found = new Set();
    const visit = (node) => {
      if (found.has(node)) return;
      found.add(node);
      node.children.filter((child) => child.keyword === 'include')
        .forEach((child) => visit(required(child.argument)));
    };
    visit(root);
    return [...found];
  };
  const unique = (nodes, name) => {
    if (nodes.length > 1) throw new Error(`Ambiguous typedef ${name}`);
    if (!nodes.length) throw new Error(`Missing typedef ${name}`);
    return nodes[0];
  };
  const find = (type) => {
    const module = owners.get(type);
    const parts = type.argument.split(':');
    if (parts.length > 2) throw new Error(`Invalid type name ${type.argument}`);
    const name = parts.at(-1);
    if (parts.length === 1) {
      for (let scope = parents.get(type); scope; scope = parents.get(scope)) {
        const declarations = scope.children.filter((node) => node.keyword === 'typedef' && node.argument === name);
        if (declarations.length) return unique(declarations, name);
      }
    }
    let target = module;
    if (parts.length === 2) {
      const binding = module.children.find((node) => ['prefix', 'belongs-to', 'import'].includes(node.keyword) &&
        (node.keyword === 'prefix' ? node.argument === parts[0] :
          node.children.some((child) => child.keyword === 'prefix' && child.argument === parts[0])));
      if (!binding) throw new Error(`Unknown type prefix ${parts[0]} in ${module.argument}`);
      target = binding.keyword === 'prefix' ? module : required(binding.argument);
    }
    return unique(family(target).flatMap((owner) => owner.children.filter((node) =>
      node.keyword === 'typedef' && node.argument === name)), type.argument);
  };
  const resolve = (type, active) => {
    if (!type || type.keyword !== 'type' || !owners.has(type)) throw new Error('Expected indexed YANG type');
    const layer = { module: owners.get(type).argument, source_line: type.line,
      name: type.argument, restrictions: type.children.filter((node) => restrictions.has(node.keyword)).map(project) };
    if (builtins.has(type.argument)) {
      const result = { builtin: type.argument, layers: [layer] };
      if (type.argument === 'union') {
        result.members = type.children.filter((node) => node.keyword === 'type').map((node) => resolve(node, active));
        if (!result.members.length) throw new Error('Empty union type');
      }
      return result;
    }
    const declaration = find(type);
    if (active.has(declaration)) throw new Error(`Cyclic typedef ${type.argument}`);
    const nested = new Set(active).add(declaration);
    const result = resolve(declaration.children.find((node) => node.keyword === 'type'), nested);
    const declaredDefault = declaration.children.find((node) => node.keyword === 'default');
    return { ...result, layers: [...result.layers, layer],
      ...(declaredDefault ? { default: declaredDefault.argument,
        default_source: { module: owners.get(declaration).argument, source_line: declaredDefault.line } } : {}) };
  };
  return (type) => resolve(type, new Set());
}
