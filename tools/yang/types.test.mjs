// Type-resolution fixtures use independent module graphs, lexical shadowing
// and inherited defaults. Each test owns all source ASTs and resolver state.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseStatements } from './statements.mjs';
import { typeResolver } from './types.mjs';

test('imported typedef chains preserve restrictions and nearest default', () => {
  const m = parseStatements(`module m { prefix m; import t { prefix x; }
    typedef local { type x:level; default two; }
    leaf a { type local; } leaf b { type x:level; } }`);
  const t = parseStatements(`module t { prefix t;
    typedef level { type enumeration { enum one; enum two; } default one; } }`);
  const resolve = typeResolver(new Map([['m', m], ['t', t]]));
  const a = resolve(m.children.find((n) => n.argument === 'a').children[0]);
  assert.equal(a.builtin, 'enumeration');
  assert.equal(a.default, 'two');
  assert.deepEqual(a.layers.map((n) => n.name), ['enumeration', 'x:level', 'local']);
  assert.equal(a.layers[0].restrictions[1].argument, 'two');
  assert.equal(resolve(m.children.find((n) => n.argument === 'b').children[0]).default, 'one');
});

test('included declarations and lexical typedefs resolve without importing another namespace', () => {
  const m = parseStatements(`module m { prefix own; include s;
    typedef number { type uint32; default 8; }
    container c { typedef number { type uint8; default 2; } leaf a { type number; } }
    leaf b { type own:included; } }`);
  const s = parseStatements(`submodule s { belongs-to m { prefix own; }
    typedef included { type number { range '1..9'; } } }`);
  const resolve = typeResolver(new Map([['m', m], ['s', s]]));
  const c = m.children.find((n) => n.argument === 'c');
  assert.equal(resolve(c.children.find((n) => n.argument === 'a').children[0]).default, '2');
  const b = resolve(m.children.find((n) => n.argument === 'b').children[0]);
  assert.equal(b.builtin, 'uint32');
  assert.equal(b.default, '8');
  assert.equal(b.layers[1].restrictions[0].argument, '1..9');
});

test('union members resolve independently and invalid references fail closed', () => {
  for (const definition of ['type absent;', 'type z:missing;', 'type self;', 'type union;']) {
    const m = parseStatements(`module m { prefix m; typedef self { type self; } leaf a { ${definition} } }`);
    const resolve = typeResolver(new Map([['m', m]]));
    assert.throws(() => resolve(m.children.find((n) => n.argument === 'a').children[0]));
  }
  const m = parseStatements(`module m { typedef n { type uint8; } leaf a {
    type union { type n; type string { length '1..3'; } } } }`);
  const resolved = typeResolver(new Map([['m', m]]))(m.children[1].children[0]);
  assert.deepEqual(resolved.members.map((n) => n.builtin), ['uint8', 'string']);
  assert.equal(resolved.members[1].layers[0].restrictions[0].argument, '1..3');
});
