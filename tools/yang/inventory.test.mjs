// Inventory safety fixtures own all ASTs and check omission, identity and
// dependency failures independently of the release's source indentation.

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStatements } from "./statements.mjs";
import { dependencyClosure, groupingInventory } from "./inventory.mjs";

test("dependency closure includes parent modules and validates pinned revisions", () => {
  const modules = new Map([
    ["m", parseStatements('module m { include s; import t { prefix t; revision-date 2020-01-01; } }')],
    ["s", parseStatements('submodule s { belongs-to m { prefix m; } }')],
    ["t", parseStatements('module t { revision 2020-01-01; }')],
  ]);
  assert.deepEqual(dependencyClosure(modules, ["s"]), ["m", "s", "t"]);
  assert.throws(() => dependencyClosure(new Map([...modules].filter(([name]) => name !== "t")), ["m"]), /Missing/);
  modules.set("t", parseStatements('module t { revision 2021-01-01; }'));
  assert.throws(() => dependencyClosure(modules, ["m"]), /required revision/);
});

test("a choice keeps distinct schema rows without introducing a data context", () => {
  const module = parseStatements(`submodule s { grouping g { list isis { key id;
    leaf id { type uint8; } choice address { case named { leaf source { type string; } }
      case fixed { leaf ip { type string; } } }
    container limits { leaf threshold { type uint32 { range '1..10'; } default 2; } }
  } } }`);
  const rows = groupingInventory(module, "g", "/configure/router");
  assert.equal(rows.length, 9);
  const source = rows.find((row) => row.name === "source");
  assert.equal(source.schema_id, "/configure/router/isis/choice:address/case:named/source");
  assert.equal(source.data_path, "/configure/router/isis/source");
  assert.equal(source.structural_context, false);
  assert.equal(rows.find((row) => row.kind === "choice").structural_context, false);
  assert.deepEqual(rows.find((row) => row.name === "limits").constraints, []);
  assert.equal(rows.find((row) => row.name === "threshold").constraints[1].argument, "2");
});

test("unexpanded schema constructs and duplicate identities block inventory", () => {
  for (const source of [
    'module m { grouping g { uses elsewhere; } }',
    'module m { grouping g { container c { augment x { leaf y { type string; } } } } }',
    'module m { grouping g { leaf x { type string; } leaf x { type uint32; } } }',
  ]) assert.throws(() => groupingInventory(parseStatements(source), "g", "/configure"));
});
