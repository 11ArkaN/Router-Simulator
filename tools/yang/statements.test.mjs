// Statement-reader conformance fixtures. Tests own all source strings and ASTs
// and exercise RFC 7950 syntax independently of Nokia indentation conventions.

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStatements } from "./statements.mjs";

test("comments and quoted braces do not change statement ownership", () => {
  const root = parseStatements(`module x{yang-version 1.1;/* } */
    leaf a { type string; default "{ // not a comment }"; }
    // leaf hidden { type boolean; }
    leaf b{type boolean;default false;}
  }`);
  assert.deepEqual(root.children.map((node) => node.argument), ["1.1", "a", "b"]);
  assert.equal(root.children[1].children[1].argument, "{ // not a comment }");
  assert.equal(root.children[2].line, 4);
});

test("RFC quoting examples concatenate after escape processing", () => {
  for (const value of ["hello", '"hello"', "'hello'", '"hel" + "lo"', "'hel'/*gap*/+\n\"lo\""])
    assert.equal(parseStatements(`module x { description ${value}; }`).children[0].argument, "hello");
  assert.equal(parseStatements('module x { description "\\n"; }').children[0].argument, "\n");
  assert.equal(parseStatements("module x { description '\\n'; }").children[0].argument, "\\n");
});

test("physical indentation and trailing whitespace are stripped before escapes", () => {
  const root = parseStatements('module x {\n        description\n        "first line  \t\n           second line\\t";\n}');
  assert.equal(root.children[0].argument, "first line\n  second line\t");
  const tabs = parseStatements('module x { description\n"a\n\tb"; }');
  assert.equal(tabs.children[0].argument, "a\n       b");
});

test("extensions, choices and concatenated leafrefs retain exact source structure", () => {
  const root = parseStatements(`submodule x { yang-version 1.1; belongs-to m { prefix m; }
    grouping g { choice c { case a { leaf v { type leafref { path '../' + 'name'; }
      ext:auto-restart-to-modify; } } } }
  }`);
  const leaf = root.children[2].children[0].children[0].children[0];
  assert.equal(leaf.children[0].children[0].argument, "../name");
  assert.equal(leaf.children[1].keyword, "ext:auto-restart-to-modify");
  assert.equal(leaf.children[1].argument, null);
});

test("incomplete and ambiguous input never returns a partial inventory", () => {
  for (const text of [
    'module x {', 'module x { leaf a { type string; }',
    'module x { description "unterminated; }', 'module x { /* missing end',
    'module x { description "a" + bare; }', 'module x { leaf a extra; }',
    'module x {} }', 'module x {} module y {}', 'module x { leaf a { type string } }',
    'module"x" {}',
    'module x { yang-version 1.1; description "bad\\q"; }',
  ]) assert.throws(() => parseStatements(text, "fixture.yang"), SyntaxError, text);
});
