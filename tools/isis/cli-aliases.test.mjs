// Alias validation tests own small grammar fixtures. Optional classic instance
// syntax shares execution, while engine, source and edit-operator boundaries
// remain explicit and cannot be crossed by an alias.
import test from "node:test";
import assert from "node:assert/strict";
import { commandHandlers } from "../cli-command-aliases.mjs";

const original = {id: "classic_isis", source_id: "source", engines: ["classic"], enters_context: true,
  tokens: ["configure", "router", "isis", {parameter: "isis_instance"}]};
const alias = {...original, id: "classic_isis_default", handler_id: original.id, tokens: original.tokens.slice(0, -1)};
test("an optional-key grammar row retains one execution owner", () => {
  assert.deepEqual([...commandHandlers([original, alias])], [[original.id, original.id], [alias.id, original.id]]);
});
test("aliases reject missing handlers, chains and changed execution semantics", () => {
  for (const change of [{handler_id: "missing"}, {handler_id: alias.id}, {source_id: "other"},
    {engines: ["md"]}, {enters_context: false}, {tokens: ["configure", "router", "no", "isis"]}])
    assert.throws(() => commandHandlers([original, {...alias, ...change}]));
  assert.throws(() => commandHandlers([original, alias, {...alias, id: "chained", handler_id: alias.id}]));
});
