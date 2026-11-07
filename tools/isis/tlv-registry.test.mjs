// Registry projection tests protect octet boundaries and source-lock integrity.
// Fixtures are caller-owned values; no production file is written by these tests.

import test from "node:test";
import assert from "node:assert/strict";
import { renderTlvRegistry } from "./tlv-registry.mjs";

const facts = { schema_version: 1, sha256: "a".repeat(64), registered: [0, 63, 64, 127, 128, 191, 192, 255], purge_allowed: [63, 128, 255] };
test("registry bits cross each 64-bit word without numeric precision loss", () => {
  const output = renderTlvRegistry(facts);
  assert.ok(output.includes("0x8000000000000001ULL, 0x8000000000000001ULL, 0x8000000000000001ULL, 0x8000000000000001ULL"));
  assert.ok(output.includes("0x8000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000001ULL, 0x8000000000000000ULL"));
});
test("invalid assignments and unregistered purge permissions reject before projection", () => {
  for (const registered of [[1, 1], [2, 1], [-1], [256], [1.5], null])
    assert.throws(() => renderTlvRegistry({ ...facts, registered }));
  assert.throws(() => renderTlvRegistry({ ...facts, purge_allowed: [7] }));
  assert.throws(() => renderTlvRegistry({ ...facts, schema_version: 2 }));
  assert.throws(() => renderTlvRegistry({ ...facts, sha256: "unknown" }));
});
