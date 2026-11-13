// Registry projection tests protect octet boundaries and source-lock integrity.
// Fixtures are caller-owned values; no production file is written by these tests.

import test from "node:test";
import assert from "node:assert/strict";
import { renderTlvRegistry } from "./tlv-registry.mjs";

const permissions = {source_url: "https://www.iana.org/assignments/isis-tlv-codepoints/unit.csv", sha256: "a".repeat(64),
  registered: [0, 63, 64, 127, 128, 191, 192, 255], multipart_allowed: [63, 255], multipart_disallowed: [128]};
const facts = {schema_version: 2, ...permissions, purge_allowed: [63, 128, 255],
  subregistries: Object.fromEntries(["neighbor", "prefix", "router_capability"].map((name) => [name, {...permissions}]))};
test("registry bits cross each 64-bit word without numeric precision loss", () => {
  const output = renderTlvRegistry(facts);
  assert.ok(output.includes("0x8000000000000001ULL, 0x8000000000000001ULL, 0x8000000000000001ULL, 0x8000000000000001ULL"));
  assert.ok(output.includes("0x8000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000001ULL, 0x8000000000000000ULL"));
});
test("invalid assignments and unregistered purge permissions reject before projection", () => {
  for (const registered of [[1, 1], [2, 1], [-1], [256], [1.5], null])
    assert.throws(() => renderTlvRegistry({ ...facts, registered }));
  assert.throws(() => renderTlvRegistry({ ...facts, purge_allowed: [7] }));
  assert.throws(() => renderTlvRegistry({ ...facts, schema_version: 1 }));
  assert.throws(() => renderTlvRegistry({ ...facts, sha256: "unknown" }));
});
test("multipart applicability keeps registry namespaces and unknown permissions distinct", () => {
  const output = renderTlvRegistry(facts);
  for (const context of ["tlv", "neighbor", "prefix", "router_capability"])
    assert.ok(output.includes(`case MultipartContext::${context}: return select(${context}_multipart_codes, ${context}_nonmultipart_codes)`));
  assert.ok(output.includes("MultipartApplicability::unknown"));
  assert.throws(() => renderTlvRegistry({...facts, multipart_allowed: [7]}));
  assert.throws(() => renderTlvRegistry({...facts, multipart_disallowed: [63]}));
  assert.throws(() => renderTlvRegistry({...facts, subregistries: {prefix: permissions}}));
  assert.throws(() => renderTlvRegistry({...facts, subregistries: {...facts.subregistries,
    prefix: {...permissions, sha256: "unknown"}}}));
  assert.throws(() => renderTlvRegistry({...facts, subregistries: {...facts.subregistries,
    prefix: {...permissions, multipart_allowed: [255, 63]}}}));
});
