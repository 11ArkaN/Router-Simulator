// Portable IS-IS values share YANG ranges and presence semantics with native
// intent. Validation rejects unsupported fields and dangling level children.
import { expect, it } from "vitest";
import { encodeIsisConfigurationHex, isRouterIsisIntent, type RouterIsisIntent } from "../src/isis-configuration-v1";
function fixture(): RouterIsisIntent {
  return {instances: [{instance: 127, adminEnabled: true, ipv4Routing: null,
    ipv6Routing: null, levelCapability: null, systemId: null, routerId: null,
    lspLifetimeSeconds: null, lspMtuOctets: null,
    levels: [1, 2].map(() => ({present: false, defaultMetric: null, lspMtuOctets: null,
      preference: null, externalPreference: null, wideMetricsOnly: null})) as RouterIsisIntent["instances"][number]["levels"],
    areas: [], interfaces: []}]};
}
it("empty enabled instances and explicit defaults retain their own presence", () => {
  const value = fixture();
  expect(isRouterIsisIntent(value)).toBe(true);
  value.instances[0].levels[0].present = true;
  value.instances[0].levels[0].defaultMetric = 10;
  expect(isRouterIsisIntent(value)).toBe(true);
  value.instances[0].levels[0].present = false;
  expect(isRouterIsisIntent(value)).toBe(false);
});
it("identifier limits, area aliases and unsupported fields reject", () => {
  const value = fixture();
  value.instances[0].instance = 128;
  expect(isRouterIsisIntent(value)).toBe(false);
  value.instances[0].instance = 0;
  value.instances[0].areas = ["49.0001", "49.00.01"];
  expect(isRouterIsisIntent(value)).toBe(false);
  value.instances[0].areas.pop();
  expect(isRouterIsisIntent(value)).toBe(true);
  expect(isRouterIsisIntent({...value, unknown: true})).toBe(false);
  expect(isRouterIsisIntent({...value, "": true})).toBe(false);
});
it("level ranges do not accept NaN, fractions or a larger numeric type", () => {
  for (const metric of [0, -1, 1.5, NaN, 16777216]) {
    const value = fixture();
    value.instances[0].levels[0].present = true;
    value.instances[0].levels[0].defaultMetric = metric;
    expect(isRouterIsisIntent(value)).toBe(false);
  }
});

it("binary management payload preserves the native empty-tree golden", () => {
  expect(encodeIsisConfigurationHex({instances: []})).toBe("0500000000");
  const value = fixture();
  const instance = value.instances[0];
  instance.instance = 0; instance.adminEnabled = null;
  expect(encodeIsisConfigurationHex(value)).toBe("0501000000" + "00".repeat(39));
});

it("sparse arrays cannot bypass entry validation or wire counts", () => {
  expect(isRouterIsisIntent({instances: Array(1)})).toBe(false);
  const value = fixture();
  value.instances[0].areas = Array(1);
  expect(isRouterIsisIntent(value)).toBe(false);
  value.instances[0].areas = [];
  value.instances[0].interfaces = Array(1);
  expect(isRouterIsisIntent(value)).toBe(false);
});

it("optional wait timer intent preserves raw values and rejects invalid leaves", () => {
  const value = fixture();
  value.instances[0].spfWait = {maximumMilliseconds: 550, initialMilliseconds: 10, secondMilliseconds: 100000};
  value.instances[0].lspWait = {maximumMilliseconds: 120000, initialMilliseconds: 99, secondMilliseconds: 1000};
  expect(isRouterIsisIntent(value)).toBe(true);
  expect(encodeIsisConfigurationHex(value)).toContain("0126020000010a00000001a0860100");
  for (const invalid of [9, 120001, NaN, 550.5]) {
    value.instances[0].spfWait.maximumMilliseconds = invalid;
    expect(isRouterIsisIntent(value)).toBe(false);
  }
  value.instances[0].spfWait.maximumMilliseconds = 550;
  expect(isRouterIsisIntent({...value, instances: [{...value.instances[0], spfWait: {...value.instances[0].spfWait, unknown: 1}}]})).toBe(false);
});

it("passive-only presence is optional for older projects and remains a canonical bool", () => {
  const value = fixture();
  const absent = encodeIsisConfigurationHex(value);
  for (const configured of [null, false, true]) {
    value.instances[0].advertisePassiveOnly = configured;
    expect(isRouterIsisIntent(value)).toBe(true);
    expect(encodeIsisConfigurationHex(value).slice(0, -6).endsWith(configured === null ? "00" : configured ? "0101" : "0100")).toBe(true);
  }
  delete value.instances[0].advertisePassiveOnly;
  expect(encodeIsisConfigurationHex(value)).toBe(absent);
  for (const invalid of [0, 1, "false", undefined])
    expect(isRouterIsisIntent({...value, instances: [{...value.instances[0], advertisePassiveOnly: invalid}]})).toBe(false);
});

it("strict adjacency preserves absent, explicit false and true", () => {
  const value = fixture();
  const absent = encodeIsisConfigurationHex(value);
  for (const configured of [null, false, true]) {
    value.instances[0].strictAdjacencyCheck = configured;
    expect(isRouterIsisIntent(value)).toBe(true);
    expect(encodeIsisConfigurationHex(value).slice(0, -4).endsWith(configured === null ? "00" : configured ? "0101" : "0100")).toBe(true);
  }
  delete value.instances[0].strictAdjacencyCheck;
  expect(encodeIsisConfigurationHex(value)).toBe(absent);
  for (const invalid of [0, 1, "false", undefined])
    expect(isRouterIsisIntent({...value, instances: [{...value.instances[0], strictAdjacencyCheck: invalid}]})).toBe(false);
});

for (const field of ["ignoreAttachedBit", "suppressAttachedBit"] as const) {
  it(`${field} preserves explicit values and validates older absent fields`, () => {
    const value = fixture();
    const absent = encodeIsisConfigurationHex(value);
    for (const configured of [null, false, true]) {
      value.instances[0][field] = configured;
      expect(isRouterIsisIntent(value)).toBe(true);
      const bytes = encodeIsisConfigurationHex(value);
      const tail = field === "ignoreAttachedBit" ? bytes.slice(0, -2) : bytes;
      expect(tail.endsWith(configured === null ? "00" : configured ? "0101" : "0100")).toBe(true);
    }
    delete value.instances[0][field];
    expect(encodeIsisConfigurationHex(value)).toBe(absent);
    for (const invalid of [0, 1, "false", undefined])
      expect(isRouterIsisIntent({...value, instances: [{...value.instances[0], [field]: invalid}]})).toBe(false);
  });
}
