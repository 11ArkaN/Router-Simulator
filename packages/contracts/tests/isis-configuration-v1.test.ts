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
  expect(encodeIsisConfigurationHex({instances: []})).toBe("0100000000");
  const value = fixture();
  const instance = value.instances[0];
  instance.instance = 0; instance.adminEnabled = null;
  expect(encodeIsisConfigurationHex(value)).toBe("0101000000" + "00".repeat(29));
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
