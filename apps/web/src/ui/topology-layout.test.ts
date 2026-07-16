// Geometry regression tests for the viewport-independent automatic layout.
// Tests assert spatial invariants rather than pixel screenshots so CSS color
// changes cannot hide an overlap or an unstable identity-to-position mapping.

import { describe, expect, it } from "vitest";
import { automaticTopologyLayout } from "./topology-layout";

describe("automatic topology layout", () => {
  it("places sixteen routers at distinct ordered ring coordinates", () => {
    const routers = Array.from({ length: 16 }, (_, index) => `r${index + 1}`);
    const positions = automaticTopologyLayout(routers, []);
    const unique = new Set(routers.map((id) =>
      `${positions[id].x.toFixed(3)}:${positions[id].y.toFixed(3)}`));

    expect(unique.size).toBe(16);
    expect(positions.r1.x).toBeLessThan(positions.r9.x);
    expect(positions.r5.y).toBeLessThan(positions.r13.y);
  });

  it("keeps four hosts outside the sixteen-router ring", () => {
    const routers = Array.from({ length: 16 }, (_, index) => `r${index + 1}`);
    const hosts = ["h1", "h2", "h3", "h4"];
    const positions = automaticTopologyLayout(routers, hosts);

    expect(positions.h1.x).toBeLessThan(positions.r1.x);
    expect(positions.h2.y).toBeLessThan(positions.r5.y);
    expect(positions.h3.x).toBeGreaterThan(positions.r9.x);
    expect(positions.h4.y).toBeGreaterThan(positions.r13.y);
  });
});
