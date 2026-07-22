// Radial anchor regression tests. Spatial assertions cover cardinal direction,
// parallel-link separation and a populated MDA rather than depending on a
// screenshot whose colors cannot prove that distinct handles exist.

import { describe, expect, it } from "vitest";
import { edgePortLabelPoints, radialHandleSide, radialLinkAnchors,
  type TopologyAnchorLink } from "./topology-anchors";

function link(id: string, first: string, second: string): TopologyAnchorLink {
  return { id, endpoints: [{ nodeId: first }, { nodeId: second }] };
}

describe("radial topology link anchors", () => {
  it("places links on the rim facing their peer devices", () => {
    const centers = {
      router: { x: 100, y: 100 }, east: { x: 300, y: 100 },
      south: { x: 100, y: 300 }, west: { x: -100, y: 100 },
    };
    const anchors = radialLinkAnchors("router", centers, [
      link("east-link", "router", "east"),
      link("south-link", "router", "south"),
      link("west-link", "router", "west"),
    ]);

    expect(anchors.find((item) => item.linkId === "east-link"))
      .toMatchObject({ leftPercent: 100, topPercent: 50 });
    expect(anchors.find((item) => item.linkId === "south-link"))
      .toMatchObject({ leftPercent: 50, topPercent: 100 });
    expect(anchors.find((item) => item.linkId === "west-link")?.leftPercent)
      .toBeCloseTo(0);
  });

  it("gives parallel links separate stable points instead of two shared sides", () => {
    const links = Array.from({ length: 6 }, (_, index) =>
      link(`link-${index + 1}`, "router", "peer"));
    const anchors = radialLinkAnchors("router",
      { router: { x: 0, y: 0 }, peer: { x: 200, y: 0 } }, links);

    expect(anchors).toHaveLength(6);
    expect(new Set(anchors.map((item) => item.angleDegrees)).size).toBe(6);
  });

  it("follows a shallow symbol boundary for vertical links", () => {
    const [anchor] = radialLinkAnchors("router",
      { router: { x: 0, y: 0 }, north: { x: 0, y: -200 } },
      [link("north-link", "router", "north")],
      { xPercent: 43, yPercent: 30 });

    expect(anchor.leftPercent).toBeCloseTo(50);
    expect(anchor.topPercent).toBeCloseTo(20);
  });

  it("retains one attachment for every port in a 24-link fan", () => {
    const links = Array.from({ length: 24 }, (_, index) =>
      link(`link-${index + 1}`, "router", "peer"));
    const anchors = radialLinkAnchors("router",
      { router: { x: 0, y: 0 }, peer: { x: 200, y: 0 } }, links);

    expect(anchors).toHaveLength(24);
    expect(new Set(anchors.map((item) => item.angleDegrees)).size).toBe(24);
    expect(Math.max(...anchors.map((item) => item.angleDegrees)) -
      Math.min(...anchors.map((item) => item.angleDegrees))).toBeLessThanOrEqual(360);
  });
});

describe("physical-link port labels", () => {
  it("keeps each port label near its own endpoint", () => {
    const [sourceLabel, targetLabel] = edgePortLabelPoints(
      { x: 100, y: 50 }, { x: 300, y: 150 });

    expect(sourceLabel).toEqual({ x: 128, y: 64 });
    expect(targetLabel).toEqual({ x: 272, y: 136 });
  });
});

describe("React Flow handle orientation", () => {
  it("uses the cable-facing cardinal edge instead of a fixed left offset", () => {
    expect(radialHandleSide(0)).toBe("right");
    expect(radialHandleSide(90)).toBe("bottom");
    expect(radialHandleSide(180)).toBe("left");
    expect(radialHandleSide(270)).toBe("top");
    expect(radialHandleSide(350)).toBe("right");
  });
});
