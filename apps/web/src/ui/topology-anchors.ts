// Radial attachment geometry for topology links. This module owns presentation
// coordinates only: physical port identity remains in the project and runtime,
// while every rendered link receives one independent point on a device rim.

export interface TopologyPoint { x: number; y: number }

export interface TopologyAnchorLink {
  id: string;
  endpoints: readonly [
    { nodeId: string },
    { nodeId: string },
  ];
}

export interface RadialLinkAnchor {
  linkId: string;
  angleDegrees: number;
  leftPercent: number;
  topPercent: number;
}

export interface TopologyAnchorRadius {
  xPercent: number;
  yPercent: number;
}

export type TopologyHandleSide = "top" | "right" | "bottom" | "left";

export function radialHandleSide(angleDegrees: number): TopologyHandleSide {
  const angle = normalizedAngle(angleDegrees);
  if (angle < 45 || angle >= 315) return "right";
  if (angle < 135) return "bottom";
  if (angle < 225) return "left";
  return "top";
}

export function edgePortLabelPoints(source: TopologyPoint,
  target: TopologyPoint, inset = 0.14): readonly [TopologyPoint, TopologyPoint] {
  // Labels belong to endpoints, not to the cable midpoint. Keeping both on
  // the same straight interpolation also preserves their association after a
  // node drag without storing any derived coordinates in the project.
  const point = (fraction: number): TopologyPoint => ({
    x: source.x + (target.x - source.x) * fraction,
    y: source.y + (target.y - source.y) * fraction,
  });
  return [point(inset), point(1 - inset)];
}

function normalizedAngle(degrees: number): number {
  return (degrees % 360 + 360) % 360;
}

function angularDistance(first: number, second: number): number {
  const direct = Math.abs(first - second) % 360;
  return Math.min(direct, 360 - direct);
}

export function radialLinkAnchors(nodeId: string,
  centers: Readonly<Record<string, TopologyPoint>>,
  links: readonly TopologyAnchorLink[],
  radius: TopologyAnchorRadius = { xPercent: 50, yPercent: 50 }
): RadialLinkAnchor[] {
  const center = centers[nodeId];
  if (!center) return [];

  const raw = links.flatMap((link) => {
    const endpoint = link.endpoints.find((item) => item.nodeId === nodeId);
    if (!endpoint) return [];
    const peer = link.endpoints[0].nodeId === nodeId
      ? link.endpoints[1].nodeId : link.endpoints[0].nodeId;
    const peerCenter = centers[peer];
    if (!peerCenter) return [];
    return [{ linkId: link.id, angleDegrees: normalizedAngle(
      Math.atan2(peerCenter.y - center.y, peerCenter.x - center.x) * 180 / Math.PI
    ) }];
  });

  return raw.map((anchor) => {
    // Parallel links cannot share one two-pixel point. Nearby directions form
    // a deterministic fan with a bounded 80-degree span, so even a fully
    // populated 24-port MDA keeps every attachment independently clickable
    // without moving it to the opposite side of the device.
    const neighbors = raw.filter((candidate) =>
      angularDistance(candidate.angleDegrees, anchor.angleDegrees) <= 10)
      .sort((left, right) => left.angleDegrees - right.angleDegrees ||
        left.linkId.localeCompare(right.linkId));
    const rank = neighbors.findIndex((candidate) => candidate.linkId === anchor.linkId);
    const spacing = neighbors.length <= 1 ? 0 : Math.min(8, 80 / (neighbors.length - 1));
    const offset = (rank - (neighbors.length - 1) / 2) * spacing;
    const angleDegrees = normalizedAngle(anchor.angleDegrees + offset);
    const radians = angleDegrees * Math.PI / 180;
    return {
      linkId: anchor.linkId,
      angleDegrees,
      // Generated diagram symbols do not fill their square bitmap equally in
      // both axes. Independent radii keep top and bottom ports on a shallow
      // router silhouette without moving its side ports inward.
      leftPercent: 50 + Math.cos(radians) * radius.xPercent,
      topPercent: 50 + Math.sin(radians) * radius.yPercent,
    };
  });
}
