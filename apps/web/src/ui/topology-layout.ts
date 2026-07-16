// Deterministic fallback layout for user-owned topology nodes. This module
// owns no React or runtime state. It converts stable node identities into flow
// coordinates only, so persistence remains the final owner of every position.

export type TopologyPosition = Readonly<{ x: number; y: number }>;

// These dimensions mirror the rendered CSS contract. The layout uses the
// outer box rather than icon centers so adjacent nodes retain usable space for
// handles, edge labels and selection outlines at every React Flow zoom level.
const ROUTER_WIDTH = 164;
const ROUTER_HEIGHT = 90;
const HOST_WIDTH = 150;
const HOST_HEIGHT = 76;

function centered(x: number, y: number, width: number,
  height: number): TopologyPosition {
  return { x: x - width / 2, y: y - height / 2 };
}

export function automaticTopologyLayout(routerIds: readonly string[],
  hostIds: readonly string[]): Readonly<Record<string, TopologyPosition>> {
  const positions: Record<string, TopologyPosition> = {};

  if (routerIds.length <= 4) {
    // Small labs read better as a direct horizontal path. The fixed spacing
    // leaves room for complete port labels without making two-node labs tiny
    // after Fit View calculates the viewport.
    const startX = 420 - Math.max(0, routerIds.length - 1) * 115;
    routerIds.forEach((id, index) => {
      positions[id] = centered(startX + index * 230, 480,
        ROUTER_WIDTH, ROUTER_HEIGHT);
    });
  } else {
    // Large topologies form an ordered physical ring. R1 and the first host
    // start at the left edge, and increasing router identity proceeds around
    // the ellipse. A 16-node ring has at least 126 flow units between adjacent
    // centers on its tight vertical sides, comfortably above a 90-unit node.
    const centerX = 820;
    const centerY = 480;
    const radiusX = Math.max(420, routerIds.length * 37.5);
    const radiusY = Math.max(260, routerIds.length * 20.625);
    routerIds.forEach((id, index) => {
      const angle = Math.PI + 2 * Math.PI * index / routerIds.length;
      positions[id] = centered(centerX + radiusX * Math.cos(angle),
        centerY + radiusY * Math.sin(angle), ROUTER_WIDTH, ROUTER_HEIGHT);
    });
  }

  // Hosts occupy an outer ellipse instead of being mixed into the router
  // path. This makes endpoint links visually distinct and preserves an empty
  // center for edge labels. The formula also works when a lab has only hosts.
  const routerRadiusX = routerIds.length > 4
    ? Math.max(420, routerIds.length * 37.5) : 300;
  const routerRadiusY = routerIds.length > 4
    ? Math.max(260, routerIds.length * 20.625) : 190;
  hostIds.forEach((id, index) => {
    const angle = hostIds.length === 1 ? Math.PI
      : Math.PI + 2 * Math.PI * index / hostIds.length;
    positions[id] = centered(820 + (routerRadiusX + 180) * Math.cos(angle),
      480 + (routerRadiusY + 145) * Math.sin(angle), HOST_WIDTH, HOST_HEIGHT);
  });

  return positions;
}
