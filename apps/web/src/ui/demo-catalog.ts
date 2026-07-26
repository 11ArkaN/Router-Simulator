// Browser presentation catalog for built-in demo laboratories. This module
// owns display metadata and delegates all project construction to contracts.

import { createOspfTriangleDemoLabV5, createStaticIpv4DemoLabV5,
  type LabProjectV4 } from "@router-simulator/contracts";

export type DemoLabId = "static-ipv4" | "ospf-triangle";
export type DemoTopologySymbol = "host" | "router";

export interface DemoLabOption {
  id: DemoLabId;
  title: string;
  eyebrow: string;
  summary: string;
  checkTarget: string;
  primarySelection: string;
  counts: { devices: number; links: number };
  topology: readonly DemoTopologySymbol[];
  createProject(): LabProjectV4;
}

export const DEMO_LAB_CATALOG: readonly DemoLabOption[] = [{
  id: "static-ipv4",
  title: "Static IPv4 path",
  eyebrow: "BASIC ROUTING",
  summary: "Two routers join two hosts with explicit IPv4 routes in both directions.",
  checkTarget: "Host A reaches 192.0.2.6",
  primarySelection: "h1",
  counts: { devices: 4, links: 3 },
  topology: ["host", "router", "router", "host"],
  createProject: () => createStaticIpv4DemoLabV5()
}, {
  id: "ospf-triangle",
  title: "OSPF triangle",
  eyebrow: "DYNAMIC ROUTING",
  summary: "Three routers learn access networks through OSPF with a higher cost backup edge.",
  checkTarget: "Branch host reaches 198.51.100.10",
  primarySelection: "h1",
  counts: { devices: 5, links: 5 },
  topology: ["host", "router", "router", "router", "host"],
  createProject: () => createOspfTriangleDemoLabV5()
}];
