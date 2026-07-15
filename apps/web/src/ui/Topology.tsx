// React Flow projection of project topology. Node IDs, physical bindings and
// positions come from the validated project and generated profile.

import { Background, Controls, Handle, Position, ReactFlow, type Edge,
  type Node, type NodeProps, type ReactFlowInstance } from "@xyflow/react";
import { GENERATED_PROFILE, type HostConfig, type LinkConfig,
  type RuntimeSnapshot, type UiLayout } from "@router-simulator/contracts";
import { useMemo, useRef } from "react";

type DeviceData = { kind: "host" | "router"; title: string; subtitle: string };

function DeviceNode({ data, selected }: NodeProps<Node<DeviceData>>) {
  // One renderer handles hosts and routers while the profile supplies identity,
  // text and position. Handles are visual attachment points only.
  const router = data.kind === "router";
  return (
    <div className={`device-node ${router ? "router-node" : "host-node"} ${selected ? "selected" : ""}`}>
      <Handle type="target" position={Position.Left} id="left" />
      <div className="device-icon" aria-hidden>{router
        ? <span className="rack-face"><i /><i /><i /><i /><i /></span> : "H"}</div>
      <div><strong>{data.title}</strong><span>{data.subtitle}</span></div>
      <Handle type="source" position={Position.Right} id="right" />
    </div>
  );
}

const nodeTypes = { device: DeviceNode };

interface Props {
  hosts: HostConfig[];
  links: LinkConfig[];
  layout: UiLayout;
  systemName: string;
  snapshot?: RuntimeSnapshot;
  selected: string;
  onSelect(id: string): void;
  onLayoutChange(id: string, position: { x: number; y: number }): void;
  onLinkToggle(portId: string, up: boolean): void;
  onOpenHardware(): void;
  tool: "select" | "link";
  onToolChange(tool: "select" | "link"): void;
}

function speedLabel(speedMbps: number): string {
  // Avoid rounding non-integral gigabit profiles in physical link labels.
  return speedMbps % 1000 === 0 ? `${speedMbps / 1000}G` : `${speedMbps}M`;
}

export function Topology({ hosts, links, layout, systemName, snapshot, selected,
  onSelect, onLayoutChange, onLinkToggle, onOpenHardware, tool, onToolChange }: Props) {
  // Node positions remain portable project data. React Flow may animate a drag,
  // but only the final finite coordinate is persisted through App.
  const routerId = GENERATED_PROFILE.uiDefaults.router_id;
  const topologyRef = useRef<HTMLDivElement>(null);
  const flowRef = useRef<ReactFlowInstance<Node<DeviceData>, Edge> | null>(null);
  // Snapshot counters change frequently but node identity and measurement do
  // not. Memoized arrays keep React Flow from restarting its layout pass.
  const nodes = useMemo<Node<DeviceData>[]>(() => [
    ...hosts.map((host) => ({
      id: host.id,
      type: "device",
      position: layout.nodes[host.id],
      selected: selected === host.id,
      data: { kind: "host" as const, title: host.name, subtitle: host.address }
    })),
    {
      id: routerId,
      type: "device",
      position: layout.nodes[routerId],
      selected: selected === routerId,
      data: { kind: "router" as const, title: systemName, subtitle: GENERATED_PROFILE.chassis }
    }
  ], [hosts, layout.nodes, routerId, selected, systemName]);
  const edges = useMemo<Edge[]>(() => links.map((link) => {
    // Edge orientation follows stored coordinates so handles remain on the
    // inward side for endpoints placed on either side of the router.
    const hostOnLeft = layout.nodes[link.host].x < layout.nodes[routerId].x;
    const port = snapshot?.ports.find((item) => item.id === link.routerPort);
    const up = port?.oper === "up";
    return {
      id: link.id,
      source: hostOnLeft ? link.host : routerId,
      target: hostOnLeft ? routerId : link.host,
      sourceHandle: "right",
      targetHandle: "left",
      className: up ? "link-up" : "link-down",
      label: `${link.routerPort} · ${speedLabel(GENERATED_PROFILE.ports.speedMbps)}`,
      // Edge interaction changes the cable signal, not ifOperStatus. Keeping
      // both values separate is essential when the port is admin-down.
      data: { portId: link.routerPort, up: Boolean(port?.physicalLink) }
    };
  }), [layout.nodes, links, routerId, snapshot?.ports]);
  return (
    <div className="topology" ref={topologyRef}>
      <div className="canvas-toolbar" aria-label="Topology tools">
        <button className={tool === "select" ? "active" : ""} title="Select and move devices" aria-label="Select and move devices" onClick={() => onToolChange("select")}>⌁</button>
        <button title="Open router hardware" aria-label="Open router hardware" onClick={onOpenHardware}>⊞</button>
        <button title="Fit topology" aria-label="Fit topology" onClick={() => void flowRef.current?.fitView({ padding: 0.22, duration: 260 })}>⌑</button>
        <button title="Fullscreen topology" aria-label="Fullscreen topology" onClick={() => void (document.fullscreenElement ? document.exitFullscreen() : topologyRef.current?.requestFullscreen())}>⛶</button>
      </div>
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView
        minZoom={0.35} maxZoom={1.8} nodesDraggable={tool === "select"}
        onInit={(instance) => { flowRef.current = instance; }}
        onNodeDragStop={(_, node) => onLayoutChange(node.id, node.position)}
        onNodeClick={(_, node) => onSelect(node.id)}
        onEdgeClick={(_, edge) => {
          if (tool !== "link") return;
          const data = edge.data as { portId?: string; up?: boolean } | undefined;
          if (data?.portId) onLinkToggle(data.portId, !data.up);
        }}
        proOptions={{ hideAttribution: true }}>
        <Background color="#252b2d" gap={22} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
