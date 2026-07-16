// React Flow projection of the user-owned project topology. The visual DOM and
// CSS classes retain the approved interface while node, link and port identity
// now come exclusively from project format 3 and runtime snapshot ABI 5.

import { Background, ConnectionMode, Controls, Handle, Position, ReactFlow,
  type Connection, type Edge, type Node, type NodeProps,
  type ReactFlowInstance } from "@xyflow/react";
import type { LabProjectV3, LabRuntimeSnapshotV5 } from "@router-simulator/contracts";
import { useMemo, useRef } from "react";
import { Cpu, Maximize2, Monitor, MousePointer2, Scan,
  Router as RouterIcon } from "lucide-react";

type DeviceData = { kind: "host" | "router"; title: string; subtitle: string };

function DeviceNode({ data, selected }: NodeProps<Node<DeviceData>>) {
  // The renderer stays identical for any number of nodes. Handles identify a
  // visual attachment side only; the port chooser owns physical binding.
  const router = data.kind === "router";
  return <div className={`device-node ${router ? "router-node" : "host-node"} ${selected ? "selected" : ""}`}>
    <Handle type="source" position={Position.Left} id="left" />
    <div className="device-icon" aria-hidden>{router
      ? <RouterIcon size={26} strokeWidth={1.6} />
      : <Monitor size={24} strokeWidth={1.6} />}</div>
    <div><strong>{data.title}</strong><span>{data.subtitle}</span></div>
    <Handle type="source" position={Position.Right} id="right" />
  </div>;
}

const nodeTypes = { device: DeviceNode };

interface Props {
  project: LabProjectV3;
  snapshot?: LabRuntimeSnapshotV5;
  selected?: string;
  onSelect(id: string): void;
  onLayoutChange(id: string, position: { x: number; y: number }): void;
  onLinkToggle(linkId: string, up: boolean): void;
  onConnect(firstNodeId: string, secondNodeId: string): void;
  onDropDevice(kind: "router" | "host", position: { x: number; y: number }): void;
  onOpenHardware(): void;
  tool: "select" | "link";
  onToolChange(tool: "select" | "link"): void;
}

function speedLabel(speedMbps: number): string {
  return speedMbps % 1000 === 0 ? `${speedMbps / 1000}G` : `${speedMbps}M`;
}

function delayLabel(nanoseconds: number): string {
  // Preserve exact configured time whenever division would lose information.
  // The label is presentation only; the runtime continues to own the integer
  // nanosecond value used by each directional propagation deadline.
  if (nanoseconds >= 1_000_000 && nanoseconds % 1_000_000 === 0)
    return `${nanoseconds / 1_000_000} ms`;
  if (nanoseconds >= 1_000 && nanoseconds % 1_000 === 0)
    return `${nanoseconds / 1_000} us`;
  return `${nanoseconds} ns`;
}

export function Topology({ project, snapshot, selected, onSelect,
  onLayoutChange, onLinkToggle, onConnect, onDropDevice, onOpenHardware, tool,
  onToolChange }: Props) {
  const topologyRef = useRef<HTMLDivElement>(null);
  const flowRef = useRef<ReactFlowInstance<Node<DeviceData>, Edge> | null>(null);
  const nodes = useMemo<Node<DeviceData>[]>(() => [
    ...project.hosts.map((host, index) => ({
      id: host.id,
      type: "device",
      position: project.layout.nodes[host.id] ?? { x: 100, y: 160 + index * 130 },
      selected: selected === host.id,
      data: { kind: "host" as const, title: host.name, subtitle: host.eth0.address }
    })),
    ...project.routers.map((router, index) => ({
      id: router.id,
      type: "device",
      position: project.layout.nodes[router.id] ?? { x: 340 + index * 210, y: 240 },
      selected: selected === router.id,
      data: { kind: "router" as const, title: router.systemName,
        subtitle: snapshot?.routers.find((item) => item.id === router.id)?.chassis ?? router.profileId }
    }))
  ], [project.hosts, project.routers, project.layout.nodes, selected, snapshot?.routers]);

  const edges = useMemo<Edge[]>(() => project.links.map((link) => {
    // Carrier and effective media rate are link-owned runtime facts. Deriving
    // them from visible router ports incorrectly marks host-host media and can
    // combine two observations from different supervisor turns.
    const live = snapshot?.links.find((item) => item.id === link.id);
    const up = Boolean(live?.carrier);
    const first = project.layout.nodes[link.endpoints[0].nodeId];
    const second = project.layout.nodes[link.endpoints[1].nodeId];
    const leftToRight = !first || !second || first.x <= second.x;
    return {
      id: link.id,
      source: link.endpoints[0].nodeId,
      target: link.endpoints[1].nodeId,
      sourceHandle: leftToRight ? "right" : "left",
      targetHandle: leftToRight ? "left" : "right",
      className: up ? "link-up" : "link-down",
      selected: selected === link.id,
      label: `${link.endpoints[0].portId} · ${link.endpoints[1].portId}` +
        `${live?.speedMbps ? ` · ${speedLabel(live.speedMbps)}` : ""}` +
        ` · ${delayLabel(link.propagationDelayNs)}`,
      data: { up: live?.admin ?? link.admin === "up" }
    };
  }), [project.links, project.layout.nodes, snapshot?.links]);

  const connect = (connection: Connection) => {
    // React Flow supplies stable node identities only. App opens the catalog
    // backed free-port chooser and never guesses a physical endpoint.
    if (connection.source && connection.target && connection.source !== connection.target) {
      onConnect(connection.source, connection.target);
    }
  };

  return <div className="topology" ref={topologyRef}
    onDragOver={(event) => {
      if (event.dataTransfer.types.includes("application/x-router-lab-device")) {
        event.preventDefault();
        event.dataTransfer.dropEffect = "copy";
      }
    }}
    onDrop={(event) => {
      const kind = event.dataTransfer.getData("application/x-router-lab-device");
      if ((kind === "router" || kind === "host") && flowRef.current) {
        event.preventDefault();
        // React Flow owns zoom and pan transforms. Converting through its API
        // prevents dropped nodes from shifting when the canvas is not at 100%.
        onDropDevice(kind, flowRef.current.screenToFlowPosition({
          x: event.clientX, y: event.clientY
        }));
      }
    }}>
    <div className="canvas-toolbar" aria-label="Topology tools">
      <button className={tool === "select" ? "active" : ""} title="Select and move devices" aria-label="Select and move devices" onClick={() => onToolChange("select")}><MousePointer2 size={17} /></button>
      <button title="Open router hardware" aria-label="Open router hardware" onClick={onOpenHardware}><Cpu size={17} /></button>
      <button title="Fit topology" aria-label="Fit topology" onClick={() => void flowRef.current?.fitView({ padding: 0.22, duration: 260 })}><Scan size={17} /></button>
      <button title="Fullscreen topology" aria-label="Fullscreen topology" onClick={() => void (document.fullscreenElement ? document.exitFullscreen() : topologyRef.current?.requestFullscreen())}><Maximize2 size={16} /></button>
    </div>
    {/* React Flow enables edge-triggered camera movement by default. A large
        lab makes that default harmful: moving a node near the canvas border
        changes the coordinate transform underneath the pointer and shifts
        every later placement. Keep the camera under explicit pan/zoom control
        so a drag has one stable screen-to-flow transform from start to stop. */}
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView
      connectionMode={ConnectionMode.Loose} minZoom={0.35} maxZoom={1.8}
      autoPanOnNodeDrag={false}
      nodesDraggable={tool === "select"} nodesConnectable={tool === "link"}
      onInit={(instance) => { flowRef.current = instance; }} onConnect={connect}
      onNodeDragStop={(_, node) => onLayoutChange(node.id, node.position)}
      onNodeClick={(_, node) => onSelect(node.id)}
      onEdgeClick={(_, edge) => {
        if (tool === "link") {
          const data = edge.data as { up?: boolean } | undefined;
          onLinkToggle(edge.id, !data?.up);
        } else {
          // Link selection opens its property inspector. Administrative
          // toggling remains an explicit link-tool action and cannot occur from
          // an ordinary selection click.
          onSelect(edge.id);
        }
      }} proOptions={{ hideAttribution: true }}>
      <Background color="#2a2630" gap={22} size={1} />
      <Controls showInteractive={false} />
    </ReactFlow>
  </div>;
}
