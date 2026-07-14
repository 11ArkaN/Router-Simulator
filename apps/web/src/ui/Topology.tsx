import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { GENERATED_PROFILE, type HostConfig, type RuntimeSnapshot } from "@router-simulator/contracts";
import { useMemo } from "react";

type DeviceData = { kind: "host" | "router"; title: string; subtitle: string };

function DeviceNode({ data, selected }: NodeProps<Node<DeviceData>>) {
  const router = data.kind === "router";
  return (
      <div className={`device-node ${router ? "router-node" : "host-node"} ${selected ? "selected" : ""}`}>
      <Handle type="target" position={Position.Left} id="left" />
      <div className="device-icon" aria-hidden>{router ? <span className="rack-face"><i /><i /><i /><i /><i /></span> : "H"}</div>
      <div>
        <strong>{data.title}</strong>
        <span>{data.subtitle}</span>
      </div>
      <Handle type="source" position={Position.Right} id="right" />
    </div>
  );
}

const nodeTypes = { device: DeviceNode };

interface Props {
  hosts: [HostConfig, HostConfig];
  snapshot?: RuntimeSnapshot;
  selected: string;
  onSelect(id: string): void;
}

export function Topology({ hosts, snapshot, selected, onSelect }: Props) {
  // Link and endpoint state are derived per physical segment. A failure on
  // 1/1/2 must not paint Host A's still-operational segment as down.
  const leftUp = snapshot?.ports[0]?.oper === "up";
  const rightUp = snapshot?.ports[1]?.oper === "up";
  // Snapshot nowMs changes at 2 Hz but has no visual meaning for the graph.
  // Stable object identities let React Flow retain measured node dimensions.
  // Recreating these arrays for every sample leaves nodes perpetually hidden
  // while the library repeatedly restarts its measurement pass.
  const nodes = useMemo<Node<DeviceData>[]>(() => [
    { id: "host-a", type: "device", position: { x: 80, y: 190 }, selected: selected === "host-a", data: { kind: "host", title: hosts[0].name, subtitle: hosts[0].address } },
    { id: "r1", type: "device", position: { x: 390, y: 175 }, selected: selected === "r1", data: { kind: "router", title: "R1", subtitle: GENERATED_PROFILE.chassis } },
    { id: "host-b", type: "device", position: { x: 710, y: 190 }, selected: selected === "host-b", data: { kind: "host", title: hosts[1].name, subtitle: hosts[1].address } }
  ], [hosts, selected]);
  const edges = useMemo<Edge[]>(() => [
    { id: "a-r1", source: "host-a", target: "r1", sourceHandle: "right", targetHandle: "left", className: leftUp ? "link-up" : "link-down", label: `1/1/1 · ${GENERATED_PROFILE.portSpeedMbps / 1000}G` },
    { id: "r1-b", source: "r1", target: "host-b", sourceHandle: "right", targetHandle: "left", className: rightUp ? "link-up" : "link-down", label: `1/1/2 · ${GENERATED_PROFILE.portSpeedMbps / 1000}G` }
  ], [leftUp, rightUp]);
  return (
    <div className="topology">
      <div className="canvas-toolbar"><button className="active">⌁</button><button>⊞</button><button>⌗</button><button>⛶</button></div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.6}
        maxZoom={1.6}
        nodesDraggable
        onNodeClick={(_, node) => onSelect(node.id)}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#252b2d" gap={22} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
