// React Flow projection of the user-owned project topology. The visual DOM and
// CSS classes retain the approved interface while node, link and port identity
// now come exclusively from project format 5 and runtime snapshot ABI 8.
// Free-form text annotations share the same canvas but never reach the runtime:
// they are browser presentation intent, like node coordinates and panel sizes.

import { Background, BaseEdge, ConnectionMode, Controls, EdgeLabelRenderer,
  Handle, NodeResizeControl, Position, ReactFlow, ResizeControlVariant,
  getStraightPath, useNodesState, useUpdateNodeInternals,
  type Connection, type Edge,
  type EdgeProps, type Node, type NodeProps,
  type ReactFlowInstance } from "@xyflow/react";
import { ANNOTATION_LIMITS, type LabProjectV4, type LabRuntimeSnapshotV6,
  type TopologyAnnotationV4 } from "@router-simulator/contracts";
import { useCallback, useEffect, useMemo, useRef, useState,
  type CSSProperties, type MouseEvent as ReactMouseEvent } from "react";
import { Cpu, Maximize2, Scan, Type } from "lucide-react";
import { edgePortLabelPoints, radialHandleSide, radialLinkAnchors,
  type RadialLinkAnchor } from "./topology-anchors";

type DeviceData = { kind: "host" | "router" | "dhcp-server" | "switch";
  title: string; subtitle: string;
  diameter: number; anchors: readonly RadialLinkAnchor[] };

const HANDLE_POSITION = {
  top: Position.Top,
  right: Position.Right,
  bottom: Position.Bottom,
  left: Position.Left,
} as const;

function DeviceNode({ id, data, selected }: NodeProps<Node<DeviceData>>) {
  const updateNodeInternals = useUpdateNodeInternals();
  useEffect(() => {
    // React Flow caches handle coordinates. Re-measure after a node moves or a
    // link is added so its straight path terminates at the newly rotated point
    // rather than the previous side of the circle.
    updateNodeInternals(id);
  }, [data.anchors, id, updateNodeInternals]);
  const router = data.kind === "router";
  const dhcpServer = data.kind === "dhcp-server";
  const ethernetSwitch = data.kind === "switch";
  return <div className={`device-node ${router ? "router-node" :
    ethernetSwitch ? "switch-node" :
      dhcpServer ? "dhcp-server-node" : "host-node"} ${selected ? "selected" : ""}`}
    style={{ width: data.diameter, height: data.diameter }}>
    {/* Link creation owns one small rim target instead of covering the symbol.
        This separation lets the symbol drag the device while the target starts
        a connection, with no global interaction mode or pointer ambiguity. */}
    <Handle type="source" position={Position.Right} id="connect"
      className="device-connect-handle" title="Drag to connect" />
    {data.anchors.map((anchor) => <Handle key={anchor.linkId} type="source"
      position={HANDLE_POSITION[radialHandleSide(anchor.angleDegrees)]}
      id={`edge-${anchor.linkId}`}
      className="device-link-handle" style={{
        left: `${anchor.leftPercent}%`, top: `${anchor.topPercent}%`,
        right: "auto", bottom: "auto",
        transform: `translate(-50%, -50%) rotate(${anchor.angleDegrees}deg)`,
      }} />)}
    {/* These project-owned, vendor-neutral diagram symbols intentionally live
        below the attachment handles. A new device class can select another
        asset without changing edge routing or the physical-port model. */}
    <img className="device-icon" aria-hidden alt="" draggable={false}
      src={router ? "/assets/topology/router-diagram.png" :
        ethernetSwitch ? "/assets/topology/switch-diagram.png" :
          "/assets/topology/host-diagram.png"} />
    <div className="device-copy"><strong>{data.title}</strong><span>{data.subtitle}</span></div>
  </div>;
}

interface AnnotationGeometry { x: number; y: number; width: number }

type AnnotationData = {
  annotation: TopologyAnnotationV4;
  // Editing is derived state: an empty annotation edits itself so a freshly
  // placed label is immediately typeable, while an existing one enters edit on
  // an explicit double-click. Both share one committed exit path.
  editing: boolean;
  onCommit(id: string, text: string): void;
  onCancel(id: string): void;
  onResize(id: string, geometry: AnnotationGeometry): void;
};

function AnnotationNode({ id, data, selected }:
  NodeProps<Node<AnnotationData>>) {
  const { annotation, editing, onCommit, onCancel, onResize } = data;
  const inputRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    // Focus and place the caret at the end whenever the box enters edit mode.
    // The textarea is uncontrolled so re-renders from unrelated canvas state
    // cannot move the caret while the user is typing.
    if (!editing) return;
    const element = inputRef.current;
    if (!element) return;
    element.focus();
    element.setSelectionRange(element.value.length, element.value.length);
  }, [editing]);

  const style: CSSProperties = {
    width: annotation.width,
    fontSize: annotation.fontSize,
    fontWeight: annotation.bold ? 700 : 400,
    fontStyle: annotation.italic ? "italic" : "normal",
    textAlign: annotation.align,
    color: annotation.color,
    ...(annotation.background ? { background: annotation.background } : {})
  };
  const resizeHandle = (position: "left" | "right") =>
    <NodeResizeControl className="annotation-resizer" position={position}
      variant={ResizeControlVariant.Line} minWidth={ANNOTATION_LIMITS.minWidth}
      maxWidth={ANNOTATION_LIMITS.maxWidth}
      onResizeEnd={(_, params) => onResize(id,
        { x: params.x, y: params.y, width: params.width })} />;

  return <div className={`annotation-node ${selected ? "selected" : ""} ${annotation.border ? "bordered" : ""} ${editing ? "editing" : ""}`} style={style}>
    {selected && !editing && <>{resizeHandle("left")}{resizeHandle("right")}</>}
    {editing
      ? <textarea ref={inputRef} className="annotation-input nodrag nowheel"
          defaultValue={annotation.text} rows={1} spellCheck={false}
          maxLength={1000} placeholder="Type a label…"
          onPointerDown={(event) => event.stopPropagation()}
          onBlur={(event) => onCommit(id, event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Escape") { event.preventDefault(); onCancel(id); }
            else if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
              event.preventDefault();
              onCommit(id, event.currentTarget.value);
            }
          }} />
      : <div className="annotation-text">{annotation.text}</div>}
  </div>;
}

const nodeTypes = { device: DeviceNode, annotation: AnnotationNode };

type PhysicalLinkData = { sourcePort: string; targetPort: string };

function PhysicalLinkEdge({ id, sourceX, sourceY, targetX, targetY,
  markerEnd, style, data }: EdgeProps<Edge<PhysicalLinkData>>) {
  const [path] = getStraightPath({ sourceX, sourceY, targetX, targetY });
  const [sourceLabel, targetLabel] = edgePortLabelPoints(
    { x: sourceX, y: sourceY }, { x: targetX, y: targetY });
  const label = (portId: string, point: { x: number; y: number }, side: string) =>
    <span className={`edge-port-label ${side}`} style={{
      transform: `translate(-50%, -50%) translate(${point.x}px, ${point.y}px)`
    }}>{portId}</span>;

  return <>
    <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />
    <EdgeLabelRenderer>
      {label(data?.sourcePort ?? "", sourceLabel, "source")}
      {label(data?.targetPort ?? "", targetLabel, "target")}
    </EdgeLabelRenderer>
  </>;
}

const edgeTypes = { physical: PhysicalLinkEdge };

export type TopologyTool = "select" | "link" | "text";

const DEVICE_DIAMETER = {
  host: 98, router: 112, dhcpServer: 104, switch: 112
} as const;
const DEVICE_ANCHOR_RADIUS = {
  // The values follow the non-transparent alpha bounds of the generated PNGs,
  // with a small outward allowance so the solid port marker stays readable.
  host: { xPercent: 40, yPercent: 37 },
  router: { xPercent: 43, yPercent: 30 },
  dhcpServer: { xPercent: 40, yPercent: 37 },
  switch: { xPercent: 43, yPercent: 30 },
} as const;

interface Props {
  project: LabProjectV4;
  snapshot?: LabRuntimeSnapshotV6;
  selected?: string;
  onSelect(id: string): void;
  onLayoutChange(id: string, position: { x: number; y: number }): void;
  onConnect(firstNodeId: string, secondNodeId: string): void;
  onDropDevice(kind: "router" | "dhcp-server" | "host" | "switch",
    position: { x: number; y: number }): void;
  onOpenHardware(): void;
  onAnnotationCreate(position: { x: number; y: number }): void;
  onAnnotationMove(id: string, position: { x: number; y: number }): void;
  onAnnotationResize(id: string, geometry: AnnotationGeometry): void;
  onAnnotationCommitText(id: string, text: string): void;
  onAnnotationDelete(id: string): void;
  tool: TopologyTool;
  onToolChange(tool: TopologyTool): void;
}

export function Topology({ project, snapshot, selected, onSelect,
  onLayoutChange, onConnect, onDropDevice, onOpenHardware,
  onAnnotationCreate, onAnnotationMove, onAnnotationResize,
  onAnnotationCommitText, onAnnotationDelete, tool, onToolChange }: Props) {
  const topologyRef = useRef<HTMLDivElement>(null);
  const flowRef = useRef<ReactFlowInstance<Node, Edge> | null>(null);
  // Double-click editing is a view concern local to the canvas. A freshly
  // created annotation edits itself because its text is empty, so this state
  // only tracks re-entering an existing label.
  const [editingId, setEditingId] = useState<string>();
  // The ref marks the only node whose local React Flow coordinate may override
  // project input. It does not trigger renders and cannot become another owner
  // of durable layout state.
  const draggingNodeId = useRef<string | undefined>(undefined);
  const annotationsRef = useRef(project.annotations);
  annotationsRef.current = project.annotations;

  useEffect(() => {
    // Link and text placement are one-shot operations, not global canvas
    // modes. Escape always restores the normal drag-and-pan interaction.
    if (tool === "select") return;
    const cancelTransientTool = (event: KeyboardEvent) => {
      if (event.key === "Escape") onToolChange("select");
    };
    window.addEventListener("keydown", cancelTransientTool);
    return () => window.removeEventListener("keydown", cancelTransientTool);
  }, [tool, onToolChange]);

  const commitText = useCallback((id: string, text: string) => {
    // A label emptied by the user is a request to remove it. Non-blank text is
    // preserved verbatim, including its internal line breaks.
    if (text.trim() === "") onAnnotationDelete(id);
    else onAnnotationCommitText(id, text);
    setEditingId((current) => current === id ? undefined : current);
  }, [onAnnotationCommitText, onAnnotationDelete]);

  const cancelEdit = useCallback((id: string) => {
    // Escaping a never-typed placeholder discards it; escaping an existing
    // label keeps its stored text and simply leaves edit mode.
    const annotation = annotationsRef.current.find((item) => item.id === id);
    if (annotation && annotation.text === "") onAnnotationDelete(id);
    setEditingId((current) => current === id ? undefined : current);
  }, [onAnnotationDelete]);

  const devicePositions = useMemo(() => Object.fromEntries([
    ...project.hosts.map((host, index) => [host.id,
      project.layout.nodes[host.id] ??
        { x: 100, y: 160 + index * 130 }] as const),
    ...project.routers.map((router, index) => [router.id,
      project.layout.nodes[router.id] ??
        { x: 340 + index * 210, y: 240 }] as const),
    ...project.dhcpServers.map((server, index) => [server.id,
      project.layout.nodes[server.id] ??
        { x: 340 + index * 210, y: 560 }] as const),
    ...project.switches.map((ethernetSwitch, index) => [ethernetSwitch.id,
      project.layout.nodes[ethernetSwitch.id] ??
        { x: 340 + index * 210, y: 420 }] as const),
  ]), [project.hosts, project.routers, project.dhcpServers, project.switches,
    project.layout.nodes]);
  const deviceCenters = useMemo(() => Object.fromEntries([
    ...project.hosts.map((host) => [host.id, {
      x: devicePositions[host.id].x + DEVICE_DIAMETER.host / 2,
      y: devicePositions[host.id].y + DEVICE_DIAMETER.host / 2,
    }] as const),
    ...project.routers.map((router) => [router.id, {
      x: devicePositions[router.id].x + DEVICE_DIAMETER.router / 2,
      y: devicePositions[router.id].y + DEVICE_DIAMETER.router / 2,
    }] as const),
    ...project.dhcpServers.map((server) => [server.id, {
      x: devicePositions[server.id].x + DEVICE_DIAMETER.dhcpServer / 2,
      y: devicePositions[server.id].y + DEVICE_DIAMETER.dhcpServer / 2,
    }] as const),
    ...project.switches.map((ethernetSwitch) => [ethernetSwitch.id, {
      x: devicePositions[ethernetSwitch.id].x + DEVICE_DIAMETER.switch / 2,
      y: devicePositions[ethernetSwitch.id].y + DEVICE_DIAMETER.switch / 2,
    }] as const),
  ]), [project.hosts, project.routers, project.dhcpServers, project.switches,
    devicePositions]);

  const projectedNodes = useMemo<Node[]>(() => [
    ...project.hosts.map((host) => ({
      id: host.id,
      type: "device",
      position: devicePositions[host.id],
      selected: selected === host.id,
      data: { kind: "host" as const, title: host.name, subtitle: host.eth0.address,
        diameter: DEVICE_DIAMETER.host,
        anchors: radialLinkAnchors(host.id, deviceCenters, project.links,
          DEVICE_ANCHOR_RADIUS.host) }
    })),
    ...project.routers.map((router) => ({
      id: router.id,
      type: "device",
      position: devicePositions[router.id],
      selected: selected === router.id,
      data: { kind: "router" as const, title: router.systemName,
        subtitle: snapshot?.routers.find((item) => item.id === router.id)?.chassis ?? router.profileId,
        diameter: DEVICE_DIAMETER.router,
        anchors: radialLinkAnchors(router.id, deviceCenters, project.links,
          DEVICE_ANCHOR_RADIUS.router) }
    })),
    ...project.dhcpServers.map((server) => ({
      id: server.id,
      type: "device",
      position: devicePositions[server.id],
      selected: selected === server.id,
      data: { kind: "dhcp-server" as const, title: server.name,
        subtitle: "Dedicated DHCP server",
        diameter: DEVICE_DIAMETER.dhcpServer,
        anchors: radialLinkAnchors(server.id, deviceCenters, project.links,
          DEVICE_ANCHOR_RADIUS.dhcpServer) }
    })),
    ...project.switches.map((ethernetSwitch) => ({
      id: ethernetSwitch.id,
      type: "device",
      position: devicePositions[ethernetSwitch.id],
      selected: selected === ethernetSwitch.id,
      data: { kind: "switch" as const, title: ethernetSwitch.name,
        subtitle: ethernetSwitch.profileId,
        diameter: DEVICE_DIAMETER.switch,
        anchors: radialLinkAnchors(ethernetSwitch.id, deviceCenters,
          project.links, DEVICE_ANCHOR_RADIUS.switch) }
    })),
    // Annotations render on top of devices so a label stays readable. They are
    // never connectable. Editing temporarily owns pointer input; otherwise a
    // label remains draggable under the same always-on canvas interaction.
    ...project.annotations.map((annotation) => ({
      id: annotation.id,
      type: "annotation",
      position: { x: annotation.x, y: annotation.y },
      selected: selected === annotation.id,
      draggable: !(editingId === annotation.id || annotation.text === ""),
      connectable: false,
      data: {
        annotation,
        editing: editingId === annotation.id || annotation.text === "",
        onCommit: commitText, onCancel: cancelEdit, onResize: onAnnotationResize
      } satisfies AnnotationData
    }))
  ], [project.hosts, project.routers, project.dhcpServers, project.switches,
    project.annotations,
    project.links,
    devicePositions, deviceCenters,
    selected, snapshot?.routers, snapshot?.dhcpServers, tool, editingId,
    commitText, cancelEdit,
    onAnnotationResize]);

  const [nodes, setNodes, onNodesChange] = useNodesState(projectedNodes);
  useEffect(() => {
    // Project and telemetry renders still refresh labels, hardware subtitles,
    // selection and link handles. While a node is being dragged, merge those
    // fields with React Flow's latest pointer coordinate instead of replacing
    // it with the last persisted drop coordinate.
    setNodes((current) => {
      const currentById = new Map(current.map((node) => [node.id, node]));
      return projectedNodes.map((projected) => {
        const local = currentById.get(projected.id);
        return draggingNodeId.current === projected.id && local
          ? { ...projected, position: local.position }
          : projected;
      });
    });
  }, [projectedNodes, setNodes]);

  const edges = useMemo<Edge[]>(() => project.links.map((link) => {
    // Carrier and effective media rate are link-owned runtime facts. Deriving
    // them from visible router ports incorrectly marks host-host media and can
    // combine two observations from different supervisor turns.
    const live = snapshot?.links.find((item) => item.id === link.id);
    const up = Boolean(live?.carrier);
    return {
      id: link.id,
      source: link.endpoints[0].nodeId,
      target: link.endpoints[1].nodeId,
      sourceHandle: `edge-${link.id}`,
      targetHandle: `edge-${link.id}`,
      type: "physical",
      className: up ? "link-up" : "link-down",
      selected: selected === link.id,
      data: {
        sourcePort: link.endpoints[0].portId,
        targetPort: link.endpoints[1].portId,
      }
    };
  }), [project.links, project.layout.nodes, snapshot?.links, selected]);

  const connect = (connection: Connection) => {
    // React Flow supplies stable node identities only. App opens the catalog
    // backed free-port chooser and never guesses a physical endpoint.
    if (connection.source && connection.target && connection.source !== connection.target) {
      onConnect(connection.source, connection.target);
    }
  };

  const placeAnnotation = (event: ReactMouseEvent) => {
    // A pane click in text mode drops a label at the cursor, then returns to
    // the select tool so the very next click does not spawn a second empty box
    // and orphan the one still being typed.
    if (tool !== "text" || !flowRef.current) return;
    onAnnotationCreate(flowRef.current.screenToFlowPosition({
      x: event.clientX, y: event.clientY
    }));
    onToolChange("select");
  };

  return <div className={`topology ${tool === "text" ? "tool-text" : ""} ${tool === "link" ? "tool-link" : ""}`} ref={topologyRef}
    onDragOver={(event) => {
      if (event.dataTransfer.types.includes("application/x-router-lab-device")) {
        event.preventDefault();
        event.dataTransfer.dropEffect = "copy";
      }
    }}
    onDrop={(event) => {
      const kind = event.dataTransfer.getData("application/x-router-lab-device");
       if ((kind === "router" || kind === "dhcp-server" ||
            kind === "host" || kind === "switch") &&
          flowRef.current) {
        event.preventDefault();
        // React Flow owns zoom and pan transforms. Converting through its API
        // prevents dropped nodes from shifting when the canvas is not at 100%.
        onDropDevice(kind, flowRef.current.screenToFlowPosition({
          x: event.clientX, y: event.clientY
        }));
      }
    }}>
    <div className="canvas-toolbar" aria-label="Topology tools">
      <button className={tool === "text" ? "active" : ""} title="Add a text annotation" aria-label="Add a text annotation" onClick={() => onToolChange(tool === "text" ? "select" : "text")}><Type size={17} /></button>
      <button title="Open router hardware" aria-label="Open router hardware" onClick={onOpenHardware}><Cpu size={17} /></button>
      <button title="Fit topology" aria-label="Fit topology" onClick={() => void flowRef.current?.fitView({ padding: 0.22, duration: 260 })}><Scan size={17} /></button>
      <button title="Fullscreen topology" aria-label="Fullscreen topology" onClick={() => void (document.fullscreenElement ? document.exitFullscreen() : topologyRef.current?.requestFullscreen())}><Maximize2 size={16} /></button>
    </div>
    {tool === "text" && <div className="canvas-hint" role="status">Click the canvas to place a text label. Double-click any label to edit it.</div>}
    {/* React Flow enables edge-triggered camera movement by default. A large
        lab makes that default harmful: moving a node near the canvas border
        changes the coordinate transform underneath the pointer and shifts
        every later placement. Keep the camera under explicit pan/zoom control
        so a drag has one stable screen-to-flow transform from start to stop. */}
    {/* The camera is user-owned state. The former fitView prop could refit
        after node initialization changed, making the whole topology appear
        to move when one device was added. Initial coordinates are already
        visible in the project layout and explicit fitting remains available
        through the toolbar button. */}
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      connectionMode={ConnectionMode.Loose} minZoom={0.35} maxZoom={1.8}
      autoPanOnNodeDrag={false} panOnDrag nodesDraggable
      nodesConnectable={tool === "link"}
      onInit={(instance) => { flowRef.current = instance; }} onConnect={connect}
      onPaneClick={placeAnnotation}
      onMoveStart={() => { if (tool === "text") onToolChange("select"); }}
      onNodeDragStart={(_, node) => {
        // From this point onNodesChange owns the live coordinate. Parent
        // refreshes may update every other node field but preserve this value.
        draggingNodeId.current = node.id;
        onToolChange("select");
      }}
      onNodeDragStop={(_, node) => {
        // The stop event is authoritative. The parent becomes the durable
        // owner with one write, avoiding persistence work at pointer frequency.
        if (node.type === "annotation")
          onAnnotationMove(node.id, node.position);
        else onLayoutChange(node.id, node.position);
        draggingNodeId.current = undefined;
      }}
      onNodesChange={onNodesChange}
      onNodeClick={(_, node) => onSelect(node.id)}
      onNodeDoubleClick={(_, node) => {
        if (node.type === "annotation") setEditingId(node.id);
      }}
      onEdgeClick={(_, edge) => {
        // Edge clicks only select. Link administration remains an explicit
        // inspector operation, preventing an attempted canvas pan from
        // silently changing carrier state.
        onSelect(edge.id);
      }} proOptions={{ hideAttribution: true }}>
      <Background color="#2a2630" gap={22} size={1} />
      <Controls showInteractive={false} />
    </ReactFlow>
  </div>;
}
