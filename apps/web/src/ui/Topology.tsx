// React Flow projection of the user-owned project topology. The visual DOM and
// CSS classes retain the approved interface while node, link and port identity
// now come exclusively from project format 4 and runtime snapshot ABI 6.
// Free-form text annotations share the same canvas but never reach the runtime:
// they are browser presentation intent, like node coordinates and panel sizes.

import { Background, ConnectionMode, Controls, Handle, NodeResizeControl,
  Position, ReactFlow, ResizeControlVariant, type Connection, type Edge,
  type Node, type NodeProps, type ReactFlowInstance } from "@xyflow/react";
import { ANNOTATION_LIMITS, type LabProjectV4, type LabRuntimeSnapshotV6,
  type TopologyAnnotationV4 } from "@router-simulator/contracts";
import { useCallback, useEffect, useMemo, useRef, useState,
  type CSSProperties, type MouseEvent as ReactMouseEvent } from "react";
import { Cpu, Maximize2, Monitor, MousePointer2, Scan,
  Router as RouterIcon, Type } from "lucide-react";

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

export type TopologyTool = "select" | "link" | "text";

interface Props {
  project: LabProjectV4;
  snapshot?: LabRuntimeSnapshotV6;
  selected?: string;
  onSelect(id: string): void;
  onLayoutChange(id: string, position: { x: number; y: number }): void;
  onLinkToggle(linkId: string, up: boolean): void;
  onConnect(firstNodeId: string, secondNodeId: string): void;
  onDropDevice(kind: "router" | "host", position: { x: number; y: number }): void;
  onOpenHardware(): void;
  onAnnotationCreate(position: { x: number; y: number }): void;
  onAnnotationMove(id: string, position: { x: number; y: number }): void;
  onAnnotationResize(id: string, geometry: AnnotationGeometry): void;
  onAnnotationCommitText(id: string, text: string): void;
  onAnnotationDelete(id: string): void;
  tool: TopologyTool;
  onToolChange(tool: TopologyTool): void;
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
  onLayoutChange, onLinkToggle, onConnect, onDropDevice, onOpenHardware,
  onAnnotationCreate, onAnnotationMove, onAnnotationResize,
  onAnnotationCommitText, onAnnotationDelete, tool, onToolChange }: Props) {
  const topologyRef = useRef<HTMLDivElement>(null);
  const flowRef = useRef<ReactFlowInstance<Node, Edge> | null>(null);
  // Double-click editing is a view concern local to the canvas. A freshly
  // created annotation edits itself because its text is empty, so this state
  // only tracks re-entering an existing label.
  const [editingId, setEditingId] = useState<string>();
  const annotationsRef = useRef(project.annotations);
  annotationsRef.current = project.annotations;

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

  const nodes = useMemo<Node[]>(() => [
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
    })),
    // Annotations render on top of devices so a label stays readable. They are
    // never connectable and, unlike devices, remain draggable outside the
    // select tool so a label can be repositioned while placing more of them.
    ...project.annotations.map((annotation) => ({
      id: annotation.id,
      type: "annotation",
      position: { x: annotation.x, y: annotation.y },
      selected: selected === annotation.id,
      draggable: tool !== "link" &&
        !(editingId === annotation.id || annotation.text === ""),
      connectable: false,
      data: {
        annotation,
        editing: editingId === annotation.id || annotation.text === "",
        onCommit: commitText, onCancel: cancelEdit, onResize: onAnnotationResize
      } satisfies AnnotationData
    }))
  ], [project.hosts, project.routers, project.annotations, project.layout.nodes,
    selected, snapshot?.routers, tool, editingId, commitText, cancelEdit,
    onAnnotationResize]);

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

  return <div className={`topology ${tool === "text" ? "tool-text" : ""}`} ref={topologyRef}
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
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView
      connectionMode={ConnectionMode.Loose} minZoom={0.35} maxZoom={1.8}
      autoPanOnNodeDrag={false}
      nodesDraggable={tool === "select"} nodesConnectable={tool === "link"}
      onInit={(instance) => { flowRef.current = instance; }} onConnect={connect}
      onPaneClick={placeAnnotation}
      onNodeDragStop={(_, node) => node.type === "annotation"
        ? onAnnotationMove(node.id, node.position)
        : onLayoutChange(node.id, node.position)}
      onNodeClick={(_, node) => onSelect(node.id)}
      onNodeDoubleClick={(_, node) => {
        if (node.type === "annotation") setEditingId(node.id);
      }}
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
