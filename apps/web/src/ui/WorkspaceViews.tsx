// Secondary workspaces for the router lab. These panels edit portable project
// intent or invoke typed runtime operations supplied by App. No view assembles
// management protocol strings or fabricates operational device state.

import { GENERATED_PROFILE, type HostConfig, type LabProject,
  type RunningConfig, type RuntimeSnapshot } from "@router-simulator/contracts";
import type { ChangeEvent, RefObject } from "react";

export type WorkspaceView = "topology" | "devices" | "captures" | "configs" |
  "snapshots" | "notes" | "settings";

interface DevicesProps {
  project: LabProject;
  snapshot?: RuntimeSnapshot;
  onInspect(id: string): void;
  onConsole(): void;
}

export function DevicesWorkspace({ project, snapshot, onInspect, onConsole }: DevicesProps) {
  // Inventory rows are projections of actual project and runtime objects. A
  // row opens the same inspector used by the canvas, so this is navigation to
  // one owner rather than a second configuration surface.
  const routerId = GENERATED_PROFILE.uiDefaults.router_id;
  // Runtime availability is not inferred from port carrier. A healthy router
  // remains running while every network port is administratively down.
  const routerUp = snapshot?.status === "ready";
  return (
    <section className="workspace-page devices-page" aria-labelledby="devices-title">
      <header className="workspace-page-head"><div><span>INVENTORY</span><h1 id="devices-title">Devices</h1></div><button onClick={onConsole}>Open console</button></header>
      <div className="device-table" role="list">
        <div role="listitem"><button onClick={() => onInspect(routerId)}>
          <span className="inventory-icon router">R</span><strong>{project.runningConfig.systemName}</strong>
          <small>{GENERATED_PROFILE.chassis}</small><b className={routerUp ? "good" : "muted"}>{routerUp ? "Running" : "Unavailable"}</b>
        </button></div>
        {project.hosts.map((host) => <div role="listitem" key={host.id}><button onClick={() => onInspect(host.id)}>
          <span className="inventory-icon">H</span><strong>{host.name}</strong><small>{host.address}</small><b className="good">Configured</b>
        </button></div>)}
      </div>
    </section>
  );
}

interface CaptureProps {
  snapshot?: RuntimeSnapshot;
  active: boolean;
  onToggle(): void;
  onExport(): void;
  onCheckpoint(): void;
}

export function CaptureWorkspace({ snapshot, active, onToggle, onExport, onCheckpoint }: CaptureProps) {
  // Capture counters are bounded aggregate projections. The UI never renders
  // one element per frame and export reads the binary store directly.
  return (
    <section className="workspace-page capture-page" aria-labelledby="capture-title">
      <header className="workspace-page-head"><div><span>PACKET OBSERVATION</span><h1 id="capture-title">Capture session</h1></div><b className={active ? "status-live" : "status-idle"}>{active ? "Recording" : "Stopped"}</b></header>
      <div className="metric-strip">
        <div><small>Records</small><strong>{snapshot?.captureCount ?? 0}</strong></div>
        <div><small>Dropped</small><strong>{snapshot?.captureDropped ?? 0}</strong></div>
        <div><small>Observation points</small><strong>{GENERATED_PROFILE.captureInterfaces.length}</strong></div>
      </div>
      <div className="workspace-actions"><button className="primary" onClick={onToggle}>{active ? "Stop capture" : "Start capture"}</button><button onClick={onExport}>Export PCAPNG</button><button onClick={onCheckpoint}>Export checkpoint</button></div>
      <div className="observation-list">{GENERATED_PROFILE.captureInterfaces.map((point) => <span key={point}>{point}</span>)}</div>
    </section>
  );
}

interface ConfigProps {
  config: RunningConfig;
  onChange(config: RunningConfig): void;
}

export function ConfigWorkspace({ config, onChange }: ConfigProps) {
  // Edits replace one immutable running-config draft. App validates the entire
  // project before sending one netstring-framed transaction to C++.
  // Index-based replacement is safe here because port order and identity are
  // validated profile data. The immutable replacement keeps App as the only
  // project owner and allows one schema check before crossing into C++.
  const updatePort = (index: number, patch: Partial<RunningConfig["ports"][number]>) =>
    onChange({ ...config, ports: config.ports.map((port, item) => item === index ? { ...port, ...patch } : port) });
  const updateInterface = (index: number,
    patch: Partial<RunningConfig["interfaces"][number]>) =>
    onChange({ ...config, interfaces: config.interfaces.map((value, item) =>
      item === index ? { ...value, ...patch } : value) });
  const updateRoute = (index: number, key: "prefix" | "nextHop", value: string) =>
    onChange({ ...config, staticRoutes: config.staticRoutes.map((route, item) => item === index ? { ...route, [key]: value } : route) });
  // A new row is intentionally blank. Supplying a documentation prefix or a
  // guessed next hop would silently create network intent the user never chose.
  const addRoute = () => onChange({ ...config, staticRoutes: [...config.staticRoutes,
    { prefix: "", nextHop: "" }] });
  return (
    <section className="workspace-page config-page" aria-labelledby="config-title">
      <header className="workspace-page-head"><div><span>RUNNING DATASTORE</span><h1 id="config-title">Configuration</h1></div><small>Changes apply after validation</small></header>
      <label className="field-row"><span>System name</span><input value={config.systemName} onChange={(event) => onChange({ ...config, systemName: event.target.value })} /></label>
      <h2>Physical ports</h2>
      <div className="config-grid config-grid-ports"><span>Port</span><span>Admin</span><span>MTU</span><span>Description</span>
        {config.ports.map((port, index) => <div className="config-grid-row" key={port.id}>
          <strong>{port.id}</strong><select value={port.admin} onChange={(event) => updatePort(index, { admin: event.target.value as "up" | "down" })}><option value="up">up</option><option value="down">down</option></select>
          <input type="number" min={GENERATED_PROFILE.ports.minimumMtu} max={GENERATED_PROFILE.ports.maximumMtu} value={port.mtu} onChange={(event) => updatePort(index, { mtu: Number(event.target.value) })} />
          <input value={port.description} maxLength={GENERATED_PROFILE.limits.port_description_bytes} onChange={(event) => updatePort(index, { description: event.target.value })} />
        </div>)}
      </div>
      <h2>Router interfaces</h2>
      <div className="config-grid config-grid-interfaces"><span>Interface</span><span>Admin</span><span>Port</span><span>Primary IPv4</span>
        {config.interfaces.map((item, index) => <div className="config-grid-row" key={item.name}>
          <strong>{item.name}</strong>
          <select value={item.admin} onChange={(event) => updateInterface(index, { admin: event.target.value as "up" | "down" })}><option value="up">up</option><option value="down">down</option></select>
          <select value={item.port} onChange={(event) => updateInterface(index, { port: event.target.value })}>{GENERATED_PROFILE.ports.ids.map((port) => <option key={port} value={port}>{port}</option>)}</select>
          <input value={item.address} aria-label={`${item.name} primary IPv4`} onChange={(event) => updateInterface(index, { address: event.target.value })} />
        </div>)}
      </div>
      <div className="section-heading"><h2>Static routes</h2><button disabled={config.staticRoutes.length >= GENERATED_PROFILE.resources.static_route_capacity} onClick={addRoute}>Add route</button></div>
      <div className="route-list">{config.staticRoutes.length ? config.staticRoutes.map((route, index) => <div key={`${index}-${route.prefix}`}><input aria-label="Route prefix" value={route.prefix} onChange={(event) => updateRoute(index, "prefix", event.target.value)} /><input aria-label="Route next hop" value={route.nextHop} onChange={(event) => updateRoute(index, "nextHop", event.target.value)} /><button aria-label={`Remove route ${route.prefix}`} onClick={() => onChange({ ...config, staticRoutes: config.staticRoutes.filter((_, item) => item !== index) })}>Remove</button></div>) : <p className="empty-copy">No static routes configured.</p>}</div>
    </section>
  );
}

interface SnapshotProps {
  checkpointInput: RefObject<HTMLInputElement | null>;
  onExport(): void;
  onImport(event: ChangeEvent<HTMLInputElement>): void;
}

export function SnapshotWorkspace({ checkpointInput, onExport, onImport }: SnapshotProps) {
  // The visible import action delegates to the native file input so the
  // browser retains permission ownership. Parsing and ABI validation remain in
  // persistence and RuntimeClient, never in this presentation component.
  return (
    <section className="workspace-page snapshot-page" aria-labelledby="snapshot-title">
      <header className="workspace-page-head"><div><span>RUNTIME STATE</span><h1 id="snapshot-title">Snapshots</h1></div></header>
      <div className="snapshot-card"><strong>Portable checkpoint</strong><p>Preserves configuration, hardware lifecycle, RIB, FIB and live adjacency timers for this profile.</p><div className="workspace-actions"><button className="primary" onClick={onExport}>Export checkpoint</button><button onClick={() => checkpointInput.current?.click()}>Import checkpoint</button></div><input ref={checkpointInput} hidden type="file" accept=".bin,.checkpoint,application/octet-stream" onChange={onImport} /></div>
    </section>
  );
}

export function NotesWorkspace({ value, onChange }: { value: string; onChange(value: string): void }) {
  // Notes are stored inside the validated project and therefore survive Save,
  // IndexedDB restoration and .netsim export without entering device runtime.
  return <section className="workspace-page notes-page" aria-labelledby="notes-title"><header className="workspace-page-head"><div><span>PROJECT DOCUMENT</span><h1 id="notes-title">Notes</h1></div><small>{value.length} / {GENERATED_PROFILE.limits.project_notes_bytes}</small></header><textarea value={value} maxLength={GENERATED_PROFILE.limits.project_notes_bytes} onChange={(event) => onChange(event.target.value)} placeholder="Document addressing, test intent and expected results." /></section>;
}

interface SettingsProps {
  project: LabProject;
  onChange(project: LabProject): void;
  onResetLayout(): void;
}

export function SettingsWorkspace({ project, onChange, onResetLayout }: SettingsProps) {
  // Propagation delay is physical project intent. Editing it triggers the same
  // configureLinks transaction used during restore, preserving link ownership
  // in the forwarding shard instead of timing frames in React.
  const updateDelay = (index: number, propagationDelayNs: number) => onChange({ ...project,
    links: project.links.map((link, item) => item === index ? { ...link, propagationDelayNs } : link) });
  return (
    <section className="workspace-page settings-page" aria-labelledby="settings-title">
      <header className="workspace-page-head"><div><span>LOCAL PROJECT</span><h1 id="settings-title">Settings</h1></div></header>
      <label className="field-row"><span>Project name</span><input value={project.name} maxLength={GENERATED_PROFILE.limits.project_name_bytes} onChange={(event) => onChange({ ...project, name: event.target.value })} /></label>
      <h2>Physical propagation</h2>
      {project.links.map((link, index) => <label className="field-row" key={link.id}><span>{link.routerPort}</span><input type="number" min="0" step="1" value={link.propagationDelayNs} onChange={(event) => updateDelay(index, Number(event.target.value))} /><small>ns</small></label>)}
      <h2>Workspace layout</h2>
      <label className="field-row"><span>Sidebar width</span><input type="number" min={GENERATED_PROFILE.uiDefaults.sidebar_width_min} max={GENERATED_PROFILE.uiDefaults.sidebar_width_max} value={project.layout.sidebarWidth} onChange={(event) => onChange({ ...project, layout: { ...project.layout, sidebarWidth: Number(event.target.value) } })} /><small>preferred px</small></label>
      <label className="field-row"><span>Inspector width</span><input type="number" min={GENERATED_PROFILE.uiDefaults.inspector_width_min} max={GENERATED_PROFILE.uiDefaults.inspector_width_max} value={project.layout.inspectorWidth} onChange={(event) => onChange({ ...project, layout: { ...project.layout, inspectorWidth: Number(event.target.value) } })} /><small>preferred px</small></label>
      <label className="field-row"><span>Terminal height</span><input type="number" min={GENERATED_PROFILE.uiDefaults.terminal_height_min} max={GENERATED_PROFILE.uiDefaults.terminal_height_max} value={project.layout.terminalHeight} onChange={(event) => onChange({ ...project, layout: { ...project.layout, terminalHeight: Number(event.target.value) } })} /><small>preferred px</small></label>
      <button className="secondary-action" onClick={onResetLayout}>Reset canvas layout</button>
    </section>
  );
}
