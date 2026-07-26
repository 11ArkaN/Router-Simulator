// Secondary workspace panels for project format 4. Their established markup
// and CSS classes remain unchanged; only data contracts now address arbitrary
// router and host collections instead of a hidden singleton router.

import { PROFILE_CATALOG, type LabProjectV4, type LabRuntimeSnapshotV6,
  type RouterProjectV4 } from "@router-simulator/contracts";
import { useEffect, useState, type ChangeEvent, type RefObject } from "react";
import { VirtualizedList } from "./VirtualizedList";
import type { DemoLabId, DemoLabOption } from "./demo-catalog";
import { Monitor, Router as RouterIcon } from "lucide-react";

export type WorkspaceView = "topology" | "demos" | "devices" | "captures" |
  "configs" | "snapshots" | "notes" | "settings";

export function DemosWorkspace({ demos, pendingDemoId, onLaunch }: {
  demos: readonly DemoLabOption[];
  pendingDemoId?: DemoLabId;
  onLaunch(id: DemoLabId): void;
}) {
  const icon = (kind: "host" | "router") =>
    kind === "host" ? "/assets/topology/host-diagram.png" :
      "/assets/topology/router-diagram.png";
  return <section className="workspace-page demos-page" aria-labelledby="demos-title">
    <header className="workspace-page-head"><div><span>READY LABS</span><h1 id="demos-title">Demos</h1></div></header>
    <div className="demo-grid">{demos.map((demo) => <article className="demo-card" key={demo.id}>
      <div className="demo-card-head"><div><span>{demo.eyebrow}</span><h2>{demo.title}</h2></div><b>{demo.counts.devices} devices</b></div>
      <div className="demo-topology-strip" aria-hidden>{demo.topology.map((kind, index) =>
        <span className={`demo-symbol ${kind}`} key={`${demo.id}-${index}`}><img src={icon(kind)} alt="" draggable={false} /></span>)}</div>
      <p>{demo.summary}</p>
      <dl className="demo-facts"><div><dt>Links</dt><dd>{demo.counts.links}</dd></div><div><dt>Check</dt><dd>{demo.checkTarget}</dd></div></dl>
      <div className="workspace-actions"><button className="primary" disabled={pendingDemoId === demo.id} onClick={() => onLaunch(demo.id)}>{pendingDemoId === demo.id ? "Loading" : "Launch demo"}</button></div>
    </article>)}</div>
  </section>;
}

export function DevicesWorkspace({ project, snapshot, onInspect, onConsole }: {
  project: LabProjectV4; snapshot?: LabRuntimeSnapshotV6;
  onInspect(id: string): void; onConsole(id: string): void;
}) {
  const devices = [
    ...project.routers.map((router) => ({ kind: "router" as const, router })),
    ...project.hosts.map((host) => ({ kind: "host" as const, host }))
  ];
  return <section className="workspace-page devices-page" aria-labelledby="devices-title">
    <header className="workspace-page-head"><div><span>INVENTORY</span><h1 id="devices-title">Devices</h1></div></header>
    <VirtualizedList className="device-table" items={devices} itemHeight={63}
      itemKey={(item) => item.kind === "router" ? item.router.id : item.host.id}
      renderItem={(item) => {
        if (item.kind === "host") return <button onClick={() =>
          onInspect(item.host.id)}><span className="inventory-icon"><Monitor size={16} /></span>
          <strong>{item.host.name}</strong><small>{item.host.eth0.address}</small>
          <b className="good">Configured</b></button>;
        const live = snapshot?.routers.find((value) =>
          value.id === item.router.id);
        return <button onDoubleClick={() => onConsole(item.router.id)}
          onClick={() => onInspect(item.router.id)}><span
            className="inventory-icon router"><RouterIcon size={16} /></span>
          <strong>{item.router.systemName}</strong>
          <small>{live?.chassis ?? item.router.profileId}</small>
          <b className={live ? "good" : "muted"}>{live
            ? "Running" : "Unavailable"}</b></button>;
      }} />
  </section>;
}

type CaptureKind = "link-direction" | "router-ingress" | "router-egress" |
  "cpm-punt";

export function CaptureWorkspace({ project, snapshot, selections, onSelection,
  onToggle, onExport, onCheckpoint }: {
  project: LabProjectV4; snapshot?: LabRuntimeSnapshotV6;
  selections: readonly string[];
  onSelection(kind: CaptureKind, objectId: string, portId: string,
    direction: 0 | 1, selected: boolean): void;
  onToggle(): void; onExport(): void; onCheckpoint(): void;
}) {
  const active = selections.length > 0;
  const selected = (kind: CaptureKind, objectId: string, portId: string,
    direction: 0 | 1) => selections.includes(
      `${kind}:${objectId}:${portId}:${direction}`);
  const point = (label: string, kind: CaptureKind, objectId: string,
    portId: string, direction: 0 | 1) => {
    const enabled = selected(kind, objectId, portId, direction);
    return <button className={enabled ? "capture-point selected" : "capture-point"}
      onClick={() => onSelection(kind, objectId, portId, direction, !enabled)}>
      <i />{label}<span>{enabled ? "recording" : "off"}</span>
    </button>;
  };
  return <section className="workspace-page capture-page" aria-labelledby="capture-title">
    <header className="workspace-page-head"><div><span>PACKET OBSERVATION</span><h1 id="capture-title">Capture session</h1></div><b className={active ? "status-live" : "status-idle"}>{active ? "Recording" : "Stopped"}</b></header>
    <div className="metric-strip"><div><small>Records</small><strong>{snapshot?.capturedFrames ?? 0}</strong></div><div><small>Dropped</small><strong>{snapshot?.captureDropped ?? 0}</strong></div><div><small>Active links</small><strong>{snapshot?.activeLinks ?? 0}</strong></div></div>
    <div className="workspace-actions"><button className="primary" onClick={onToggle}>{active ? "Stop capture" : "Start capture"}</button><button onClick={onExport}>Export PCAPNG</button><button onClick={onCheckpoint}>Export checkpoint</button></div>
    <div className="capture-tree">
      <section><h2>Physical links</h2>{project.links.length ? project.links.map((link) => <div className="capture-group" key={link.id}><strong>{link.id}</strong><small>{link.endpoints[0].nodeId} / {link.endpoints[0].portId} to {link.endpoints[1].nodeId} / {link.endpoints[1].portId}</small><div>{point("First to second", "link-direction", link.id, "", 0)}{point("Second to first", "link-direction", link.id, "", 1)}</div></div>) : <p className="empty-copy">No physical links are configured.</p>}</section>
      <section><h2>Routers</h2>{project.routers.map((router) => { const live = snapshot?.routers.find((item) => item.id === router.id); return <div className="capture-group" key={router.id}><strong>{router.systemName}</strong><div>{point("CPM punt", "cpm-punt", router.id, "", 0)}</div>{live?.ports.map((port) => <div className="capture-port" key={port.id}><small>{port.id}</small><div>{point("Ingress", "router-ingress", router.id, port.id, 0)}{point("Egress", "router-egress", router.id, port.id, 0)}</div></div>)}</div>; })}</section>
    </div>
  </section>;
}

export function ConfigWorkspace({ router, onChange }: {
  router?: RouterProjectV4; onChange(router: RouterProjectV4): void;
}) {
  const [draft, setDraft] = useState<RouterProjectV4>();
  useEffect(() => {
    // A router selection or accepted runtime mutation becomes the new editing
    // baseline. Keystrokes remain local until Apply, so temporarily incomplete
    // IPv4 and MAC strings never cross the validated project boundary.
    setDraft(router ? structuredClone(router) : undefined);
  }, [router]);
  if (!router) return <section className="workspace-page config-page"><header className="workspace-page-head"><div><span>RUNNING DATASTORE</span><h1>Configuration</h1></div></header><p className="empty-copy">Select a router to edit its configuration.</p></section>;
  if (!draft) return null;
  const config = draft.running;
  const update = (running: RouterProjectV4["running"]) => setDraft({ ...draft,
    systemName: running.systemName, running });
  const updatePort = (index: number, patch: Partial<typeof config.ports[number]>) =>
    update({ ...config, ports: config.ports.map((port, item) => item === index ? { ...port, ...patch } : port) });
  const updateInterface = (index: number, patch: Partial<typeof config.interfaces[number]>) =>
    update({ ...config, interfaces: config.interfaces.map((value, item) => item === index ? { ...value, ...patch } : value) });
  const primaryIpv6Address = (index: number) => {
    const addresses = config.interfaces[index].ipv6Addresses;
    return addresses.reduce<typeof addresses[number] | undefined>(
      (selected, address) => !selected ||
          address.primaryPreference < selected.primaryPreference
        ? address : selected, undefined)?.address ?? "";
  };
  const updatePrimaryIpv6Address = (index: number, address: string) => {
    const current = config.interfaces[index];
    if (!address) {
      updateInterface(index, { ipv6Addresses: [] });
      return;
    }
    const addresses = current.ipv6Addresses.map((value) => ({ ...value }));
    if (!addresses.length) {
      addresses.push({ address, duplicateAddressDetection: true, eui64: false,
        eui64SourceMac: null,
        primaryPreference: 0, tag: null });
    } else {
      let selected = 0;
      for (let candidate = 1; candidate < addresses.length; ++candidate)
        if (addresses[candidate].primaryPreference <
            addresses[selected].primaryPreference) selected = candidate;
      addresses[selected].address = address;
    }
    updateInterface(index, { ipv6Addresses: addresses });
  };
  const updateRoute = (index: number,
    patch: Partial<typeof config.staticRoutes[number]>) =>
    update({ ...config, staticRoutes: config.staticRoutes.map((route, item) =>
      item === index ? { ...route, ...patch } : route) });
  const updateIpv6Route = (index: number,
    patch: Partial<typeof config.ipv6StaticRoutes[number]>) =>
    update({ ...config, ipv6StaticRoutes: config.ipv6StaticRoutes.map(
      (route, item) => item === index ? { ...route, ...patch } : route) });
  // Both route sections retain the existing visible control text. Distinct
  // accessible names identify the address family to keyboard automation and
  // assistive technology without changing the established visual design.
  return <section className="workspace-page config-page" aria-labelledby="config-title">
    <header className="workspace-page-head"><div><span>RUNNING DATASTORE</span><h1 id="config-title">Configuration</h1></div><div className="workspace-actions"><button onClick={() => setDraft(structuredClone(router))}>Discard</button><button className="primary" onClick={() => onChange(draft)}>Apply</button></div></header>
    <label className="field-row"><span>System name</span><input value={config.systemName} onChange={(event) => update({ ...config, systemName: event.target.value })} /></label>
    <label className="field-row"><span>Maximum ECMP routes</span><input type="number" min={1} max={PROFILE_CATALOG.runtime.maximum_ecmp_paths} value={config.maximumEcmpPaths} onChange={(event) => update({ ...config, maximumEcmpPaths: Number(event.target.value) })} /></label>
    <h2>Physical ports</h2><div className="config-grid config-grid-ports"><span>Port</span><span>Admin</span><span>MTU</span><span>Description</span>{config.ports.map((port, index) => <div className="config-grid-row" key={port.id}><strong>{port.id}</strong><select value={port.admin} onChange={(event) => updatePort(index, { admin: event.target.value as "up" | "down" })}><option value="up">up</option><option value="down">down</option></select><input type="number" min={PROFILE_CATALOG.ethernet.minimum_network_mtu} max={PROFILE_CATALOG.ethernet.maximum_network_mtu} value={port.mtu} onChange={(event) => updatePort(index, { mtu: Number(event.target.value) })} /><input value={port.description} maxLength={80} onChange={(event) => updatePort(index, { description: event.target.value })} /></div>)}</div>
    <div className="section-heading"><h2>Router interfaces</h2><button onClick={() => update({ ...config, interfaces: [...config.interfaces, { name: "", admin: "down", portId: "", address: "", arpTimeoutSeconds: null, arpRetryTimerDeciseconds: null, ipv6Addresses: [] }] })}>Add interface</button></div><div className="config-grid config-grid-interfaces"><span>Interface</span><span>Admin</span><span>Port</span><span>Addresses</span>{config.interfaces.map((item, index) => <div className="config-grid-row config-interface-row" key={index}><input placeholder="Interface name" value={item.name} onChange={(event) => updateInterface(index, { name: event.target.value })} /><select value={item.admin} onChange={(event) => updateInterface(index, { admin: event.target.value as "up" | "down" })}><option value="up">up</option><option value="down">down</option></select><select value={item.portId} onChange={(event) => updateInterface(index, { portId: event.target.value })}><option value="">No port</option>{config.ports.map((port) => <option key={port.id}>{port.id}</option>)}</select><div className="interface-address-fields"><input placeholder="IPv4 prefix" value={item.address} onChange={(event) => updateInterface(index, { address: event.target.value })} /><input placeholder="IPv6 prefix" value={primaryIpv6Address(index)} onChange={(event) => updatePrimaryIpv6Address(index, event.target.value)} /><button onClick={() => update({ ...config, interfaces: config.interfaces.filter((_, itemIndex) => itemIndex !== index) })}>Remove</button></div></div>)}</div>
    <div className="section-heading"><h2>Static routes</h2><button aria-label="Add IPv4 route" disabled={config.staticRoutes.length >= PROFILE_CATALOG.runtime.static_routes_per_router} onClick={() => update({ ...config, staticRoutes: [...config.staticRoutes, { prefix: "", nextHop: "", indirect: false }] })}>Add route</button></div><div className="route-list route-list-ipv4">{config.staticRoutes.length ? config.staticRoutes.map((route, index) => <div key={`${index}-${route.prefix}-${route.nextHop}`}><input aria-label="IPv4 destination prefix" placeholder="IPv4 prefix" value={route.prefix} onChange={(event) => updateRoute(index, { prefix: event.target.value })} /><input aria-label="IPv4 next hop" placeholder="Next hop" value={route.nextHop} onChange={(event) => updateRoute(index, { nextHop: event.target.value })} /><select aria-label="IPv4 static route resolution" value={route.indirect ? "indirect" : "next-hop"} onChange={(event) => updateRoute(index, { indirect: event.target.value === "indirect" })}><option value="next-hop">Direct next-hop</option><option value="indirect">Indirect</option></select><button onClick={() => update({ ...config, staticRoutes: config.staticRoutes.filter((_, item) => item !== index) })}>Remove</button></div>) : <p className="empty-copy">No static routes configured.</p>}</div>
    <div className="section-heading"><h2>IPv6 static routes</h2><button aria-label="Add IPv6 route" disabled={config.ipv6StaticRoutes.length >= PROFILE_CATALOG.runtime.static_routes_per_router} onClick={() => update({ ...config, ipv6StaticRoutes: [...config.ipv6StaticRoutes, { prefix: "", nextHop: "", outgoingPortId: "", indirect: false }] })}>Add route</button></div><div className="route-list route-list-ipv6">{config.ipv6StaticRoutes.length ? config.ipv6StaticRoutes.map((route, index) => <div key={`${index}-${route.prefix}-${route.nextHop}`}><input placeholder="IPv6 prefix" value={route.prefix} onChange={(event) => updateIpv6Route(index, { prefix: event.target.value })} /><input placeholder="Next hop" value={route.nextHop} onChange={(event) => updateIpv6Route(index, { nextHop: event.target.value })} /><select value={route.outgoingPortId} disabled={route.indirect} onChange={(event) => updateIpv6Route(index, { outgoingPortId: event.target.value })}><option value="">Route-selected interface</option>{config.ports.map((port) => <option key={port.id}>{port.id}</option>)}</select><select aria-label="IPv6 static route resolution" value={route.indirect ? "indirect" : "next-hop"} onChange={(event) => updateIpv6Route(index, { indirect: event.target.value === "indirect", ...(event.target.value === "indirect" ? { outgoingPortId: "" } : {}) })}><option value="next-hop">Direct next-hop</option><option value="indirect">Indirect</option></select><button onClick={() => update({ ...config, ipv6StaticRoutes: config.ipv6StaticRoutes.filter((_, item) => item !== index) })}>Remove</button></div>) : <p className="empty-copy">No IPv6 static routes configured.</p>}</div>
  </section>;
}

export function SnapshotWorkspace({ checkpointInput, onExport, onImport }: {
  checkpointInput: RefObject<HTMLInputElement | null>; onExport(): void;
  onImport(event: ChangeEvent<HTMLInputElement>): void;
}) {
  return <section className="workspace-page snapshot-page" aria-labelledby="snapshot-title"><header className="workspace-page-head"><div><span>RUNTIME STATE</span><h1 id="snapshot-title">Snapshots</h1></div></header><div className="snapshot-card"><strong>Portable checkpoint</strong><p>Preserves the full multi-device runtime and user-owned topology.</p><div className="workspace-actions"><button className="primary" onClick={onExport}>Export checkpoint</button><button onClick={() => checkpointInput.current?.click()}>Import checkpoint</button></div><input ref={checkpointInput} hidden type="file" accept=".bin,.checkpoint,application/octet-stream" onChange={onImport} /></div></section>;
}

export function NotesWorkspace({ value, onChange }: { value: string; onChange(value: string): void }) {
  return <section className="workspace-page notes-page" aria-labelledby="notes-title"><header className="workspace-page-head"><div><span>PROJECT DOCUMENT</span><h1 id="notes-title">Notes</h1></div><small>{value.length} / 65536</small></header><textarea value={value} maxLength={65536} onChange={(event) => onChange(event.target.value)} placeholder="Document addressing, test intent and expected results." /></section>;
}

export function SettingsWorkspace({ project, onChange, onResetLayout }: {
  project: LabProjectV4; onChange(project: LabProjectV4): void; onResetLayout(): void;
}) {
  return <section className="workspace-page settings-page" aria-labelledby="settings-title"><header className="workspace-page-head"><div><span>PROJECT</span><h1 id="settings-title">Settings</h1></div></header><label className="field-row"><span>Lab name</span><input value={project.name} onChange={(event) => onChange({ ...project, name: event.target.value })} /></label><label className="field-row"><span>Routers</span><small>{project.routers.length} / {PROFILE_CATALOG.limits.routers}</small></label><label className="field-row"><span>Links</span><small>{project.links.length} / {PROFILE_CATALOG.limits.links}</small></label><button className="secondary-action" onClick={onResetLayout}>Reset canvas layout</button></section>;
}
