// Inspector for the selected format 4 device. It retains the approved panel,
// tab and control styling while all inventory choices come from the generated
// release catalog and all operational values come from runtime snapshot ABI 6.

import { useEffect, useMemo, useState } from "react";
import { ANNOTATION_LIMITS, PROFILE_CATALOG, type HostProjectV4,
  type LabProjectV4, type LabRuntimeSnapshotV6, type RouterProjectV4,
  type TopologyAnnotationV4 } from "@router-simulator/contracts";
import { PanelResizeHandle } from "./PanelResizeHandle";
import { AlignCenter, AlignLeft, AlignRight, Bold, Italic, X } from "lucide-react";

function expandHex(hex: string): string {
  // Native colour inputs require the six-digit form. Expanding #rgb(a) keeps a
  // hand-authored short value from resetting the picker to black.
  if (hex.length === 4 || hex.length === 5) {
    return "#" + hex.slice(1).split("").map((digit) => digit + digit).join("");
  }
  return hex;
}

function fillColor(background: string | null): string {
  return background ? expandHex(background).slice(0, 7) : "#b47cf0";
}

function fillAlpha(background: string | null): number {
  if (!background) return 100;
  const expanded = expandHex(background);
  return expanded.length >= 9
    ? Math.round(Number.parseInt(expanded.slice(7, 9), 16) / 255 * 100) : 100;
}

function composeFill(color: string, alphaPercent: number): string {
  // The stored fill is always #rrggbbaa so a grouping region can be translucent
  // without a second opacity leaf. Solid #rrggbb only appears from six-digit
  // hand editing, which validation still accepts.
  const clamped = Math.round(Math.min(Math.max(alphaPercent, 0), 100) / 100 * 255);
  return `${expandHex(color).slice(0, 7)}${clamped.toString(16).padStart(2, "0")}`;
}

export type RouterTab = "chassis" | "cpm" | "cards" | "ports" | "operational";

interface Props {
  selected?: string;
  tab: RouterTab;
  onTabChange(tab: RouterTab): void;
  project: LabProjectV4;
  snapshot?: LabRuntimeSnapshotV6;
  updateHost(host: HostProjectV4): void;
  updateRouter(router: RouterProjectV4): void;
  setCard(routerId: string, slot: number, provisioned: string | null,
    equipped: string | null): void;
  setMda(routerId: string, cardSlot: number, mdaSlot: number,
    provisioned: string | null, equipped: string | null): void;
  setCardAdmin(routerId: string, slot: number, enabled: boolean): void;
  setMdaAdmin(routerId: string, cardSlot: number, mdaSlot: number,
    enabled: boolean): void;
  setLink(linkId: string, up: boolean): void;
  updateLink(linkId: string, up: boolean, propagationDelayNs: number,
    configuredSpeedMbps: number | null): void;
  deleteLink(linkId: string): void;
  deleteNode(nodeId: string): void;
  updateAnnotation(annotation: TopologyAnnotationV4): void;
  deleteAnnotation(annotationId: string): void;
  ping(sourceId: string, destination: string): Promise<string>;
  width: number;
  onWidthChange(value: number): void;
  openConsole(routerId: string): void;
  close(): void;
}

function StatePill({ up, children }: { up: boolean; children: string }) {
  return <span className={`state-pill ${up ? "good" : "muted"}`}>{children}</span>;
}

function speedLabel(speedMbps: number): string {
  return speedMbps % 1000 === 0 ? `${speedMbps / 1000}G` : `${speedMbps}M`;
}

export function Inspector({ selected, tab, onTabChange, project, snapshot,
  updateHost, updateRouter, setCard, setMda, setCardAdmin, setMdaAdmin,
  setLink, updateLink, deleteLink,
  deleteNode, updateAnnotation, deleteAnnotation, ping, width, onWidthChange,
  openConsole, close }: Props) {
  const [pingResult, setPingResult] = useState("");
  const [pingBusy, setPingBusy] = useState(false);
  const host = project.hosts.find((item) => item.id === selected);
  const router = project.routers.find((item) => item.id === selected);
  const link = project.links.find((item) => item.id === selected);
  const annotation = project.annotations.find((item) => item.id === selected);
  const live = snapshot?.routers.find((item) => item.id === selected);
  const profile = useMemo(() => router
    ? PROFILE_CATALOG.profiles.find((item) => item.id === router.profileId)
    : undefined, [router]);
  const [hostDraft, setHostDraft] = useState<HostProjectV4>();
  useEffect(() => {
    // Host addressing is validated as one record. Keeping edits local permits
    // a user to replace a prefix, gateway or MAC without submitting every
    // incomplete intermediate character to the running endpoint stack.
    setHostDraft(host ? structuredClone(host) : undefined);
  }, [host]);
  const resizeHandle = <PanelResizeHandle axis="x" className="inspector-resizer"
    defaultValue={324} direction={-1} label="Resize inspector" min={64}
    max={Math.max(64, window.innerWidth - 64)} value={width}
    onChange={onWidthChange} />;

  if (link) {
    const hostOnly = link.endpoints.every((endpoint) =>
      project.hosts.some((host) => host.id === endpoint.nodeId));
    return <aside className="inspector">
      <div className="inspector-title"><div><h2>{link.id}</h2><p>Point-to-point Ethernet</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
      <div className="host-form">
        <label>First endpoint<input readOnly value={`${link.endpoints[0].nodeId} / ${link.endpoints[0].portId}`} /></label>
        <label>Second endpoint<input readOnly value={`${link.endpoints[1].nodeId} / ${link.endpoints[1].portId}`} /></label>
        <label>Administrative state<select value={link.admin} onChange={(event) => updateLink(link.id, event.target.value === "up", link.propagationDelayNs, link.configuredSpeedMbps)}><option value="up">up</option><option value="down">down</option></select></label>
        {hostOnly && <label>Medium speed in Mb/s<input type="number" min={1} step={1} value={link.configuredSpeedMbps ?? ""} onChange={(event) => { const value = Number(event.target.value); if (Number.isSafeInteger(value) && value > 0) updateLink(link.id, link.admin === "up", link.propagationDelayNs, value); }} /></label>}
        <label>Propagation delay in ns<input type="number" min={0} step={1} value={link.propagationDelayNs} onChange={(event) => { const value = Number(event.target.value); if (Number.isSafeInteger(value) && value >= 0) updateLink(link.id, link.admin === "up", value, link.configuredSpeedMbps); }} /></label>
        <button className="inspector-action" onClick={() => setLink(link.id, link.admin !== "up")}>{link.admin === "up" ? "Disconnect" : "Connect"}</button>
        <button className="secondary-action" onClick={() => deleteLink(link.id)}>Delete link</button>
      </div>{resizeHandle}
    </aside>;
  }

  if (annotation) {
    const alignButton = (value: TopologyAnnotationV4["align"],
      Icon: typeof AlignLeft, label: string) =>
      <button type="button" className={`seg ${annotation.align === value ? "active" : ""}`} aria-pressed={annotation.align === value} aria-label={label} onClick={() => updateAnnotation({ ...annotation, align: value })}><Icon size={15} /></button>;
    const clampInteger = (value: number, min: number, max: number) =>
      Math.min(Math.max(Math.round(value), min), max);
    return <aside className="inspector">
      <div className="inspector-title"><div><h2>Text label</h2><p>Canvas annotation</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
      <div className="host-form annotation-form">
        <label>Label text<textarea className="annotation-editor" value={annotation.text} maxLength={1000} rows={3} placeholder="e.g. 10.0.12.0/30 · R1 ↔ R2" onChange={(event) => updateAnnotation({ ...annotation, text: event.target.value })} /></label>
        <div className="annotation-grid">
          <label className="stack">Font size<input type="number" min={ANNOTATION_LIMITS.minFontSize} max={ANNOTATION_LIMITS.maxFontSize} value={annotation.fontSize} onChange={(event) => { const value = Number(event.target.value); if (Number.isFinite(value)) updateAnnotation({ ...annotation, fontSize: clampInteger(value, ANNOTATION_LIMITS.minFontSize, ANNOTATION_LIMITS.maxFontSize) }); }} /></label>
          <label className="stack">Box width<input type="number" min={ANNOTATION_LIMITS.minWidth} max={ANNOTATION_LIMITS.maxWidth} step={10} value={annotation.width} onChange={(event) => { const value = Number(event.target.value); if (Number.isFinite(value)) updateAnnotation({ ...annotation, width: clampInteger(value, ANNOTATION_LIMITS.minWidth, ANNOTATION_LIMITS.maxWidth) }); }} /></label>
        </div>
        <div className="annotation-segmented">
          <div className="seg-group" role="group" aria-label="Emphasis">
            <button type="button" className={`seg ${annotation.bold ? "active" : ""}`} aria-pressed={annotation.bold} aria-label="Bold" onClick={() => updateAnnotation({ ...annotation, bold: !annotation.bold })}><Bold size={15} /></button>
            <button type="button" className={`seg ${annotation.italic ? "active" : ""}`} aria-pressed={annotation.italic} aria-label="Italic" onClick={() => updateAnnotation({ ...annotation, italic: !annotation.italic })}><Italic size={15} /></button>
          </div>
          <div className="seg-group" role="group" aria-label="Text alignment">
            {alignButton("left", AlignLeft, "Align left")}
            {alignButton("center", AlignCenter, "Align centre")}
            {alignButton("right", AlignRight, "Align right")}
          </div>
        </div>
        <label className="color-row"><span>Text colour</span><input type="color" value={expandHex(annotation.color)} onChange={(event) => updateAnnotation({ ...annotation, color: event.target.value })} /></label>
        <label className="toggle-row"><span>Background fill</span><input type="checkbox" checked={annotation.background !== null} onChange={(event) => updateAnnotation({ ...annotation, background: event.target.checked ? composeFill("#b47cf0", 20) : null })} /></label>
        {annotation.background !== null && <>
          <label className="color-row"><span>Fill colour</span><input type="color" value={fillColor(annotation.background)} onChange={(event) => updateAnnotation({ ...annotation, background: composeFill(event.target.value, fillAlpha(annotation.background)) })} /></label>
          <label className="stack">Fill opacity · {fillAlpha(annotation.background)}%<input type="range" min={0} max={100} value={fillAlpha(annotation.background)} onChange={(event) => updateAnnotation({ ...annotation, background: composeFill(fillColor(annotation.background), Number(event.target.value)) })} /></label>
        </>}
        <label className="toggle-row"><span>Border</span><input type="checkbox" checked={annotation.border} onChange={(event) => updateAnnotation({ ...annotation, border: event.target.checked })} /></label>
        <button className="secondary-action" onClick={() => deleteAnnotation(annotation.id)}>Delete label</button>
      </div>{resizeHandle}
    </aside>;
  }

  if (host) {
    const editable = hostDraft ?? host;
    const peer = project.hosts.find((item) => item.id !== host.id);
    const runPing = async () => {
      if (!peer || pingBusy) return;
      setPingBusy(true);
      try { setPingResult(await ping(host.id, peer.eth0.address.split("/")[0])); }
      catch { setPingResult("The echo test could not be completed."); }
      finally { setPingBusy(false); }
    };
    return <aside className="inspector">
      <div className="inspector-title"><div><h2>{host.name}</h2><p>External IPv4 host</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
      <div className="host-form">
        <label>Name<input value={editable.name} onChange={(event) => setHostDraft({ ...editable, name: event.target.value })} /></label>
        <label>IPv4 prefix<input value={editable.eth0.address} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, address: event.target.value } })} /></label>
        <label>Default gateway<input value={editable.eth0.gateway} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, gateway: event.target.value } })} /></label>
        <label>MAC address<input value={editable.eth0.mac} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, mac: event.target.value } })} /></label>
        <label>Interface MTU<input type="number" min={PROFILE_CATALOG.ethernet.minimum_host_ipv4_mtu} max={PROFILE_CATALOG.ethernet.maximum_network_mtu} value={editable.eth0.mtu} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, mtu: Number(event.target.value) } })} /></label>
        <label>IPv6 autoconfiguration<select value={editable.eth0.ipv6.autoconfiguration ? "enabled" : "disabled"} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, ipv6: { ...editable.eth0.ipv6, autoconfiguration: event.target.value === "enabled" } } })}><option value="enabled">enabled</option><option value="disabled">disabled</option></select></label>
        <label>IPv6 interface identifier<select value={editable.eth0.ipv6.interfaceIdentifierMode} onChange={(event) => { const mode = event.target.value as "modified-eui64" | "stable-opaque"; setHostDraft({ ...editable, eth0: { ...editable.eth0, ipv6: { ...editable.eth0.ipv6, interfaceIdentifierMode: mode, stableIidSecret: mode === "modified-eui64" ? null : editable.eth0.ipv6.stableIidSecret } } }); }}><option value="modified-eui64">modified EUI-64</option><option value="stable-opaque">stable opaque</option></select></label>
        {editable.eth0.ipv6.interfaceIdentifierMode === "stable-opaque" && <label>IPv6 network identity<input value={editable.eth0.ipv6.networkId} maxLength={PROFILE_CATALOG.runtime.ipv6_stable_iid_network_id_octets} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, ipv6: { ...editable.eth0.ipv6, networkId: event.target.value } } })} /></label>}
        <div className="button-pair"><button onClick={() => setHostDraft(structuredClone(host))}>Discard</button><button className="inspector-action" onClick={() => updateHost(editable)}>Apply</button></div>
        <button className="inspector-action" disabled={!peer || pingBusy} onClick={() => void runPing()}>{pingBusy ? "Pinging" : `Ping ${peer?.name ?? "peer"}`}</button>
        <button className="secondary-action" onClick={() => deleteNode(host.id)}>Delete host</button>
        {pingResult && <pre className="operation-result">{pingResult}</pre>}
      </div>{resizeHandle}
    </aside>;
  }

  if (!router || !profile) {
    return <aside className="inspector"><div className="inspector-title"><div><h2>Inspector</h2><p>Select a device</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>{resizeHandle}</aside>;
  }
  const runtimeReady = Boolean(live);
  const hardwareReady = Boolean(live?.ports.length || profile.fixed);

  const renderTab = () => {
    if (tab === "chassis") return <>
      <div className="panel-kicker inspector-section-title">CHASSIS</div>
      <div className="spec-grid"><span>Model</span><strong>{profile.chassis}</strong><span>Slot count</span><strong>{profile.card_slots}</strong><span>Release</span><strong>{PROFILE_CATALOG.release}</strong><span>Runtime state</span><strong className={runtimeReady ? "text-good" : "text-warning"}>{runtimeReady ? "ready" : "Starting"}</strong><span>Hardware</span><strong className={hardwareReady ? "text-good" : "text-warning"}>{hardwareReady ? "Ready" : "Incomplete"}</strong></div>
      <div className="chassis-slots"><div className="panel-kicker">SLOTS</div>{router.hardware.cards.map((item) => <div key={item.slot}><span>{item.slot}</span><strong>{item.equippedType ?? "Blank"}</strong><StatePill up={item.equippedType === item.provisionedType && Boolean(item.equippedType)}>{item.equippedType ? item.equippedType === item.provisionedType ? "ready" : "mismatch" : "absent"}</StatePill></div>)}</div>
    </>;
    if (tab === "cpm") return <><div className="panel-kicker inspector-section-title">CONTROL PLANE</div><div className="spec-grid"><span>Slot</span><strong>{profile.control.slot}</strong><span>Type</span><strong>{profile.control.types.join(", ")}</strong><span>State</span><strong className="text-good">active</strong></div></>;
    if (tab === "cards") return <>{router.hardware.cards.map((card) => {
      const compatible = profile.cards;
      const selectedCard = compatible.find((item) => item.type === card.provisionedType);
      return <div className="hardware-slot" key={card.slot}>
        <div className="slot-head"><span>SLOT {card.slot}</span><StatePill up={Boolean(card.admin === "up" && card.equippedType && card.equippedType === card.provisionedType)}>{card.equippedType ? card.equippedType === card.provisionedType ? card.admin === "up" ? "ready" : "shutdown" : "mismatch" : "absent"}</StatePill></div>
        <strong>{card.equippedType ?? "No line card"}</strong>
        <div className="button-pair"><select disabled={profile.fixed} value={card.provisionedType ?? ""} onChange={(event) => setCard(router.id, card.slot, event.target.value || null, card.equippedType)}><option value="">Not provisioned</option>{compatible.map((item) => <option key={item.type}>{item.type}</option>)}</select><select disabled={profile.fixed} value={card.equippedType ?? ""} onChange={(event) => setCard(router.id, card.slot, card.provisionedType, event.target.value || null)}><option value="">Absent</option>{compatible.map((item) => <option key={item.type}>{item.type}</option>)}</select></div>
        <label className="hardware-admin">Administrative state<select disabled={profile.fixed || !card.provisionedType} value={card.admin} onChange={(event) => setCardAdmin(router.id, card.slot, event.target.value === "up")}><option value="down">down</option><option value="up">up</option></select></label>
        {card.mdas.slice(0, selectedCard?.mda_slots ?? 0).map((mda) => <div className="mda-editor" key={mda.slot}><div className="slot-head"><span>MDA {card.slot}/{mda.slot}</span><StatePill up={mda.admin === "up" && Boolean(mda.equippedType && mda.equippedType === mda.provisionedType)}>{mda.equippedType ? mda.equippedType === mda.provisionedType ? mda.admin === "up" ? "ready" : "shutdown" : "mismatch" : "absent"}</StatePill></div><div className="button-pair"><select disabled={profile.fixed} value={mda.provisionedType ?? ""} onChange={(event) => setMda(router.id, card.slot, mda.slot, event.target.value || null, mda.equippedType)}><option value="">Not provisioned</option>{selectedCard?.mdas.map((type) => <option key={type}>{type}</option>)}</select><select disabled={profile.fixed} value={mda.equippedType ?? ""} onChange={(event) => setMda(router.id, card.slot, mda.slot, mda.provisionedType, event.target.value || null)}><option value="">Absent</option>{selectedCard?.mdas.map((type) => <option key={type}>{type}</option>)}</select></div><label className="hardware-admin">Administrative state<select disabled={profile.fixed || !mda.provisionedType} value={mda.admin} onChange={(event) => setMdaAdmin(router.id, card.slot, mda.slot, event.target.value === "up")}><option value="down">down</option><option value="up">up</option></select></label></div>)}
      </div>;
    })}</>;
    if (tab === "ports") return <div className="ports-summary"><div className="panel-kicker">PHYSICAL PORTS</div>{live?.ports.length ? live.ports.map((port) => {
      const link = project.links.find((item) => item.endpoints.some((endpoint) => endpoint.nodeId === router.id && endpoint.portId === port.id));
      return <div key={port.id}><span><i className={port.oper ? "dot-good" : "dot-muted"} />{port.id}</span><strong>{port.admin ? "up" : "down"} · {speedLabel(port.speedMbps)}</strong>{link ? <button onClick={() => setLink(link.id, link.admin !== "up")}>{link.admin === "up" ? "Disconnect" : "Connect"}</button> : <small>No medium</small>}</div>;
    }) : <p className="empty-copy inspector-empty">No ports are exposed by equipped hardware.</p>}</div>;
    return <div className="operational-panel"><div className="metric-strip compact"><div><small>Routes</small><strong>{live?.staticRoutes.length ?? 0}</strong></div><div><small>Links</small><strong>{project.links.filter((item) => item.endpoints.some((endpoint) => endpoint.nodeId === router.id)).length}</strong></div><div><small>Ports</small><strong>{live?.ports.filter((port) => port.oper).length ?? 0}</strong></div></div><button className="inspector-action" onClick={() => openConsole(router.id)}>Open console</button><button className="secondary-action" onClick={() => deleteNode(router.id)}>Delete router</button><div className="operational-list"><h3>Static routes</h3>{live?.staticRoutes.map((route) => <div key={route.prefix}><strong>{route.prefix}</strong><span>{route.nextHop}</span></div>)}</div></div>;
  };

  return <aside className="inspector">
    <div className="inspector-title"><div><h2>{router.systemName}<i className={runtimeReady ? "dot-good" : "dot-muted"} /></h2><p>{runtimeReady ? "Running" : "Unavailable"}</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
    <nav className="inspector-tabs">{(["chassis", "cpm", "cards", "ports", "operational"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTabChange(item)}>{item === "cpm" ? "CPM" : item[0].toUpperCase() + item.slice(1)}</button>)}</nav>
    {renderTab()}{resizeHandle}
  </aside>;
}
