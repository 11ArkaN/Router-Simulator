// Inspector for the selected format 3 device. It retains the approved panel,
// tab and control styling while all inventory choices come from the generated
// release catalog and all operational values come from runtime snapshot ABI 5.

import { useEffect, useMemo, useState } from "react";
import { PROFILE_CATALOG, type HostProjectV3, type LabProjectV3,
  type LabRuntimeSnapshotV5, type RouterProjectV3 } from "@router-simulator/contracts";
import { PanelResizeHandle } from "./PanelResizeHandle";
import { X } from "lucide-react";

export type RouterTab = "chassis" | "cpm" | "cards" | "ports" | "operational";

interface Props {
  selected?: string;
  tab: RouterTab;
  onTabChange(tab: RouterTab): void;
  project: LabProjectV3;
  snapshot?: LabRuntimeSnapshotV5;
  updateHost(host: HostProjectV3): void;
  updateRouter(router: RouterProjectV3): void;
  setCard(routerId: string, slot: number, provisioned: string | null,
    equipped: string | null): void;
  setMda(routerId: string, cardSlot: number, mdaSlot: number,
    provisioned: string | null, equipped: string | null): void;
  setCardAdmin(routerId: string, slot: number, enabled: boolean): void;
  setMdaAdmin(routerId: string, cardSlot: number, mdaSlot: number,
    enabled: boolean): void;
  setLink(linkId: string, up: boolean): void;
  updateLink(linkId: string, up: boolean, propagationDelayNs: number): void;
  deleteLink(linkId: string): void;
  deleteNode(nodeId: string): void;
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
  deleteNode, ping, width, onWidthChange, openConsole, close }: Props) {
  const [pingResult, setPingResult] = useState("");
  const [pingBusy, setPingBusy] = useState(false);
  const host = project.hosts.find((item) => item.id === selected);
  const router = project.routers.find((item) => item.id === selected);
  const link = project.links.find((item) => item.id === selected);
  const live = snapshot?.routers.find((item) => item.id === selected);
  const profile = useMemo(() => router
    ? PROFILE_CATALOG.profiles.find((item) => item.id === router.profileId)
    : undefined, [router]);
  const [hostDraft, setHostDraft] = useState<HostProjectV3>();
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
    return <aside className="inspector">
      <div className="inspector-title"><div><h2>{link.id}</h2><p>Point-to-point Ethernet</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
      <div className="host-form">
        <label>First endpoint<input readOnly value={`${link.endpoints[0].nodeId} / ${link.endpoints[0].portId}`} /></label>
        <label>Second endpoint<input readOnly value={`${link.endpoints[1].nodeId} / ${link.endpoints[1].portId}`} /></label>
        <label>Administrative state<select value={link.admin} onChange={(event) => updateLink(link.id, event.target.value === "up", link.propagationDelayNs)}><option value="up">up</option><option value="down">down</option></select></label>
        <label>Propagation delay in ns<input type="number" min={0} step={1} value={link.propagationDelayNs} onChange={(event) => { const value = Number(event.target.value); if (Number.isSafeInteger(value) && value >= 0) updateLink(link.id, link.admin === "up", value); }} /></label>
        <button className="inspector-action" onClick={() => setLink(link.id, link.admin !== "up")}>{link.admin === "up" ? "Disconnect" : "Connect"}</button>
        <button className="secondary-action" onClick={() => deleteLink(link.id)}>Delete link</button>
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
