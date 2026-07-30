// Inspector for the selected format 5 device. It retains the approved panel,
// tab and control styling while all inventory choices come from the generated
// release catalog and all operational values come from runtime snapshot ABI 8.

import { useEffect, useMemo, useState } from "react";
import { ANNOTATION_LIMITS, PROFILE_CATALOG, type HostProjectV4,
  type DhcpServerProjectV5, type LabProjectV4, type LabRuntimeSnapshotV6,
  type RouterProjectV4, type TopologyAnnotationV4,
  dhcpv4RelayedScopeIdentity, equippedRouterPortSpeeds,
  physicalPortLinkIdentity
} from "@router-simulator/contracts";
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

function randomSecretHex(): string {
  // DHCP transaction IDs must not be derived from a visible address or MAC.
  // The runtime receives a persistent private seed and performs its own
  // domain-separated HMAC derivation for each new transaction.
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function ipv4Attachment(address: string): {
  address: string; mask: string } | undefined {
  const [host, prefixText, extra] = address.split("/");
  const prefix = Number(prefixText);
  if (extra !== undefined || !host || !Number.isInteger(prefix) ||
      prefix < 0 || prefix > 32) return undefined;
  const octets = host.split(".").map(Number);
  if (octets.length !== 4 || octets.some((value) =>
    !Number.isInteger(value) || value < 0 || value > 255)) return undefined;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { address: host, mask: [24, 16, 8, 0].map((shift) =>
    String((mask >>> shift) & 0xff)).join(".") };
}

function isIpv4Address(address: string): boolean {
  // The Inspector validates only dotted-decimal syntax. Reachability, local
  // source state, route selection, ARP and ICMP outcomes remain forwarding
  // decisions and are never inferred from the project graph.
  const octets = address.split(".");
  return octets.length === 4 && octets.every((octet) =>
    /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255);
}

function randomDuidUuid(): string {
  // RFC 6355 DUID-UUID stores type 4 followed by the 128-bit UUID. The value
  // is generated once in the draft and then persisted with the project, so
  // reopening the lab cannot silently change server identity.
  return `0004${globalThis.crypto.randomUUID().replaceAll("-", "")}`;
}

export type RouterTab = "chassis" | "cpm" | "cards" | "ports" | "operational";

interface Props {
  selected?: string;
  tab: RouterTab;
  onTabChange(tab: RouterTab): void;
  project: LabProjectV4;
  snapshot?: LabRuntimeSnapshotV6;
  updateHost(host: HostProjectV4): void;
  updateDhcpServer(server: DhcpServerProjectV5): void;
  updateRouter(router: RouterProjectV4): void;
  setCard(routerId: string, slot: number, provisioned: string | null,
    equipped: string | null): void;
  setMda(routerId: string, cardSlot: number, mdaSlot: number,
    provisioned: string | null, equipped: string | null): void;
  setCardAdmin(routerId: string, slot: number, enabled: boolean): void;
  setMdaAdmin(routerId: string, cardSlot: number, mdaSlot: number,
    enabled: boolean): void;
  setSwitchName(switchId: string, name: string): void;
  setSwitchPort(switchId: string, portId: string, enabled: boolean,
    speedMbps: number, mtu: number): void;
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

function dhcpStateLabel(state: string | undefined): string {
  if (!state) return "Unavailable";
  return state.split("-").map((part) =>
    part.slice(0, 1).toUpperCase() + part.slice(1)).join(" ");
}

export function Inspector({ selected, tab, onTabChange, project, snapshot,
  updateHost, updateDhcpServer, updateRouter, setCard, setMda, setCardAdmin,
  setMdaAdmin,
  setSwitchName, setSwitchPort,
  setLink, updateLink, deleteLink,
  deleteNode, updateAnnotation, deleteAnnotation, ping, width, onWidthChange,
  openConsole, close }: Props) {
  const [pingResult, setPingResult] = useState("");
  const [pingBusy, setPingBusy] = useState(false);
  const [pingDestination, setPingDestination] = useState("");
  const host = project.hosts.find((item) => item.id === selected);
  const dhcpServer = project.dhcpServers.find((item) => item.id === selected);
  const router = project.routers.find((item) => item.id === selected);
  const ethernetSwitch = project.switches.find(
    (item) => item.id === selected);
  const link = project.links.find((item) => item.id === selected);
  const annotation = project.annotations.find((item) => item.id === selected);
  const live = snapshot?.routers.find((item) => item.id === selected);
  const liveHost = snapshot?.hosts.find((item) => item.id === selected);
  const liveDhcpServer = snapshot?.dhcpServers.find(
    (item) => item.id === selected);
  const liveSwitch = snapshot?.switches.find(
    (item) => item.id === selected);
  const profile = useMemo(() => router
    ? PROFILE_CATALOG.profiles.find((item) => item.id === router.profileId)
    : undefined, [router]);
  const [hostDraft, setHostDraft] = useState<HostProjectV4>();
  const [dhcpServerDraft, setDhcpServerDraft] =
    useState<DhcpServerProjectV5>();
  const [switchNameDraft, setSwitchNameDraft] = useState("");
  useEffect(() => {
    // Host addressing is validated as one record. Keeping edits local permits
    // a user to replace a prefix, gateway or MAC without submitting every
    // incomplete intermediate character to the running endpoint stack.
    setHostDraft(host ? structuredClone(host) : undefined);
  }, [host]);
  useEffect(() => {
    // A dedicated server owns one coherent routed-interface configuration.
    // Drafting the whole record prevents a half-entered prefix from reaching
    // the native network owner and preserves atomic Apply/Discard semantics.
    setDhcpServerDraft(dhcpServer ? structuredClone(dhcpServer) : undefined);
  }, [dhcpServer]);
  useEffect(() => {
    // A name is a complete configuration leaf. Editing it locally avoids
    // publishing invalid empty and partial names to the runtime on each
    // keystroke; blur commits the final value through the switch owner.
    setSwitchNameDraft(ethernetSwitch?.name ?? "");
  }, [ethernetSwitch]);
  useEffect(() => {
    // Echo-test input and output belong to the selected host. A project can
    // reuse a stable node ID for a different endpoint, so neither a target nor
    // an old result may survive that ownership change.
    setPingDestination("");
    setPingResult("");
    setPingBusy(false);
  }, [host?.id, host?.eth0.address]);
  const resizeHandle = <PanelResizeHandle axis="x" className="inspector-resizer"
    defaultValue={324} direction={-1} label="Resize inspector" min={64}
    max={Math.max(64, window.innerWidth - 64)} value={width}
    onChange={onWidthChange} />;

  if (link) {
    const hostOnly = link.endpoints.every((endpoint) =>
      project.hosts.some((host) => host.id === endpoint.nodeId));
    return <aside className="inspector">
      <div className="inspector-title"><div><h2>{link.id}</h2><p>Point-to-point Ethernet</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
      <div className="host-form switch-inspector-form">
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
    const runPing = async () => {
      if (!isIpv4Address(pingDestination) || pingBusy) return;
      setPingBusy(true);
      try { setPingResult(await ping(host.id, pingDestination)); }
      catch { setPingResult("The echo test could not be completed."); }
      finally { setPingBusy(false); }
    };
    return <aside className="inspector">
      <div className="inspector-title"><div><h2>{host.name}</h2><p>IP host</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
      <div className="host-form">
        <label>Name<input value={editable.name} onChange={(event) => setHostDraft({ ...editable, name: event.target.value })} /></label>
        <label>IPv4 configuration<select value={
          editable.eth0.dhcpv4.client ? "dhcp"
            : editable.eth0.address === "0.0.0.0/0" &&
              editable.eth0.gateway === "0.0.0.0"
              ? "unconfigured" : "static"} onChange={(event) => {
          const dynamic = event.target.value === "dhcp";
          const unconfigured = event.target.value === "unconfigured";
          setHostDraft({ ...editable, eth0: {
            ...editable.eth0,
            address: dynamic || unconfigured ? "0.0.0.0/0" : "",
            gateway: dynamic || unconfigured ? "0.0.0.0" : "",
            dhcpv4: { ...editable.eth0.dhcpv4, client: dynamic ? {
              clientIdentifierHex: "",
              transactionSecretHex: randomSecretHex(),
              parameterRequestList: [1, 3, 6],
              maximumMessageSize: 576,
              broadcast: false
            } : null }
          } });
        }}><option value="unconfigured">unconfigured</option>
          <option value="static">static</option>
          <option value="dhcp">DHCP</option></select></label>
        {!editable.eth0.dhcpv4.client &&
          editable.eth0.address !== "0.0.0.0/0" && <>
          <label>IPv4 prefix<input value={editable.eth0.address} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, address: event.target.value } })} /></label>
          <label>Default gateway<input value={editable.eth0.gateway} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, gateway: event.target.value } })} /></label>
        </>}
        {editable.eth0.dhcpv4.client && <>
          <div className="spec-grid host-operational-grid">
            <span>DHCP state</span><strong className={
              liveHost?.dhcpv4.state === "bound" ? "text-good"
                : "text-warning"}>
              {dhcpStateLabel(liveHost?.dhcpv4.state)}
            </strong>
            <span>Assigned address</span>
            <strong>{liveHost?.dhcpv4.address || "None"}</strong>
            <span>Subnet mask</span>
            <strong>{liveHost?.dhcpv4.subnetMask || "None"}</strong>
            <span>Default gateway</span>
            <strong>{liveHost?.dhcpv4.router || "None"}</strong>
            <span>DHCP server</span>
            <strong>{liveHost?.dhcpv4.serverIdentifier || "None"}</strong>
            <span>Lease remaining</span>
            <strong>{liveHost?.dhcpv4.leasePresent
              ? `${Math.ceil(liveHost.dhcpv4.validRemainingMs / 1000)} s`
              : "None"}</strong>
          </div>
          <label>DHCP client identifier<input value={editable.eth0.dhcpv4.client.clientIdentifierHex} placeholder="Use hardware address" onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, dhcpv4: { ...editable.eth0.dhcpv4, client: { ...editable.eth0.dhcpv4.client!, clientIdentifierHex: event.target.value } } } })} /></label>
          <label>DHCP broadcast flag<select value={editable.eth0.dhcpv4.client.broadcast ? "enabled" : "disabled"} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, dhcpv4: { ...editable.eth0.dhcpv4, client: { ...editable.eth0.dhcpv4.client!, broadcast: event.target.value === "enabled" } } } })}><option value="disabled">disabled</option><option value="enabled">enabled</option></select></label>
          <label>Maximum DHCP message size<input type="number" min={576} max={65535} value={editable.eth0.dhcpv4.client.maximumMessageSize} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, dhcpv4: { ...editable.eth0.dhcpv4, client: { ...editable.eth0.dhcpv4.client!, maximumMessageSize: Number(event.target.value) } } } })} /></label>
        </>}
        <label>MAC address<input value={editable.eth0.mac} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, mac: event.target.value } })} /></label>
        <label>Interface MTU<input type="number" min={PROFILE_CATALOG.ethernet.minimum_host_ipv4_mtu} max={PROFILE_CATALOG.ethernet.maximum_network_mtu} value={editable.eth0.mtu} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, mtu: Number(event.target.value) } })} /></label>
        <label>IPv6 autoconfiguration<select value={editable.eth0.ipv6.autoconfiguration ? "enabled" : "disabled"} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, ipv6: { ...editable.eth0.ipv6, autoconfiguration: event.target.value === "enabled" } } })}><option value="enabled">enabled</option><option value="disabled">disabled</option></select></label>
        <label>IPv6 interface identifier<select value={editable.eth0.ipv6.interfaceIdentifierMode} onChange={(event) => { const mode = event.target.value as "modified-eui64" | "stable-opaque"; setHostDraft({ ...editable, eth0: { ...editable.eth0, ipv6: { ...editable.eth0.ipv6, interfaceIdentifierMode: mode, stableIidSecret: mode === "modified-eui64" ? null : editable.eth0.ipv6.stableIidSecret } } }); }}><option value="modified-eui64">modified EUI-64</option><option value="stable-opaque">stable opaque</option></select></label>
        {editable.eth0.ipv6.interfaceIdentifierMode === "stable-opaque" && <label>IPv6 network identity<input value={editable.eth0.ipv6.networkId} maxLength={PROFILE_CATALOG.runtime.ipv6_stable_iid_network_id_octets} onChange={(event) => setHostDraft({ ...editable, eth0: { ...editable.eth0, ipv6: { ...editable.eth0.ipv6, networkId: event.target.value } } })} /></label>}
        <div className="button-pair"><button onClick={() => setHostDraft(structuredClone(host))}>Discard</button><button className="inspector-action" onClick={() => updateHost(editable)}>Apply</button></div>
        <label>Ping destination<input inputMode="decimal"
          placeholder="IPv4 address" value={pingDestination}
          aria-invalid={pingDestination.length > 0 &&
            !isIpv4Address(pingDestination)}
          onChange={(event) => {
            setPingDestination(event.target.value.trim());
            setPingResult("");
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              void runPing();
            }
          }} /></label>
        <button className="inspector-action"
          disabled={!isIpv4Address(pingDestination) || pingBusy}
          onClick={() => void runPing()}>
          {pingBusy ? "Pinging" : "Ping"}</button>
        <button className="secondary-action" onClick={() => deleteNode(host.id)}>Delete host</button>
        {pingResult && <pre className="operation-result">{pingResult}</pre>}
      </div>{resizeHandle}
    </aside>;
  }

  if (dhcpServer) {
    const editable = dhcpServerDraft ?? dhcpServer;
    const serverProfile = PROFILE_CATALOG.profiles.find(
      (item) => item.id === dhcpServer.profileId);
    const updateInterface = (index: number,
      patch: Partial<typeof editable.running.interfaces[number]>) => {
      setDhcpServerDraft({ ...editable, running: {
        ...editable.running,
        interfaces: editable.running.interfaces.map((item, itemIndex) =>
          itemIndex === index ? { ...item, ...patch } : item)
      } });
    };
    const poolAttachments = editable.running.interfaces.flatMap((item) => {
      const parsed = ipv4Attachment(item.address);
      const linkIdentity = physicalPortLinkIdentity(editable, item.portId);
      return parsed && linkIdentity
        ? [{ name: item.name, linkIdentity, ...parsed }] : [];
    });
    const updateV4Server = (serverIndex: number,
      configuration: typeof editable.dhcpv4Servers[number]["configuration"]) => {
      setDhcpServerDraft({ ...editable,
        dhcpv4Servers: editable.dhcpv4Servers.map((item, index) =>
          index === serverIndex ? { ...item, configuration } : item) });
    };
    const updateV6Server = (serverIndex: number,
      configuration: typeof editable.dhcpv6Servers[number]["configuration"]) => {
      setDhcpServerDraft({ ...editable,
        dhcpv6Servers: editable.dhcpv6Servers.map((item, index) =>
          index === serverIndex ? { ...item, configuration } : item) });
    };
    return <aside className="inspector">
      <div className="inspector-title"><div><h2>{dhcpServer.name}<i
        className={liveDhcpServer ? "dot-good" : "dot-muted"} /></h2>
        <p>Dedicated DHCP server</p></div><button
          aria-label="Close inspector" onClick={close}><X size={18} /></button>
      </div>
      <div className="host-form">
        <label>Name<input value={editable.name} onChange={(event) =>
          setDhcpServerDraft({ ...editable, name: event.target.value,
            running: { ...editable.running,
              systemName: event.target.value } })} /></label>
        <div className="spec-grid"><span>Profile</span>
          <strong>{serverProfile?.chassis ?? editable.profileId}</strong>
          <span>Transit forwarding</span><strong>Disabled</strong>
          <span>DHCPv4 instances</span>
          <strong>{editable.dhcpv4Servers.length}</strong>
          <span>DHCPv6 instances</span>
          <strong>{editable.dhcpv6Servers.length}</strong></div>
        <div className="section-heading"><h3>Network interfaces</h3>
          <button type="button" onClick={() => setDhcpServerDraft({
            ...editable, running: { ...editable.running,
              interfaces: [...editable.running.interfaces, {
                name: "", admin: "down", portId: "", address: "",
                arpTimeoutSeconds: null, arpRetryTimerDeciseconds: null,
                ipv6Addresses: []
              }]
            }
          })}>Add interface</button></div>
        {editable.running.interfaces.map((item, index) =>
          <div className="server-interface-editor" key={index}>
            <label>Interface<input value={item.name} onChange={(event) =>
              updateInterface(index, { name: event.target.value })} /></label>
            <label>Interface state<select value={item.admin} onChange={(event) =>
              updateInterface(index, { admin: event.target.value as
                "up" | "down" })}><option value="down">down</option>
              <option value="up">up</option></select></label>
            <label>Port<select value={item.portId} onChange={(event) =>
              updateInterface(index, { portId: event.target.value })}>
              <option value="">No port</option>
              {editable.running.ports.map((port) =>
                <option key={port.id}>{port.id}</option>)}</select></label>
            <label>Physical port state<select
              disabled={!item.portId}
              value={editable.running.ports.find(
                (port) => port.id === item.portId)?.admin ?? "down"}
              onChange={(event) => setDhcpServerDraft({
                ...editable, running: { ...editable.running,
                  ports: editable.running.ports.map((port) =>
                    port.id === item.portId
                      ? { ...port, admin: event.target.value as "up" | "down" }
                      : port)
                }
              })}><option value="down">down</option>
              <option value="up">up</option></select></label>
            <label>Port speed<select
              disabled={!item.portId}
              value={editable.running.ports.find(
                (port) => port.id === item.portId)?.speedMbps ?? ""}
              onChange={(event) => setDhcpServerDraft({
                ...editable, running: { ...editable.running,
                  ports: editable.running.ports.map((port) =>
                    port.id === item.portId
                      ? { ...port, speedMbps: Number(event.target.value) }
                      : port)
                }
              })}>{equippedRouterPortSpeeds(editable, item.portId).map(
                (speed) => <option key={speed} value={speed}>
                  {speedLabel(speed)}</option>)}</select></label>
            <label>IPv4 prefix<input value={item.address}
              onChange={(event) => updateInterface(index,
                { address: event.target.value })} /></label>
            <button type="button" className="secondary-action"
              onClick={() => setDhcpServerDraft({ ...editable, running: {
                ...editable.running,
                interfaces: editable.running.interfaces.filter(
                  (_, itemIndex) => itemIndex !== index)
              } })}>Remove interface</button>
          </div>)}
        <div className="section-heading"><h3>Static routes</h3>
          <button type="button" onClick={() => setDhcpServerDraft({
            ...editable, running: { ...editable.running,
              staticRoutes: [...editable.running.staticRoutes, {
                prefix: "", nextHop: "", indirect: false
              }]
            }
          })}>Add route</button></div>
        {editable.running.staticRoutes.map((route, index) =>
          <div className="server-route-editor"
            key={`${route.prefix}-${route.nextHop}-${index}`}>
            <label>Destination prefix<input value={route.prefix}
              placeholder="0.0.0.0/0" onChange={(event) =>
                setDhcpServerDraft({ ...editable, running: {
                  ...editable.running,
                  staticRoutes: editable.running.staticRoutes.map(
                    (item, itemIndex) => itemIndex === index
                      ? { ...item, prefix: event.target.value } : item)
                } })} /></label>
            <label>Next hop<input value={route.nextHop}
              placeholder="192.0.2.254" onChange={(event) =>
                setDhcpServerDraft({ ...editable, running: {
                  ...editable.running,
                  staticRoutes: editable.running.staticRoutes.map(
                    (item, itemIndex) => itemIndex === index
                      ? { ...item, nextHop: event.target.value } : item)
                } })} /></label>
            <button type="button" className="secondary-action"
              onClick={() => setDhcpServerDraft({ ...editable, running: {
                ...editable.running,
                staticRoutes: editable.running.staticRoutes.filter(
                  (_, itemIndex) => itemIndex !== index)
              } })}>Remove route</button>
          </div>)}
        {!editable.running.staticRoutes.length &&
          <p className="inspector-empty">No static routes configured.</p>}
        <div className="section-heading"><h3>DHCPv4 servers</h3>
          <button type="button" disabled={!poolAttachments.length}
            onClick={() => {
              const attachment = poolAttachments[0];
              const used = new Set(editable.dhcpv4Servers.map(
                (item) => item.configuration.serverInstance));
              let instance = 1;
              while (used.has(instance)) instance += 1;
              setDhcpServerDraft({ ...editable,
                dhcpv4Servers: [...editable.dhcpv4Servers, {
                  name: `server-${instance}`,
                  configuration: {
                    serverIdentifier: attachment.address,
                    serverInstance: instance, routingContext: 0,
                    offerHoldSeconds:
                      PROFILE_CATALOG.protocol_defaults.dhcpv4_offer_time_seconds,
                    // RFC 2131 does not define a decline quarantine default.
                    // Zero keeps the incomplete draft visibly required instead
                    // of fabricating a server policy behind the user's back.
                    declineHoldSeconds: 0, authoritative: true,
                    domainNameServers: [], pools: [], reservations: [],
                    exclusions: []
                  }
                }]
              });
            }}>Add IPv4 server</button></div>
        {!poolAttachments.length && <p className="inspector-empty">
          Configure an IPv4 interface and physical port before adding a pool.
        </p>}
        {editable.dhcpv4Servers.map((server, serverIndex) => {
          const configuration = server.configuration;
          const updatePool = (poolIndex: number,
            patch: Partial<typeof configuration.pools[number]>) =>
            updateV4Server(serverIndex, { ...configuration,
              pools: configuration.pools.map((pool, index) =>
                index === poolIndex ? { ...pool, ...patch } : pool) });
          return <section className="dhcp-instance-editor"
            key={`${server.name}-${serverIndex}`}>
            <div className="dhcp-instance-title"><strong>IPv4 instance</strong>
              <button type="button" onClick={() => setDhcpServerDraft({
                ...editable, dhcpv4Servers: editable.dhcpv4Servers.filter(
                  (_, index) => index !== serverIndex)
              })}>Remove</button></div>
            <div className="dhcp-instance-grid">
              <label>Name<input value={server.name} onChange={(event) =>
                setDhcpServerDraft({ ...editable,
                  dhcpv4Servers: editable.dhcpv4Servers.map((item, index) =>
                    index === serverIndex
                      ? { ...item, name: event.target.value } : item) })} /></label>
              <label>Server identifier<input
                value={configuration.serverIdentifier}
                onChange={(event) => updateV4Server(serverIndex, {
                  ...configuration, serverIdentifier: event.target.value
                })} /></label>
              <label>Instance ID<input type="number" min={1}
                value={configuration.serverInstance}
                onChange={(event) => updateV4Server(serverIndex, {
                  ...configuration, serverInstance: Number(event.target.value)
                })} /></label>
              <label>Offer hold, seconds<input type="number" min={1}
                value={configuration.offerHoldSeconds}
                onChange={(event) => updateV4Server(serverIndex, {
                  ...configuration, offerHoldSeconds: Number(event.target.value)
                })} /></label>
              <label>Decline hold, seconds<input type="number" min={1}
                value={configuration.declineHoldSeconds || ""}
                placeholder="Required"
                onChange={(event) => updateV4Server(serverIndex, {
                  ...configuration, declineHoldSeconds:
                    Number(event.target.value)
                })} /></label>
              <label>Authoritative<select
                value={configuration.authoritative ? "enabled" : "disabled"}
                onChange={(event) => updateV4Server(serverIndex, {
                  ...configuration,
                  authoritative: event.target.value === "enabled"
                })}><option value="enabled">enabled</option>
                <option value="disabled">disabled</option></select></label>
            </div>
            <div className="dhcp-pool-heading"><span>Address ranges</span>
              <button type="button" disabled={!poolAttachments.length}
                onClick={() => {
                  const attachment = poolAttachments[0];
                  const nextId = configuration.pools.reduce(
                    (maximum, pool) => Math.max(maximum, pool.id), 0) + 1;
                  updateV4Server(serverIndex, { ...configuration,
                    pools: [...configuration.pools, {
                      id: nextId,
                      serverInstance: configuration.serverInstance,
                      routingContext: configuration.routingContext,
                      linkIdentity: attachment.linkIdentity,
                      first: "", last: "", subnetMask: attachment.mask,
                      router: attachment.address,
                      leaseSeconds: PROFILE_CATALOG.protocol_defaults
                        .dhcpv4_minimum_lease_time_seconds,
                      renewalSeconds: 0, rebindingSeconds: 0, enabled: true
                    }]
                  });
                }}>Add range</button></div>
            {!configuration.pools.length && <p className="inspector-empty">
              No IPv4 address ranges configured.
            </p>}
            {configuration.pools.map((pool, poolIndex) =>
              <div className="dhcp-pool-grid" key={pool.id}>
                <label>Client network<select value={
                  poolAttachments.some((candidate) =>
                    candidate.linkIdentity === pool.linkIdentity)
                    ? pool.linkIdentity : "relayed"}
                  onChange={(event) => {
                    const attachment = poolAttachments.find((candidate) =>
                      candidate.linkIdentity === event.target.value);
                    updatePool(poolIndex, {
                      // A direct request is scoped by its receiving interface.
                      // A relayed request is selected from giaddr and receives
                      // a stable non-interface identity for lease ownership.
                      linkIdentity: attachment?.linkIdentity ??
                        dhcpv4RelayedScopeIdentity(
                          configuration.serverInstance, pool.id),
                      subnetMask: attachment?.mask ?? pool.subnetMask,
                      router: attachment?.address ?? pool.router
                    });
                  }}><option value="relayed">Relayed subnet</option>
                  {poolAttachments.map((attachment) =>
                    <option key={attachment.linkIdentity}
                      value={attachment.linkIdentity}>{attachment.name}
                    </option>)}</select></label>
                <label>First address<input value={pool.first}
                  placeholder="192.0.2.10" onChange={(event) =>
                    updatePool(poolIndex, { first: event.target.value })} /></label>
                <label>Last address<input value={pool.last}
                  placeholder="192.0.2.200" onChange={(event) =>
                    updatePool(poolIndex, { last: event.target.value })} /></label>
                <label>Subnet mask<input value={pool.subnetMask}
                  onChange={(event) => updatePool(poolIndex,
                    { subnetMask: event.target.value })} /></label>
                <label>Default router<input value={pool.router}
                  onChange={(event) => updatePool(poolIndex,
                    { router: event.target.value })} /></label>
                <label>Lease, seconds<input type="number" min={1}
                  value={pool.leaseSeconds} onChange={(event) =>
                    updatePool(poolIndex,
                      { leaseSeconds: Number(event.target.value) })} /></label>
                <label>State<select value={pool.enabled ? "enabled" : "disabled"}
                  onChange={(event) => updatePool(poolIndex,
                    { enabled: event.target.value === "enabled" })}>
                  <option value="enabled">enabled</option>
                  <option value="disabled">disabled</option></select></label>
                <button type="button" className="secondary-action"
                  onClick={() => updateV4Server(serverIndex, {
                    ...configuration,
                    pools: configuration.pools.filter(
                      (_, index) => index !== poolIndex)
                  })}>Remove range</button>
              </div>)}
          </section>;
        })}
        <div className="section-heading"><h3>DHCPv6 servers</h3>
          <button type="button" onClick={() => {
            const index = editable.dhcpv6Servers.length + 1;
            setDhcpServerDraft({ ...editable,
              dhcpv6Servers: [...editable.dhcpv6Servers, {
                name: `server-${index}`,
                configuration: {
                  duidHex: randomDuidUuid(), preference: 0,
                  rapidCommit: false, leaseQuery: false,
                  dnsRecursiveServers: [],
                  // RFC 9915 carries the RFC 8415 default Information Refresh
                  // Time of 86400 seconds. This is a wire-protocol default,
                  // unlike the explicitly required decline hold below.
                  informationRefreshTimeSeconds: 86400,
                  solicitMaximumRetransmissionSeconds: null,
                  informationMaximumRetransmissionSeconds: null,
                  declineHoldTimeSeconds: 0, addressPoolIndex: 0,
                  prefixPoolIndex: 0, addressPools: [], prefixPools: []
                }
              }]
            });
          }}>Add IPv6 server</button></div>
        {editable.dhcpv6Servers.map((server, serverIndex) => {
          const configuration = server.configuration;
          const poolEditor = (kind: "addressPools" | "prefixPools",
            label: string) => <div className="dhcp-pool-family">
            <div className="dhcp-pool-heading"><span>{label}</span>
              <button type="button" onClick={() =>
                updateV6Server(serverIndex, { ...configuration,
                  [kind]: [...configuration[kind], {
                    prefix: "", allocationSecretHex: randomSecretHex(),
                    preferredLifetimeSeconds: 0, validLifetimeSeconds: 0,
                    t1Seconds: 0, t2Seconds: 0,
                    delegatedLength: kind === "prefixPools" ? 64 : null
                  }]
                })}>Add pool</button></div>
            {configuration[kind].map((pool, poolIndex) =>
              <div className="dhcp-pool-grid" key={`${kind}-${poolIndex}`}>
                <label>Prefix<input value={pool.prefix}
                  placeholder={kind === "addressPools"
                    ? "2001:db8:1::/64" : "2001:db8:100::/56"}
                  onChange={(event) => updateV6Server(serverIndex, {
                    ...configuration, [kind]: configuration[kind].map(
                      (item, index) => index === poolIndex
                        ? { ...item, prefix: event.target.value } : item)
                  })} /></label>
                {kind === "prefixPools" && <label>Delegated length<input
                  type="number" min={1} max={128}
                  value={pool.delegatedLength ?? ""}
                  onChange={(event) => updateV6Server(serverIndex, {
                    ...configuration, [kind]: configuration[kind].map(
                      (item, index) => index === poolIndex ? {
                        ...item, delegatedLength: Number(event.target.value)
                      } : item)
                  })} /></label>}
                {(["preferredLifetimeSeconds", "validLifetimeSeconds",
                  "t1Seconds", "t2Seconds"] as const).map((field) =>
                  <label key={field}>{field === "preferredLifetimeSeconds"
                    ? "Preferred lifetime" : field === "validLifetimeSeconds"
                      ? "Valid lifetime" : field === "t1Seconds" ? "T1" : "T2"}
                    <input type="number" min={0} value={pool[field] || ""}
                      onChange={(event) => updateV6Server(serverIndex, {
                        ...configuration, [kind]: configuration[kind].map(
                          (item, index) => index === poolIndex
                            ? { ...item, [field]: Number(event.target.value) }
                            : item)
                      })} /></label>)}
                <button type="button" className="secondary-action"
                  onClick={() => updateV6Server(serverIndex, {
                    ...configuration, [kind]: configuration[kind].filter(
                      (_, index) => index !== poolIndex)
                  })}>Remove pool</button>
              </div>)}
          </div>;
          return <section className="dhcp-instance-editor"
            key={`${server.name}-${serverIndex}`}>
            <div className="dhcp-instance-title"><strong>IPv6 instance</strong>
              <button type="button" onClick={() => setDhcpServerDraft({
                ...editable, dhcpv6Servers: editable.dhcpv6Servers.filter(
                  (_, index) => index !== serverIndex)
              })}>Remove</button></div>
            <div className="dhcp-instance-grid">
              <label>Name<input value={server.name} onChange={(event) =>
                setDhcpServerDraft({ ...editable,
                  dhcpv6Servers: editable.dhcpv6Servers.map((item, index) =>
                    index === serverIndex
                      ? { ...item, name: event.target.value } : item) })} /></label>
              <label>Preference<input type="number" min={0} max={255}
                value={configuration.preference}
                onChange={(event) => updateV6Server(serverIndex, {
                  ...configuration, preference: Number(event.target.value)
                })} /></label>
              <label>Decline hold, seconds<input type="number" min={1}
                value={configuration.declineHoldTimeSeconds || ""}
                placeholder="Required"
                onChange={(event) => updateV6Server(serverIndex, {
                  ...configuration,
                  declineHoldTimeSeconds: Number(event.target.value)
                })} /></label>
              <label>Rapid Commit<select
                value={configuration.rapidCommit ? "enabled" : "disabled"}
                onChange={(event) => updateV6Server(serverIndex, {
                  ...configuration,
                  rapidCommit: event.target.value === "enabled"
                })}><option value="disabled">disabled</option>
                <option value="enabled">enabled</option></select></label>
            </div>
            {poolEditor("addressPools", "IA_NA address pools")}
            {poolEditor("prefixPools", "IA_PD prefix pools")}
          </section>;
        })}
        <div className="button-pair"><button onClick={() =>
          setDhcpServerDraft(structuredClone(dhcpServer))}>Discard</button>
          <button className="inspector-action" onClick={() =>
            updateDhcpServer(editable)}>Apply</button></div>
        <button className="secondary-action" onClick={() =>
          deleteNode(dhcpServer.id)}>Delete server</button>
      </div>{resizeHandle}
    </aside>;
  }

  if (ethernetSwitch) {
    const switchProfile = PROFILE_CATALOG.switch_profiles.find(
      (item) => item.id === ethernetSwitch.profileId);
    // Project validation guarantees that every selected profile comes from
    // the generated catalog. Refusing to render an invented fallback keeps a
    // corrupt project visible as an integrity problem rather than fake data.
    if (!switchProfile) {
      return <aside className="inspector"><div className="inspector-title">
        <div><h2>{ethernetSwitch.name}</h2><p>Unknown switch profile</p></div>
        <button aria-label="Close inspector" onClick={close}><X size={18} /></button>
      </div>{resizeHandle}</aside>;
    }
    return <aside className="inspector">
      <div className="inspector-title"><div><h2>{ethernetSwitch.name}<i className={liveSwitch ? "dot-good" : "dot-muted"} /></h2><p>Ethernet switch</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
      <div className="host-form">
        <label>Name<input value={switchNameDraft}
          onChange={(event) => setSwitchNameDraft(event.target.value)}
          onBlur={() => {
            const committed = switchNameDraft.trim();
            if (committed && committed !== ethernetSwitch.name)
              setSwitchName(ethernetSwitch.id, committed);
            else setSwitchNameDraft(ethernetSwitch.name);
          }} /></label>
        <div className="spec-grid"><span>Profile</span><strong>{switchProfile.display_name}</strong><span>Broadcast domains</span><strong>{switchProfile.untagged_broadcast_domains}</strong><span>FDB capacity</span><strong>{switchProfile.fdb_entries}</strong></div>
        <div className="ports-summary switch-ports">
          <div className="panel-kicker switch-ports-heading">
            <span>PHYSICAL PORTS</span>
            <strong>{ethernetSwitch.ports.length}</strong>
          </div>
          {ethernetSwitch.ports.map((port) => {
          const runtimePort = liveSwitch?.ports.find((item) => item.id === port.id);
          const attached = project.links.find((item) => item.endpoints.some(
            (endpoint) => endpoint.nodeId === ethernetSwitch.id &&
              endpoint.portId === port.id));
          return <div className="switch-port-editor" key={port.id}>
            <span className="switch-port-identity">
              <i className={runtimePort?.admin && attached
                ? "dot-good" : "dot-muted"} />
              {port.id}
            </span>
            <div className="switch-port-controls">
              <label>State<select value={port.admin} onChange={(event) => setSwitchPort(ethernetSwitch.id, port.id, event.target.value === "up", port.speedMbps, port.mtu)}><option value="up">up</option><option value="down">down</option></select></label>
              <label>Speed<select value={port.speedMbps} onChange={(event) => setSwitchPort(ethernetSwitch.id, port.id, port.admin === "up", Number(event.target.value), port.mtu)}>{switchProfile.supported_speeds_mbps.map((speed) => <option key={speed} value={speed}>{speedLabel(speed)}</option>)}</select></label>
              <label>MTU<input type="number" min={switchProfile.minimum_mtu} max={switchProfile.maximum_mtu} value={port.mtu} onChange={(event) => { const mtu = Number(event.target.value); if (Number.isSafeInteger(mtu)) setSwitchPort(ethernetSwitch.id, port.id, port.admin === "up", port.speedMbps, mtu); }} /></label>
            </div>
          </div>;
        })}</div>
        <button className="secondary-action" onClick={() => deleteNode(ethernetSwitch.id)}>Delete switch</button>
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
        {/* Provisioned and equipped types are intentionally separate. SR OS
            configuration may reserve a slot before hardware is inserted, and
            the runtime must expose a mismatch instead of silently repairing it. */}
        <div className="hardware-type-pair">
          <label>Provisioned type<select disabled={profile.fixed}
            value={card.provisionedType ?? ""}
            onChange={(event) => setCard(router.id, card.slot,
              event.target.value || null, card.equippedType)}>
            <option value="">Not provisioned</option>
            {compatible.map((item) => <option key={item.type}>{item.type}</option>)}
          </select></label>
          <label>Equipped type<select disabled={profile.fixed}
            value={card.equippedType ?? ""}
            onChange={(event) => setCard(router.id, card.slot,
              card.provisionedType, event.target.value || null)}>
            <option value="">Absent</option>
            {compatible.map((item) => <option key={item.type}>{item.type}</option>)}
          </select></label>
        </div>
        <label className="hardware-admin">Administrative state<select disabled={profile.fixed || !card.provisionedType} value={card.admin} onChange={(event) => setCardAdmin(router.id, card.slot, event.target.value === "up")}><option value="down">down</option><option value="up">up</option></select></label>
        {card.mdas.slice(0, selectedCard?.mda_slots ?? 0).map((mda) =>
          <div className="mda-editor" key={mda.slot}>
            <div className="slot-head"><span>MDA {card.slot}/{mda.slot}</span>
              <StatePill up={mda.admin === "up" && Boolean(mda.equippedType &&
                mda.equippedType === mda.provisionedType)}>
                {mda.equippedType ? mda.equippedType === mda.provisionedType
                  ? mda.admin === "up" ? "ready" : "shutdown"
                  : "mismatch" : "absent"}
              </StatePill>
            </div>
            {/* An MDA follows the same configured-versus-inserted contract as
                its parent card. Keeping both controls visible makes physical
                replacement and deliberate mismatch testing possible. */}
            <div className="hardware-type-pair">
              <label>Provisioned type<select disabled={profile.fixed}
                value={mda.provisionedType ?? ""}
                onChange={(event) => setMda(router.id, card.slot, mda.slot,
                  event.target.value || null, mda.equippedType)}>
                <option value="">Not provisioned</option>
                {selectedCard?.mdas.map((type) =>
                  <option key={type}>{type}</option>)}
              </select></label>
              <label>Equipped type<select disabled={profile.fixed}
                value={mda.equippedType ?? ""}
                onChange={(event) => setMda(router.id, card.slot, mda.slot,
                  mda.provisionedType, event.target.value || null)}>
                <option value="">Absent</option>
                {selectedCard?.mdas.map((type) =>
                  <option key={type}>{type}</option>)}
              </select></label>
            </div>
            <label className="hardware-admin">Administrative state<select
              disabled={profile.fixed || !mda.provisionedType}
              value={mda.admin}
              onChange={(event) => setMdaAdmin(router.id, card.slot, mda.slot,
                event.target.value === "up")}>
              <option value="down">down</option><option value="up">up</option>
            </select></label>
          </div>)}
      </div>;
    })}</>;
    if (tab === "ports") return <div className="ports-summary"><div className="panel-kicker">PHYSICAL PORTS</div>{live?.ports.length ? live.ports.map((port) => {
      const link = project.links.find((item) => item.endpoints.some((endpoint) => endpoint.nodeId === router.id && endpoint.portId === port.id));
      return <div key={port.id}><span><i className={port.oper ? "dot-good" : "dot-muted"} />{port.id}</span><strong>{port.admin ? "up" : "down"} · {speedLabel(port.speedMbps)}</strong>{link ? <button onClick={() => setLink(link.id, link.admin !== "up")}>{link.admin === "up" ? "Disconnect" : "Connect"}</button> : <small>No medium</small>}</div>;
    }) : <p className="empty-copy inspector-empty">No ports are exposed by equipped hardware.</p>}</div>;
    return <div className="operational-panel"><div className="metric-strip compact"><div><small>Routes</small><strong>{live?.staticRoutes.length ?? 0}</strong></div><div><small>Links</small><strong>{project.links.filter((item) => item.endpoints.some((endpoint) => endpoint.nodeId === router.id)).length}</strong></div><div><small>Ports</small><strong>{live?.ports.filter((port) => port.oper).length ?? 0}</strong></div></div><button className="inspector-action" onClick={() => openConsole(router.id)}>Open console</button><button className="secondary-action" onClick={() => deleteNode(router.id)}>Delete router</button><div className="operational-list"><h3>Static routes</h3>{live?.staticRoutes.map((route) => <div key={`${route.prefix}|${route.nextHop}|${route.indirect}`}><strong>{route.prefix}</strong><span>{route.indirect ? "indirect " : ""}{route.nextHop}</span></div>)}</div></div>;
  };

  return <aside className="inspector">
    <div className="inspector-title"><div><h2>{router.systemName}<i className={runtimeReady ? "dot-good" : "dot-muted"} /></h2><p>{runtimeReady ? "Running" : "Unavailable"}</p></div><button aria-label="Close inspector" onClick={close}><X size={18} /></button></div>
    <nav className="inspector-tabs">{(["chassis", "cpm", "cards", "ports", "operational"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTabChange(item)}>{item === "cpm" ? "CPM" : item[0].toUpperCase() + item.slice(1)}</button>)}</nav>
    {renderTab()}{resizeHandle}
  </aside>;
}
