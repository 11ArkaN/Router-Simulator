# Router Simulator

**Status: Work in progress. This is not a complete Nokia SR OS implementation.**

Router Simulator is a browser-based network emulator that runs in real time. You build a topology of modular routers and hosts, provision their hardware, and drive them from a CLI, while a packet engine underneath moves real Ethernet, ARP, IPv4, IPv6, ICMP and ICMPv6 frames across the links, carries a working TCP and UDP transport, and runs host application services on top of it. A ping or a DNS lookup succeeds only when its packet is actually forwarded, queued and delivered.

Router Simulator is an independent, unofficial educational project. It is not affiliated with, sponsored by, endorsed by or produced by Nokia. The application uses Nokia SR OS 26.7.R1 documentation as a behavior reference. It does not use the Nokia logo and does not claim full product compatibility.

## Implemented capabilities

A lab holds up to 16 routers, 16 hosts and 64 physical links. Routers come from generated 7750 SR-1, SR-7 and SR-12 catalogs, and you provision their cards and MDAs from whatever combinations the catalog allows. Insertion, removal and type mismatches are all handled. Ports aren't fixed up front. They appear as you equip the chassis, card and MDA inventory, and the model keeps inventory, provisioning, running and operational state apart instead of merging them.

MD-CLI and classic CLI render contextual `info` and `info detail` from the same typed running or candidate datastore while preserving their engine-specific hierarchy and spelling. Local verification checks renderer ownership against the generated command catalog and executes both forms from configured present working contexts in each supported configuration family. Router interface subtrees, BOF autoconfiguration and static-route destination, route-type and next-hop levels are scoped from their canonical typed trees rather than separate context-specific copies.

Every console runs the MD-CLI and classic CLI engines in one session. The exact `//` command changes the persistent terminal engine, while `//command` executes one absolute command through the other engine and restores the original context. MD-CLI edits land as transactions, classic edits take effect immediately. MD-CLI supports the implicit `configure <mode>` workflow and the explicit `edit-config <mode>` workflow. In an explicit workflow, `configure` navigates from the candidate root into the configure region, while `edit-config` itself never becomes a configuration context. Configuration workflow ownership is generated from the release command catalog, so every configuration family follows the same candidate and operational-mode rules. The Base router key is omitted from MD-CLI input and is resolved to the canonical `router "Base"` datastore path. Help and completion expose the Base router's children directly without inserting its default key into the editable command. Unique Tab and Spacebar completion ends the completed element with one separator, absolute-path completion preserves its leading slash, and Enter never rewrites the exact `//` engine command as an inline command. Compound IPv4 primary-address syntax requires both `address` and `prefix-length` before execution and never creates a context from a scalar address value. Classic keyed `create` commands enter the created or already existing object context; trailing `create` and create-time arguments such as IES `customer` or OSPF `router-id` stay out of the stored prompt. Classic `no` of an OSPF instance, OSPF area, OSPF interface, Base router interface, DHCP server, or TLS client, server or cert profile requires that object to be shut down first. The system interface is permanent and neither engine removes it. MD-CLI `delete` of an IES list entry removes the whole subtree and does not copy that classic shutdown cascade. MD-CLI `delete` of a static route, next hop or indirect path removes it regardless of its admin-state leaf. MD-CLI `delete` of an absent or already-default element succeeds silently per the MD-CLI guide and never creates configuration, while classic `no` keeps the rejected result for absent elements and classic context entry keeps its create-on-entry behavior. MD OSPF `asbr`, `graceful-restart` and `loopfree-alternate` are presence containers, and graceful restart defaults to present per YANG. OSPF `summaries` and `default-metric` live only under area stub and area nssa. MD IPv6 `prefix-length` accepts 4 through 128. MD-CLI `delete` accepts absolute, relative and mid-path placement, while classic `no` retains command-specific reset, disable and removal behavior. Neither edit operator can become part of a present working context, and both generated-schema validation and the session path owner enforce this invariant. Static IPv4 and IPv6 next-hop and indirect commands select their real keyed contexts. Their administrative state is retained in configuration, reflected as `admin-state` in MD-CLI and `shutdown` or `no shutdown` in classic CLI, and controls RIB and FIB installation independently of deletion. A unique disabled classic static route can be removed by its prefix. Destinations with multiple next hops require a qualified `no` form that selects one disabled child. The terminal carries prompts, context navigation, completion, line editing, three history regions and paging. Its visible window stays virtualized while the full transcript is archived to OPFS. Contextual `info` and `info detail` read the active candidate in MD-CLI and running configuration in classic CLI, with braces for MD hierarchy and `exit` delimiters for classic hierarchy. Card, MDA, physical Ethernet, DHCP, MLD, policy-options, TLS, IPsec, PKI and IES contexts render the shared typed configuration through each engine's native hierarchy. Tests and production builds reject a release command family that has no contextual renderer in either engine. Release-schema output modifiers provide `detail` only for commands that document it, including port, router interface, OSPF interface, neighbor and database reports in both terminal engines. The configuration surface covers ports, router and system interfaces, dual-stack addressing, IPv6 neighbors, MLD, static routes, IES service interfaces, TLS profiles, IPsec templates, IPsec client databases, RADIUS authentication policies and PKI certificate authority with OCSP, CMPv2 and automatic CRL update, common-name, EST, certificate update and auto-update profiles. IES interfaces carry multiple IPv4 addresses and OSPF instances export through a chain of up to five route policies. Operational interface reports select running objects by name, IP address, address family or global interface index and expose forwarding-owned traffic counters. Neighbor reports add the `all` selector, the `interface` keyword form and IPv6 address filtering. FIB reports filter by family, prefix with longer-match and summary. ARP reports add local, static and managed type filters. `clear` is a classic CLI operation while MD-CLI uses the corresponding `reset` commands with the same selectors. Port detail reports include deterministic virtual transceiver identity while leaving unmodeled DDM sensor values as unavailable. System alarm reports expose active and cleared equipment alarms with source-backed alarm IDs, latched timestamps, severity, count and newer-than filters. Route-table reports support IPv4 and IPv6 families, canonical prefix filtering, `longer`, `exact`, protocol and instance filters, summaries, extensive rows, inactive configured static routes and installed loop-free alternatives. Standard route rows include owner-recorded route age.

The packet plane is the point of the whole thing. Frames are encoded, serialized onto links with propagation delay and bounded queues, and forwarded for real. It is dual stack. ARP and IPv6 neighbor discovery are learned and aged, duplicate address detection and router advertisement run per interface, and MLD tracks multicast listeners. Connected, static, OSPFv2 and OSPFv3 routes feed per-router RIB selection and versioned FIB generations for both address families, with equal-cost multipath and scoped indirect next hops. Static-route next hops use typed, unquoted IPv4 and IPv6 address keys in MD-CLI input and configuration output. IPv4 and IPv6 forwarding cover TTL and hop limit, fragmentation and reassembly, Path MTU discovery, extension headers and ICMP and ICMPv6 errors. A host can ping any entered IPv4 destination instead of being limited to another host already present on the canvas. Host and router ping reports use the release-defined five probes and show each reply or timeout, received TTL, forwarding-measured RTT, loss and min, average, max and population standard deviation. Failing a link or pulling a line card cascades through everything downstream.

OSPF runs as a distributed control-plane protocol. Routers exchange encoded Hello, Database Description, Link State Request, Link State Update and Link State Acknowledgment packets through their physical interfaces and Ethernet switches. Each process owns its interface and neighbor state machines, LSDB, flooding, retransmission, local timers and Dijkstra calculations. The implemented scope covers OSPFv2, OSPFv3 IPv6 and IPv4 unicast address families, point-to-point and multi-access networks, NBMA and point-to-multipoint operation, virtual links, normal, stub and NSSA areas, ABR and ASBR behavior, external redistribution policies, authentication, graceful-restart helper behavior, IP LFA and ECMP. Ethernet OSPF interfaces default to broadcast. OSPFv3 IPsec AH uses the RFC 2104 key rule for HMAC-MD5-96 and HMAC-SHA-1-96, including keys longer than the digest size. MD-CLI uses YANG `p2mp-nbma` for the point-to-multipoint network type while classic CLI documents broadcast, point-to-point and non-broadcast. Detailed neighbor reports read protocol instance, advertised options, queue occupancy, event and restart counters, state age, dead-timer remainder, graceful-restart helper state and FSM errors directly from the control-plane owner. The MD-CLI and classic CLI expose the corresponding configuration, inspection and reset commands from the generated release schema.

Vendor-neutral Ethernet switches provide real shared broadcast domains with profile-defined ports, queues and MTU. Their forwarding owner learns source MAC addresses, ages FDB entries, forwards known unicast and floods unknown unicast, broadcast and multicast traffic. Physical L2 loops are rejected until a spanning-tree subsystem exists.

Above the network layer the runtime carries a real transport and a set of host application services. TCP implements the connection state machine, initial sequence generation, option negotiation, congestion control, RTO estimation, SACK loss recovery, delayed acknowledgement and persist behavior; UDP provides its own datagram sockets. DHCPv4 clients, servers and relays exchange encoded datagrams over the normal Ethernet, IPv4 and UDP path, including address conflict detection, lease renewal and Base router local-server operation. The host Inspector reports the forwarding-owned DHCPv4 state, assigned address, subnet mask, router, server identifier and remaining lease time. DHCPv6 clients, servers and relays use the corresponding IPv6 multicast, unicast and UDP path, stable DUID and IAID identities, address lifetimes and router-advertisement coordination. A dedicated non-forwarding server can own multiple routed interfaces, DHCPv4 address ranges, IA_NA address pools and IA_PD prefix pools. Its Inspector edit is committed as one native runtime transaction. Hosts also run an iterative DNS resolver with a negative cache and authoritative zones loaded from master-file text, plus DNSSEC record handling and zone signing. A TLS 1.3 engine, a local PKI and secret vault, QUIC, HTTP/2, HTTP/3, the encrypted DNS transports (DoT, DoH over HTTP/2 and HTTP/3, DoQ), DNSSEC response validation, IKEv2, IPsec and DHCP failover protocol engines are working foundations rather than complete implementations. The capability matrix marks each feature as implemented, partially implemented or unsupported. The IPsec classic CLI follows the documented 26.7 grammar: numeric dh-group and pfs-dh-group values with pfs-dh-group inherit, the extended-sequence-number flag form, no invented no forms for ike-transform leaves, and the YANG group-14 and sha-256 defaults restored by the MD delete operators. The interface IPv4 ICMP redirects context follows the YANG path (interface ipv4 icmp redirects), the MD dns-options leaf is include-rdnss while classic keeps include-dns, interface-level MLD robust-count is gone in favour of the protocol leaf, and policy-options prefix entries carry the mandatory YANG match type key. Classic OSPF spells loopfree-alternates and exports clear with a bare no export, the classic keychain tolerance keyword is forever and begin-time now stays classic only, the classic OSPF interface-type accepts p2mp-nbma, and the classic DHCP remote-id spells string with no none value. The DHCPv6 pool prefix lifetime leaves restore their fixed YANG defaults (3600, 86400, 1800 and 2880 seconds) on delete and no forms instead of inheriting the server defaults, and the tunnel-template ICMP generation no forms revert the documented interval and message-count defaults. Service identifiers cap at the YANG external-service-id range, DHCP pool names follow the named-item 32-octet limit, IES interface descriptions allow 255 octets and the interface ip-mtu spans 512 through 9786. Classic no forms carry no undocumented shutdown preconditions for DHCP local servers or TLS profiles, the classic IES no interface removes a shut down interface with a configured SAP, a classic no of an absent static route errors, and OSPF graceful restart defaults to absent per the YANG presence container.

Live traffic can be captured at link, ingress, egress and CPM points and exported as PCAPNG that `tshark` opens cleanly. A project saves to `.netsim` as portable intent or as a full structural checkpoint, and import is locked to the matching profile.

The Workspace sidebar includes a Demos tab with ready-to-run labs. The current catalog ships a static IPv4 two-router path and an OSPF triangle with a higher cost backup link, and each launch replaces the active lab only after confirmation when the current workspace contains user-owned content.

Routers and hosts are dragged onto the canvas, and a link picks its physical ports when you connect it. A new host is created immediately with a cryptographically generated locally administered unicast MAC address, the catalog-defined 1500-byte host MTU and no IPv4 address. Static addressing or DHCP can be selected later in the Inspector. Device positions and attached links follow the pointer continuously during a drag, while the durable project coordinate is written once when the device is dropped. Device and link graphics remain visually stable while they are hovered or selected. The built-in black theme is declared to the browser before styles load, so native controls and accessibility extensions recognize that the page is already dark. The topology, inspector, sidebar and terminal panels resize on desktop. The terminal recalculates its row and column geometry from the available panel rectangle, so long prompts reflow instead of being clipped when neighboring panels change width. Below 900px the sidebar folds into a drawer and the inspector into an overlay.

## Architecture

The packet runtime is written in C++20 and compiled with Emscripten to WebAssembly. It runs outside the React thread and requires pthreads with shared WebAssembly memory.

At startup, the generated CPU policy creates three, five or seven pthreads in addition to the browser control Worker. Hosts with up to four logical CPUs use one control owner and one combined forwarding and link owner. Hosts with five to eight logical CPUs use one control, two forwarding and one link owner. Larger hosts use two control, three forwarding and one link owner. Every policy also starts separate permanent OSPF and IS-IS owners. Stable device handles select owner shards and live devices do not migrate. Shared packet state does not cross the browser boundary through per-packet `postMessage` calls.

Each IS-IS forwarding/control direction has 16 maximum-frame credits per forwarding shard. Full egress retains unsent protocol work and completed frame credits return only after receipt consumption. The six channel rings fit within 1 MiB and share the unchanged 24 MiB network metadata reserve with OSPF and forwarding. These transport capacities are emulator budgets; active-instance scale remains subject to the IS-IS acceptance measurements.

Protocol frame publication wakes the selected forwarding owner directly, including when the network is idle. Route publications wake their link-owner consumer. Bounded frame drainers continue while ready work and output credits remain, and returned credits wake blocked forwarding work.

Forwarding starts after protocol callback targets are fully constructed. Shutdown joins the protocol threads while retaining their notification storage, joins forwarding producers, then destroys protocol objects and shared channels. A stopped protocol owner rejects new control commands.

The runtime uses the host monotonic clock. It has no simulation timeline, global future-event heap, pause control, step control or speed multiplier. Protocol and hardware deadlines pass in real time.

Main components:

- React, Vite and TanStack Router for the application shell
- React Flow for topology rendering
- xterm.js for terminal rendering
- lucide-react for the interface icons
- C++20 for hardware, configuration, CLI, routing, packet processing, transport, host services and capture
- OpenSSL, nghttp2, nghttp3 and ngtcp2, all compiled to the Emscripten target, for TLS, HTTP/2, HTTP/3 and QUIC
- WebAssembly pthreads and `SharedArrayBuffer` for the runtime
- IndexedDB for project metadata
- OPFS for terminal history, checkpoints and binary captures

The C++ core has no dependency on React, the DOM, xterm.js, IndexedDB or OPFS.

The Emscripten build enables C++ exception handling during both compilation and linking so native constructor and allocation-error handlers remain active in WebAssembly. Cross-translation-unit rejection tests run in the native and Wasm module suites.

## Current scope

The hard ceilings are 16 routers, 16 hosts, 64 links and four terminal sessions per router. Hardware is whatever the active release catalog defines, down to its Ethernet card functions and port layouts, and the CLI exposes only the commands its capability matrix backs. The dual-stack, transport and host-service stacks cover the functions listed above rather than the full RFC surface, and the features called foundations still have partial behavior. Routing currently includes connected, static, OSPFv2 and OSPFv3 routes. IS-IS, BGP, MPLS, spanning tree, most of QoS, high availability, LAG and the bulk of SR OS management are not built yet, and terminal users are limited to `admin` without AAA. OSPF integrations that require BFD, VPRN, MPLS traffic engineering, Segment Routing, Remote LFA, RSVP forwarding adjacencies or LDP remain unavailable until those subsystems exist. Card and MDA initialization times are emulator profile estimates, not measured hardware.

Checkpoint import only accepts a file whose profile, checkpoint ABI and build hash match the running build. Without cross-origin isolation the runtime refuses to start at all. A command it doesn't support returns an explicit error, and it reports success only after it has actually changed router state.

## Requirements

- Windows 10 or Windows 11 for the repository PowerShell scripts
- Node.js 22
- pnpm 11
- Chrome, Edge or Firefox with `SharedArrayBuffer` support
- PowerShell 7 or Windows PowerShell 5.1
- Visual Studio 2022 Build Tools for native MSVC builds
- Git for Windows, whose `perl` configures OpenSSL during the dependency bootstrap
- Network access for the one-time toolchain and native dependency bootstrap
- Wireshark with `tshark` for local PCAPNG conformance tests

WSL is not required or used by the local workflow.

## Setup

Install JavaScript dependencies, the repository-local compiler toolchain and the native libraries the core links against:

```powershell
pnpm install
pnpm toolchain:bootstrap
pnpm dependencies:bootstrap
pnpm yang:bootstrap
```

`toolchain:bootstrap` installs the pinned toolchain under the ignored `.tools` directory:

- Emscripten 6.0.3
- CMake 4.4.0
- Ninja 1.13.0

`dependencies:bootstrap` downloads, verifies and compiles the native crypto and transport libraries for the same Emscripten pthread target, also under `.tools`. These back TLS, QUIC, HTTP/2, HTTP/3 and the encrypted DNS transports:

- OpenSSL 3.5.7
- nghttp2 1.69.0
- nghttp3 1.17.0
- ngtcp2 1.24.0

Publish the current WebAssembly build and start the development server:

```powershell
pnpm core:publish
pnpm dev
```

Open `http://127.0.0.1:5173/`. The Vite server sends the COOP and COEP headers required by WebAssembly threads. Startup stops with an error if the page is not cross-origin isolated or any owner selected by the generated shard policy does not start.

## Build and verification

Create a production build:

```powershell
pnpm build
```

Run source validation, generated-profile checks, dependency checks, type checking, C++ and TypeScript tests, benchmark regression checks and the production build:

```powershell
pnpm verify
```

Changes to the UI or browser runtime must also be checked manually against the production build with cross-origin isolation active. Create the topology through product controls and exercise the affected terminal, persistence and recovery paths.

Individual core commands are also available:

```powershell
pnpm core:build
pnpm core:test
pnpm core:manual
pnpm core:benchmark
pnpm core:structure-benchmark
pnpm core:runtime-benchmark
```

Native CTest builds include a PCAPNG fixture. When `tshark` is installed under `C:\Program Files\Wireshark`, CMake adds the `tshark_pcapng` conformance test automatically.

## Projects, checkpoints and captures

IndexedDB stores the active project and UI layout. OPFS stores the terminal transcript, latest capture and latest structural checkpoint. Autosave serializes complete persistence transactions and writes the runtime checkpoint before the project head, so configuration committed through either CLI engine survives reload together with the topology without a manual save control.

A `.netsim` file has one of two modes:

- `project` stores portable intent, topology, hardware choices, running configuration, notes, layout and an optional capture
- `checkpoint` adds the live operational state: dual-stack RIBs and FIBs, ARP and IPv6 neighbor caches, router advertisement, Path MTU and reassembly state, MLD, DHCPv4 and DHCPv6 client state, server leases, pending offers, conflict probes, stable DUID and IAID identities, UDP and TCP sockets, the DNS resolver and DNSSEC caches, fabric link transmissions, capture selection and counters, the project secret vault, relative deadlines, counters, alarms, CLI semantics, terminal editor state, histories, queued input and pager position

Packet capture is encoded incrementally as PCAPNG and appended by the runtime Worker to project-scoped OPFS. A session has no fixed 32 MiB runtime limit. Export flushes the active generation before downloading the complete file.

An incompatible checkpoint is rejected before runtime replacement. The user can explicitly import only its project data, which starts a new runtime without the incompatible operational state.

## Sources and capability tracking

[`sources/catalog.yaml`](sources/catalog.yaml) records the normative source, release, implementation files, tests and verification status for each implemented behavior. [`sources/capabilities.yaml`](sources/capabilities.yaml) marks features as implemented, partially implemented, experimental or unsupported.

The agreed [IS-IS implementation plan](docs/isis-implementation-plan.md) covers the Base-router scope, pinned SR OS 26.7.R1 YANG models, both CLI engines, packet processing, routing, checkpoint continuity and acceptance gates.

The Ethernet LLC UI codec supports ordinary Length framing and the IEEE 802.1AC `0x8870` encapsulation, including QinQ and bounded jumbo frames. Ordinary receive views exclude Ethernet padding. A protocol-neutral SPSC frame channel supplies the shared ownership mechanism for control protocols; OSPF uses the same implementation through its existing API. LLC runtime dispatch and the IS-IS worker remain in progress.

Core tests send all nine IS-IS PDU types through physical link queues and a learning bridge. The forwarding boundary admits configured protocol multicast without requiring an IP address and enforces the egress port MTU. The P2P adjacency owner keeps ISO state, three-way state and holding expiry separate; the instance worker and runtime configuration still need to connect these components.

IS-IS egress requires the protocol owner's encoded source MAC to match the current physical port and passes the complete frame unchanged into its queue. An obsolete local MAC projection is rejected for the protocol owner to reconcile.

LAN adjacency records track two-way neighbor MAC reporting and independent holding deadlines at each level. Capacity decisions follow the ISO priority and MAC order, with insertion waiting for the victim's Down completion. Periodic jitter uses the ISO 25 percent range and a caller-owned PRNG continuation.

Hello composition splits neighbor and interface-address lists across complete TLVs, places IID first and authenticates the final padding. A one-octet padding gap remains below the selected PDU maximum. Shared frame channels reject duplicate slot returns and invalid frame lengths before either can corrupt ownership.

CSNP and PSNP composition preserves ascending LSP-ID order across complete TLV 9 lists, checks CSNP range bounds and authenticates the final batch. A batch that exceeds the selected PDU size fails without emitting partial acknowledgements. Empty CSNP ranges can describe an empty database. Instance scheduling, range partitioning and flood-flag updates after real egress remain in progress.

The RFC 5120 wire layer encodes topology membership and MT reachability for neighbors, IPv4 and IPv6. Membership unions repeated options, an absent membership option implies MT0 only, and O/A flags apply only to nonzero topologies in fragment-zero LSPs. Hello composition carries membership independently of instance-specific topology identifiers. Per-topology adjacency use, SPF and route publication remain in progress.

A bounded per-level LAN collection owns neighbor area projections and preflights retention before refreshing a holding timer. Capacity admission includes Initializing neighbors and completes the evicted peer's local Down processing before inserting its replacement. Accepted area changes, one-way loss, expiry and circuit shutdown pass through the same synchronous owner callback. The instance process still needs to connect those callbacks to area and flooding state.

Protocol frame channels can return the forwarding owner's port-queue admission result with the frame handle. This optional mode holds producer credits until the result is consumed, allowing IS-IS to keep SRM and SSN set after a saturated physical link refuses output. The default channel retains its existing automatic reclamation. Runtime integration of IS-IS completion handling remains in progress.

[`sources/yang/26.7.R1.lock.yaml`](sources/yang/26.7.R1.lock.yaml) pins 361 source modules in the dependency closure of the selected IS-IS configuration, state and management roots to the exact release commit. Byte sizes and SHA-256 digests use the original Git blobs, preserving identity across Windows line-ending conversion. [`schemas/cli/isis-26.7.R1-inventory.json`](schemas/cli/isis-26.7.R1-inventory.json) records 405 configuration nodes, 592 state nodes and 454 management nodes with their source locations, resolved typedef chains, inherited defaults, union members, restriction layers and choice/case structure. Runtime support and command mapping remain planned.

`pnpm yang:bootstrap` acquires the exact-release source cache under `.tools`. `pnpm yang:check` verifies source hashes and generated inventory drift, and `pnpm yang:generate` regenerates the project-authored metadata. Source validation also runs the statement-reader and dependency-inventory tests. Vendor YANG source files remain outside the distributed repository and application.

[`sources/normative/iso10589-2002.lock.yaml`](sources/normative/iso10589-2002.lock.yaml) identifies the verified complete ISO/IEC 10589:2002 English document used for the IS-IS implementation. The PDF remains local.

```powershell
pnpm sources:validate
```

The validator rejects missing sources, missing tests, invalid implementation paths and unknown source identifiers used by code comments.

## License and trademarks

Project source code is licensed under the [Apache License 2.0](LICENSE). Contributions submitted for inclusion are licensed on the same terms.

Nokia is a registered trademark of Nokia Corporation. Nokia, SR OS and product identifiers are used only to identify the compatibility profile and the behavior being researched. The Apache License does not grant rights to third-party trademarks. See [TRADEMARKS.md](TRADEMARKS.md) for the complete trademark policy.

Vendor documentation, firmware, software images, YANG files and logos are not distributed in this repository. The source catalog stores links and project-authored compatibility metadata. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency and redistribution information. Production builds include the project license, notice, trademark policy and complete dependency license texts.

```powershell
pnpm public-release:check
```

The public-release check rejects missing legal files, undeclared redistribution payloads, vendor logo filenames and package metadata without the project license.

## Repository layout

```text
apps/web/                 React application and browser runtime bridge
core/                     C++20 device, CLI, dual-stack network, transport, service and runtime modules
core/include/router/      Stable public C++ headers
core/src/<domain>/        Implementations grouped by protocol or state owner
core/tests/<domain>/      Tests mirroring the production domain layout
core/tests/runners/       Aggregate native and Wasm test entry points
packages/contracts/       Versioned browser contracts and generated profile, catalog and DNSSEC data
profiles/                 Hardware, timing, resource, DNSSEC and UI profile values
schemas/                  CLI, runtime and checkpoint schemas
sources/                  Source catalog and capability matrix
scripts/                  PowerShell toolchain, dependency and core build scripts
tools/                    Profile, catalog, DNSSEC, source and benchmark generators and validators
benchmarks/               Packet-path baseline and regression thresholds
docs/                     Implementation plans and architecture decisions
policies/                 Public redistribution allowlist
```

The C++ implementation and tests use the same domain directories: `cli`, `device`, `dhcpv6`, `dns`, `forwarding`, `ip`, `isis`, `ospf`, `runtime`, `security` and `transport`. The IS-IS domain currently contains bounded PDU, area, neighbor, interface-address, narrow and extended reachability codecs, authentication and instance-identifier helpers, a bounded per-level LSP repository, ISO adjacency and DIS decisions, SRM/SSN flood transitions and the RFC 5303 three-way transition table under conformance testing. The repository preserves accepted wire bytes, detects equal-sequence checksum confusion and retains finalized purges through their owner-local deadlines. IS-IS and OSPF share segmented digest primitives and ISO checksum arithmetic. Private implementation headers remain with their owner. Public includes keep the stable `router/...` paths.

`pnpm verify` builds the complete C++ graph once during the test gate. The following benchmark and publication gates reuse those exact artifacts. Standalone benchmark and publication commands still perform their own incremental build. Core build processes are serialized around the shared Ninja dependency database, while each build uses all logical processors.

IS-IS distance calculation uses the same bounded indexed Dijkstra mechanism as OSPF with protocol-specific metric limits. Narrow IS-IS keeps distance 1023 finite, wide IS-IS saturates at 0xFE000000, and OSPF continues to exclude LSInfinity. IS-IS gives pseudonodes precedence at equal cost and keeps selected PATHS entries closed. Complete LSDB graph translation and IS-IS route installation remain in progress.

The IS-IS level database owner combines accepted encoded LSP storage with per-circuit flood obligations. It validates wire data before reserving new flag storage and mutating the LSDB, so malformed or corrupt LSPs cannot trigger Waiting merely because the record budget is full. It rejects completion receipts for superseded LSP versions. Missing LSP advertisements reserve bounded zero-sequence PSNP requests that never acquire SRM. Partial-SNP selection rotates through pending entries and sorts each batch for wire composition. Complete SNP reception validates every entry before mutation, applies CSNP omissions only inside the advertised range and rejects LAN PSNPs when the local circuit is not DIS. Instance dispatch, transient acknowledgements, circuit epochs and timers remain integration work.

Each IS-IS Hello class has an independent monotonic schedule. Content changes preserve its periodic deadline, LAN transmissions respect same-level spacing, and egress receipts commit successful emission times. Circuit dispatch and checkpoint continuation still need to connect this schedule to the runtime.

The P2P circuit owner connects scheduled authenticated Hello frames, received peer attributes, three-way negotiation and holding expiry. Its tests converge two owners over physical queues and verify rejection without timer refresh, Down attribute lifetime, shutdown and reactivation. Runtime configuration, epoch filtering and instance-level routing remain in progress.

A dedicated IS-IS control pthread admits P2P circuit owners through an owned SPSC command channel. Runtime startup creates it before any router configuration and publishes its distinct identity in the worker directory. Encoded frame channels return actual egress admission receipts, and circuit generations reject stale input before adjacency processing. Tests connect this thread through physical link queues and inspect immutable results. Product circuit dispatch, instance flooding, key-vault selection and route publication remain in progress.

P2P Hello acceptance checks IPv4 and IPv6 family declarations before holding refresh. Strict adjacency policy requires identical family sets, while the default policy requires a common family. A mismatched established peer is removed through the circuit's Down event.

The LAN circuit owner schedules per-level Hello frames, retains received neighbors and drives delayed DIS election. Its test discovers three routers through physical queues and a learning bridge, then verifies replacement after the selected DIS loses carrier. Pseudonode generation and runtime LAN admission remain in progress.

Unknown-purge acknowledgement metadata has a separate bounded owner outside the LSDB. Distinct received versions keep independent tickets, queue refusal retains them, and old receipts cannot remove later obligations. SNP batches contain at most one version per LSP ID and retire entries only after actual egress admission.

CSNP sequences partition the complete LSP-ID space into contiguous packet-sized ranges, including an empty database. Queue refusal retries the same range, and another timer request cannot restart an unfinished sequence ahead of higher IDs.

Protocol egress metadata carries a transmission ticket as well as a circuit configuration generation. The IS-IS Hello worker checks both before accepting a receipt. Packet channels also preserve an independent protocol reservation epoch through forwarding and physical admission, and guarded slot release compares it with the original metadata. Operational cancellation preserves ticket progression, preventing an old receipt from completing replacement output in the same configuration.

Transmission classes and local instance IDs distinguish independent Hello, LSP and SNP ticket sequences. Delayed physical-admission receipts validate the complete metadata before returning a borrowed frame handle, so slot reuse across PDU classes or instances cannot release replacement output.

Local LSP composition inserts the selected instance option and authentication, then finalizes the digest and ISO checksum before returning raw PDU bytes. Its bounded owner-provided buffers can exceed a physical frame's capacity. The LSDB can retain such an LSP, while each circuit still applies its own transmission limit. Oversized circuit output clears only its SRM and returns an explicit result for the parent alarm; temporary scratch-capacity refusal retains its obligations. Fragment partitioning and alarm publication remain integration work. Explicit experimental programs use the runtime origination scheduler.

Local generation schedules keep independent sequence counters, minimum spacing and jittered refresh deadlines. Content changes preserve periodic refresh. Failed LSDB publication consumes no sequence and waits for an explicit resource event. Maximum sequence exhaustion stops a schedule without wrapping. An own-copy receive path permits duplicate acknowledgement and older-copy retransmission while leaving newer live copies, confusion and purges of active bodies with the local originator. The runtime current-set owner applies these schedules to explicitly supplied semantic content. Circuit-derived semantic root composition remains incomplete.

Originated LSDB admission can reserve a local record's future content within the existing byte budget. This supports the required storage guarantee for the local non-pseudonode zeroth LSP. Received packets cannot request that reservation. A full-budget test verifies growth into reserved capacity without relocating the retained buffer; experimental automatic root admission uses this reservation.

A current local LSP set retains semantic content independently of installed wire copies. It publishes bounded round-robin generations through the actual update owner, reserves complete root buffers and preserves sequence floors through missing transmit keys. Content replacement uses reserved storage. Runtime admission, circuit-driven root composition, withdrawal and entity-wide cooldown are still required before this owner can run in production.

The entity sequence-recovery gate selects the longest enabled-level MaxAge plus ZeroAgeLifetime. Repeated input cannot shorten or restart that cooldown. Failed reconstruction uses an explicitly supplied emulator resource retry interval, and clock overflow keeps the entity disabled. The runtime stops the complete entity, retains its gate through deletion and recreation, and reconstructs its processes only after cooldown. Structural checkpoint and restore remain blocked while cooldown is pending; active protocol checkpoint recovery remains incomplete.

Experimental automatic instances periodically validate every retained live LSP checksum using an owner-local jittered schedule derived from each enabled level's explicit maximum generation interval. Bounded scans retain an identity cursor across database mutations. A completed scan advances the decision notification generation even when topology is unchanged. Corruption latches the offending LSP identity, stops the entire entity and uses the existing full-lifetime cooldown before discarding and reacquiring databases with fresh local counters. This conservative recovery policy prevents potentially stale own copies from shortening safety intervals. Manual raw-PDU experiments and production SPF consumption remain incomplete.

Runtime instance shells now own replaceable update processes, and their parent retains recovery gates outside instance lifetime. Immutable effective LSP headers can be queried through the control channel. Idle registration is released only after the IS-IS owner reports that no cooldown is pending, keeping structural checkpoint and restore excluded while recovery is unsafe. Explicit experimental origination programs now create and refresh current local LSPs on the protocol pthread. Their semantic content is supplied by the configuration owner. Raw local PDU injection is refused while this owner is active. Circuit-derived root composition, withdrawal and production CLI admission remain incomplete.

The circuit-level SNP exchange composes complete ranges, partial acknowledgements and transient purge acknowledgements under one pending transmission reservation. Real port-queue refusal preserves obligations and scan positions. A matching successful receipt advances only the transmitted range or version; cancellation and configuration replacement reject delayed receipts. The runtime owner schedules P2P exchanges and dispatches them through physical queues; LAN dispatch remains in progress.

LSP output uses the same exact receipt identity. Its encoded lifetime includes elapsed holding time and at least one second for transit, without rewriting retained LSDB bytes. Entries reaching zero require finalized purge construction before dispatch. Successful LAN egress clears only the unchanged version's SRM; P2P retains SRM until peer acknowledgement. The runtime supplies interface burst pacing and finalizes actual expiration before dispatch.

The instance update owner connects authenticated P2P adjacency events to independent L1 and L2 databases. It checks received update frames before mutation and distinguishes transport configuration epochs from synchronization epochs, so adjacency recovery cancels old reservations without a configuration edit. Queue-based tests exchange LSPs and PSNP acknowledgements at both levels. Self-originated input returns an explicit pending fight-back or purge result. Cold circuit admission preserves existing reservations and rolls back both levels on failure. Retired Down bindings reuse their stable level slots without replacing the LSDB or resetting ticket counters. Admission rollback checks a unique owner-local ticket before touching a slot. The parent supplies an initial synchronization epoch above the retained fence of any previous entity. The runtime schedules these P2P owners and experimental local origination. LAN integration remains in progress.

Experimental update instances now run on the permanent IS-IS pthread and connect to both NetworkPlane placements. Source-resolved programs supply identity, level budgets, SNP periods, retransmission, interface-wide burst pacing and PDU limits. Local encoded LSPs cross the protocol channel, forwarding owner, physical queue and link before peer LSDB admission; returned PSNPs retire flood obligations only after real queue receipts. Failed physical admission preserves work. Preparation reserves new Down bindings transactionally, abort restores them, and commit reuses changed stable slots without replacing retained databases. Removing every interface preserves the instance and its LSDB. Removing and recreating the instance advances its parent-retained synchronization fence. Unsupported authentication selection and nonzero update IIDs reject admission while their integration remains incomplete. Structural checkpoints reject registered update instances even without interfaces. Production configuration, circuit-derived local content, LAN, routing and protocol persistence remain incomplete.

Purge option acceptance uses an explicitly selected compatibility policy. The registry policy rejects registered forbidden TLVs and accepts unknown TLVs only when a POI TLV is present. Accepted purge bytes remain unchanged through storage and forwarding. POI values decode independently, so malformed or misplaced POI information does not reject an otherwise valid live LSP under RFC 8918. Local construction rejects POI in live LSPs. The pinned IANA facts in `sources/normative/isis-tlv-codepoints.lock.yaml` produce immutable membership maps through `pnpm profiles:generate`; `pnpm profiles:check` detects drift. Production policy selection remains in progress.

The level process joins database admission, circuit epochs and LSP/SNP reservations. Explicit emulator budgets permit new initially Down circuit slots without replacing retained LSPs or existing transmission reservations; failed admission publishes no slot. Circuit Down clears obsolete obligations before reactivation, and delayed receipts cannot affect replacement output. Separate L1 and L2 Waiting states preserve flooding during resource recovery. Expiration purges require an expired retained record and retain for ZeroAgeLifetime. Initiated local purges retain for MaxAge, including identities from an earlier incarnation that are absent from the LSDB. Received unknown purges remain transient. Experimental parent-instance origination is active. The LAN unknown-purge acknowledgement form remains in progress.

The IS-IS owner finalizes actual LSP expiration with an explicit purge policy, optional transmit authentication and the immutable instance selector. Foreign purges preserve their original source checksum, and HMAC remains valid with that checksum. Mandatory purge-envelope capacity is reserved when a live record is admitted, within the existing byte budget. A bounded deadline service handles both runtime placements; a resource wait blocks only the affected expiration, leaving other records and purge retirements eligible. Tests verify delayed construction, exact retention deadlines and full-budget replacement without buffer relocation.

The same purge composer handles accepted unknown live own-source identities and checksum confusion. Unknown own identities retain the received sequence and start MaxAge retention at the new observation, including replacement of an expired older body. Confusion purges preserve a retained foreign checksum and use ZeroAgeLifetime from detection. A separate receive path accepts only purges of identities the parent has retired from its current generated set. Live local replacements remain excluded from that path.

The LSDB exposes the earliest owner-local expiration or purge-retirement deadline as an immutable value. Expired active bodies remain pending until finalized purge construction, and delayed construction preserves the original expiration time for retention. Deadline arithmetic saturates at the monotonic clock limit.

Experimental P2P generations connect the IS-IS owner to both runtime placements. Forwarding validates logical circuit epochs and the encoded instance selector; the link owner independently checks the same epoch and physical port generation. A separate SPSC receipt path returns actual fabric-queue admission before releasing protocol frame credits. Replacing hardware requires a newer circuit epoch. New logical circuits must also exceed the maximum retired epoch for their device handle, including after complete protocol withdrawal; unchanged live circuits retain their independent epochs.

Generation preparation stages changed circuits and multicast groups before the forwarding barrier. Unchanged epochs preserve adjacency, timer and pending-transmission state. Commit and multicast rollback exchange preallocated values without allocation. Active experimental IS-IS transport rejects structural checkpoint and restore until protocol-state persistence is implemented. Product CLI admission, LAN integration, circuit-derived origination content and routing remain in progress.

Control generations with dynamic containers transfer ownership through fixed shared slots and SPSC handle rings. Packet metadata retains the circuit configuration generation. The ownership and stale-generation rules are recorded in [ADR 0006](docs/adr/0006-control-generation-handoff.md).
