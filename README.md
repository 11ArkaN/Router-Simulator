# Router Simulator

**Status: Work in progress. This is not a complete Nokia SR OS implementation.**

Router Simulator is a browser-based network emulator that runs in real time. You build a topology of modular routers and hosts, provision their hardware, and drive them from a CLI, while a packet engine underneath moves real Ethernet, ARP, IPv4, IPv6, ICMP and ICMPv6 frames across the links, carries a working TCP and UDP transport, and runs host application services on top of it. A ping or a DNS lookup succeeds only when its packet is actually forwarded, queued and delivered.

Router Simulator is an independent, unofficial educational project. It is not affiliated with, sponsored by, endorsed by or produced by Nokia. The application uses Nokia SR OS 26.7.R1 documentation as a behavior reference. It does not use the Nokia logo and does not claim full product compatibility.

## Implemented capabilities

A lab holds up to 16 routers, 16 hosts and 64 physical links. Routers come from generated 7750 SR-1, SR-7 and SR-12 catalogs, and you provision their cards and MDAs from whatever combinations the catalog allows. Insertion, removal and type mismatches are all handled. Ports aren't fixed up front. They appear as you equip the chassis, card and MDA inventory, and the model keeps inventory, provisioning, running and operational state apart instead of merging them.

MD-CLI and classic CLI render contextual `info` and `info detail` from the same typed running or candidate datastore while preserving their engine-specific hierarchy and spelling. Local verification checks renderer ownership against the generated command catalog and executes both forms from configured present working contexts in each supported configuration family. Router interface subtrees, BOF autoconfiguration and static-route destination, route-type and next-hop levels are scoped from their canonical typed trees rather than separate context-specific copies.

Every console runs the MD-CLI and classic CLI engines in one session. The exact `//` command changes the persistent terminal engine, while `//command` executes one absolute command through the other engine and restores the original context. MD-CLI edits land as transactions, classic edits take effect immediately. MD-CLI supports the implicit `configure <mode>` workflow and the explicit `edit-config <mode>` workflow. In an explicit workflow, `configure` navigates from the candidate root into the configure region, while `edit-config` itself never becomes a configuration context. Configuration workflow ownership is generated from the release command catalog, so every configuration family follows the same candidate and operational-mode rules. The Base router key is omitted from MD-CLI input and is resolved to the canonical `router "Base"` datastore path. Help and completion expose the Base router's children directly without inserting its default key into the editable command. Unique Tab and Spacebar completion ends the completed element with one separator, absolute-path completion preserves its leading slash and full root path from nested contexts, and contextual completion uses the execution tokenizer to retain quoted interface names containing spaces, and Enter never rewrites the exact `//` engine command as an inline command. Compound IPv4 primary-address syntax requires both `address` and `prefix-length` before execution and never creates a context from a scalar address value. Classic keyed `create` commands enter the created or already existing object context; trailing `create` and create-time arguments such as IES `customer` or OSPF `router-id` stay out of the stored prompt. Classic `no` of an OSPF instance, OSPF area, OSPF interface, Base router interface, DHCP server, or TLS client, server or cert profile requires that object to be shut down first. The system interface is permanent and neither engine removes it. MD-CLI `delete` of an IES list entry removes the whole subtree and does not copy that classic shutdown cascade. MD-CLI `delete` of a static route, next hop or indirect path removes it regardless of its admin-state leaf. MD-CLI `delete` of an absent or already-default element succeeds silently per the MD-CLI guide and never creates configuration, while classic `no` keeps the rejected result for absent elements and classic context entry keeps its create-on-entry behavior. MD OSPF `asbr`, `graceful-restart` and `loopfree-alternate` are presence containers, and graceful restart defaults to present per YANG. OSPF `summaries` and `default-metric` live only under area stub and area nssa. MD IPv6 `prefix-length` accepts 4 through 128. MD-CLI `delete` accepts absolute, relative and mid-path placement, while classic `no` retains command-specific reset, disable and removal behavior. Neither edit operator can become part of a present working context, and both generated-schema validation and the session path owner enforce this invariant. Static IPv4 and IPv6 next-hop and indirect commands select their real keyed contexts. Their administrative state is retained in configuration, reflected as `admin-state` in MD-CLI and `shutdown` or `no shutdown` in classic CLI, and controls RIB and FIB installation independently of deletion. A unique disabled classic static route can be removed by its prefix. Destinations with multiple next hops require a qualified `no` form that selects one disabled child. The terminal carries prompts, context navigation, completion, line editing, three history regions and paging. Its visible window stays virtualized while the full transcript is archived to OPFS. Clearing the visible terminal preserves the archive and returns to live input without opening the read-only history overlay. Contextual `info` and `info detail` read the active candidate in MD-CLI and running configuration in classic CLI, with braces for MD hierarchy and `exit` delimiters for classic hierarchy. Card, MDA, physical Ethernet, DHCP, MLD, policy-options, TLS, IPsec, PKI and IES contexts render the shared typed configuration through each engine's native hierarchy. Tests and production builds reject a release command family that has no contextual renderer in either engine. Release-schema output modifiers provide `detail` only for commands that document it, including port, router interface, OSPF interface, neighbor and database reports in both terminal engines. The configuration surface covers ports, router and system interfaces, dual-stack addressing, IPv6 neighbors, MLD, static routes, IES service interfaces, TLS profiles, IPsec templates, IPsec client databases, RADIUS authentication policies and PKI certificate authority with OCSP, CMPv2 and automatic CRL update, common-name, EST, certificate update and auto-update profiles. IES interfaces carry multiple IPv4 addresses and OSPF instances export through a chain of up to five route policies. Operational interface reports select running objects by name, IP address, address family or global interface index and expose forwarding-owned traffic counters. Neighbor reports add the `all` selector, the `interface` keyword form and IPv6 address filtering. FIB reports filter by family, prefix with longer-match and summary. ARP reports add local, static and managed type filters. `clear` is a classic CLI operation while MD-CLI uses the corresponding `reset` commands with the same selectors. Port detail reports include deterministic virtual transceiver identity while leaving unmodeled DDM sensor values as unavailable. System alarm reports expose active and cleared equipment alarms with source-backed alarm IDs, latched timestamps, severity, count and newer-than filters. Route-table reports support IPv4 and IPv6 families, canonical prefix filtering, `longer`, `exact`, protocol and instance filters, summaries, extensive rows, inactive configured static routes and installed loop-free alternatives. Standard route rows include owner-recorded route age.

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

The Snapshots panel exports and imports protected `.checkpoint.netsim` files through the same passphrase and validated project-replacement flow as project import. A replacement runtime restores a complete checkpoint directly before any configuration replay can create a second protocol generation.

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

[`sources/yang/26.7.R1.lock.yaml`](sources/yang/26.7.R1.lock.yaml) pins 361 source modules in the dependency closure of the selected IS-IS configuration, state and management roots to the exact release commit. Byte sizes and SHA-256 digests use the original Git blobs, preserving identity across Windows line-ending conversion. [`schemas/cli/isis-26.7.R1-inventory.json`](schemas/cli/isis-26.7.R1-inventory.json) records 405 configuration nodes, 592 state nodes and 454 management nodes with their source locations, resolved typedef chains, inherited defaults, union members, restriction layers and choice/case structure. Exact command bindings cover the admitted basic configuration nodes; the capability matrix identifies the remaining protocol and CLI surface. [ADR-0007](docs/adr/0007-isis-yang-defaults-and-cli-references.md) selects the pinned YANG defaults for the shared IS-IS profile and records the conflicting classic CSNP P2P description and default-metric range and parameter typography; both terminal engines retain one effective configuration.

`pnpm isis:coverage:check` validates explicit scope and acceptance records for all 1451 pinned IS-IS configuration, state and management nodes in `schemas/cli/isis-26.7.R1-coverage.yaml`. `pnpm isis:coverage:complete` additionally requires implemented Base capabilities and verified exclusions; it remains failing while any planned behavior or dependency decision is unfinished. Source validation always checks coverage integrity and evidence paths.

`pnpm yang:bootstrap` acquires the exact-release source cache under `.tools`. `pnpm yang:check` verifies source hashes and generated inventory drift, and `pnpm yang:generate` regenerates the project-authored metadata. Source validation also tests statement parsing, dependency inventory and RFC 7950 default resolution. Key leaves require explicit values, mandatory leaves do not inherit typedef defaults, and leaf-list defaults retain their declared order without bypassing minimum cardinality. Vendor YANG source files remain outside the distributed repository and application.

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

## IS-IS implementation

IS-IS is under implementation against Nokia SR OS 26.7.R1. The [pinned YANG lock](sources/yang/26.7.R1.lock.yaml), [source inventory](schemas/cli/isis-26.7.R1-inventory.json), source catalog and capability matrix distinguish experimental components from production behavior. The inventory covers 405 configuration nodes, 592 state nodes, 454 management nodes and 361 dependencies. [The implementation plan](docs/isis-implementation-plan.md) defines the complete scope. Production IS-IS commands and demos are not enabled yet.

| Area | Working experimental components | Remaining integration |
| --- | --- | --- |
| Transport | Dedicated permanent IS-IS pthread, owned control generations, SPSC frame channels, physical queues and links, exact egress receipts | Production configuration and complete active-instance admission limits |
| P2P | Hello scheduling, three-way negotiation, accepted peer attributes, holding expiry and reactivation | Complete sourced timer, authentication and lifecycle policy |
| LAN | Independent L1/L2 Hello and update owners, two-way neighbors, delayed DIS election, broadcast scans, per-level receipts and copied neighbor/DIS queries on the permanent pthread | Complete profile-resolved pacing, MT/MI modes and production CLI activation |
| LSDB and flooding | Bounded wire retention, checksum and lifetime validation, SRM/SSN, CSNP ranges, PSNP requests, transient acknowledgements, epoch cancellation and actual egress completion | Mesh groups and profile-resolved optional burst pacing |
| Local LSPs | Cold root composition for areas, NLPIDs, addresses, hostname and local IPv4/IPv6 prefixes with whole-TLV fragment packing, reserved identities and semantic buffers, sequence counters, refresh, purge retention, fight-back, sequence recovery, automatic P2P neighbor composition | Complete root extension contents, additional-system-ID ownership and sourced CLI admission |
| LAN origination | Automatic root/pseudonode composition on the protocol pthread, actual DIS-role activation/withdrawal, retained sequence floors and encoded switch tests | Complete root extension contents and sourced CLI admission |
| Graph and SPF | Narrow/wide LSDB translation, MT0/MT2, live-root and reverse-link checks, overload rules, pseudonode transit and actual local first-hop seeds | Complete configured SPF policy and hierarchy |
| IP route publication | Automatic wide MT0 P2P and LAN IPv4/IPv6 decisions, accepted-Hello next hops, complete router generations and keyed installation receipts | MT2 publication, leaking, policies, aggregation, unnumbered, weighted ECMP and IP LFA |
| Prefix metadata | Ordered 32/64-bit tags, attribute flags, source router IDs, retained sub-TLVs and separate family/path distance classes | Complete policy consumption and extension lifecycle |
| Authentication and restart | Authentication composition/verification codecs, borrowed-key contracts and owner-local recovery gates | Runtime key-vault/keychain selection, key rollover and GR helper |
| Management and persistence | Pinned-YANG defaults and typed configuration intent, source-bound basic CLI editors, atomic new-instance and circuit admission, atomic protocol, RIB/FIB and transport retirement, typed experimental diagnostics, protected active protocol checkpoints with scoped route provenance in ABI 11 and atomic restoration | Complete sourced MD-CLI/classic CLI surface, removal semantics and demos |

LSDB transfer snapshots retain original wire, fractional ages, expiry-notification state, allocation reservations and purge-retention offsets. Level snapshots join those bytes to stable circuit slots, SRM/SSN and zero-sequence requests. Reservation snapshots retain epochs, pending tickets, contiguous CSNP progress, cyclic PSNP cursors and transient acknowledgement order. Superseded ordinary LSP versions retain receipt checks; transient tickets require exact matches. Restore validates bounded repositories before replacement, while malformed data and resource failures preserve the destination. Fresh heap owners restore their own database references and relative Waiting timers. Secret-bearing wire requires protected serialization by the enclosing coordinator.

Local fragment transactions validate all encoded members and their aggregate retained budget before LSDB mutation. New flag storage and growing buffers stage first; every affected SRM flag becomes visible before the first decision notification. Recency, checksum, metadata or capacity refusal preserves the old complete set. A bounded semantic planner keeps complete TLV units, reserves fragment-zero-only content first and preserves previous placements where they fit. Caller-buffer composition refuses before changing any output when framing or capacity fails. Changed source families stage encoded preparations across bounded calls and commit their live replacements and retired-fragment purges together. Checkpoint restoration reconstructs prepared bytes from generation reservations. Current authentication keys validate cached preparation before admission; rejected relocation can advertise overload from the retained root contents. Pending replacements continue periodic refresh of the retained layout without exposing the proposed new fragments. Automatic MT0 P2P and LAN composition feeds complete neighbor units from accepted local circuits into these transactions. Base root TLVs remain independently movable when new links need space; only Area Addresses stay pinned to fragment zero. Cold admission reserves inactive IDs within the explicit emulator LSDB record budget and validates all configured link sizes. Complete root extension contents, additional System IDs and sourced CLI integration remain under implementation.

Instance snapshots prepare both levels with accepted peer catalogs, circuit epochs and admission counters. Local semantic/generation snapshots retain withdrawn identities, sequence floors, jitter, pending output, blocked retirement, overload projections and round-robin progress. Recovery and integrity snapshots retain cooldown/retry policy, clock saturation, scan cursors and corruption latches. Decision snapshots preserve the last complete identity/cost/token projection and ordered prefix attributes without recalculating from a newer LSDB.

Circuit snapshots retain Hello jitter, pending emissions, fractional holding time, accepted identities and non-secret peer TLVs. LAN areas rebuild from the same validated TLVs. LAN level snapshots cross-check DIS selection, advertised LAN ID, election delay and effective Hello role against accepted neighbors. Interface pairs restore both levels together; the broadcast scan preserves its random stream and actual-success backlog spacing.

Quiescent channel snapshots retain free-stack order, ready FIFO, borrowed handles and unconsumed completion FIFO with exact occupied wire prefixes. Owned-generation channels also preserve producer edits. Preparation copies large values directly into heap storage before an allocation-free commit; route channels restore pointer projections and actual installation/refusal results. [ADR-0008](docs/adr/0008-quiescent-protocol-channel-checkpoints.md) defines this boundary. The IS-IS worker has an internal token-checked quiescence barrier that suspends protocol service while preserving queued work. Stale release and configuration mutation during the barrier refuse explicitly. The protocol owner captures joined component images only with a matching barrier and the time anchor sampled by that protocol owner when acknowledging quiescence. Joined capture and restore reuse this acknowledged sample, avoiding strict comparisons between independently rounded browser pthread clocks. Detached restoration prepares instance, circuit and device owners before an allocation-free registry swap. Preparation or abort preserves the live registry; a pending preparation prevents barrier release. Forwarding transfer images retain queued wire, physical results and their exact borrowed-credit references. Joined validation checks current Hello/LSP/SNP reservations and route generations while retaining canceled stale frames for ordinary rejection. The network snapshot also retains the RIB owner's last accepted IS-IS candidates and installation high water independently of unconsumed protocol receipts. Detached checkpoint encryption binds protocol wire to the enclosing structural image without consuming credential handles. The protected protocol codec uses one explicit field order, fixed-width integers and bounded detached decoding; unused route capacity is omitted. The existing OSPF owner also stages restored processes before a token-checked, allocation-free commit. The network coordinator captures these owners under the same forwarding/protocol barrier and prepares their replacements before publishing the enclosing network state. Restoring a different forwarding shard layout refuses explicitly; configuration-only import does not preserve that layout. Full lifecycle and browser recovery acceptance remain pending.

Each circuit generation constructs only its selected P2P or LAN state owner. LAN levels share immutable local identity and explicit multicast groups while retaining separate neighbor, DIS and Hello schedules. Cold preparation allocates before the forwarding barrier; failed admission preserves the live generation. Update-owner rebinding reserves larger LAN peer buffers before Down; preparation preserves accepted peers, LSDB bytes and pending receipts, and spare capacity does not alter the configured peer limit. Unchanged epochs retain timers and pending tickets. An explicit effective update policy can override the experimental instance policy per interface; timers, PDU bounds and shared L1/L2 credits use that same resolved value. Policy edits require a new circuit epoch. LAN restart clears received peers and DIS identity, restarts election delay and continues its existing random sequence. Changing configuration under an unchanged epoch rejects. LAN Hello generations admit distinct wire instance identifiers on one interface and reject a duplicate selector without replacing live state. Callback contexts borrow the current owner only during synchronous calls, so circuit-vector moves retain no stale observer pointer.

Encoded PDU type, local instance, interface configuration generation, protocol synchronization epoch and transmission ticket identify output. Protocol, forwarding and link owners validate the same immutable transport projection and active level mask. Only actual physical queue admission commits successful output. Failed admission retains reliable obligations. P2P LSPs retain SRM until acknowledgement; LAN clears only the unchanged transmitted version. Oversized LSPs clear only that circuit's obligation and report refusal.

Hello acceptance validates instance, authentication policy, family declarations, known address encodings and level-specific area rules before refreshing holding time. Strict family policy requires identical local and peer sets; ordinary policy requires a common family. LAN adjacency formation does not require a common MT. Bounded retained Hello options survive receive-buffer reuse and omit secret authentication data. Invalid options or exhausted retention resources preserve the accepted peer and timer. Initializing LAN adjacencies participate in same-level update-source checks; pseudonode and forwarding membership require Up.

A complete CSNP sequence covers the LSP-ID space, including an empty database, without restarting an unfinished range. Missing advertisements reserve zero-sequence PSNP requests that never acquire SRM. Transient unknown-purge acknowledgements remain outside the LSDB, including the local DIS exception under ISO 10589 section 7.3.16.4. Failed admission never acknowledges responsibility, and stale receipts cannot clear a replacement version.

Local generation reserves identity slots and semantic capacity before activation. Inactive slots emit nothing until activated. Minimum spacing, independent sequence floors, jittered refresh and purge retention remain with the local owner. Expiration notifies routing independently of deferred purge construction. Missing keys cannot keep expired routes usable. Sequence exhaustion and self-originated checksum corruption use parent-retained recovery gates instead of wrapping identifiers. Periodic retained-checksum validation distinguishes wire refresh from semantic changes that require SPF.

Graph translation reads only the instance's local LSDB. A live fragment zero gates other fragments, reverse advertisements establish connectivity, and family/MT support plus overload and maximum metrics control transit. MT2 uses router TLV 222 with shared pseudonode TLV 22. Narrow distance 1023 remains finite; wide distance saturates at 0xFE000000. Pseudonodes precede routers at equal cost. Actual local Up adjacencies seed SPF independently of stale own advertisements. A new DIS still advertising the old LAN ID delays indirect initialization while direct peers remain usable. Invalid input preserves the previous complete decision.

Automatic wide MT0 P2P and LAN publications contain every configured router instance, family and level. Exact epochs and decision revisions fence construction. Next-hop binding checks accepted Hello addresses, both NLPID projections and current logical interface scope. IPv4 subnet equality is not required; IPv6 uses link-local addresses scoped to the logical interface. The emulator selects the numerically lowest usable address as an explicit local policy, without claiming a vendor ranking. ARP and ND resolve actual neighbors through encoded packets.

The shared RIB retains OSPF and IS-IS in separate partitions of one bounded arena per family. IS-IS path classes and structured distance ranks remain distinct from OSPF metadata and precede administrative preference. The network owner prepares both RIB families and OSPF redistribution before one forwarding transaction. Refusal preserves installed generations and returns an explicit result. Successful empty IS-IS publication withdraws only IS-IS. Same-handle protocol removal preserves publication high water, and circuit replacement cannot invalidate an installed route scope before withdrawal.

The experimental LAN single-LSP scan chooses uniformly from the complete combined L1/L2 SRM set without allocating a candidate catalog. Queued incoming LSPs inhibit output except the permitted one-per-second path. Successful physical admission anchors its spacing; failure retains obligations. Consumer-only ready-frame snapshots inspect a bounded published queue extent without removing frames, copying packets or changing credits. Experimental LAN update instances require explicit scan and CSNP separation timing with a positive complete-set period; unresolved programs reject before replacing live state. One ready-frame snapshot per ingress channel classifies pending LSPs by the actual current circuit and encoded selector. Actual DIS roles govern CSNP and PSNP output, and a shared physical receipt fence serializes complete SNPs across levels. Complete-set periodic deadlines start before emission work. Automatic LAN composition reserves pseudonode records before publication, activates them only for the actual local DIS and retains sequence floors after withdrawal and reacquisition. Holding-time and election transitions precede fresh origination and SPF. Successful decisions retain their exact first-hop binding catalogs for route publication. Physical forwarding tests cover independent L1/L2 DIS elections and off-subnet IPv4/IPv6 routes through real ARP and ND. Root-content edits retain automatically composed LAN edges. A newly elected DIS purges cached fragments of the previous foreign pseudonode through the authenticated purge owner, preserving sequence/checksum and MaxAge retention. Fragment cursors share bounded control work, retain the last remote DIS across an empty neighbor set and cancel on role loss. Fragment packing preserves complete narrow/wide neighbor units and commits changed bodies and purges through atomic local transactions. Complete root extension contents and profile-resolved optional burst pacing remain incomplete. Nonzero update instances remain blocked pending complete configured MI-mode and physical-peer capability integration.

Active experimental IS-IS participates in structural checkpoint and staged restoration with its protocol owners, packet queues, physical receipts and accepted RIB generations. Checkpoint ABI 11 retains canonical IS-IS intent in running and candidate datastores alongside the protected IS-IS owner graph and seals the complete structural payload when that graph is present, including fabric queues and captures; older structural images reject. Configuration-only manifests with a supported project schema remain importable across earlier runtime ABIs. Portable project format 5 accepts an optional typed IS-IS tree; absence retains the empty configuration. Runtime snapshot ABI 10 includes that canonical tree. Restoring running enabled IS-IS intent requires its protocol owner in the same checkpoint, while a candidate may retain an uncommitted activation. Generated YANG lifecycle paths distinguish instance restart leaves, including LSP lifetime, from ordinary level edits. Source-resolved P2P parameters use interface level 1 even when the operational capability is level 2; broadcast parameters remain independent per level. Effective DIS timing divides the ordinary Hello interval by three and rounds transmitted holding seconds upward while preserving oversized results for explicit wire-policy validation. Manifest import tests use the checked-in `apps/web/src/fixtures/four-router-reference.netsim.json` fixture. Synchronous forwarding requests materialize large payloads in owner-held heap storage, inline foreign-CLI execution avoids recursive parser frames, and forwarding pause acknowledgements publish only after arming their resume predicate.

Both terminal engines share canonical IS-IS intent, and MD compare renders keyed hierarchical changes with scalar before/after values and area-address additions or removals. Classic prompts omit instance, interface and level keys while retaining them in the session path. The complete CLI and removal matrix, active persistence, three demos, measured protocol limits and every-command T3 Preview acceptance remain required before the IS-IS feature is ready. [ADR-0007](docs/adr/0007-isis-yang-defaults-and-cli-references.md) records source precedence and conflicting CSNP prose. Experimental programs never assign guessed SR OS defaults or report an unimplemented command as successful.
