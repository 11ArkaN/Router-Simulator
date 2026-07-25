# Router Simulator

**Status: Work in progress. This is not a complete Nokia SR OS implementation.**

Router Simulator is a browser-based network emulator that runs in real time. You build a topology of modular routers and hosts, provision their hardware, and drive them from a CLI, while a packet engine underneath moves real Ethernet, ARP, IPv4, IPv6, ICMP and ICMPv6 frames across the links, carries a working TCP and UDP transport, and runs host application services on top of it. A ping or a DNS lookup succeeds only when its packet is actually forwarded, queued and delivered.

Router Simulator is an independent, unofficial educational project. It is not affiliated with, sponsored by, endorsed by or produced by Nokia. The application uses Nokia SR OS 26.7.R1 documentation as a behavior reference. It does not use the Nokia logo and does not claim full product compatibility.

## Implemented capabilities

A lab holds up to 16 routers, 16 hosts and 64 physical links. Routers come from generated 7750 SR-1, SR-7 and SR-12 catalogs, and you provision their cards and MDAs from whatever combinations the catalog allows. Insertion, removal and type mismatches are all handled. Ports aren't fixed up front. They appear as you equip the chassis, card and MDA inventory, and the model keeps inventory, provisioning, running and operational state apart instead of merging them.

Every console runs the MD-CLI and classic CLI engines in one session. MD-CLI edits land as transactions, classic edits take effect immediately. The terminal carries prompts, context navigation, completion, line editing, three history regions and paging. Its visible window stays virtualized while the full transcript is archived to OPFS. Contextual `info` and `info detail` read the active candidate in MD-CLI and running configuration in classic CLI, with the syntax and hierarchy of the selected engine. Release-schema output modifiers provide `detail` only for commands that document it, including port, router interface, OSPF interface, neighbor and database reports in both terminal engines. The configuration surface covers ports, router and system interfaces, dual-stack addressing, IPv6 neighbors, MLD, static routes, IES service interfaces, TLS profiles and IPsec templates. Operational reports read live state back with `show` commands for cards, ports, interfaces, the route table, the FIB, ARP and the IPv6 neighbor cache, including installed OSPF and OSPF3 route-table filters.

The packet plane is the point of the whole thing. Frames are encoded, serialized onto links with propagation delay and bounded queues, and forwarded for real. It is dual stack. ARP and IPv6 neighbor discovery are learned and aged, duplicate address detection and router advertisement run per interface, and MLD tracks multicast listeners. Connected, static, OSPFv2 and OSPFv3 routes feed per-router RIB selection and versioned FIB generations for both address families, with equal-cost multipath and scoped indirect next hops. IPv4 and IPv6 forwarding cover TTL and hop limit, fragmentation and reassembly, Path MTU discovery, extension headers and ICMP and ICMPv6 errors. Host and router pings ride real packets, so failing a link or pulling a line card cascades through everything downstream.

OSPF runs as a distributed control-plane protocol. Routers exchange encoded Hello, Database Description, Link State Request, Link State Update and Link State Acknowledgment packets through their physical interfaces and Ethernet switches. Each process owns its interface and neighbor state machines, LSDB, flooding, retransmission, local timers and Dijkstra calculations. The implemented scope covers OSPFv2, OSPFv3 IPv6 and IPv4 unicast address families, point-to-point and multi-access networks, NBMA and point-to-multipoint operation, virtual links, normal, stub and NSSA areas, ABR and ASBR behavior, external redistribution policies, authentication, graceful-restart helper behavior, IP LFA and ECMP. The MD-CLI and classic CLI expose the corresponding configuration, inspection and reset commands from the generated release schema.

Vendor-neutral Ethernet switches provide real shared broadcast domains with profile-defined ports, queues and MTU. Their forwarding owner learns source MAC addresses, ages FDB entries, forwards known unicast and floods unknown unicast, broadcast and multicast traffic. Physical L2 loops are rejected until a spanning-tree subsystem exists.

Above the network layer the runtime carries a real transport and a set of host application services. TCP implements the connection state machine, initial sequence generation, option negotiation, congestion control, RTO estimation, SACK loss recovery, delayed acknowledgement and persist behavior; UDP provides its own datagram sockets. Hosts run an iterative DNS resolver with a negative cache and authoritative zones loaded from master-file text, DHCPv6 client, server and relay, and DNSSEC record handling and zone signing. A TLS 1.3 engine, a local PKI and secret vault, QUIC, HTTP/2, HTTP/3, the encrypted DNS transports (DoT, DoH over HTTP/2 and HTTP/3, DoQ), DNSSEC response validation and an IKEv2 and IPsec data path are present as working foundations rather than complete implementations. The capability matrix marks each feature as implemented, partially implemented or unsupported.

Live traffic can be captured at link, ingress, egress and CPM points and exported as PCAPNG that `tshark` opens cleanly. A project saves to `.netsim` as portable intent or as a full structural checkpoint, and import is locked to the matching profile.

Routers and hosts are dragged onto the canvas, and a link picks its physical ports when you connect it. Device and link graphics remain visually stable while they are hovered or selected. The built-in black theme is declared to the browser before styles load, so native controls and accessibility extensions recognize that the page is already dark. The topology, inspector, sidebar and terminal panels resize on desktop. The terminal recalculates its row and column geometry from the available panel rectangle, so long prompts reflow instead of being clipped when neighboring panels change width. Below 900px the sidebar folds into a drawer and the inspector into an overlay.

## Architecture

The packet runtime is written in C++20 and compiled with Emscripten to WebAssembly. It runs outside the React thread and requires pthreads with shared WebAssembly memory.

At startup, the generated CPU policy creates one, three or five pthreads in addition to the browser control Worker. Hosts with up to four logical CPUs use one control owner and one combined forwarding and link owner. Hosts with five to eight logical CPUs use one control, two forwarding and one link owner. Larger hosts use two control, three forwarding and one link owner. Stable device handles select owner shards and live devices do not migrate. Shared packet state does not cross the browser boundary through per-packet `postMessage` calls.

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
- `checkpoint` adds the live operational state: dual-stack RIBs and FIBs, ARP and IPv6 neighbor caches, router advertisement, Path MTU and reassembly state, MLD, DHCPv6 leases, UDP and TCP sockets, the DNS resolver and DNSSEC caches, fabric link transmissions, capture selection and counters, the project secret vault, relative deadlines, counters, alarms, CLI semantics, terminal editor state, histories, queued input and pager position

Packet capture is encoded incrementally as PCAPNG and appended by the runtime Worker to project-scoped OPFS. A session has no fixed 32 MiB runtime limit. Export flushes the active generation before downloading the complete file.

An incompatible checkpoint is rejected before runtime replacement. The user can explicitly import only its project data, which starts a new runtime without the incompatible operational state.

## Sources and capability tracking

[`sources/catalog.yaml`](sources/catalog.yaml) records the normative source, release, implementation files, tests and verification status for each implemented behavior. [`sources/capabilities.yaml`](sources/capabilities.yaml) marks features as implemented, partially implemented, experimental or unsupported.

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
