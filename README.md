# Router Simulator

**Status: Work in progress. This is not a complete Nokia SR OS implementation.**

Router Simulator is a local, real-time network device emulator that runs in a browser. It models modular router hardware, terminal management, packet forwarding, links and host traffic. The runtime processes encoded Ethernet, ARP, IPv4 and ICMP traffic instead of calculating connectivity from the topology graph.

Router Simulator is an independent, unofficial educational project. It is not affiliated with, sponsored by, endorsed by or produced by Nokia. The application uses Nokia SR OS 26.7.R1 documentation as a behavior reference. It does not use the Nokia logo and does not claim full product compatibility.

## Implemented capabilities

Implemented behavior includes:

- empty user-defined topologies with up to 16 routers, 16 hosts and 64 links
- generated 7750 SR-1, SR-7 and SR-12 hardware catalogs
- card and MDA provisioning for compatible catalog combinations
- MDA provisioning, insertion, removal and mismatch handling
- dynamic port creation from the selected chassis, card and MDA inventory
- separate inventory, provisioning, running and operational state
- MD-CLI and classic CLI engines in the same router terminal session
- transactional MD-CLI configuration and immediate classic CLI configuration
- prompts, context navigation, completion, line editing, three history regions and paging
- a virtualized terminal window with the complete transcript archived in OPFS
- Ethernet frame encoding, link serialization, propagation delay and bounded queues
- ARP learning and expiry, connected routes, static routes, RIB selection and FIB generations
- IPv4 forwarding, TTL handling, fragmentation, Path MTU behavior and ICMP errors
- host and router ping through encoded packets
- physical link failure and hardware removal cascades
- live capture at link, ingress, egress and CPM observation points
- PCAPNG export accepted by `tshark`
- project export, structural checkpoints and profile-locked `.netsim` import
- responsive topology, inspector, sidebar and terminal panels with user-controlled resizing
- drag and drop router and host creation with physical-port link selection

## Architecture

The packet runtime is written in C++20 and compiled with Emscripten to WebAssembly. It runs outside the React thread and requires pthreads with shared WebAssembly memory.

At startup, the generated CPU policy creates one, three or five pthreads in addition to the browser control Worker. Hosts with up to four logical CPUs use one control owner and one combined forwarding and link owner. Hosts with five to eight logical CPUs use one control, two forwarding and one link owner. Larger hosts use two control, three forwarding and one link owner. Stable device handles select owner shards and live devices do not migrate. Shared packet state does not cross the browser boundary through per-packet `postMessage` calls.

The runtime uses the host monotonic clock. It has no simulation timeline, global future-event heap, pause control, step control or speed multiplier. Protocol and hardware deadlines pass in real time.

The main components are:

- React, Vite and TanStack Router for the application shell
- React Flow for topology rendering
- xterm.js for terminal rendering
- C++20 for hardware, configuration, CLI, routing, packet processing and capture
- WebAssembly pthreads and `SharedArrayBuffer` for the runtime
- IndexedDB for project metadata
- OPFS for terminal history, checkpoints and binary captures

The C++ core has no dependency on React, the DOM, xterm.js, IndexedDB or OPFS.

## Current scope

The following boundaries apply to the current implementation:

- up to 16 routers, 16 hosts, 64 physical links and four terminal sessions per router
- Ethernet card functions and port layouts covered by the active release catalog
- MD-CLI and classic CLI expose only commands backed by the current capability matrix
- the IPv4 and host stacks implement the documented functions listed above, not every RFC option
- broader SR OS routing protocols, services, MPLS, QoS, HA and management protocols are not implemented
- card and MDA initialization times are experimental emulator profile values
- checkpoint import requires the matching profile, checkpoint ABI and build hash
- there is no single-thread fallback when cross-origin isolation is unavailable

Unsupported commands return an explicit error. They do not report success without changing router state.

## Requirements

- Windows 10 or Windows 11 for the repository PowerShell scripts
- Node.js 22
- pnpm 11
- Chrome, Edge or Firefox with `SharedArrayBuffer` support
- PowerShell 7 or Windows PowerShell 5.1
- Visual Studio 2022 Build Tools for native MSVC builds
- Wireshark with `tshark` for local PCAPNG conformance tests

WSL is not required or used by the local workflow.

## Setup

Install JavaScript dependencies and the repository-local compiler toolchain:

```powershell
pnpm install
pnpm toolchain:bootstrap
```

The bootstrap command installs the pinned toolchain under the ignored `.tools` directory:

- Emscripten 6.0.3
- CMake 4.4.0
- Ninja 1.13.0

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

Install the Playwright-managed Firefox build and run the production browser scenario in Chrome, Edge and Firefox:

```powershell
pnpm test:e2e:install
pnpm verify:browser
```

The browser scenario verifies cross-origin isolation, every selected pthread owner, multi-router topology editing, CLI provisioning, physical insertion, routed traffic, carrier failure, project import, checkpoint import, terminal restoration and reload recovery.

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

IndexedDB stores the active project and UI layout. OPFS stores the terminal transcript, latest capture and latest structural checkpoint.

A `.netsim` file has one of two modes:

- `project` stores portable intent, topology, hardware choices, running configuration, notes, layout and an optional capture
- `checkpoint` adds ARP, RIB, FIB, queues, packets, link transmissions, relative deadlines, counters, alarms, CLI semantics, terminal editor state, histories, queued input and pager position

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
core/                     C++20 device, CLI, network and runtime modules
packages/contracts/       Versioned browser contracts and generated profile data
profiles/                 Hardware, timing, resource and UI profile values
schemas/                  CLI, runtime and checkpoint schemas
sources/                  Source catalog and capability matrix
e2e/                      Chrome, Edge and Firefox acceptance scenario
tools/                    Profile, source and benchmark validation tools
docs/                     Implementation plan and architecture decisions
policies/                 Public redistribution allowlist
```
