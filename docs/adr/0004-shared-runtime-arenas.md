# Shared runtime arenas

## Decision

The WebAssembly runtime starts with fixed 256 MiB shared memory. It owns one 64 MiB packet pool, one 32 MiB capture store and one 16 MiB terminal output arena. These resources are laboratory-wide and are not multiplied per router or per link.

The packet pool stores complete encoded frames. A packet handle has one owner at every stage. The global fabric has one in-flight metadata node per packet-pool slot, so metadata cannot impose an independent frame ceiling. TX, propagation and RX transfers move ownership without copying packet bytes again.

Device arenas are sized from generated hardware bounds. The generator derives the maximum physical port count from every compatible card and MDA combination. A build-time budget check must include 16 maximum SR-12 devices before the multi-router runtime becomes the production ABI.

## Overload behavior

- Packet-pool exhaustion rejects admission and increments an explicit drop counter.
- Full physical queues apply tail drop and preserve previously admitted order.
- Terminal result exhaustion applies backpressure or returns an explicit error.
- Capture exhaustion increments capture drops and does not overwrite retained records.
- No arena grows after shard startup.

## Consequences

Addresses remain stable in shared Wasm memory and packet-path allocation is bounded. Resource exhaustion remains observable. Exact ASIC buffer sizes are not claimed where the vendor does not publish them. Such queue values remain documented emulator profiles and require measurements before being described as hardware-accurate.
