# Shard placement and messaging

## Decision

The runtime uses a fixed pthread pool created at startup. Logical devices are assigned to control and forwarding shards by stable handle. One link shard owns the physical fabric. A live device does not migrate between shards in the initial multi-router release.

Known one-producer and one-consumer paths use SPSC rings. A matrix of SPSC rings is used where several shards communicate. MPSC and MPMC structures are not introduced without a separate ownership analysis, benchmark and ADR.

Each worker drains bounded work budgets and rotates its starting device. It then waits for a mailbox signal, shutdown request or its nearest local `steady_clock` deadline. Deadline inspection selects a sleep bound only. It does not move protocol state or execute future work.

## Placement policy

- Up to 4 logical CPUs use one control shard and one combined forwarding and link shard.
- From 5 through 8 logical CPUs use one control shard, two forwarding shards and one link shard.
- More than 8 logical CPUs use two control shards, three forwarding shards and one link shard.

## Invariants

- The UI thread never owns live device state.
- The runtime has no single-threaded fallback.
- A router never calls another router.
- Network data crosses device boundaries only as encoded frames through queues and the fabric.
- A busy device cannot consume an unbounded worker turn.

## Consequences

The number of browser Workers follows available CPUs rather than router count. Device count can grow to 16 without creating 16 Wasm instances or duplicating shared pools. Deterministic shard placement also makes checkpoint barriers and stale-message tests reproducible.
