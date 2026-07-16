# Release profile catalog

## Decision

The hand-maintained YAML catalog is the release-scoped source for supported chassis, cards, MDAs, port groups and compatibility. An offline generator validates the complete graph and emits immutable C++ and TypeScript projections. Production code does not download or scrape documentation.

The initial catalog is pinned to SR OS 26.7.R1 and contains 7750 SR-1, 7750 SR-7 and 7750 SR-12. Runtime resource bounds are stored separately from vendor hardware profiles. Generated records use compact contiguous indexes on control and packet paths.

## Validation

- Every profile ID is unique and release-pinned.
- Fixed and modular slot counts are internally consistent.
- Every card references known compatible MDAs.
- Every default inventory is a compatible subset.
- Every Ethernet MDA has bounded port groups and supported speeds.
- Generated C++ and TypeScript files must match the same YAML bytes in CI.
- Maximum port arena size is derived from compatible hardware, not starter inventory.

## Consequences

UI filtering and runtime validation cannot drift into separate hardcoded model lists. Adding a release requires a separate catalog or explicit versioned extension. Unsupported specialized card functions remain unavailable even when their physical inventory identity is represented.
