# IS-IS YANG defaults and CLI references

## Decision

The immutable SR OS 26.7.R1 YANG closure defines IS-IS datastore paths, keys, types, restrictions and configuration defaults. MD-CLI and classic CLI address the same datastore and effective router state. Each engine uses its own documented spelling, edit operators and dependency conditions.

A conflicting default in a prose CLI reference does not create a second protocol default for the other terminal engine. The pinned YANG value governs the shared release profile. The source catalog retains the conflicting reference and the selected value. Protocol standards continue to govern encoded PDUs and distributed behavior.

## CSNP interval

The pinned `nokia-conf-router-isis.yang` leaf `/configure/router/isis/interface/csnp-interval` has range 1..65535 seconds and default 10. The [26.7.R1 MD-CLI reference](https://documentation.nokia.com/sr/26-7/7750-sr/books/md-cli-command-reference/router-router_0.html#d46533) also gives default 10.

The [26.7.R1 classic reference](https://documentation.nokia.com/sr/26-7/7750-sr/cli-books/classic-cli-command-reference/classic-c-commands-clie-2.html#ai9j785fkf) gives LAN default 10 and P2P default 5. The shared profile selects the pinned YANG default 10. No automatic media-dependent conversion to 5 is inferred. An explicitly configured value remains effective across terminal-engine changes.

The internal update program supplies an explicit effective interval. Its zero-period value selects ISO startup-only CSNP behavior and is outside the supported CLI range. Configuration default resolution and internal protocol scheduling remain separate contracts.

## Validation

The source inventory verifies the immutable Git blobs, typedef resolution and declared defaults. Generated command validation must retain each engine's documented removal operator and restore the shared configuration default. Protocol tests use explicit effective intervals and independently verify periodic or startup-only transmission.
