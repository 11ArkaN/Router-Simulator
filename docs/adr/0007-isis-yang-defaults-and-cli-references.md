# IS-IS YANG defaults and CLI references

## Decision

The immutable SR OS 26.7.R1 YANG closure defines IS-IS datastore paths, keys, types, restrictions and configuration defaults. MD-CLI and classic CLI address the same datastore and effective router state. Each engine uses its own documented spelling, edit operators and dependency conditions.

A conflicting default in a prose CLI reference does not create a second protocol default for the other terminal engine. The pinned YANG value governs the shared release profile. The source catalog retains the conflicting reference and the selected value. Protocol standards continue to govern encoded PDUs and distributed behavior.

## CSNP interval

The pinned `nokia-conf-router-isis.yang` leaf `/configure/router/isis/interface/csnp-interval` has range 1..65535 seconds and default 10. The [26.7.R1 MD-CLI reference](https://documentation.nokia.com/sr/26-7/7750-sr/books/md-cli-command-reference/router-router_0.html#d46533) also gives default 10.

The [26.7.R1 classic reference](https://documentation.nokia.com/sr/26-7/7750-sr/cli-books/classic-cli-command-reference/classic-c-commands-clie-2.html#ai9j785fkf) gives LAN default 10 and P2P default 5. The shared profile selects the pinned YANG default 10. No automatic media-dependent conversion to 5 is inferred. An explicitly configured value remains effective across terminal-engine changes.

The internal update program supplies an explicit effective interval. Its zero-period value selects ISO startup-only CSNP behavior and is outside the supported CLI range. Configuration default resolution and internal protocol scheduling remain separate contracts.

## Validation

The source inventory verifies the immutable Git blobs, typedef resolution and declared defaults. RFC 7950 sections 7.6.1, 7.7.2 and 7.8.2 govern default projection: keys ignore defaults, mandatory leaves cannot inherit them and leaf-list minimum cardinality controls inheritance. Lexical values preserve type identity and full integer precision. Ancestor presence, choice selection and when/feature activation remain separate checks. Generated command validation must retain each engine's documented removal operator and restore the shared configuration default. Protocol tests use explicit effective intervals and independently verify periodic or startup-only transmission.

## Default metric

The pinned YANG `/configure/router/isis/level/default-metric` and [MD-CLI reference](https://documentation.nokia.com/sr/26-7/7750-sr/books/md-cli-command-reference/router-router_0.html#d46618) define range 1..16777215 and default 10. The [classic command reference](https://documentation.nokia.com/sr/26-7/7750-sr/cli-books/classic-cli-command-reference/classic-d-commands-d-pa-1.html#ai9j785fqx) gives range 1..16777214. Both engines use the pinned YANG range 1..16777215 for the shared configuration leaf. The different upper bound in classic prose does not silently narrow the common datastore.

The classic release PDF, printed pages 1910 and 1911, renders `default-metric` in bold and the complete parameter name `ipv4 metric` in italics. Its parameter description treats that phrase as the numeric IPv4-unicast metric. The executable setter therefore has one numeric argument; `ipv4` is not an additional literal keyword. The documented removal is `no default-metric`. Text-only extraction must not turn a multiword italic parameter label into grammar keywords.

## Per-level LSP MTU

The root `lsp-mtu-size` and `/configure/router/isis/level/lsp-mtu-size` each declare default 1492 in the pinned YANG. The [per-level MD reference](https://documentation.nokia.com/sr/26-7/7750-sr/books/md-cli-command-reference/router-router_0.html#d46623) confirms this independent leaf default. Removing the level value restores its own default in the datastore projection. The effective wire-program compiler must resolve any additional global buffer policy separately; the configuration projection does not invent inheritance from the root leaf.

## Instance restart lifecycle

The pinned schema marks root `lsp-lifetime`, `lsp-mtu-size`, `router-id` and `system-id` with `sros-ext:auto-restart-to-modify`. The independent level `lsp-mtu-size` has no such extension. Generation retains exact data paths for every restart extension rather than matching leaf names. An active identity change also requires a restart when the resolved System ID changes because its Base identity input changed. Removing an explicit numeric default restores the same effective value and does not itself require a restart. Inactive edits retain configuration without constructing a protocol entity. Active publication still requires a prepared runtime transaction; classifying a change does not apply it.

## Point-to-point interface parameters

The [26.7.R1 interface configuration note](https://documentation.nokia.com/sr/26-7/7x50-shared/unicast-routing-protocols/is-is.html#configure-interfaces-with-level-capability__note_qpv_3gb_kxb) specifies that point-to-point interfaces use parameters configured under interface level 1 regardless of the operational level. The release Unicast Routing Protocols Guide repeats this rule in the interface configuration procedure. The P2P projection therefore selects level-1 metric, Hello interval, multiplier and passive parameters even for a level-2-only interface. An absent interface metric still inherits the global default-metric for the advertised level, whose exact classic reference explicitly applies it to all interfaces on that level. The common Hello enabled gate uses the intersection of instance and interface level capabilities. Broadcast circuits retain independent per-level parameters. Configured level-2 values remain in the datastore and its CLI output; switching media does not erase them.

## Designated Hello timing

The exact [26.7.R1 Hello multiplier reference](https://documentation.nokia.com/sr/26-7/7750-sr/cli-books/classic-cli-command-reference/classic-h-commands.html#ai9j785htd) divides the ordinary Hello interval and hold product by three while the local system is LAN DIS. [RFC 4444, isisCircLevelHelloMultiplier](https://www.rfc-editor.org/rfc/rfc4444.html) specifies upward rounding of transmitted holding seconds. The effective projection keeps these operations separate: the Hello timer retains the runtime microsecond resolution, while the hold product divides with ceiling. The full result remains 32-bit. A value larger than the 16-bit wire field does not acquire an inferred Nokia saturation or truncation rule.
