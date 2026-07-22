# Contributing

Contributions are accepted under the Apache License 2.0. By submitting a contribution for inclusion, the contributor agrees that it is licensed under those terms as described by Section 5 of the license.

Contributors must have the right to submit every added file. Do not add vendor firmware, software images, manuals, YANG modules, logos, screenshots copied from vendor products or other material whose redistribution terms are not recorded and compatible with public distribution.

Vendor and product names may be used in plain text when needed to identify a compatibility profile, normative source or verified behavior. They must not be used as project branding or in a way that implies affiliation, sponsorship, certification or endorsement.

Every production behavior requires:

- a source record in `sources/catalog.yaml`
- a capability entry in `sources/capabilities.yaml`
- an implementation that has an observable effect or returns an explicit unsupported error
- tests at the appropriate unit, integration or browser level
- comments that explain ownership, invariants, timing, concurrency and source-dependent decisions

Run the complete local gate before submitting a change:

```powershell
pnpm verify
```

Changes to the UI or browser runtime also require manual verification against the production build with cross-origin isolation active.
