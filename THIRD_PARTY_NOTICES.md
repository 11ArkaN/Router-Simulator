# Third-party notices

## OpenSSL 3.5.7 LTS

Copyright OpenSSL contributors.

License: Apache License 2.0.

Source: https://www.openssl-library.org/source/

The source archive is verified by its published SHA-256 digest and compiled
locally for WebAssembly. No prebuilt OpenSSL binary is distributed.

Router Simulator does not redistribute Nokia firmware, software images, YANG modules, manuals, logos or other vendor-owned content. The source catalog contains links, short identifiers and project-authored compatibility metadata.

## nghttp2 1.69.0

Copyright nghttp2 contributors.

License: MIT.

Source: https://github.com/nghttp2/nghttp2/releases/tag/v1.69.0

The official source archive is verified by its published SHA-256 digest and
compiled locally as a static WebAssembly HTTP/2 library.

## ngtcp2 1.24.0

Copyright ngtcp2 contributors.

License: MIT.

Source: https://github.com/ngtcp2/ngtcp2/releases/tag/v1.24.0

The official source archive is verified by its published SHA-256 digest and
compiled locally as static WebAssembly QUIC and OpenSSL integration libraries.

## nghttp3 1.17.0

Copyright nghttp3 contributors.

License: MIT.

Source: https://github.com/ngtcp2/nghttp3/releases/tag/v1.17.0

The official source archive is verified by its published SHA-256 digest and
compiled locally as a static WebAssembly HTTP/3 library.

The production browser bundle currently includes the following direct dependencies:

| Package | Resolved version | License |
| --- | ---: | --- |
| `@tanstack/react-router` | 1.170.17 | MIT |
| `@xterm/addon-fit` | 0.10.0 | MIT |
| `@xterm/xterm` | 5.5.0 | MIT |
| `@xyflow/react` | 12.11.2 | MIT |
| `react` | 19.2.7 | MIT |
| `react-dom` | 19.2.7 | MIT |

The complete resolved dependency graph is recorded in `pnpm-lock.yaml`. Production transitive dependencies use MIT, ISC, BSD-3-Clause or Unlicense terms in the current lockfile.

`pnpm build` generates `apps/web/dist/THIRD_PARTY_NOTICES.txt` from the license files installed with every production dependency. The generated file is shipped with the static application and preserves the package names, versions, copyright notices and license terms supplied by their authors. The build also ships `LICENSE.txt`, `NOTICE.txt` and `TRADEMARKS.txt` beside the application bundle.

Standards and vendor documentation linked by `sources/catalog.yaml` remain on their publishers' websites. A link or compatibility citation does not place the linked work under the project license.
