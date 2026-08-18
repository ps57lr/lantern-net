# Development release ledger

Lantern development tags are immutable historical markers. A Git tag and the
Python package version are separate pieces of evidence; both must agree before an
artifact is described as a coherent release.

| Git tag or line | Commit/package identity | Status |
|---|---|---|
| `v0.2.1` | `0871248` / `0.2.1` | Frozen CLI baseline. |
| `v0.3.0-dev1` | `008c666` / `0.3.0.dev1` | Local-only Phase 2.1 development preview. |
| `v0.3.0-dev2` | Public integration tag; packaged code still identifies itself as `0.3.0.dev1` | Historical tag-label mismatch. Do not move or delete the tag, and do not use it as a reproducible package version. |
| `v0.3.0-dev3` | `26d00cb` / `0.3.0.dev3` | Immutable Phase 2.2 development baseline. Preserve this tag and its unsigned-development history. |
| `v0.3.0-dev4` | `32e12310d73c9c4fca9a066f4a067259833adb23` / `0.3.0.dev4` | Immutable Developer ID signed, Apple-notarized, stapled family beta. Its local Lantern page can open in Safari behind other windows and appear not to start. Preserve the tag and artifact as historical release evidence; do not move, replace, or relabel either one. |
| Untagged internal candidate | `1b1d7db0a033c5318c78195891ceca70cdb41b5c` / `0.3.0.dev5` | Rejected and never distributed. The foreground correction passed, but signed Finder low-impact smoke exposed the inherited multiline gateway-ping serialization failure. No `v0.3.0-dev5` tag or family handoff was created. |
| `0.3.0.dev6` source line | Current foreground and gateway-ping serialization corrections | Corrected family-beta candidate. It is not a distributable dev6 family beta until a clean Developer ID signed, Apple-notarized, stapled artifact passes all release, Finder-opening, low-impact smoke, and clean-machine gates; even then it remains a limited family beta, not production or enterprise assurance. |

The next development tag is `v0.3.0-dev6`. Create it only after the exact dev6
artifact passes the full release gates, then point it at that artifact's exact,
clean source commit. Never create a dev5 tag after the fact or move
`v0.3.0-dev4` to a corrected source line.

For every future development tag, record the exact commit, package version,
artifact SHA-256, clean-install result, and scope limitations. Checksums detect a
byte mismatch; they are not publisher identity and do not replace signing or
notarization.
