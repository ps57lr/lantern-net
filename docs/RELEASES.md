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
| `0.3.0.dev4` source line | Current signing-aware packaging work | Unreleased development line. It is not a distributable family beta until a clean Developer ID signed, Apple-notarized, stapled artifact passes all release and clean-machine gates; even then it remains a limited family beta, not production. |

For every future development tag, record the exact commit, package version,
artifact SHA-256, clean-install result, and scope limitations. Checksums detect a
byte mismatch; they are not publisher identity and do not replace signing or
notarization.
