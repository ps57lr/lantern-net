# Development release ledger

Lantern development tags are immutable historical markers. A Git tag and the
Python package version are separate pieces of evidence; both must agree before an
artifact is described as a coherent release.

| Git tag or line | Commit/package identity | Status |
|---|---|---|
| `v0.2.1` | `0871248` / `0.2.1` | Frozen CLI baseline. |
| `v0.3.0-dev1` | `008c666` / `0.3.0.dev1` | Local-only Phase 2.1 development preview. |
| `v0.3.0-dev2` | Public integration tag; packaged code still identifies itself as `0.3.0.dev1` | Historical tag-label mismatch. Do not move or delete the tag, and do not use it as a reproducible package version. |
| `0.3.0.dev3` source line | Current Phase 2.2 work | Unreleased until source, browser, clean wheel, and packaging gates all pass and a new immutable tag is created. |

For every future development tag, record the exact commit, package version,
artifact SHA-256, clean-install result, and scope limitations. Checksums detect a
byte mismatch; they are not publisher identity and do not replace signing or
notarization.
