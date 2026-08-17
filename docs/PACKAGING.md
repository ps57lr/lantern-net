# Lantern local developer packaging

## Release posture

This pipeline produces a **local, unsigned development artifact** for supervised testing.
It is not yet a frictionless family distribution, production installer, managed endpoint
agent, or enterprise deployment package.

The default development build is not Developer ID signed or notarized. PyInstaller applies
an ad-hoc signature on macOS so executable pages can be validated; an ad-hoc signature does
not identify a publisher. The Linux build is likewise unsigned. The separate sealed macOS
release path described below can create a signed/notarized candidate. The manifest and checksums
detect changed bytes only when compared with a value obtained through a separate trusted
channel. They do not prove who built the package.

The packaging layer adds none of the following:

- an automatic software download/update mechanism, telemetry, or a remote service;
- an installer, persistence, launch-on-login, autorun, or USB behavior;
- privilege elevation or an administrator-password prompt;
- broader diagnostic scope or different consent behavior.

Lantern itself retains its existing consented diagnostic behavior. Opening the artifact
starts only the short-lived loopback UI; it does not start a diagnostic. Passive remains
the default, and network-generating checks remain explicitly disclosed and selected in the
application. The person at the computer can still explicitly download Lantern's redacted
JSON report; that user-requested report export is not a software updater or download channel.

## Supported build targets

PyInstaller artifacts must be built separately on each target operating system and CPU:

| Build host | Output |
|---|---|
| macOS arm64 | `Start Lantern (Unsigned Dev).app` inside a labeled folder |
| glibc Linux arm64 or x86_64 | one-folder `Start Lantern (Unsigned Dev)` payload |

Cross-compilation is not supported. Windows packaging is not claimed by this project.

## Locked build environment

The generic virtual-environment recipe in this section is for **Linux development builds**.
The macOS family candidate does not accept an arbitrary local Python installation: use the
sealed macOS bootstrap documented under “Sign a macOS artifact.” It verifies and freshly
extracts the exact pinned arm64 runtime before any candidate-runtime code executes.

For a Linux development build, use a disposable virtual environment. First, on a connected
build machine, download the reviewed binary wheels:

```bash
python3 -m venv /tmp/lantern-package-tools
/tmp/lantern-package-tools/bin/python -m pip download \
  --disable-pip-version-check --no-input --only-binary=:all: --require-hashes \
  --destination /tmp/lantern-package-wheelhouse \
  --requirement packaging/requirements-build.lock
```

Then install from that wheelhouse without contacting an index:

```bash
/tmp/lantern-package-tools/bin/python -m pip install \
  --disable-pip-version-check --no-input --no-index --only-binary=:all: \
  --require-hashes --find-links /tmp/lantern-package-wheelhouse \
  --requirement packaging/requirements-build.lock
```

The build refuses unreviewed tool versions. The lock covers PyInstaller and its direct
build dependencies for the supported hosts.

## Build

Build the Linux development artifact from a reviewed, clean commit:

```bash
/tmp/lantern-package-tools/bin/python scripts/package_family_beta.py
```

The default destination is `dist/family-beta/`. The builder never overwrites an existing
artifact. It records the commit, source-tree state, commit timestamp, exact PyInstaller
version, build-lock digest, target, application/report/UI schema versions, UI asset hashes,
and every packaged file or relative symlink.

For local pipeline debugging only, a dirty build can be created with `--allow-dirty`. Its
folder, start instructions, and manifest explicitly record that it contains uncommitted
source. Do not hand a dirty artifact to a tester.

The builder sets a stable source epoch, file order, ZIP timestamps, ZIP modes, compression,
Python hash seed, isolated build home, and isolated PyInstaller cache. This minimizes incidental variance, but the project does **not** yet
claim bit-for-bit reproducible PyInstaller binaries across machines, SDKs, operating-system
patches, or absolute checkout paths.

PyInstaller is launched with Python isolated mode (`-I`) under an allowlisted environment:
fixed system `PATH`, isolated home/config/temp directories, fixed locale, version/build
metadata, and deterministic Python/source settings only. Ambient Python paths, loader
variables, compiler settings, and shell customization are not inherited. Source provenance
uses the exact `/usr/bin/git` executable with system/global configuration, optional locks,
and prompting disabled; packaging fails closed if that reviewed path is unavailable.

## Produced files

For version `0.3.0.dev4` on Apple Silicon, the names are:

```text
lantern-family-beta-0.3.0.dev4-macos-arm64-UNSIGNED-DEV/
lantern-family-beta-0.3.0.dev4-macos-arm64-UNSIGNED-DEV.zip
lantern-family-beta-0.3.0.dev4-macos-arm64-UNSIGNED-DEV.zip.sha256
```

The unpacked directory contains:

- `START-HERE.txt` with tester-safe opening and consent guidance;
- `UNSIGNED-DEVELOPMENT-BUILD.txt` with the trust limitations;
- `package-manifest.json` with bounded provenance and per-entry SHA-256 values;
- `SHA256SUMS.txt`, which anchors the manifest's transfer-integrity check;
- the one-folder application payload and an offline verification executable.

PEP 440 development versions are kept in the runtime and package manifest. macOS bundle
metadata uses Apple's numeric forms: `0.3.0.dev4` maps to marketing version `0.3.0` and
bundle build `4`.

## Verification

Verify an unpacked artifact on its target operating system:

```bash
python3 scripts/verify_family_beta.py \
  --require-clean-source \
  dist/family-beta/lantern-family-beta-0.3.0.dev4-macos-arm64-UNSIGNED-DEV
```

The verifier is stdlib-only and checks:

- the exact manifest and safety-label contract, with strict JSON parsing;
- every file, executable mode, safe relative symlink, and canonical tree digest;
- runtime version, Report 1.1 schema bytes, `lantern.ui.v2`, and all four UI assets;
- a frozen self-test under a new empty home, temporary directory, and working directory;
- an audit guard that proves socket creation is denied during that offline self-test;
- absence of files written into the clean test profile;
- on macOS, numeric plist versions, the whole app's strict deep signature integrity, the
  nested verifier/runtime, and the absence of a Developer ID authority/team identity.

The self-test deliberately does not launch Lantern, bind a loopback port, probe a network,
open a browser, or run a diagnostic. Browser and consent behavior remain covered by the
separate Playwright and installed-wheel test matrices.

Run the package-focused source tests with:

```bash
python -m pytest tests/packaging
python -m ruff check packaging scripts/package_support.py \
  scripts/bootstrap_macos_release.py scripts/package_family_beta.py scripts/verify_family_beta.py \
  scripts/macos_codesign.py scripts/macos_notarize.py \
  scripts/release_family_beta_macos.py tests/packaging
python -m ruff format --check packaging scripts/package_support.py \
  scripts/bootstrap_macos_release.py scripts/package_family_beta.py scripts/verify_family_beta.py \
  scripts/macos_codesign.py scripts/macos_notarize.py \
  scripts/release_family_beta_macos.py tests/packaging
```

## Tester opening behavior

On macOS, the tester opens `Start Lantern (Unsigned Dev).app`. If Gatekeeper blocks it,
they may Control-click and choose **Open** only after confirming the artifact came directly
from a trusted person and its ZIP hash matches a separately communicated value. Never tell
a tester to disable Gatekeeper globally. If the windowed launcher cannot start the private
local UI, it shows one fixed, non-secret failure dialog and confirms that no diagnostic was
started.

Because this build is unsigned and unnotarized, Gatekeeper friction is expected. A genuinely
one-click external family beta requires the release gates below.

## Gates before family distribution

The unsigned development pipeline remains available for supervised local testing. A
separate macOS release step produces a Developer ID signed family-beta artifact and can
optionally complete Apple notarization and stapling.

### Sign a macOS artifact

Run the sealed bootstrap on the Mac that holds the pinned Developer ID Application private key.
It verifies the reviewed runtime archive before executing it, extracts it into a fresh private
directory, removes all executable bytecode caches, verifies the complete transformed runtime
tree, installs the exact six hash-pinned wheels offline with bytecode compilation disabled,
and verifies the complete build-environment tree. The release then builds its own unsigned
precursor from the same clean commit and signs only those fresh bytes. External unsigned
artifacts are not accepted as signing input, and there is no dirty-release override.

```bash
/usr/bin/python3 -I -B scripts/bootstrap_macos_release.py \
  --runtime-archive /absolute/path/to/cpython-3.11.15+20260728-aarch64-apple-darwin-install_only.tar.gz \
  --wheelhouse /absolute/path/to/lantern-package-wheelhouse \
  --output-dir /absolute/path/to/new-empty-release-directory
```

This creates:

```text
lantern-family-beta-0.3.0.dev4-macos-arm64-SIGNED/
lantern-family-beta-0.3.0.dev4-macos-arm64-SIGNED.zip
lantern-family-beta-0.3.0.dev4-macos-arm64-SIGNED.zip.sha256
```

Before any signing operation, the release tool fully verifies and snapshots every freshly
built unsigned input byte and binds its archive, manifest, tree, contracts, target, and build
provenance into the signed app. It pins Developer ID certificate SHA-1
`DFE4DF368133715BAAE725CC68CC7BA8A7246BEB` and team `HY2MDL9DND`; a same-name, renewed,
or different-team certificate is rejected until a reviewed source change updates the pin.
Identity, team, certificate SHA-256, input/tree/manifest hashes, entitlements hash, system
tool hashes, release-source hashes, and the clean release-tool commit are embedded inside
the application before the outer signature is created.

`packaging/macos/family-beta.entitlements.plist` is intentionally empty. Hardened Runtime
and a secure timestamp are required on the outer bundle and every nested Mach-O. Dylibs,
Python extensions, and frameworks never receive executable entitlements. Verification
enumerates every Mach-O rather than trusting `codesign --deep`; it checks the pinned leaf
certificate/team, runtime flag, timestamp, absence of `get-task-allow`, the entitlement
allowlist, an arm64 slice, and a minimum macOS version no newer than the bundle's
`LSMinimumSystemVersion`. Static `.a` and object `.o` material are rejected.

The release manifest retains a sorted per-object signature inventory: fixed relative path and
object type, architecture/minimum-OS evidence, code-directory hash, designated requirement,
Hardened Runtime and secure-timestamp evidence, exact leaf-certificate hashes/team, and the
canonical entitlement digest. It records the full inventory hash and outer-app CDHash, and the
independent verifier recomputes the exact inventory from the published application.

The runtime input is pinned by `packaging/macos/runtime.lock.json`: Astral
python-build-standalone CPython 3.11.15 release `20260728`, arm64, minimum macOS 11.0, with
archive SHA-256
`7dc10e31eede05a6ab1ec9e0b961f521078b0959f838ed1d7452597d529ff802`.
The lock also pins the transformed runtime tree, Python executable, libpython, exact wheel
filenames/hashes, and the installed site-packages tree. The builder rejects any added or
changed source, bytecode cache, wheel, module, or runtime file.

Identity, team, certificate, entitlements, and runtime overrides are deliberately unsupported.

### Notarize and staple

Store an App Store Connect **Team API key** once in the build Mac's Keychain profile. Keep
the downloaded `.p8` outside the repository:

```bash
xcrun notarytool store-credentials lantern-notary \
  --key /absolute/path/to/AuthKey_YOUR_KEY_ID.p8 \
  --key-id YOUR_KEY_ID \
  --issuer YOUR_ISSUER_UUID
```

Then request notarization explicitly:

```bash
/usr/bin/python3 -I -B scripts/bootstrap_macos_release.py \
  --runtime-archive /absolute/path/to/cpython-3.11.15+20260728-aarch64-apple-darwin-install_only.tar.gz \
  --wheelhouse /absolute/path/to/lantern-package-wheelhouse \
  --output-dir /absolute/path/to/new-empty-release-directory \
  --notarize
```

The only supported authentication path is the fixed `lantern-notary` Keychain profile.
Before signing, the tool performs a read-only JSON `notarytool history` preflight. It uploads
with `submit --no-wait`, requires a canonical lowercase submission UUID, and immediately
fsyncs an owner-private, read-only receipt that binds the UUID and uploaded ZIP hash to the
exact signed app snapshot and clean release-tool commit. It then uses bounded `wait`/`info`
checks, retrieves the Apple log, and validates the UUID, `Accepted` status, zero status code,
empty issue set, and exact input archive hash before stapling.

If Apple is still processing, the terminal closes, or the Mac restarts, the complete
pre-staple signed app, submitted ZIP, and immutable receipt remain in the private state
directory printed by the error. Resume that one existing submission—without signing or
uploading again—through the same sealed bootstrap and original output directory:

```bash
/usr/bin/python3 -I -B scripts/bootstrap_macos_release.py \
  --runtime-archive /absolute/path/to/cpython-3.11.15+20260728-aarch64-apple-darwin-install_only.tar.gz \
  --wheelhouse /absolute/path/to/lantern-package-wheelhouse \
  --output-dir /absolute/path/to/the-original-release-directory \
  --resume-notarization /absolute/path/to/.lantern-...notarization-STATE
```

Resume revalidates the receipt, submitted ZIP, signed app snapshot, full signature inventory,
certificate/team/entitlements, embedded source binding, and output collisions before it asks
Apple for status. Finalization always copies the immutable pre-staple app into a fresh attempt,
then staples, verifies, archives, round-trips, and exclusively publishes that copy. A failed
attempt is never reported as a release. If an operating-system copy or final verification fails,
any paths already created by that attempt are retained for explicit manual review; the tool never
recursively deletes a publication pathname because a same-user replacement race could otherwise
delete unrelated files. A successful run also retains that bounded,
owner-private evidence directory and reports its exact path. The release tool intentionally never
recursively deletes a notarization-state pathname because a same-user rename/replacement race could
otherwise delete unrelated files. After independently verifying the published artifact, move the
reported state directory to Trash in Finder if it is no longer needed. `Invalid`, malformed/missing
log, UUID/hash mismatch, or stapler failure therefore cannot become a release. A successful run
produces the `SIGNED-NOTARIZED` name and records the accepted UUID/log and complete signature
inventory in the manifest.

Notarization-input and final distribution ZIPs are written with Apple's `ditto --keepParent`
path so bundle metadata and the stapled ticket survive transport. Each ZIP is path-checked,
round-tripped into an isolated directory, compared with the source tree, and—after
notarization—required to pass `stapler validate` again from the extracted copy.

The sealed release path uses the fixed `lantern-notary` Keychain profile. Apple IDs,
app-specific passwords, `.p8` private keys, and raw credentials are never accepted through
the release process environment.

No Apple ID, app-specific password, or signing private key belongs in this repository.

### Remaining gates before family distribution

Do not relabel this as a frictionless family release until all of these are complete:

1. The pinned Apple Developer Program private key remains access-controlled and its renewal
   procedure is reviewed.
2. Any future non-empty Hardened Runtime entitlement receives independent review first.
3. The complete `.app` is Developer ID signed, submitted to Apple notarization, stapled,
   and independently assessed on a clean supported Mac.
4. Signing and notarization provenance are recorded without exposing credentials.
5. The ZIP is produced after signing/stapling and its hash is published through a separate
   authenticated channel.
6. Installation/opening is tested on clean macOS user profiles with Gatekeeper enabled.
7. Equivalent Linux distribution trust, dependency, and desktop-integration decisions are
   made before claiming a supported Linux family installer.

The unsigned development pipeline remains available until those gates are satisfied on a
clean machine.
