# Lantern local developer packaging

## Release posture

This pipeline produces a **local, unsigned development artifact** for supervised testing.
It is not yet a frictionless family distribution, production installer, managed endpoint
agent, or enterprise deployment package.

The macOS build is not Developer ID signed or notarized. PyInstaller applies an ad-hoc
signature on macOS so executable pages can be validated; an ad-hoc signature does not
identify a publisher. The Linux build is likewise unsigned. The manifest and checksums
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
| macOS arm64 or x86_64 | `Start Lantern (Unsigned Dev).app` inside a labeled folder |
| glibc Linux arm64 or x86_64 | one-folder `Start Lantern (Unsigned Dev)` payload |

Cross-compilation is not supported. Windows packaging is not claimed by this project.

## Locked build environment

Use a disposable virtual environment. First, on a connected build machine, download the
reviewed binary wheels:

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

Build from a reviewed, clean commit:

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

For version `0.3.0.dev3` on Apple Silicon, the names are:

```text
lantern-family-beta-0.3.0.dev3-macos-arm64-UNSIGNED-DEV/
lantern-family-beta-0.3.0.dev3-macos-arm64-UNSIGNED-DEV.zip
lantern-family-beta-0.3.0.dev3-macos-arm64-UNSIGNED-DEV.zip.sha256
```

The unpacked directory contains:

- `START-HERE.txt` with tester-safe opening and consent guidance;
- `UNSIGNED-DEVELOPMENT-BUILD.txt` with the trust limitations;
- `package-manifest.json` with bounded provenance and per-entry SHA-256 values;
- `SHA256SUMS.txt`, which anchors the manifest's transfer-integrity check;
- the one-folder application payload and an offline verification executable.

PEP 440 development versions are kept in the runtime and package manifest. macOS bundle
metadata uses Apple's numeric forms: `0.3.0.dev3` maps to marketing version `0.3.0` and
bundle build `3`.

## Verification

Verify an unpacked artifact on its target operating system:

```bash
python3 scripts/verify_family_beta.py \
  --require-clean-source \
  dist/family-beta/lantern-family-beta-0.3.0.dev3-macos-arm64-UNSIGNED-DEV
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
  scripts/package_family_beta.py scripts/verify_family_beta.py tests/packaging
python -m ruff format --check packaging scripts/package_support.py \
  scripts/package_family_beta.py scripts/verify_family_beta.py tests/packaging
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

Do not relabel this as a signed beta until all of these are complete:

1. An Apple Developer Program identity is held in an access-controlled signing service.
2. Hardened Runtime entitlements are minimized and reviewed.
3. The complete `.app` is Developer ID signed, submitted to Apple notarization, stapled,
   and independently assessed on a clean supported Mac.
4. Signing and notarization provenance are recorded without exposing credentials.
5. The ZIP is produced after signing/stapling and its hash is published through a separate
   authenticated channel.
6. Installation/opening is tested on clean macOS user profiles with Gatekeeper enabled.
7. Equivalent Linux distribution trust, dependency, and desktop-integration decisions are
   made before claiming a supported Linux family installer.

No signing identity or notarization credential is present in this repository, so those
gates are intentionally blocked rather than simulated.
