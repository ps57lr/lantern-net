# ADR 0005: Portable development packaging

Status: accepted for prototype builds

Portable development artifacts use PyInstaller one-folder builds produced on each target operating system. The USB presents an obvious Start Lantern launcher and never uses autorun, installs persistence, or elevates during a baseline scan.

Artifacts bundle all UI assets, store mutable state in protected temporary directories, emit hashes and a build manifest, and disclose unsigned development status. macOS signing/notarization, Windows signing/reputation, protected provenance, and update security are later release gates; they must not be implied by checksums alone.
