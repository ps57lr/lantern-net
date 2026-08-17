# ADR 0006: Platform-specific rescue boundaries

Status: accepted for read-only guidance

Rescue reports hardware, storage/filesystem, operating-system, data-recoverability, and network viability independently. Unknown and encrypted states stay unknown until supported evidence exists.

Windows uses supported WinRE/Startup Settings guidance and later an authorized WinPE collector. Linux begins as a read-only collector in a reputable live environment; a signed custom image is a later proof. macOS guides built-in Recovery, Safe Mode, Share Disk, Disk Utility, and Apple Diagnostics rather than promising a universal boot USB.

No automatic disk repair, write mount, partition, bootloader, BCD, NVRAM, Secure Boot, FileVault, BitLocker, reset, reinstall, or recovery-key capture is permitted in this phase.
