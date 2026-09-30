# CachyOS Enterprise Hardening - Boot Partition & Artifact Integrity
Standard: CIS Linux Benchmark 1.4.1 - 1.4.2

## Architectural Perspective
The boot partition (`/boot`) contains uncompressed kernel images, symbol tables (`System.map`), and initial RAM disks (`initramfs`). Allowing unprivileged users (UID != 0) read access to these artifacts leaks exact kernel memory layouts, facilitating Return-Oriented Programming (ROP) offset calculations and cryptanalysis of early-boot hooks.

## Enforced Security Baseline
1. **Directory Permissions:** The `/boot` EFI mount point enforces mode `0700` (`drwx------`) owned by `root:root`.
2. **Artifact Permissions:** Kernel binaries and initramfs archives restricted to mode `0600` (`-rw-------`).
3. **Initramfs Generation:** Image creation utilities (`mkinitcpio`) must operate under a strict `0077` umask.