# CachyOS Enterprise Hardening - Ring 0 Boot Parameters (GRUB)

This document outlines the kernel command-line parameters applied to the bootloader.

## Zero-Overhead & High Security
- `vsyscall=none`: Disables the legacy vsyscall page to eliminate fixed-address ROP targets.

- `page_alloc.shuffle=1`: Randomizes page allocator freelists to prevent predictable memory layout exploitation.

- `randomize_kstack_offset=on`: Randomizes kernel stack offsets on every syscall, mitigating stack-based exploits with negligible.

- `slab_nomerge`: Disables slab cache merging. Disrupts heap-overflow exploit reliability. **Trade-off:** Consumes ~50MB of additional RAM footprint, deemed acceptable within modern capacities constraints.

- `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`: Explicitly defines the Linux Security Modules (LSM) stacking order and activation. This specific chain is critical for the architecture:
  - `landlock`: Enables unprivileged sandboxing. Crucial for modern browser and Flatpak security.
  - `lockdown`: Enforces kernel boundaries, preventing root (UID 0) from directly modifying kernel code or memory (e.g., via `/dev/mem`).
  - `yama`: Mitigates unauthorized memory injection by restricting `ptrace` scope to descendant processes only.
  - `integrity`: Enables the Integrity Measurement Architecture (IMA).
  - `apparmor`: Enforces Mandatory Access Control (MAC) profiles.
  - `bpf`: Activates eBPF security hooks, an absolute hardware-level requirement for active EDR/IDS monitoring (Falco/nova-ids).

## Gaming & Low-Latency Tuning
- `nowatchdog`: Disables the NMI watchdog. Prevents the kernel from generating constant hardware interrupts to check for lockups, significantly reducing micro-stuttering in high-framerate scenarios.

