# CachyOS Enterprise Hardening - Ring 0 Boot Parameters (GRUB)

This document outlines the kernel command-line parameters applied to the bootloader.

## Architectural Philosophy (Constraint-Based)
The parameters are curated to provide Exploit Mitigation (Memory Randomization, ROP chain mitigation) against opportunistic threat actors, governed by strict environmental constraints: **16 GB RAM capacity, Zero-FPS-drop requirement, and compatibility with containerized Pentesting workflows**.

## Applied Parameters (Zero-Overhead & High Security)
* `vsyscall=none`: Disables the legacy vsyscall page to eliminate fixed-address ROP targets. Zero performance impact.
* `page_alloc.shuffle=1`: Randomizes page allocator freelists to prevent predictable memory layout exploitation (Heap Feng Shui).
* `randomize_kstack_offset=on`: Randomizes kernel stack offsets on every syscall, mitigating stack-based exploits with negligible (<0.1%) CPU overhead.
* `slab_nomerge`: Disables slab cache merging. Disrupts heap-overflow exploit reliability. **Trade-off:** Consumes ~50MB of additional RAM footprint, deemed acceptable within a 16GB capacity constraint for the security ROI.

## Excluded Parameters (Documented Architectural Decisions)
* `debugfs=off`: Explicitly excluded. While it prevents kernel information leakage, it breaks eBPF tracing tools, advanced pentesting network captures, and GPU frequency/voltage tuning interfaces required by the user.
* `init_on_alloc=1` / `init_on_free=1`: Excluded to prevent measurable memory allocation latency during high-framerate gaming.
