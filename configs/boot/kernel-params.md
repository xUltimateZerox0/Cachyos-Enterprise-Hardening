# Ring 0 — Kernel Command Line (GRUB)

Hardening-relevant kernel parameters:

```
vsyscall=none page_alloc.shuffle=1 randomize_kstack_offset=on loglevel=3 \
lsm=landlock,lockdown,yama,integrity,apparmor,bpf \
rd.luks.name=<LUKS-UUID>=cryptroot rd.luks.options=<LUKS-UUID>=tpm2-device=auto,discard \
root=/dev/mapper/cryptroot
```

## Hardening parameters
- `vsyscall=none`: removes the legacy fixed-address vsyscall page (ROP target).
- `page_alloc.shuffle=1`: randomizes the page allocator freelist at boot (heap grooming).
- `randomize_kstack_offset=on`: per-syscall kernel stack offset randomization.
- `loglevel=3`: quiet console, limits boot-time information disclosure.
- `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`: explicit LSM order — landlock
  (unprivileged sandboxing), yama (`ptrace_scope=1` via sysctl), apparmor (MAC),
  bpf (eBPF hooks for monitoring).
- `rd.luks.name=<LUKS-UUID>=cryptroot` + `rd.luks.options=<LUKS-UUID>=tpm2-device=auto,discard`
  + `root=/dev/mapper/cryptroot`: LUKS2 unlock chain — TPM2 auto-unlock with passphrase fallback
  (keyslot 0, argon2id; TPM policy: PCRs `0+2+4+7+8+9`, sha256).