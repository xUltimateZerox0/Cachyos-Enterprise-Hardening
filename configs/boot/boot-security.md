# Ring 0 — Boot Partition & Bootloader Security

## /boot artifact integrity
ESP mount options `fmask=0177,dmask=0077` (vfat has no native permissions; the masks are the
enforcement) yield `/boot` mode `0700` and `0600 root:root` artifacts.

## Bootloader
- `GRUB_DISABLE_OS_PROBER=true`: no foreign-OS probing, no unintended boot entries.
- `GRUB_DISABLE_BOOTNEXT=true`: no phantom entries via UEFI BootNext.
- Single-user/rescue access requires root password authentication (`sulogin`).