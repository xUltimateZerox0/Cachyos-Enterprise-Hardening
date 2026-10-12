# Ring 0 — LUKS2 + TPM2 Unlock

## Configuration
- LUKS2, `aes-xts-plain64`, 512-bit key, on the NVMe root partition.
- Keyslot 0: passphrase (argon2id, 1 GiB, t=13) — recovery path.
- Keyslot 1: TPM2 token, PCRs `0+2+4+7+8+9`, `sha256` bank, RSA SRK, no PIN, no salt.
- Unlock via `rd.luks.*` kernel parameters + `/etc/crypttab` (`tpm2-device=auto,discard`), `sd-encrypt` initramfs hook.

## Trade-offs
- `discard` passthrough enabled for NVMe performance/endurance (reveals used-block patterns).
- No TPM PIN: unattended boot.

## Re-enrollment after firmware or boot changes
```
systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=0+2+4+7+8+9 /dev/nvme0n1p2
```
Enter the LUKS passphrase when prompted; verify with `cryptsetup luksDump` (`tpm2-hash-pcrs`) and
`systemd-cryptenroll`.
