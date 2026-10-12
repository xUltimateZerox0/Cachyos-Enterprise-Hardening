# MOR (MemoryOverwriteRequestControl) — cold-boot mitigation

Purpose: encrypted-disk secrets reside in RAM; an attacker who forces a reset could dump memory from a subsequent boot. 
When the MOR bit is set, the platform firmware must overwrite all memory before continuing to boot (TCG reset-attack mitigation).

Who sets it: the TCG model assigns this to the EFI OS loader; on GRUB-based systems nothing sets it (the kernel does it only when booted as an EFI application).
`mor-arm.service` arms it at every boot with value `0x01` (ClearMemory only).

Behavior: the firmware wipes memory after resets that bypass an orderly shutdown (crash, forced power-off, power loss) and skip the wipe after an orderly shutdow (firmware autodetect). 
Accepted residual: the OS does not purge all memory secrets at standard shutdown, so a cold-boot attack after an orderly shutdown is not covered.

Notes: the bit is consumed by the firmware after each wipe, hence the re-arm on every boot; 
efivarfs marks the variable immutable (the script clears and restores the flag); do not set MORControlLock (it would prevent re-arming).
