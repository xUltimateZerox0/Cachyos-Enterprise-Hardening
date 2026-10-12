# Ring 0 — Core Dump Disabling

Controls:
1. `kernel.core_pattern=/dev/null` — the kernel stores no cores.
2. `Storage=none` + `ProcessSizeMax=0` (`coredump.conf.d/99-hardening.conf`) — systemd-coredump handling
   disabled per the documented procedure (systemd-coredump(8)).
3. `DefaultLimitCORE=0` (`system.conf.d/99-hardening.conf`) — hard limit 0 for systemd units.
4. `* hard core 0` (`/etc/security/limits.conf`) + `ulimit -c 0` (`profile.d/99-core-dumps.sh`).
5. `fs.suid_dumpable=0`.

Temporary debugging when a core is needed:
```
sudo sysctl -w kernel.core_pattern='core.%p'
sudo systemd-run --pty -p LimitCORE=infinity bash
```
