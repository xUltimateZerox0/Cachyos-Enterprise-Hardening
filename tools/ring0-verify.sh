#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 xUltimateZerox0
#
# Ring 0 verification: checks every applied measure and records evidence.
# Usage: sudo ./tools/ring0-verify.sh
# Output: terminal + <workspace>/sysinfo/ring0-verify.txt

set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
WS_DIR="$(cd -- "$REPO_DIR/.." && pwd)"
OUTDIR="$WS_DIR/sysinfo"
TMP="$(mktemp)"
PASS=0
FAIL=0

[ "$(id -u)" -eq 0 ] || { echo "error: run as root (sudo $0)" >&2; exit 1; }
mkdir -p "$OUTDIR"

say() { echo "$@" | tee -a "$TMP"; }
ok()  { say "PASS  $1"; PASS=$((PASS + 1)); }
bad() { say "FAIL  $1"; FAIL=$((FAIL + 1)); }
info(){ say "INFO  $1"; }

chk_sysctl() {
  local k="$1" want="$2" got
  got="$(sysctl -n "$k" 2>/dev/null || true)"
  if [ "$got" = "$want" ]; then ok "sysctl $k = $want"; else bad "sysctl $k = '${got:-<missing>}' (want '$want')"; fi
}

say "Ring 0 verification — $(date '+%Y-%m-%d %H:%M:%S')"
say "kernel: $(uname -r)   boot_id: $(cat /proc/sys/kernel/random/boot_id)"
say ""

say "== 1. Kernel command line =="
for p in vsyscall=none page_alloc.shuffle=1 randomize_kstack_offset=on nowatchdog; do
  grep -q -- "$p" /proc/cmdline && ok "cmdline contains $p" || bad "cmdline missing $p"
done
grep -q "lsm=landlock,lockdown,yama,integrity,apparmor,bpf" /proc/cmdline \
  && ok "LSM chain active" || bad "LSM chain not as documented"
info "bridge-nf sysctl: $(sysctl -n net.bridge.bridge-nf-call-iptables 2>&1 | head -1)"

say ""
say "== 2. /boot artifact permissions =="
[ "$(stat -c %a /boot)" = "700" ] && ok "/boot mode 700" || bad "/boot mode $(stat -c %a /boot)"
[ "$(stat -c %a /root)" = "700" ] && ok "/root mode 700" || bad "/root mode $(stat -c %a /root)"
for f in /boot/vmlinuz-linux-cachyos /boot/initramfs-linux-cachyos.img /boot/grub/grub.cfg; do
  [ -e "$f" ] || { bad "$f missing"; continue; }
  [ "$(stat -c %a "$f")" = "600" ] && ok "$(basename "$f") mode 600" || bad "$(basename "$f") mode $(stat -c %a "$f")"
done
say "-- /boot leftovers pending review (not touched) --"
for f in /boot/PK /boot/KEK /boot/db /boot/dbt /boot/dbx /boot/mach_kernel; do
  [ -e "$f" ] && info "$f : $(file -b "$f" 2>/dev/null) ($(stat -c %s "$f") bytes)"
done
[ -d /boot/System ] && info "/boot/System entries: $(find /boot/System -maxdepth 2 2>/dev/null | head -8 | tr '\n' ' ')"
[ -d /boot/EFI ] && info "/boot/EFI entries: $(find /boot/EFI -maxdepth 3 2>/dev/null | head -8 | tr '\n' ' ')"

say ""
say "== 3. sysctl baseline (managed keys) =="
chk_sysctl kernel.kptr_restrict 2
chk_sysctl kernel.dmesg_restrict 1
chk_sysctl kernel.yama.ptrace_scope 1
chk_sysctl dev.tty.ldisc_autoload 0
chk_sysctl kernel.kexec_load_disabled 1
chk_sysctl vm.memfd_noexec 0
chk_sysctl fs.suid_dumpable 0
chk_sysctl fs.protected_fifos 2
chk_sysctl fs.protected_regular 2
chk_sysctl fs.protected_symlinks 1
chk_sysctl fs.protected_hardlinks 1
chk_sysctl kernel.sysrq 0
chk_sysctl kernel.unprivileged_bpf_disabled 1
chk_sysctl kernel.perf_event_paranoid 2
chk_sysctl kernel.unprivileged_userns_clone 1
chk_sysctl net.core.bpf_jit_harden 2
chk_sysctl net.ipv4.ip_forward 1
chk_sysctl net.ipv4.conf.all.rp_filter 2
chk_sysctl net.ipv4.tcp_syncookies 1
chk_sysctl net.ipv4.tcp_rfc1337 1
chk_sysctl net.ipv4.conf.all.accept_source_route 0
chk_sysctl net.ipv4.conf.default.accept_source_route 0
chk_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
chk_sysctl net.ipv4.conf.all.accept_redirects 0
chk_sysctl net.ipv4.conf.all.log_martians 1
chk_sysctl net.ipv6.conf.all.accept_redirects 0
chk_sysctl net.ipv6.conf.all.accept_source_route 0

say ""
say "== 4. kernel module blacklists =="
[ -f /etc/modprobe.d/99-hardening.conf ] && ok "99-hardening.conf present" || bad "99-hardening.conf missing"
[ -f /etc/modprobe.d/hardening-blacklist.conf ] && bad "legacy hardening-blacklist.conf still present" || ok "legacy file retired"
grep -q "firewire-core" /etc/modprobe.d/99-hardening.conf && ok "firewire-core blocked" || bad "firewire-core rule missing"
for m in dccp sctp rds tipc firewire-core; do
  out="$(modprobe -n -v "$m" 2>&1 || true)"
  echo "$out" | grep -q "install /bin/true" && ok "$m intercepted by install rule" || bad "$m interception not visible ($out)"
done
if lsmod | grep -qE '^(dccp|sctp|rds|tipc|firewire)'; then bad "blacklisted module loaded"; else ok "no blacklisted module loaded"; fi

say ""
say "== 5. core-dump closure =="
grep -q "kernel.core_pattern = /dev/null" /etc/sysctl.d/99-hardening.conf && ok "core_pattern=/dev/null in profile" || bad "core_pattern not in profile"
[ "$(sysctl -n kernel.core_pattern)" = "/dev/null" ] && ok "runtime core_pattern=/dev/null" || bad "runtime core_pattern=$(sysctl -n kernel.core_pattern)"
grep -q "Storage=none" /etc/systemd/coredump.conf.d/99-hardening.conf 2>/dev/null && ok "coredump Storage=none" || bad "coredump drop-in missing"
grep -q "ProcessSizeMax=0" /etc/systemd/coredump.conf.d/99-hardening.conf 2>/dev/null && ok "coredump ProcessSizeMax=0" || bad "ProcessSizeMax=0 missing"
systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | grep -q "Storage=none" && ok "merged coredump config contains Storage=none" || bad "merged coredump config not active"
systemd-analyze cat-config systemd/system.conf 2>/dev/null | grep -q "DefaultLimitCORE=0" && ok "merged system.conf contains DefaultLimitCORE=0" || bad "DefaultLimitCORE=0 not merged"
grep -q "ulimit -c 0" /etc/profile.d/99-core-dumps.sh 2>/dev/null && ok "profile.d ulimit -c 0" || bad "profile.d ulimit missing"
grep -Eq '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf && ok "limits.conf hard core 0" || bad "limits.conf hard core 0 missing"

say ""
say "== 6. LUKS2 + TPM2 =="
LUKSDEV="$(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null | head -1)"
if [ -n "$LUKSDEV" ]; then
  ok "LUKS device: $LUKSDEV"
  tpm_ok=0
  if cryptsetup luksDump "$LUKSDEV" 2>&1 | tr -s '[:space:]' ' ' | grep -qF "tpm2-hash-pcrs: 0+2+4+7+8+9"; then
    tpm_ok=1
  else
    for tid in $(cryptsetup luksDump "$LUKSDEV" 2>/dev/null | sed -n 's/^  \([0-9][0-9]*\): .*/\1/p'); do
      if cryptsetup token export --token-id "$tid" "$LUKSDEV" 2>/dev/null | tr -d ' \n\t' | grep -qF '"tpm2-pcrs":[0,2,4,7,8,9]'; then
        tpm_ok=1
        break
      fi
    done
  fi
  [ "$tpm_ok" -eq 1 ] && ok "TPM PCR policy 0+2+4+7+8+9" || bad "TPM PCR policy not as documented"
  cryptsetup luksDump "$LUKSDEV" 2>/dev/null | grep -q "0: luks2" && ok "keyslot 0 present (passphrase recovery)" || bad "keyslot 0 missing"
  info "cryptenroll slots: $(systemd-cryptenroll "$LUKSDEV" 2>/dev/null | tr '\n' ' ')"
  say "-- LUKS token export (evidence) --"
  for tid in $(cryptsetup luksDump "$LUKSDEV" 2>/dev/null | sed -n 's/^  \([0-9][0-9]*\): .*/\1/p'); do
    cryptsetup token export --token-id "$tid" "$LUKSDEV" 2>&1 | sed 's/^/  /' | tee -a "$TMP"
    echo | tee -a "$TMP"
    break
  done
  info "GRUB TPM modules present: $(ls /boot/grub/x86_64-efi/ 2>/dev/null | grep -i '^tpm' | tr '\n' ' ')"
  info "grub.cfg TPM measurement commands: $(grep -icE 'tpm2_key_protector_init|insmod (tpm|tpm2)' /boot/grub/grub.cfg 2>/dev/null || echo 0)"
else
  bad "no LUKS device found"
fi
info "TPM PCRs (compare across reboots):"
for p in 0 2 4 7 8 9; do info "  PCR-$p = $(cat /sys/class/tpm/tpm0/pcr-sha256/$p 2>/dev/null || echo unavailable)"; done

say ""
say "== 7. zram / systemd-sysctl =="
swapon --show 2>/dev/null | grep -q zram && ok "zram swap active" || info "zram swap not listed"
zramctl 2>/dev/null | sed 's/^/  /' | tee -a "$TMP"
info "systemd-sysctl journal (current boot):"
journalctl -b --no-pager -u systemd-sysctl 2>/dev/null | tail -5 | sed 's/^/  /' | tee -a "$TMP"

say ""
say "summary: PASS=$PASS FAIL=$FAIL"

cp "$TMP" "$OUTDIR/ring0-verify.txt"
rm -f "$TMP"
owner="${SUDO_USER:-}"
[ -n "$owner" ] && id "$owner" >/dev/null 2>&1 && chown "$owner" "$OUTDIR/ring0-verify.txt" 2>/dev/null || true
chmod a+r "$OUTDIR/ring0-verify.txt" 2>/dev/null || true
echo "evidence: $OUTDIR/ring0-verify.txt"
exit "$FAIL"
