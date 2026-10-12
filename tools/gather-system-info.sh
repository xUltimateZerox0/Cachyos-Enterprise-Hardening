#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 xUltimateZerox0
#
# gather-system-info.sh - reproducible hardening evidence snapshot.
#
# Usage: sudo ./tools/gather-system-info.sh [-o OUTPUT_DIR] [--with-lynis]
# Default OUTPUT_DIR: <workspace>/sysinfo (../../sysinfo relative to this file).
# Output ownership is returned to $SUDO_USER and made world-readable so the
# raw evidence can be read back from an unprivileged sandbox.
#
# Raw output may contain host identifiers (MACs, IPs, UUIDs, usernames).
# Publish only sanitized copies via tools/sanitize-evidence.py.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)/sysinfo"
WITH_LYNIS=0

usage() { sed -n '3,13p' "$0"; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUTDIR="${2:?missing directory for -o}"; shift 2 ;;
    -o*) OUTDIR="${1#-o}"; shift ;;
    -h|--help) usage ;;
    --with-lynis) WITH_LYNIS=1; shift ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run as root (sudo $0)" >&2
  exit 1
fi

mkdir -p "$OUTDIR"
OUTDIR="$(cd -- "$OUTDIR" && pwd)"
echo "[*] collecting system state into $OUTDIR"

capture() {
  local name="$1"; shift
  if "$@" > "$OUTDIR/$name" 2>&1; then
    printf '  + %s\n' "$name"
  else
    printf '  ! %s (non-zero exit, captured anyway)\n' "$name"
  fi
}

# ---- platform ---------------------------------------------------------------
capture uname.txt          uname -a
capture os_release.txt     cat /etc/os-release
capture hostnamectl.txt    hostnamectl status
capture timedatectl.txt    timedatectl status
capture uptime.txt         uptime

# ---- ring 0: boot and kernel ------------------------------------------------
capture proc_cmdline.txt   cat /proc/cmdline
capture grub_default.txt   cat /etc/default/grub
capture grub_password_check.txt bash -c \
  'for f in /boot/grub/grub.cfg /etc/grub.d/10_linux /etc/grub.d/41_snapshots-btrfs /etc/grub.d/40_custom; do [ -f "$f" ] && { echo "### $f"; grep -niE "password|superuser" "$f" || echo "(no password/superuser entries)"; }; done'
capture grub_cfg_perm.txt  stat -c '%a %U:%G %n' /boot/grub/grub.cfg
ls /boot/ >/dev/null 2>&1
capture boot_ls.txt        ls -la /boot/
capture boot_artifacts.txt bash -c \
  'for f in /boot/vmlinuz-* /boot/initramfs-*.img; do [ -e "$f" ] && stat -c "%a %U:%G %n" "$f"; done'
capture mkinitcpio_conf.txt cat /etc/mkinitcpio.conf
capture mkinitcpio_presets.txt bash -c 'cat /etc/mkinitcpio.d/*.preset 2>/dev/null'
capture sysctl_conf.txt    bash -c \
  'for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do [ -f "$f" ] && { echo "### $f"; cat "$f"; echo; }; done'
capture sysctl_runtime.txt sysctl -a
capture sysctl_checks.txt  bash -c \
  'for k in kernel.unprivileged_userns_clone net.bridge.bridge-nf-call-iptables kernel.unprivileged_bpf_disabled kernel.modules_disabled kernel.kptr_restrict kernel.yama.ptrace_scope vm.swappiness vm.memfd_noexec; do printf "%-45s = " "$k"; sysctl -n "$k" 2>&1 || true; done'
capture modprobe_all.txt   bash -c \
  'for f in /etc/modprobe.d/*.conf; do [ -f "$f" ] && { echo "### $f"; cat "$f"; echo; }; done'
capture modprobe_lib_list.txt ls -la /usr/lib/modprobe.d/
capture lsmod.txt          lsmod
capture secureboot.txt     bash -c \
  '{ bootctl status 2>&1 | head -40; echo "--- mokutil ---"; mokutil --sb-state 2>&1; echo "--- efivars ---"; for v in SecureBoot SetupMode; do p=$(ls /sys/firmware/efi/efivars/${v}-* 2>/dev/null | head -1); [ -n "$p" ] && { printf "%s: " "$v"; od -An -tu1 "$p"; }; done; echo "--- efi vars of interest ---"; ls /sys/firmware/efi/efivars/ 2>/dev/null | grep -iE "MOR|dbx|KEK|PK-|SecureBoot|SetupMode" || true; }'
capture tpm_pcrs.txt       bash -c \
  'echo "TPM version: $(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null)"; for p in 0 2 4 7 8 9; do printf "PCR-%s sha256: " "$p"; cat "/sys/class/tpm/tpm0/pcr-sha256/$p" 2>&1 || echo unavailable; done'
capture cryptsetup_luks.txt bash -c \
  'for d in $(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null); do echo "### $d"; cryptsetup luksDump "$d"; done'
capture cryptenroll_list.txt bash -c \
  'for d in $(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null); do echo "### $d"; systemd-cryptenroll "$d" 2>&1; done'
capture cryptsetup_token.txt bash -c \
  'for d in $(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null); do tid=$(cryptsetup luksDump "$d" 2>/dev/null | sed -n "s/^  \([0-9][0-9]*\): .*/\1/p" | head -1); if [ -n "$tid" ]; then echo "### $d token $tid"; cryptsetup token export --token-id "$tid" "$d" 2>&1; fi; done'
capture crypttab.txt       cat /etc/crypttab
capture zram_swap.txt      bash -c \
  '{ zramctl; echo "--- swapon ---"; swapon --show; echo "--- zram-generator ---"; for f in /etc/systemd/zram-generator.conf /usr/lib/systemd/zram-generator.conf; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done; }'
capture coredump_conf.txt  systemd-analyze cat-config systemd/coredump.conf
capture limits_all.txt     bash -c \
  'for f in /etc/security/limits.conf /etc/security/limits.d/*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done'
capture journal_sysctl.txt bash -c \
  'journalctl -b --no-pager -u systemd-sysctl 2>&1 | tail -40'
capture file_capabilities.txt getcap -r /usr/bin /usr/sbin /usr/local/bin 2>/dev/null
capture setuid_files.txt   bash -c \
  'find /usr/bin /usr/sbin /usr/local/bin -xdev -type f -perm -4000 -exec stat -c "%a %U:%G %n" {} + 2>/dev/null'

# ---- ring 1: access control -------------------------------------------------
capture pam_d_list.txt     ls -la /etc/pam.d/
capture pam_system_auth.txt cat /etc/pam.d/system-auth
capture pam_system_auth_pacnew.txt cat /etc/pam.d/system-auth.pacnew
capture pam_system_auth_bak.txt  cat /etc/pam.d/system-auth.bak
capture pwquality.txt      cat /etc/security/pwquality.conf
capture faillock_conf.txt  cat /etc/security/faillock.conf
capture login_defs_filtered.txt bash -c \
  'grep -vE "^\s*#|^\s*$" /etc/login.defs'
capture sudoers_all.txt    bash -c \
  'for f in /etc/sudoers /etc/sudoers.d/*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done'
capture users.txt          getent passwd
capture user_status.txt    passwd -S -a
capture admin_groups.txt   bash -c 'getent group wheel; getent group sudo; getent group audio; getent group video'
capture sshd_config.txt    cat /etc/ssh/sshd_config
capture sshd_config_d.txt  bash -c 'for f in /etc/ssh/sshd_config.d/*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done'
capture sshd_effective.txt bash -c 'sshd -T 2>&1; echo "--- exit $? ---"'
capture sshd_state.txt     bash -c 'systemctl is-enabled sshd 2>&1; systemctl is-active sshd 2>&1; ss -tlnp | grep -E ":(45936|22)\b" || echo "(no ssh listener)"'

# ---- ring 2: MAC, audit, integrity -----------------------------------------
capture apparmor_status.txt aa-status
capture apparmor_parser.conf cat /etc/apparmor/parser.conf
capture apparmor_d_list.txt ls /etc/apparmor.d/
capture auditd_conf.txt    cat /etc/audit/auditd.conf
capture auditd_state.txt   bash -c 'systemctl is-enabled auditd 2>&1; systemctl is-active auditd 2>&1; auditctl -s 2>&1'
capture audit_rules.txt    bash -c \
  'for f in /etc/audit/rules.d/*.rules; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done'
capture auditctl_rules.txt auditctl -l
capture aide_state.txt     bash -c \
  'ls -la /etc/aide.conf /var/lib/aide/ 2>&1; systemctl list-timers --all --no-pager 2>/dev/null | grep -iE "aide|rkhunter|nova" || true'
capture rkhunter_state.txt bash -c \
  'command -v rkhunter && rkhunter --version 2>&1 | head -3; ls -la /var/lib/rkhunter/db 2>&1 | head -8'
capture systemd_security.txt systemd-analyze security --no-pager
capture systemd_enabled.txt systemctl list-unit-files --state=enabled --no-pager
capture systemd_failed.txt systemctl --failed --no-pager
capture systemd_timers.txt systemctl list-timers --all --no-pager
capture systemd_dropins.txt bash -c \
  'find /etc/systemd/system -maxdepth 3 \( -name "*.conf" -o -name "*.d" \) | sort; echo "---"; for f in $(find /etc/systemd/system -name "*.conf" 2>/dev/null); do echo "### $f"; cat "$f"; echo; done'
capture falco_nova_state.txt bash -c \
  'systemctl status falco-modern-bpf.service nova-ids.service --no-pager -l 2>&1 | head -80'
capture lynis_profile.txt  cat /etc/lynis/custom.prf

# ---- ring 3: network --------------------------------------------------------
capture ufw_state.txt      bash -c 'systemctl is-enabled ufw 2>&1; systemctl is-active ufw 2>&1; ufw status verbose'
capture ufw_numbered.txt   ufw status numbered
capture ufw_user_rules.txt bash -c 'echo "### ipv4"; cat /etc/ufw/user.rules 2>/dev/null; echo "### ipv6"; cat /etc/ufw/user6.rules 2>/dev/null'
capture nftables.txt       nft list ruleset
capture nftables_conf.txt  cat /etc/nftables.conf
capture nftables_service.txt bash -c 'systemctl is-enabled nftables 2>&1; systemctl is-active nftables 2>&1'
capture iptables.txt       iptables -L -n -v
capture ss_tulpn.txt       ss -tulpn
capture ss_summary.txt     ss -s
capture ip_addr.txt        ip -details addr
capture ip_route.txt       bash -c 'ip route; echo "--- ipv6 ---"; ip -6 route'
capture resolv_conf.txt    cat /etc/resolv.conf
capture resolvectl.txt     resolvectl status
capture dnscrypt_config.txt cat /etc/dnscrypt-proxy/dnscrypt-proxy.toml
capture dnscrypt_state.txt bash -c 'systemctl status dnscrypt-proxy --no-pager -l 2>&1 | head -25'
capture nm_conf.txt        bash -c 'for f in /etc/NetworkManager/conf.d/* /etc/NetworkManager/NetworkManager.conf; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done'
capture nm_dispatcher.txt  bash -c 'for f in /etc/NetworkManager/dispatcher.d/* /usr/lib/NetworkManager/dispatcher.d/*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done'
capture tailscale_state.txt bash -c 'systemctl is-enabled tailscaled 2>&1; systemctl is-active tailscaled 2>&1'

# ---- ring 4: storage and peripherals ---------------------------------------
capture fstab.txt          cat /etc/fstab
capture findmnt.txt        findmnt -A
capture mount.txt          mount
capture lsblk.txt          lsblk -f
capture df.txt             df -hT
capture cryptsetup_status.txt cryptsetup status cryptroot
capture usbguard_daemon.conf bash -c 'grep -vE "^\s*#|^\s*$" /etc/usbguard/usbguard-daemon.conf'
capture usbguard_rules.conf cat /etc/usbguard/rules.conf
capture usbguard_state.txt bash -c 'systemctl is-enabled usbguard 2>&1; systemctl is-active usbguard 2>&1; usbguard list-devices 2>&1 | head -20'
capture efibootmgr.txt     efibootmgr -v
capture efi_boot_dir.txt   bash -c 'ls -la /boot/EFI/ 2>&1; find /boot/EFI -maxdepth 3 -type f -exec stat -c "%a %U:%G %n" {} + 2>/dev/null'

# ---- ring 5: userland hygiene ----------------------------------------------
capture pacman_conf.txt    bash -c 'grep -vE "^\s*#|^\s*$" /etc/pacman.conf'
capture pacman_updates.txt pacman -Qu
capture packages_security.txt bash -c \
  'pacman -Q | grep -Ei "apparmor|audit|falco|lynis|aide|rkhunter|usbguard|ufw|nftables|iptables|openssh|tpm2|sbctl|cryptsetup|bubblewrap|podman|libvirt|qemu|nvidia|linux-cachyos|zram|firejail|clamav|suricata|wireshark|nmap|metasploit|hashcat|john|hydra|sqlmap"'
capture compilers.txt      bash -c 'command -v gcc g++ clang cc as python3 rustc go 2>&1'
capture compiler_perms.txt bash -c 'ls -la /usr/bin/gcc /usr/bin/clang* /usr/bin/cc 2>&1 | head -10'
capture umask_files.txt    bash -c 'echo "### /etc/profile"; grep -i umask /etc/profile 2>/dev/null; echo "### /etc/profile.d"; grep -ri umask /etc/profile.d/ 2>/dev/null; echo "### /etc/bash.bashrc"; grep -i umask /etc/bash.bashrc 2>/dev/null'
capture pacnew_list.txt    bash -c 'find /etc -name "*.pacnew" -o -name "*.pacsave" 2>/dev/null | sort'
capture logrotate.txt      bash -c 'grep -vE "^\s*#|^\s*$" /etc/logrotate.conf; echo "### available"; ls /etc/logrotate.d/ 2>&1'
capture services_check.txt bash -c 'for s in sshd cups bluetooth nftables usbguard auditd apparmor tailscaled syncthing; do printf "%-12s " "$s"; systemctl is-enabled "$s" 2>&1; done'
capture syncthing_state.txt bash -c 'systemctl status syncthing --no-pager -l 2>&1 | head -15; echo "--- processes ---"; ps -eo user,pid,args 2>/dev/null | grep -i "[s]yncthing" || echo "(no syncthing process)"'

# ---- optional lynis ---------------------------------------------------------
if [ "$WITH_LYNIS" -eq 1 ] && command -v lynis >/dev/null 2>&1; then
  echo "[*] running lynis audit (this takes ~30s)"
  lynis audit system --quick \
        --logfile "$OUTDIR/lynis.log" \
        --report-file "$OUTDIR/lynis-report.dat" >/dev/null 2>&1 || true
fi

# ---- manifest + ownership ---------------------------------------------------
( cd "$OUTDIR" && sha256sum ./* > manifest.sha256 2>/dev/null || true )

owner="${SUDO_USER:-}"
if [ -n "$owner" ] && id "$owner" >/dev/null 2>&1; then
  chown -R "$owner:$owner" "$OUTDIR" 2>/dev/null || chown -R "$owner" "$OUTDIR" 2>/dev/null || true
fi
chmod -R a+rX "$OUTDIR" 2>/dev/null || true

echo "[*] done: $(find "$OUTDIR" -type f | wc -l) files in $OUTDIR"
