#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 xUltimateZerox0
#
# sanitize-evidence.py - produce a publishable, redacted evidence set from the
# raw gather-system-info.sh output. Raw evidence stays in sysinfo/ (local only);
# only this script's output is intended for the public repository.
#
# Usage: ./tools/sanitize-evidence.py [--input DIR] [--output DIR] [--lynis FILE]

import argparse
import datetime
import hashlib
import os
import re
import sys

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_DIR = os.path.dirname(REPO_DIR)

PUBLISH = [
    # ring 0
    "proc_cmdline.txt", "uname.txt", "os_release.txt", "grub_default.txt",
    "grub_password_check.txt", "grub_cfg_perm.txt", "boot_ls.txt",
    "boot_artifacts.txt", "mkinitcpio_conf.txt", "mkinitcpio_presets.txt",
    "sysctl_conf.txt", "sysctl_runtime.txt", "sysctl_checks.txt",
    "modprobe_all.txt", "modprobe_lib_list.txt", "lsmod.txt",
    "secureboot.txt", "tpm_pcrs.txt", "cryptsetup_luks.txt",
    "cryptenroll_list.txt", "crypttab.txt", "zram_swap.txt",
    "coredump_conf.txt", "limits_all.txt", "journal_sysctl.txt",
    "file_capabilities.txt", "setuid_files.txt", "ring0-verify.txt",
    # ring 1
    "pam_d_list.txt", "pam_system_auth.txt", "pam_system_auth_pacnew.txt",
    "pam_system_auth_bak.txt", "pwquality.txt", "faillock_conf.txt",
    "login_defs_filtered.txt", "sudoers_all.txt", "users.txt",
    "user_status.txt", "admin_groups.txt", "sshd_config.txt",
    "sshd_config_d.txt", "sshd_effective.txt", "sshd_state.txt",
    # ring 2
    "apparmor_status.txt", "apparmor_parser.conf", "apparmor_d_list.txt",
    "auditd_conf.txt", "auditd_state.txt", "audit_rules.txt",
    "auditctl_rules.txt", "aide_state.txt", "rkhunter_state.txt",
    "systemd_security.txt", "systemd_enabled.txt", "systemd_failed.txt",
    "systemd_timers.txt", "systemd_dropins.txt", "falco_nova_state.txt",
    "falco_conf.txt", "lynis_profile.txt",
    # ring 3
    "ufw_state.txt", "ufw_numbered.txt", "ufw_user_rules.txt", "nftables.txt",
    "nftables_conf.txt", "nftables_service.txt", "iptables.txt",
    "ss_tulpn.txt", "ss_summary.txt", "ip_addr.txt", "ip_route.txt",
    "resolv_conf.txt", "resolvectl.txt", "dnscrypt_config.txt",
    "dnscrypt_state.txt", "nm_conf.txt", "nm_dispatcher.txt", "tailscale_state.txt",
    # ring 4
    "fstab.txt", "findmnt.txt", "mount.txt", "lsblk.txt", "df.txt",
    "cryptsetup_status.txt", "usbguard_daemon.conf", "usbguard_rules.conf",
    "usbguard_state.txt", "efibootmgr.txt", "efi_boot_dir.txt",
    # ring 5
    "pacman_conf.txt", "pacman_updates.txt", "packages_security.txt",
    "compilers.txt", "compiler_perms.txt", "umask_files.txt",
    "pacnew_list.txt", "logrotate.txt", "services_check.txt",
    "syncthing_state.txt",
]

ALLOWED_IPV4 = {
    "127.0.0.1", "127.0.0.53", "127.0.1.1", "0.0.0.0", "255.255.255.255",
    "192.168.122.0", "192.168.122.1", "192.168.1.0", "100.64.0.0",
    "224.0.0.251", "239.255.255.250",
}

LEGEND = [
    "<MAC:n>          MAC address (stable index across all files)",
    "<UUID:n>         filesystem/LUKS/EFI UUID or GUID",
    "<IP4:n>          host-identifying IPv4 address",
    "<IP6:n>          IPv6 address",
    "<HOST>           workstation hostname",
    "<USER>/<USER2>   human usernames",
    "<OWNER>          real name / forge handle in account metadata",
    "<EMAIL:n>        email address",
    "<HEX32:n>        machine-id class 32-hex identifier",
    "<SERIAL>/<HASH>  USBGuard device serial / hash values",
    "<SYNCTHING_ID>   Syncthing device ID",
    "<SENSITIVE_FILE> audited sensitive filenames (vault/pcap/key material)",
    "<LAB_PATH>       pentest lab directory tree",
    "<TOOL>           local monitoring tool name (nova-*/vault-* scripts)",
    "<REDACTED>       free-form sensitive value (e.g. Lynis HostID)",
]


class Pools:
    def __init__(self):
        self.assigned = {}
        self.counters = {}

    def tag(self, kind, value):
        key = (kind, value)
        if key not in self.assigned:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.assigned[key] = "<%s:%d>" % (kind, self.counters[kind])
        return self.assigned[key]


def build_rules(pools):
    rules = []

    def add(pattern, repl, flags=0):
        rules.append((re.compile(pattern, flags), repl))

    add(r"\S*[Kk]ee[Pp]ass\S*", "<SENSITIVE_FILE>")
    add(r"\S*id_ed25519_target\S*", "<SENSITIVE_FILE>")
    add(r"\S*http-login_capture\S*", "<SENSITIVE_FILE>")
    add(r"\b\S+\.kdbx\b", "<SENSITIVE_FILE>")
    add(r"Raccolta/Pentest_Lab/\S+", "<LAB_PATH>")

    add(r'(?i)\b(serial|hash|parent-hash)\s+"[^"]*"',
        lambda m: '%s "<%s>"' % (m.group(1), "SERIAL" if m.group(1).lower() == "serial" else "HASH"))
    add(r"\b[A-Z0-9]{7}(?:-[A-Z0-9]{7}){7}\b", "<SYNCTHING_ID>")
    add(r"(?mi)^(HostID2?:\s*).*$", lambda m: m.group(1) + "<REDACTED>")

    add(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        lambda m: pools.tag("EMAIL", m.group(0)))
    add(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b",
        lambda m: pools.tag("MAC", m.group(0)))
    add(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b",
        lambda m: pools.tag("UUID", m.group(0)))
    add(r"\b[0-9a-f]{32}\b", lambda m: pools.tag("HEX32", m.group(0)))

    add(r"xUltimateZerox0?", "<OWNER>")
    add(r"Stefano Fiore", "<OWNER>")
    add(r"\bNova\b", "<HOST>")
    add(r"\bzero\b", "<USER>")
    add(r"\bgamer\b", "<USER2>")
    add(r"\bnova-(cdr|ids|ips|scan|vaultd-process|notify)\b", "<TOOL>")
    add(r"\bvault-(drop|extract)\b", "<TOOL>")
    add(r"/tmp/opencode/\S*", "<REDACTED>")
    add(r"\bgitcopy\b", "<TOOL>")

    def ipv4_repl(m):
        return m.group(0) if m.group(0) in ALLOWED_IPV4 else pools.tag("IP4", m.group(0))

    add(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", ipv4_repl)

    def ipv6_repl(m):
        return m.group(0) if m.group(0) in ("::1", "::") else pools.tag("IP6", m.group(0))

    add(r"\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){3,}\b", ipv6_repl)
    add(r"\b[0-9a-fA-F:]*::[0-9a-fA-F:]*\b", ipv6_repl)

    return rules


def sanitize(text, rules):
    for pattern, repl in rules:
        text = pattern.sub(repl, text)
    return text


def main():
    parser = argparse.ArgumentParser(description="Sanitize raw evidence for publication")
    parser.add_argument("--input", default=os.path.join(WORKSPACE_DIR, "sysinfo"))
    parser.add_argument("--output", default=os.path.join(REPO_DIR, "evidence"))
    parser.add_argument("--lynis", default=os.path.join(WORKSPACE_DIR, "lynis.log"))
    args = parser.parse_args()

    system_out = os.path.join(args.output, "system")
    os.makedirs(system_out, exist_ok=True)

    pools = Pools()
    rules = build_rules(pools)

    written = []
    raw_hashes = []
    source_dates = []

    for name in PUBLISH:
        src = os.path.join(args.input, name)
        if not os.path.isfile(src):
            print("  ! missing: %s" % name, file=sys.stderr)
            continue
        try:
            with open(src, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            print("  ! unreadable: %s (%s)" % (name, exc.strerror), file=sys.stderr)
            continue
        raw_hashes.append((name, hashlib.sha256(raw).hexdigest()))
        source_dates.append(os.path.getmtime(src))
        text = raw.decode("utf-8", errors="replace")
        out_path = os.path.join(system_out, name)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(sanitize(text, rules))
        written.append(os.path.join("system", name))

    lynis_published = False
    if os.path.isfile(args.lynis):
        with open(args.lynis, "rb") as fh:
            raw = fh.read()
        raw_hashes.append((os.path.basename(args.lynis), hashlib.sha256(raw).hexdigest()))
        source_dates.append(os.path.getmtime(args.lynis))
        text = raw.decode("utf-8", errors="replace")
        with open(os.path.join(args.output, "lynis-baseline.log"), "w", encoding="utf-8") as fh:
            fh.write(sanitize(text, rules))
        written.append("lynis-baseline.log")
        lynis_published = True

    manifest_lines = ["# sha256  sanitized file"]
    for rel in sorted(written):
        path = os.path.join(args.output, rel)
        with open(path, "rb") as fh:
            manifest_lines.append("%s  %s" % (hashlib.sha256(fh.read()).hexdigest(), rel))
    manifest_lines.append("")
    manifest_lines.append("# sha256  raw source file (kept local in sysinfo/)")
    for name, digest in sorted(raw_hashes):
        manifest_lines.append("%s  %s" % (digest, name))
    with open(os.path.join(args.output, "MANIFEST.sha256"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(manifest_lines) + "\n")

    capture_date = "unknown"
    if source_dates:
        capture_date = datetime.datetime.fromtimestamp(max(source_dates)).strftime("%Y-%m-%d %H:%M")

    kernel = "unknown"
    uname_path = os.path.join(args.input, "uname.txt")
    try:
        with open(uname_path, encoding="utf-8", errors="replace") as fh:
            kernel = fh.readline().strip() or "unknown"
    except OSError:
        pass

    meta = [
        "# Evidence Capture Metadata",
        "",
        "- Sanitized output generated: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "- Raw capture date: %s" % capture_date,
        "- Kernel at capture: %s" % sanitize(kernel, rules),
        "- Sanitized files: %d (system/)%s" % (len(written) - (1 if lynis_published else 0),
                                               " + lynis-baseline.log" if lynis_published else ""),
        "- Source: gather-system-info.sh output; raw evidence remains local and is never committed",
        "- Integrity: see MANIFEST.sha256 (sanitized outputs + raw source hashes)",
        "",
        "## Redaction legend",
        "",
    ] + ["- `%s`" % line for line in LEGEND]
    with open(os.path.join(args.output, "CAPTURE-META.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(meta) + "\n")

    print("[*] wrote %d sanitized files to %s" % (len(written), args.output))


if __name__ == "__main__":
    main()
