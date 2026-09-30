# CachyOS Enterprise Hardening - Network Perimeter (UFW)

This document outlines the host-based firewall architecture enforced via UFW (Uncomplicated Firewall / nftables backend). 

## Architectural Philosophy
The network perimeter is designed around **Interface Binding** and **Strict Segmentation**. Services are never exposed to `0.0.0.0/0`. Instead, they are explicitly bound to the virtual interfaces (KVM/Tailscale) that require them. The architecture strictly isolates pentesting/development Virtual Machines from the physical Local Area Network (LAN).

## 1. Default Policies & Auditing
* **Incoming:** `DENY` (Zero-trust by default).
* **Outgoing:** `ALLOW` (Workstation standard).
* **Routing/Forwarding:** `DENY` (Prevents the host from acting as an unauthorized network gateway).
* **Logging:** `LOW` (Logs blocked packets to `syslog` for auditing without causing NVMe write-amplification).

## 2. Hypervisor Network Segmentation (KVM / libvirt)
Virtual machines operate on an isolated NAT bridge (`virbr0` / `192.168.122.0/24`).
* **DNS Binding:** DNS queries (53/TCP/UDP) are explicitly permitted **only** when originating from the VM subnet and entering via the `virbr0` interface.
* **DHCP DORA Process Handling:** 
  * A broadcast rule permits `0.0.0.0` to `255.255.255.255` (67/UDP) strictly on `virbr0` to allow initializing VMs to send DHCP Discover packets.
  * A targeted rule permits standard DHCP requests from the established `192.168.122.0/24` subnet to the gateway `192.168.122.1`.
* **Pivot Prevention (Routing):** 
  * Explicit `DENY FWD` rule blocks all traffic originating from the VMs (`virbr0`) destined for the physical LAN (`wlp4s0` / `192.168.1.0/24`). This contains malware or pentesting tools within the hypervisor, preventing lateral movement into the local network.
  * Explicit `ALLOW FWD` permits VMs to route traffic strictly out to the external Internet.

## 3. Overlay Network & Remote Access (Tailscale)
Administrative access relies on an encrypted overlay network, entirely hidden from the physical LAN.
* **Encrypted Transport:** UDP Port `41641` is permitted on the physical interface (`wlp4s0`, both IPv4 and IPv6) to facilitate direct, peer-to-peer WireGuard tunnels for Tailscale, reducing latency.
* **Obfuscated & Isolated SSH:** The SSH daemon (Port `45936/TCP`) is completely invisible to the physical LAN. UFW strictly binds SSH ingress to the `tailscale0` interface, and further restricts the source IP to the Tailscale CGNAT IP space (`100.64.0.0/10`).

## Summary of Active Ruleset

| Destination IP | Port/Proto | Interface | Source IP / Subnet | Purpose | Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `255.255.255.255` | 67/UDP | `virbr0` | `0.0.0.0` | DHCP Discover (Broadcast) | **ALLOW IN** |
| `192.168.122.1` | 67/UDP | `virbr0` | `192.168.122.0/24` | DHCP Request/Renew | **ALLOW IN** |
| `192.168.122.1` | 53/TCP,UDP| `virbr0` | `192.168.122.0/24` | DNS Resolution | **ALLOW IN** |
| `Anywhere` | 41641/UDP| `wlp4s0` | `Anywhere` (v4/v6) | Tailscale WireGuard Transport | **ALLOW IN** |
| `100.64.0.0/10` | 45936/TCP| `tailscale0` | `100.64.0.0/10` | Isolated SSH Administration | **ALLOW IN** |
| `192.168.1.0/24` | ALL | `wlp4s0` | `Anywhere` on `virbr0` | Prevent VM to LAN Pivoting | **DENY FWD** |
| `Anywhere` | ALL | `wlp4s0` | `192.168.122.0/24` on `virbr0` | Allow VM to WAN (Internet) | **ALLOW FWD** |