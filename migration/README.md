# UniFi VLAN Segmentation Migration

Migration scripts for segmenting the flat <INTERNAL_IP>/24 network into
proper security zones using UniFi VLANs and firewall policies.

## Target Architecture

| VLAN | Name | Subnet | Purpose |
|------|------|--------|---------|
| 1 | Management | <INTERNAL_IP>/24 | Servers, Proxmox, iDRACs, network gear |
| 3 | Cluster | <INTERNAL_IP>/24 | OKD internal (no change) |
| 20 | DMZ | 192.168.20.0/24 | Future external-facing services |
| 50 | Personal | 192.168.50.0/24 | Personal devices (laptops, phones) |
| 100 | IoT | 192.168.100.0/24 | Smart home, cameras, TVs |
| 200 | Guest | 192.168.200.0/24 | Guest WiFi |

## Prerequisites

- **Management network access** -- scripts must run from iac-control or the
  WSL2 workstation (reachable via Tailscale on the management VLAN). All
  health checks verify management-plane services only. Cross-VLAN checks
  require a device on the target VLAN (see Phase 4 notes).
- UniFi API key in Vault at `secret/unifi`
- VAULT_ADDR and VAULT_TOKEN set (or run from iac-control)
- Python 3 with `requests` and `click` packages
- WiFi PSKs stored in Vault at `secret/unifi/wifi` (for Phase 1b)

## Migration Phases

### Phase 0: Pre-Migration Backup

```bash
sentinel-maintenance.sh enter --reason "Network segmentation" --scope remediation
python3 ./cli.py snapshot
python3 00-snapshot-backup.py
```

### Phase 1: Create VLANs + WiFi + Zones + Policies (LOW risk)

All additive. Existing traffic unaffected. Firewall policies created DISABLED.

```bash
python3 01-create-vlans.py --dry-run      # Review first
python3 01-create-vlans.py                 # Create VLANs
python3 02-create-wifi.py --dry-run        # Review first
python3 02-create-wifi.py                  # Create SSIDs
python3 03-create-firewall-zones.py        # Create zones
python3 04-create-firewall-policies.py     # Create policies (disabled)
```

### Phase 2: Migrate WiFi Devices (MEDIUM risk)

Manual process -- connect personal devices to `sentinel-home`, IoT to `sentinel-iot`.

### Phase 3: Migrate Wired Devices (MEDIUM risk)

Move personal wired devices to VLAN 50 via UniFi switch port profiles.

### Phase 4: Enable Firewall Policies (HIGH risk)

Interactive script enables policies one at a time with health checks.

**Important**: The automated health checks run from the management network and
can only verify management-plane services. Before enabling `Personal-Block-Mgmt`,
manually verify from a device on VLAN 50 (e.g. a laptop on sentinel-home):

```bash
# From a personal VLAN device -- these must work BEFORE enabling the block rule
nslookup <SERVICE>.example.com <HOST_IP>    # DNS via dnsmasq
curl -sk https://<SERVICE>.example.com            # Services via Traefik
```

If either fails, the allow rules have a payload bug. Fix before continuing.

```bash
python3 05-enable-policies.py              # Interactive mode
python3 05-enable-policies.py --auto       # Auto mode (still checks health)
python3 05-enable-policies.py --skip-policy 'Personal-Block-Mgmt'  # Skip specific rules
python3 05-enable-policies.py --auto --continue-on-fail  # Don't halt on flapping checks
```

### Phase 5: Cleanup

1. Delete disabled old firewall policies via UniFi UI
2. Fix stale DNS entries
3. Update NetBox, Grafana dashboards
4. Exit maintenance mode

## Rollback

```bash
# Standard rollback (preserves VLANs)
python3 99-rollback.py migration-backup-*.json

# Full rollback (deletes VLANs too)
python3 99-rollback.py migration-backup-*.json --delete-vlans

# Dry run
python3 99-rollback.py migration-backup-*.json --dry-run
```

## Emergency Access

If SSH to iac-control is lost:
1. Proxmox console: `https://<INTERNAL_IP>:8006` (VM 200)
2. UniFi UI: `https://<CONTROLLER_IP>` -- manually disable offending rules

## Known Risks

### Eero Mesh Nodes (VLAN 1)

The eero mesh nodes (.51/.97) stay on VLAN 1 (management). If personal or IoT
devices connect through the eeros to a VLAN-tagged SSID (sentinel-home,
sentinel-iot), the eeros must pass VLAN tags on their WiFi interfaces. Most
consumer mesh systems do NOT support VLAN tagging -- devices may silently
receive management VLAN IPs instead of the intended VLAN.

**Validate in Phase 2**: After connecting a personal device to `sentinel-home`
through an eero, check that it gets a 192.168.50.x address (not 192.168.12.x).
If it gets a management IP, the eeros are stripping VLAN tags and those devices
must connect through the UAP-AC-Pro instead. Do NOT enable any block rules
(Phase 4) until this is confirmed.

## Safety Guarantees

- Management (VLAN 1) always has unrestricted access
- Infrastructure IPs never change (no Ansible/Terraform/Traefik impact)
- All firewall policies created disabled, enabled incrementally
- Health checks after every policy enable with auto-rollback on failure
- Tailscale Pi stays on VLAN 1 (remote access preserved)

## Files

| File | Purpose |
|------|---------|
| `config.py` | Shared VLAN/WiFi/firewall definitions |
| `00-snapshot-backup.py` | Pre-migration full state backup |
| `01-create-vlans.py` | Create VLAN 50, 100, 200 |
| `02-create-wifi.py` | Create sentinel-home/iot/guest SSIDs |
| `03-create-firewall-zones.py` | Create firewall zones |
| `04-create-firewall-policies.py` | Create firewall policies (disabled) |
| `05-enable-policies.py` | Interactive policy enablement |
| `99-rollback.py` | Revert all changes |
