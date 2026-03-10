#!/usr/bin/env python3
"""Phase 1a: Create VLAN networks.

Creates Personal (VLAN 50), IoT (VLAN 100), and Guest (VLAN 200) networks
on the UniFi controller. Existing traffic is unaffected -- this is purely
additive.

Usage:
    python3 01-create-vlans.py [--dry-run]
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient

from config import VLANS, FIREWALL_ZONES


def resolve_zone_id(client, site_id, vlan_key):
    """Find the firewall zone ID for a given VLAN key."""
    if vlan_key not in FIREWALL_ZONES:
        return None
    target_name = FIREWALL_ZONES[vlan_key]
    zones = client.list_firewall_zones(site_id)
    for z in zones:
        if z.get("name") == target_name:
            return z.get("id") or z.get("_id")
    return None


def build_network_payload(vlan_cfg, zone_id=None):
    """Build the UniFi Integration API v1 payload for creating a VLAN network.

    Integration API v1 uses a different schema from the classic API:
    - management: "GATEWAY" (required)
    - ipv4Configuration with nested dhcpConfiguration
    - Boolean flags for internet, mDNS, cellular, isolation
    """
    # Parse subnet into host IP and prefix length
    subnet = vlan_cfg["subnet"]  # e.g. "192.168.10.0/24"
    prefix = int(subnet.split("/")[1])

    dhcp_cfg = {
        "mode": "SERVER",
        "ipAddressRange": {
            "start": vlan_cfg["dhcp_start"],
            "stop": vlan_cfg["dhcp_stop"],
        },
        "leaseTimeSeconds": 86400,
        "pingConflictDetectionEnabled": True,
    }

    # Set custom DNS servers if specified
    if vlan_cfg.get("dns"):
        dhcp_cfg["dnsServerIpAddressesOverride"] = vlan_cfg["dns"]

    payload = {
        "name": vlan_cfg["name"],
        "vlanId": vlan_cfg["vlan_id"],
        "management": "GATEWAY",
        "enabled": True,
        "internetAccessEnabled": True,
        "mdnsForwardingEnabled": False,
        "cellularBackupEnabled": False,
        "isolationEnabled": False,
        "ipv4Configuration": {
            "autoScaleEnabled": False,
            "hostIpAddress": vlan_cfg["gateway"],
            "prefixLength": prefix,
            "dhcpConfiguration": dhcp_cfg,
        },
    }

    if zone_id:
        payload["zoneId"] = zone_id

    return payload


def main():
    parser = argparse.ArgumentParser(description="Create VLAN networks")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created")
    args = parser.parse_args()

    print("=" * 60)
    print("UniFi Migration - Phase 1a: Create VLANs")
    print("=" * 60)

    client = UniFiClient.from_vault()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        return 1
    site_id = sites[0].get("_id") or sites[0].get("id")

    # Get existing networks to avoid duplicates
    existing = client.list_networks(site_id)
    existing_vlans = {n.get("vlanId") for n in existing}
    existing_names = {n.get("name") for n in existing}

    print(f"\nExisting networks: {len(existing)}")
    for n in existing:
        print(f"  - {n.get('name', '?')} (VLAN {n.get('vlanId', 'N/A')})")

    print()
    created = 0
    skipped = 0

    for key, vlan_cfg in VLANS.items():
        vlan_id = vlan_cfg["vlan_id"]
        name = vlan_cfg["name"]

        if vlan_id in existing_vlans:
            print(f"SKIP: VLAN {vlan_id} ({name}) already exists")
            skipped += 1
            continue

        if name in existing_names:
            print(f"SKIP: Network named '{name}' already exists")
            skipped += 1
            continue

        zone_id = resolve_zone_id(client, site_id, key)
        payload = build_network_payload(vlan_cfg, zone_id)

        if args.dry_run:
            print(f"DRY RUN: Would create {name} (VLAN {vlan_id})")
            print(f"  Subnet: {vlan_cfg['subnet']}")
            print(f"  DHCP: {vlan_cfg['dhcp_start']} - {vlan_cfg['dhcp_stop']}")
            print(f"  DNS: {vlan_cfg.get('dns') or 'UCG built-in'}")
            print(f"  Zone: {zone_id or 'NONE'}")
            print(f"  Payload: {json.dumps(payload, indent=4)}")
        else:
            print(f"Creating: {name} (VLAN {vlan_id}, {vlan_cfg['subnet']})...")
            try:
                result = client.create_network(site_id, payload)
                net_id = result.get("id") or result.get("_id", "?")
                print(f"  Created: ID={net_id}")
                created += 1
            except Exception as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                return 1

    print(f"\nSummary: {created} created, {skipped} skipped")

    if not args.dry_run and created > 0:
        print("\nVerifying...")
        networks = client.list_networks(site_id)
        for n in networks:
            vlan_id = n.get("vlanId")
            if vlan_id in [v["vlan_id"] for v in VLANS.values()]:
                print(f"  OK: {n.get('name')} (VLAN {vlan_id})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
