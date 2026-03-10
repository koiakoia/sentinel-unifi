#!/usr/bin/env python3
"""Phase 1c: Create/update firewall zones for new VLANs.

Ensures firewall zones exist for Management, Personal, IoT, Guest, and DMZ.
Maps each zone to its corresponding VLAN network. Existing zones are left
untouched if they already match.

Usage:
    python3 03-create-firewall-zones.py [--dry-run]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient

from config import FIREWALL_ZONES, VLANS, EXISTING_VLANS


def resolve_network_id(client, site_id, zone_key):
    """Find the network ID for a given zone key."""
    networks = client.list_networks(site_id)

    # Check new VLANs first
    if zone_key in VLANS:
        target_vlan = VLANS[zone_key]["vlan_id"]
        for n in networks:
            if n.get("vlanId") == target_vlan:
                return n.get("id") or n.get("_id")

    # Check existing VLANs
    if zone_key in EXISTING_VLANS:
        target_vlan = EXISTING_VLANS[zone_key]["vlan_id"]
        for n in networks:
            if n.get("vlanId") == target_vlan:
                return n.get("id") or n.get("_id")
            # VLAN 1 (default) may not have explicit vlanId
            if target_vlan == 1 and not n.get("vlanId") and n.get("purpose") == "corporate":
                return n.get("id") or n.get("_id")

    return None


def build_zone_payload(zone_name, network_id):
    """Build the UniFi API payload for a firewall zone."""
    payload = {
        "name": zone_name,
        "networkIds": [network_id] if network_id else [],
    }
    return payload


def main():
    parser = argparse.ArgumentParser(description="Create firewall zones")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created")
    args = parser.parse_args()

    print("=" * 60)
    print("UniFi Migration - Phase 1c: Create Firewall Zones")
    print("=" * 60)

    client = UniFiClient.from_vault()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        return 1
    site_id = sites[0].get("_id") or sites[0].get("id")

    # Get existing zones
    existing_zones = client.list_firewall_zones(site_id)
    existing_names = {z.get("name"): z for z in existing_zones}

    print(f"\nExisting firewall zones: {len(existing_zones)}")
    for z in existing_zones:
        zone_id = z.get("id") or z.get("_id", "")
        print(f"  - {z.get('name', '?')} (id={zone_id})")

    print()
    created = 0
    skipped = 0

    for zone_key, zone_name in FIREWALL_ZONES.items():
        if zone_name in existing_names:
            print(f"SKIP: Zone '{zone_name}' already exists")
            skipped += 1
            continue

        network_id = resolve_network_id(client, site_id, zone_key)

        payload = build_zone_payload(zone_name, network_id)

        if args.dry_run:
            print(f"DRY RUN: Would create zone '{zone_name}'")
            print(f"  Network ID: {network_id or 'N/A'}")
            print(f"  Payload: {json.dumps(payload, indent=4)}")
        else:
            print(f"Creating zone '{zone_name}'...")
            try:
                result = client.create_firewall_zone(site_id, payload)
                zone_id = result.get("id") or result.get("_id", "?")
                print(f"  Created: ID={zone_id}")
                created += 1
            except Exception as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                return 1

    print(f"\nSummary: {created} created, {skipped} skipped")

    if not args.dry_run and created > 0:
        print("\nVerifying...")
        zones = client.list_firewall_zones(site_id)
        for z in zones:
            if z.get("name") in FIREWALL_ZONES.values():
                zone_id = z.get("id") or z.get("_id", "")
                print(f"  OK: {z.get('name')} (id={zone_id})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
