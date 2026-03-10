#!/usr/bin/env python3
"""Phase 1d: Create firewall policies (all DISABLED).

Creates all inter-VLAN firewall policies defined in config.py. Every policy
is created with enabled=False. The 05-enable-policies.py script enables
them incrementally with verification after each.

Usage:
    python3 04-create-firewall-policies.py [--dry-run]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient

from config import FIREWALL_POLICIES, FIREWALL_ZONES


def resolve_zone_id(zones, zone_name):
    """Find zone ID by name from FIREWALL_ZONES config mapping.

    Maps config keys (e.g. "management") to display names (e.g. "Management"),
    then finds the zone ID. Falls back to direct name match.
    """
    # If zone_name is a config key, resolve to display name
    display_name = FIREWALL_ZONES.get(zone_name, zone_name)

    for z in zones:
        if z.get("name") == display_name:
            return z.get("id") or z.get("_id")

    # Fallback: case-insensitive match
    for z in zones:
        if z.get("name", "").lower() == zone_name.lower():
            return z.get("id") or z.get("_id")
    return None


def build_policy_payload(policy_def, zones):
    """Build a UniFi Integration API v1 firewall policy payload.

    Integration API v1 policy schema:
      action: {type: "ALLOW"|"BLOCK", allowReturnTraffic: bool}
      source: {zoneId: "...", trafficFilter: {...}}
      destination: {zoneId: "...", trafficFilter: {...}}
      ipProtocolScope: {ipVersion: "IPV4_AND_IPV6"}
    """
    # Action mapping: config uses ALLOW/DROP, API uses ALLOW/BLOCK
    action_map = {"ALLOW": "ALLOW", "DROP": "BLOCK", "REJECT": "BLOCK"}
    action_type = action_map.get(policy_def["action"], "BLOCK")

    payload = {
        "name": policy_def["name"],
        "description": policy_def.get("description", ""),
        "enabled": False,
        "action": {
            "type": action_type,
        },
        "ipProtocolScope": {
            "ipVersion": "IPV4_AND_IPV6",
        },
        "loggingEnabled": False,
    }

    if action_type == "ALLOW":
        payload["action"]["allowReturnTraffic"] = True

    # --- Source ---
    source = {}
    if "source_zone" in policy_def:
        zone_id = resolve_zone_id(zones, policy_def["source_zone"])
        if zone_id:
            source["zoneId"] = zone_id
        else:
            print(f"  WARNING: Zone '{policy_def['source_zone']}' not found", file=sys.stderr)

    # --- Destination ---
    destination = {}
    if "destination_zone" in policy_def:
        zone_id = resolve_zone_id(zones, policy_def["destination_zone"])
        if zone_id:
            destination["zoneId"] = zone_id
        else:
            print(f"  WARNING: Zone '{policy_def['destination_zone']}' not found", file=sys.stderr)

    # IP-based destination filter
    if "destination_ip" in policy_def:
        ip_items = []
        for ip in policy_def["destination_ip"].split(","):
            ip = ip.strip()
            ip_items.append({"type": "IP_ADDRESS", "value": ip})

        ip_filter = {
            "type": "IP_ADDRESS",
            "ipAddressFilter": {
                "type": "IP_ADDRESSES",
                "matchOpposite": False,
                "items": ip_items,
            },
        }

        # Port filter is nested inside the trafficFilter
        if "destination_port" in policy_def:
            port_items = []
            for port in policy_def["destination_port"].split(","):
                port = port.strip()
                port_items.append({"type": "PORT_NUMBER", "value": int(port)})
            ip_filter["portFilter"] = {
                "type": "PORTS",
                "matchOpposite": False,
                "items": port_items,
            }

        destination["trafficFilter"] = ip_filter
    elif "destination_port" in policy_def:
        # Port-only filter (no IP)
        port_items = []
        for port in policy_def["destination_port"].split(","):
            port = port.strip()
            port_items.append({"type": "PORT_NUMBER", "value": int(port)})
        destination["trafficFilter"] = {
            "type": "PORT",
            "portFilter": {
                "type": "PORTS",
                "matchOpposite": False,
                "items": port_items,
            },
        }

    payload["source"] = source
    payload["destination"] = destination

    return payload


def main():
    parser = argparse.ArgumentParser(description="Create firewall policies (disabled)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created")
    args = parser.parse_args()

    print("=" * 60)
    print("UniFi Migration - Phase 1d: Create Firewall Policies")
    print("=" * 60)
    print("NOTE: All policies are created DISABLED")
    print()

    client = UniFiClient.from_vault()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        return 1
    site_id = sites[0].get("_id") or sites[0].get("id")

    # Get existing zones for ID resolution
    zones = client.list_firewall_zones(site_id)
    print(f"Available zones: {', '.join(z.get('name', '?') for z in zones)}")

    # Get existing policies to avoid duplicates
    existing_policies = client.list_firewall_policies(site_id)
    existing_names = {p.get("name") for p in existing_policies}

    print(f"Existing policies: {len(existing_policies)}")
    print()

    created = 0
    skipped = 0
    errors = 0

    for policy_def in FIREWALL_POLICIES:
        name = policy_def["name"]

        if name in existing_names:
            print(f"SKIP: Policy '{name}' already exists")
            skipped += 1
            continue

        payload = build_policy_payload(policy_def, zones)

        if args.dry_run:
            print(f"DRY RUN: Would create policy '{name}'")
            print(f"  Action: {policy_def['action']}")
            src = policy_def.get("source_zone", "any")
            dst = policy_def.get("destination_zone",
                                 policy_def.get("destination_ip", "any"))
            print(f"  Source: {src} -> Destination: {dst}")
            if "destination_port" in policy_def:
                print(f"  Ports: {policy_def['destination_port']}")
            print(f"  Payload: {json.dumps(payload, indent=4)}")
        else:
            src = policy_def.get("source_zone", "any")
            dst = policy_def.get("destination_zone",
                                 policy_def.get("destination_ip", "any"))
            print(f"Creating: '{name}' ({policy_def['action']} {src} -> {dst})...")
            try:
                result = client.create_firewall_policy(site_id, payload)
                policy_id = result.get("id") or result.get("_id", "?")
                print(f"  Created: ID={policy_id} (DISABLED)")
                created += 1
            except Exception as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                errors += 1

    print(f"\nSummary: {created} created, {skipped} skipped, {errors} errors")

    if not args.dry_run and created > 0:
        print("\nAll new policies are DISABLED. Enable them with:")
        print("  python3 05-enable-policies.py")

    return 1 if errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
