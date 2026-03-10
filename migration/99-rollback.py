#!/usr/bin/env python3
"""Rollback: Revert migration changes using a backup snapshot.

Disables new firewall policies, deletes new WiFi SSIDs, re-enables
old SSIDs if they were disabled. VLANs are left in place (harmless).

Usage:
    python3 99-rollback.py <backup-file.json> [--delete-vlans] [--dry-run]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient

from config import VLANS, WIFI_SSIDS, FIREWALL_POLICIES, FIREWALL_ZONES


def main():
    parser = argparse.ArgumentParser(description="Rollback migration changes")
    parser.add_argument("backup_file", help="Path to migration backup JSON file")
    parser.add_argument("--delete-vlans", action="store_true",
                        help="Also delete new VLANs (may disrupt reconnected devices)")
    parser.add_argument("--delete-zones", action="store_true",
                        help="Also delete migration firewall zones")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done")
    args = parser.parse_args()

    print("=" * 60)
    print("UniFi Migration - ROLLBACK")
    print("=" * 60)

    # Load backup
    if not os.path.exists(args.backup_file):
        print(f"ERROR: Backup file not found: {args.backup_file}", file=sys.stderr)
        return 1

    with open(args.backup_file) as f:
        backup = json.load(f)

    print(f"Backup timestamp: {backup.get('timestamp', 'unknown')}")
    print(f"Backup site_id: {backup.get('site_id', 'unknown')}")

    client = UniFiClient.from_vault()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        return 1
    site_id = sites[0].get("_id") or sites[0].get("id")

    # Verify site matches
    if backup.get("site_id") and backup["site_id"] != site_id:
        print(f"WARNING: Backup site_id ({backup['site_id']}) != current ({site_id})")
        resp = input("Continue anyway? [y/N]: ").strip().lower()
        if resp != "y":
            return 1

    errors = 0

    # --- Step 1: Disable new firewall policies ---
    print("\n--- Step 1: Disable migration firewall policies ---")
    current_policies = client.list_firewall_policies(site_id)
    migration_policy_names = {p["name"] for p in FIREWALL_POLICIES}

    for policy in current_policies:
        name = policy.get("name", "")
        if name not in migration_policy_names:
            continue

        policy_id = policy.get("id") or policy.get("_id")
        if not policy.get("enabled"):
            print(f"  Already disabled: {name}")
            continue

        if args.dry_run:
            print(f"  DRY RUN: Would disable policy '{name}'")
        else:
            print(f"  Disabling: {name}...")
            try:
                client.update_firewall_policy(site_id, policy_id, {"enabled": False})
                print(f"    Disabled")
            except Exception as e:
                print(f"    ERROR: {e}", file=sys.stderr)
                errors += 1

    # --- Step 2: Delete new WiFi SSIDs ---
    print("\n--- Step 2: Delete migration WiFi SSIDs ---")
    current_wifi = client.list_wifi(site_id)
    migration_ssid_names = {s["name"] for s in WIFI_SSIDS.values()}

    for wifi in current_wifi:
        name = wifi.get("name", "")
        if name not in migration_ssid_names:
            continue

        wifi_id = wifi.get("id") or wifi.get("_id")

        if args.dry_run:
            print(f"  DRY RUN: Would delete SSID '{name}'")
        else:
            print(f"  Deleting SSID '{name}'...")
            try:
                client.delete_wifi(site_id, wifi_id)
                print(f"    Deleted")
            except Exception as e:
                print(f"    ERROR: {e}", file=sys.stderr)
                errors += 1

    # --- Step 3: Re-enable old SSIDs if they were disabled ---
    print("\n--- Step 3: Re-enable original WiFi SSIDs ---")
    backup_wifi = backup.get("wifi", [])
    current_wifi = client.list_wifi(site_id)  # Refresh after deletions

    for backup_w in backup_wifi:
        backup_name = backup_w.get("name", "")
        backup_enabled = backup_w.get("enabled", True)

        if not backup_enabled:
            continue  # Was disabled before migration, leave it

        # Find in current state
        for current_w in current_wifi:
            if current_w.get("name") == backup_name and not current_w.get("enabled"):
                wifi_id = current_w.get("id") or current_w.get("_id")
                if args.dry_run:
                    print(f"  DRY RUN: Would re-enable SSID '{backup_name}'")
                else:
                    print(f"  Re-enabling SSID '{backup_name}'...")
                    try:
                        client.update_wifi(site_id, wifi_id, {"enabled": True})
                        print(f"    Re-enabled")
                    except Exception as e:
                        print(f"    ERROR: {e}", file=sys.stderr)
                        errors += 1

    # --- Step 4: Optionally delete new VLANs ---
    if args.delete_vlans:
        print("\n--- Step 4: Delete migration VLANs ---")
        current_networks = client.list_networks(site_id)
        migration_vlan_ids = {v["vlan_id"] for v in VLANS.values()}

        for net in current_networks:
            vlan_id = net.get("vlanId")
            if vlan_id not in migration_vlan_ids:
                continue

            net_id = net.get("id") or net.get("_id")
            name = net.get("name", "?")

            if args.dry_run:
                print(f"  DRY RUN: Would delete network '{name}' (VLAN {vlan_id})")
            else:
                print(f"  Deleting network '{name}' (VLAN {vlan_id})...")
                try:
                    client.delete_network(site_id, net_id)
                    print(f"    Deleted")
                except Exception as e:
                    print(f"    ERROR: {e}", file=sys.stderr)
                    errors += 1
    else:
        print("\n--- Step 4: VLANs left in place (use --delete-vlans to remove) ---")

    # --- Step 5: Delete migration firewall policies ---
    print("\n--- Step 5: Delete migration firewall policies ---")
    current_policies = client.list_firewall_policies(site_id)  # Refresh

    for policy in current_policies:
        name = policy.get("name", "")
        if name not in migration_policy_names:
            continue

        policy_id = policy.get("id") or policy.get("_id")

        if args.dry_run:
            print(f"  DRY RUN: Would delete policy '{name}'")
        else:
            print(f"  Deleting policy '{name}'...")
            try:
                client.delete_firewall_policy(site_id, policy_id)
                print(f"    Deleted")
            except Exception as e:
                print(f"    ERROR: {e}", file=sys.stderr)
                errors += 1

    # --- Step 6: Optionally delete migration firewall zones ---
    if args.delete_zones:
        print("\n--- Step 6: Delete migration firewall zones ---")
        current_zones = client.list_firewall_zones(site_id)
        # Only delete zones we created (match by name from config)
        # Preserve any pre-existing zones from the backup
        backup_zone_names = {z.get("name", "") for z in backup.get("firewall_zones", [])}
        migration_zone_names = set(FIREWALL_ZONES.values())

        for zone in current_zones:
            zone_name = zone.get("name", "")
            if zone_name not in migration_zone_names:
                continue
            if zone_name in backup_zone_names:
                print(f"  Preserving pre-existing zone: {zone_name}")
                continue

            zone_id = zone.get("id") or zone.get("_id")
            if args.dry_run:
                print(f"  DRY RUN: Would delete zone '{zone_name}'")
            else:
                print(f"  Deleting zone '{zone_name}'...")
                try:
                    client.delete_firewall_zone(site_id, zone_id)
                    print(f"    Deleted")
                except Exception as e:
                    print(f"    ERROR: {e}", file=sys.stderr)
                    errors += 1
    else:
        print("\n--- Step 6: Zones left in place (use --delete-zones to remove) ---")

    # --- Summary ---
    print(f"\n{'=' * 60}")
    if errors > 0:
        print(f"ROLLBACK COMPLETED WITH {errors} ERROR(S)")
        print("Check errors above and verify manually via UniFi UI")
    else:
        print("ROLLBACK COMPLETE")

    print("\nPost-rollback steps:")
    print("  1. Reconnect personal devices to original WiFi (Casterly Rock)")
    print("  2. Reconnect IoT devices to original WiFi")
    print("  3. Verify all services accessible")
    print("  4. Run: python3 ./cli.py snapshot")

    return 1 if errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
