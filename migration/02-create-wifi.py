#!/usr/bin/env python3
"""Phase 1b: Create WiFi SSIDs for new VLANs.

Creates sentinel-home (VLAN 50), sentinel-iot (VLAN 100), and
sentinel-guest (VLAN 200) WiFi broadcasts. Existing SSIDs (Casterly Rock,
UniFi Identity, iot) are left untouched.

PSKs are read from Vault at secret/unifi/wifi. If the Vault path doesn't
exist yet, generates random PSKs and prints them for manual storage.

Usage:
    python3 02-create-wifi.py [--dry-run]
"""

import argparse
import json
import os
import secrets
import string
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient

from config import VLANS, WIFI_SSIDS, WIFI_VAULT_PATH


def generate_psk(length=24):
    """Generate a random WiFi PSK."""
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def load_psks_from_vault():
    """Load WiFi PSKs from Vault. Returns dict or None."""
    psks = {}
    for ssid_cfg in WIFI_SSIDS.values():
        field = ssid_cfg["vault_psk_field"]
        try:
            result = subprocess.run(
                ["vault", "kv", "get", "-field", field, WIFI_VAULT_PATH],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                psks[field] = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if len(psks) == len(WIFI_SSIDS):
        return psks
    return None


def resolve_network_id(client, site_id, vlan_id):
    """Find the network ID for a given VLAN ID."""
    networks = client.list_networks(site_id)
    for n in networks:
        if n.get("vlanId") == vlan_id:
            return n.get("id") or n.get("_id")
    return None


def build_wifi_payload(ssid_cfg, psk, network_id):
    """Build the UniFi API payload for creating a WiFi broadcast."""
    payload = {
        "name": ssid_cfg["name"],
        "enabled": True,
        "security": ssid_cfg["security"],
        "networkId": network_id,
    }

    if ssid_cfg["security"] in ("wpa2", "wpa3"):
        payload["wpaMode"] = ssid_cfg["security"]
        payload["xPassphrase"] = psk

    # Band configuration
    if ssid_cfg["band"] == "2.4":
        payload["bandSteeringMode"] = "off"
        payload["wlanBand"] = "2g"
    elif ssid_cfg["band"] == "5":
        payload["bandSteeringMode"] = "off"
        payload["wlanBand"] = "5g"
    else:
        payload["wlanBand"] = "both"

    return payload


def main():
    parser = argparse.ArgumentParser(description="Create WiFi SSIDs")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created")
    args = parser.parse_args()

    print("=" * 60)
    print("UniFi Migration - Phase 1b: Create WiFi SSIDs")
    print("=" * 60)

    client = UniFiClient.from_vault()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        return 1
    site_id = sites[0].get("_id") or sites[0].get("id")

    # Load PSKs from Vault
    print("\nLoading WiFi PSKs from Vault...")
    psks = load_psks_from_vault()
    if psks:
        print("  PSKs loaded from Vault")
    else:
        print("  PSKs not found in Vault, generating new ones")
        psks = {}
        for ssid_cfg in WIFI_SSIDS.values():
            field = ssid_cfg["vault_psk_field"]
            psks[field] = generate_psk()

        print("\n  Store these PSKs in Vault before running without --dry-run:")
        print(f"  vault kv put {WIFI_VAULT_PATH} \\")
        for i, (field, psk) in enumerate(psks.items()):
            end = " \\" if i < len(psks) - 1 else ""
            print(f"    {field}='{psk}'{end}")
        print()

        if not args.dry_run:
            print("ERROR: PSKs must be stored in Vault first.", file=sys.stderr)
            print("  Run with --dry-run to generate candidate PSKs and the vault command.", file=sys.stderr)
            print(f"  Then: vault kv put {WIFI_VAULT_PATH} personal_psk=... iot_psk=... guest_psk=...", file=sys.stderr)
            return 1

    # Get existing WiFi to avoid duplicates
    existing_wifi = client.list_wifi(site_id)
    existing_names = {w.get("name") for w in existing_wifi}

    print(f"\nExisting WiFi SSIDs: {len(existing_wifi)}")
    for w in existing_wifi:
        print(f"  - {w.get('name', '?')} (security={w.get('security', '?')}, enabled={w.get('enabled')})")

    print()
    created = 0
    skipped = 0

    for key, ssid_cfg in WIFI_SSIDS.items():
        name = ssid_cfg["name"]
        vlan_key = ssid_cfg["vlan_key"]
        vlan_id = VLANS[vlan_key]["vlan_id"]
        psk_field = ssid_cfg["vault_psk_field"]

        if name in existing_names:
            print(f"SKIP: SSID '{name}' already exists")
            skipped += 1
            continue

        # Resolve the network ID for this VLAN
        network_id = resolve_network_id(client, site_id, vlan_id)
        if not network_id:
            print(f"ERROR: No network found for VLAN {vlan_id}. Run 01-create-vlans.py first",
                  file=sys.stderr)
            return 1

        payload = build_wifi_payload(ssid_cfg, psks[psk_field], network_id)

        if args.dry_run:
            # Mask the PSK in dry-run output
            display_payload = {**payload}
            if "xPassphrase" in display_payload:
                display_payload["xPassphrase"] = "****"
            print(f"DRY RUN: Would create SSID '{name}'")
            print(f"  VLAN: {vlan_id}, Network ID: {network_id}")
            print(f"  Security: {ssid_cfg['security']}, Band: {ssid_cfg['band']}")
            print(f"  Payload: {json.dumps(display_payload, indent=4)}")
        else:
            print(f"Creating SSID '{name}' (VLAN {vlan_id}, {ssid_cfg['security']})...")
            try:
                result = client.create_wifi(site_id, payload)
                wifi_id = result.get("id") or result.get("_id", "?")
                print(f"  Created: ID={wifi_id}")
                created += 1
            except Exception as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                return 1

    print(f"\nSummary: {created} created, {skipped} skipped")

    if not args.dry_run and created > 0:
        print("\nVerifying...")
        wifi_list = client.list_wifi(site_id)
        for w in wifi_list:
            if w.get("name") in [s["name"] for s in WIFI_SSIDS.values()]:
                print(f"  OK: {w.get('name')} (enabled={w.get('enabled')})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
