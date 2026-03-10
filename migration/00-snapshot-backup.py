#!/usr/bin/env python3
"""Phase 0: Pre-migration full state backup.

Saves complete UniFi controller state (networks, WiFi, zones, policies,
clients, devices) to a timestamped JSON file locally and uploads to MinIO
for disaster recovery.

Usage:
    python3 00-snapshot-backup.py [--output-dir DIR] [--skip-minio]
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient

from config import MINIO_BACKUP_BUCKET, MINIO_BACKUP_PREFIX


def collect_full_state(client, site_id):
    """Collect every API resource into a single dict."""
    snap = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "site_id": site_id,
        "migration_version": "1.0",
    }

    endpoints = [
        ("devices", lambda: client.list_devices(site_id)),
        ("clients", lambda: client.list_clients(site_id)),
        ("networks", lambda: client.list_networks(site_id)),
        ("wifi", lambda: client.list_wifi(site_id)),
        ("firewall_zones", lambda: client.list_firewall_zones(site_id)),
        ("firewall_policies", lambda: client.list_firewall_policies(site_id)),
        ("dns_policies", lambda: client.list_dns_policies(site_id)),
        ("acl_rules", lambda: client.list_acl_rules(site_id)),
        ("wans", lambda: client.list_wans(site_id)),
    ]

    for label, fn in endpoints:
        try:
            snap[label] = fn()
            print(f"  {label}: {len(snap[label])} items")
        except Exception as e:
            snap[label] = []
            print(f"  {label}: ERROR - {e}", file=sys.stderr)

    # Per-device stats
    device_stats = {}
    for dev in snap.get("devices", []):
        dev_id = dev.get("id") or dev.get("_id", "")
        if dev_id:
            try:
                device_stats[dev_id] = client.get_device_stats(site_id, dev_id)
            except Exception:
                device_stats[dev_id] = {}
    snap["device_stats"] = device_stats

    return snap


def upload_to_minio(filepath, bucket, prefix):
    """Upload backup file to MinIO using mc CLI."""
    object_name = f"{prefix}{os.path.basename(filepath)}"
    cmd = ["mc", "cp", filepath, f"sentinel/{bucket}/{object_name}"]
    print(f"\nUploading to MinIO: sentinel/{bucket}/{object_name}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print("  Upload successful")
            return True
        else:
            print(f"  Upload failed: {result.stderr}", file=sys.stderr)
            return False
    except FileNotFoundError:
        print("  mc CLI not found, skipping MinIO upload", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print("  Upload timed out", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Pre-migration UniFi state backup")
    parser.add_argument("--output-dir", default=".", help="Directory for backup file")
    parser.add_argument("--skip-minio", action="store_true", help="Skip MinIO upload")
    args = parser.parse_args()

    print("=" * 60)
    print("UniFi Migration - Phase 0: Pre-Migration Backup")
    print("=" * 60)

    client = UniFiClient.from_vault()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        return 1
    site_id = sites[0].get("_id") or sites[0].get("id")
    print(f"Site ID: {site_id}\n")

    print("Collecting full controller state...")
    snap = collect_full_state(client, site_id)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"migration-backup-{ts}.json"
    filepath = os.path.join(args.output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(snap, f, indent=2, default=str)
    print(f"\nBackup written to: {filepath}")

    # Summary
    total_items = sum(
        len(snap.get(k, []))
        for k in ["devices", "clients", "networks", "wifi",
                   "firewall_zones", "firewall_policies", "dns_policies", "acl_rules"]
    )
    print(f"Total items backed up: {total_items}")

    if not args.skip_minio:
        upload_to_minio(filepath, MINIO_BACKUP_BUCKET, MINIO_BACKUP_PREFIX)

    print(f"\nBackup complete. Use this file with 99-rollback.py if needed:")
    print(f"  python3 99-rollback.py {filename}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
