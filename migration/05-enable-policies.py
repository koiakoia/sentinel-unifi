#!/usr/bin/env python3
"""Phase 4: Interactive incremental firewall policy enablement.

Enables firewall policies one at a time in a safe order, running health
checks after each. Prompts for confirmation before each enable.

Usage:
    python3 05-enable-policies.py [--auto] [--skip-health]
"""

import argparse
import os
import socket
import sys
import time

import requests
import urllib3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient

from config import POLICY_ENABLE_ORDER, HEALTH_CHECKS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_health_checks():
    """Run post-enable health checks. Returns (passed, failed) counts."""
    passed = 0
    failed = 0

    for name, check in HEALTH_CHECKS.items():
        if "url" in check:
            try:
                resp = requests.get(check["url"], verify=False, timeout=10)
                if resp.status_code == check.get("expect_status", 200):
                    print(f"    PASS: {name} (HTTP {resp.status_code})")
                    passed += 1
                else:
                    print(f"    FAIL: {name} (HTTP {resp.status_code}, expected {check['expect_status']})")
                    failed += 1
            except requests.RequestException as e:
                print(f"    FAIL: {name} ({e})")
                failed += 1
        elif "host" in check:
            try:
                sock = socket.create_connection(
                    (check["host"], check["port"]), timeout=10
                )
                sock.close()
                print(f"    PASS: {name} (port {check['port']} open)")
                passed += 1
            except (socket.timeout, OSError) as e:
                print(f"    FAIL: {name} ({e})")
                failed += 1

    return passed, failed


def find_policy_by_name(policies, name):
    """Find a policy dict by name."""
    for p in policies:
        if p.get("name") == name:
            return p
    return None


def enable_policy(client, site_id, policy):
    """Enable a single firewall policy."""
    policy_id = policy.get("id") or policy.get("_id")
    return client.update_firewall_policy(site_id, policy_id, {"enabled": True})


def disable_policy(client, site_id, policy):
    """Disable a single firewall policy (rollback)."""
    policy_id = policy.get("id") or policy.get("_id")
    return client.update_firewall_policy(site_id, policy_id, {"enabled": False})


def main():
    parser = argparse.ArgumentParser(description="Enable firewall policies incrementally")
    parser.add_argument("--auto", action="store_true",
                        help="Skip confirmation prompts (still runs health checks)")
    parser.add_argument("--skip-health", action="store_true",
                        help="Skip health checks after each enable")
    parser.add_argument("--continue-on-fail", action="store_true",
                        help="In auto mode, continue to next policy after health check failure")
    parser.add_argument("--start-from", type=str, default=None,
                        help="Start from this policy name (skip earlier ones)")
    parser.add_argument("--skip-policy", type=str, action="append", default=[],
                        help="Skip specific policy by name (repeatable)")
    args = parser.parse_args()

    print("=" * 60)
    print("UniFi Migration - Phase 4: Enable Firewall Policies")
    print("=" * 60)
    print()

    client = UniFiClient.from_vault()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        return 1
    site_id = sites[0].get("_id") or sites[0].get("id")

    # Pre-flight health check
    print("Pre-flight health check:")
    passed, failed = run_health_checks()
    if failed > 0:
        print(f"\nWARNING: {failed} health check(s) failed before starting")
        if not args.auto:
            resp = input("Continue anyway? [y/N]: ").strip().lower()
            if resp != "y":
                print("Aborted")
                return 1
    print()

    # Load current policies
    policies = client.list_firewall_policies(site_id)

    # Filter to our migration policies
    skip = bool(args.start_from)
    enabled_count = 0

    for policy_name in POLICY_ENABLE_ORDER:
        if skip:
            if policy_name == args.start_from:
                skip = False
            else:
                print(f"SKIP (--start-from): {policy_name}")
                continue

        if policy_name in args.skip_policy:
            print(f"SKIP (--skip-policy): {policy_name}")
            continue

        policy = find_policy_by_name(policies, policy_name)

        if not policy:
            print(f"NOT FOUND: {policy_name} (run 04-create-firewall-policies.py first)")
            continue

        if policy.get("enabled"):
            print(f"ALREADY ENABLED: {policy_name}")
            continue

        print(f"\n--- Enabling: {policy_name} ---")
        print(f"  Action: {policy.get('action', '?')}")
        desc = policy.get("description", "")
        if desc:
            print(f"  Description: {desc}")

        # Safety gate: block rules that isolate VLANs require manual
        # cross-VLAN validation that automated health checks cannot do
        # (health checks run from management network, not the target VLAN).
        if policy_name == "Personal-Block-Mgmt":
            print()
            print("  *** MANUAL VALIDATION REQUIRED ***")
            print("  Before enabling this rule, verify from a VLAN 50 device:")
            print("    nslookup <SERVICE>.example.com <HOST_IP>")
            print("    curl -sk https://<SERVICE>.example.com")
            print("  If either fails, the allow rules have a payload bug.")
            print("  This check cannot be automated from the management network.")
            resp = input("  Confirmed working from VLAN 50? [y/N/q(uit)]: ").strip().lower()
            if resp == "q":
                print("\nStopped by user")
                break
            if resp != "y":
                print(f"  Skipped (run with --start-from 'Personal-Block-Mgmt' to resume)")
                continue
        elif not args.auto:
            resp = input(f"  Enable '{policy_name}'? [y/N/q(uit)]: ").strip().lower()
            if resp == "q":
                print("\nStopped by user")
                break
            if resp != "y":
                print(f"  Skipped")
                continue

        try:
            enable_policy(client, site_id, policy)
            print(f"  ENABLED")
            enabled_count += 1
        except Exception as e:
            print(f"  ERROR enabling: {e}", file=sys.stderr)
            continue

        # Health check after enable
        if not args.skip_health:
            print("  Running health checks...")
            time.sleep(2)  # Brief pause for policy to take effect
            passed, failed = run_health_checks()

            if failed > 0:
                print(f"\n  HEALTH CHECK FAILED after enabling '{policy_name}'!")
                print(f"  Rolling back...")
                try:
                    disable_policy(client, site_id, policy)
                    print(f"  ROLLED BACK: {policy_name} disabled")
                except Exception as e:
                    print(f"  ROLLBACK ERROR: {e}", file=sys.stderr)

                if not args.auto:
                    resp = input("  Continue with next policy? [y/N]: ").strip().lower()
                    if resp != "y":
                        break
                elif not args.continue_on_fail:
                    print("  Stopping due to health check failure in auto mode")
                    print("  Use --continue-on-fail to skip past failures, or")
                    print(f"  --skip-policy '{policy_name}' to bypass this rule")
                    return 1
                else:
                    print(f"  Continuing (--continue-on-fail). '{policy_name}' was rolled back.")

    print(f"\nDone. {enabled_count} policies enabled.")
    print("\nFinal health check:")
    run_health_checks()

    return 0


if __name__ == "__main__":
    sys.exit(main())
