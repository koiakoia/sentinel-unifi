#!/usr/bin/env python3
"""Talk-HPB DMZ: Create WAN port-forward rules + External→Dmz TURN inbound policies.

MUST only be run AFTER:
  1. 10-dmz-media.py (VLAN 20 + Dmz zone assignment + Dmz/Mgmt firewall policies)
  2. CT 120 has been moved to VLAN 20 by operator:
       On pve3: create eno1.20 + vmbr20 bridge, then
       pct set 120 -net0 name=eth0,bridge=vmbr20,ip=dhcp,firewall=1
  3. CT 120 confirmed at <INTERNAL_IP> (DHCP reservation by MAC <MAC>)
  4. coturn external-ip updated to the WAN public IP (07-post-dmz-move.sh)
  5. Team-lead has given explicit clearance

Creates:

  [STEP 6a] WAN port-forwards via classic API:
    TURN-STUN-UDP:   UDP 3478  → <INTERNAL_IP>:3478
    TURN-STUN-TCP:   TCP 3478  → <INTERNAL_IP>:3478
    TURNS-TLS:       TCP 5349  → <INTERNAL_IP>:5349
    TURN-Relay-UDP:  UDP 49160-49200 → <INTERNAL_IP>:49160

  [STEP 6b] External→Dmz ALLOW policies via integration API:
    "TURN inbound to media-server"       — Ext→Dmz dst=<INTERNAL_IP> ports=3478,5349
    "TURN relay inbound to media-server" — Ext→Dmz dst=<INTERNAL_IP> UDP range 49160-49200

    These are APPENDED to the External→Dmz beforeSystemDefined ordering list,
    AFTER the existing 10 IP-blocklist block rules. The system "Block All Traffic"
    default remains at the end (handled automatically by the system).

Usage:
    python3 11-dmz-portforward.py [--dry-run]
"""

import argparse
import json
import os
import sys
import urllib.request
import ssl

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient  # noqa: E402

CLASSIC_BASE = "https://<CONTROLLER_IP>/proxy/network/api/s/default"
DMZ_CT120_IP = "<INTERNAL_IP>"
DMZ_CT120_NAME = "media-server"
DMZ_CT120_MAC = "<MAC>"

# The system-defined "Dmz" zone (lowercase) — confirmed live
DMZ_ZONE_NAME = "Dmz"
DMZ_ZONE_ID = "2a2373fd-e81a-4399-9c49-5658eb41cab1"

PORTFORWARD_RULES = [
    {
        "name": "TURN-STUN-UDP",
        "proto": "udp",
        "dst_port": "3478",
        "fwd_port": "3478",
    },
    {
        "name": "TURN-STUN-TCP",
        "proto": "tcp",
        "dst_port": "3478",
        "fwd_port": "3478",
    },
    {
        "name": "TURNS-TLS",
        "proto": "tcp",
        "dst_port": "5349",
        "fwd_port": "5349",
    },
    {
        "name": "TURN-Relay-UDP",
        "proto": "udp",
        "dst_port": "49160-49200",   # classic API range format: hyphen, NOT colon
        "fwd_port": "49160-49200",   # must match dst_port range for port-range forwarding
    },
]


def make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def classic_api(method, path, data=None, api_key=None):
    url = f"{CLASSIC_BASE}/{path}"
    body = json.dumps(data).encode() if data else None
    headers = {"Accept": "application/json", "X-API-Key": api_key}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    ctx = make_ssl_ctx()
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            content = r.read()
            return r.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read()
        return e.code, json.loads(content) if content else {}


def verify_ct120_in_dmz(client, site_id):
    """Check that CT 120's MAC is getting a 192.168.20.x IP (VLAN 20)."""
    print("\n--- Verifying CT 120 is in VLAN 20 (DMZ-media) ---")
    clients = client.list_clients(site_id)
    for c in clients:
        mac = c.get("macAddress", "").lower()
        if mac == DMZ_CT120_MAC:
            ip = c.get("ipAddress", "?")
            if ip.startswith("192.168.20."):
                print(f"  OK: CT 120 ({mac}) has VLAN 20 IP: {ip}")
                return True
            else:
                print(f"  WARN: CT 120 ({mac}) has IP {ip} — expected 192.168.20.x")
                print(f"  Has the operator created eno1.20+vmbr20 and attached CT120?")
                return False
    print(f"  WARN: CT 120 MAC ({DMZ_CT120_MAC}) not found in connected clients")
    print(f"  CT 120 may be offline or not yet moved to VLAN 20")
    return False


def create_portforward_rules(dry_run, api_key):
    """Create port-forward rules in UniFi via classic API."""
    print("\n[STEP 6a] Create WAN port-forward rules")

    status, resp = classic_api("GET", "rest/portforward", api_key=api_key)
    if status != 200:
        print(f"  ERROR: Could not get port-forwards: status={status}", file=sys.stderr)
        sys.exit(1)
    existing = resp.get("data", [])
    existing_names = {pf.get("name") for pf in existing}
    print(f"  Existing port-forwards: {len(existing)}")

    created = 0
    skipped = 0
    errors = 0

    for rule in PORTFORWARD_RULES:
        name = rule["name"]
        if name in existing_names:
            print(f"  SKIP: Port-forward '{name}' already exists")
            skipped += 1
            continue

        payload = {
            "name": name,
            "enabled": True,
            "proto": rule["proto"],
            "dst_port": rule["dst_port"],
            "fwd": DMZ_CT120_IP,
            "fwd_port": rule["fwd_port"],
            "src": "any",
            "log": False,
            "pfwd_interface": "wan",
        }

        if dry_run:
            print(f"  DRY RUN: '{name}' {rule['proto'].upper()} WAN:{rule['dst_port']} "
                  f"→ {DMZ_CT120_IP}:{rule['fwd_port']}")
        else:
            print(f"  Creating: '{name}' {rule['proto'].upper()} WAN:{rule['dst_port']} "
                  f"→ {DMZ_CT120_IP}:{rule['fwd_port']}...")
            status2, resp2 = classic_api("POST", "rest/portforward", payload, api_key=api_key)
            if status2 in (200, 201):
                pf_data = resp2.get("data", [{}])
                if isinstance(pf_data, list) and pf_data:
                    pf_id = pf_data[0].get("_id", "?")
                else:
                    pf_id = pf_data.get("_id", "?") if isinstance(pf_data, dict) else "?"
                print(f"    Created: id={pf_id}")
                created += 1
            else:
                print(f"    ERROR: status={status2} response={resp2}", file=sys.stderr)
                errors += 1

    print(f"\n  Summary: {created} created, {skipped} skipped, {errors} errors")
    return errors == 0


def create_turn_inbound_policies(dry_run, client, site_id):
    """Create External→Dmz ALLOW policies for inbound TURN traffic to CT 120.

    These are placed AFTER the existing 10 IP-blocklist rules in the
    External→Dmz beforeSystemDefined ordering, but BEFORE the system
    "Block All Traffic" default (which is always system-defined).

    Ordering logic:
    1. GET current External→Dmz beforeSystemDefined list
    2. Create new ALLOW policies
    3. PUT updated ordering = existing_blocklist + [new_policy_1, new_policy_2]
    """
    print("\n[STEP 6b] Create External→Dmz TURN inbound firewall policies")

    zones = client.list_firewall_zones(site_id)
    zone_map = {z.get("name"): (z.get("id") or z.get("_id")) for z in zones}

    ext_zone_id = zone_map.get("External")
    dmz_zone_id = zone_map.get(DMZ_ZONE_NAME)  # "Dmz" (lowercase, system-defined)

    if not ext_zone_id:
        print("  ERROR: 'External' zone not found!", file=sys.stderr)
        return False
    if not dmz_zone_id:
        print(f"  ERROR: '{DMZ_ZONE_NAME}' zone not found! Run 10-dmz-media.py first.",
              file=sys.stderr)
        return False

    print(f"  External zone: {ext_zone_id}")
    print(f"  Dmz zone:      {dmz_zone_id}")

    # Fetch current External→Dmz ordering (has 10 IP-blocklist rules)
    import urllib.request as urllib_req
    import json as _json

    current_before = []
    if not dry_run:
        try:
            resp = client._get(
                f"/sites/{site_id}/firewall/policies/ordering",
                params={
                    "sourceFirewallZoneId": ext_zone_id,
                    "destinationFirewallZoneId": dmz_zone_id,
                }
            )
            current_before = resp.get("orderedFirewallPolicyIds", {}).get("beforeSystemDefined", [])
            print(f"  Current External→Dmz beforeSystemDefined: {len(current_before)} rules (IP blocklist)")
        except Exception as e:
            print(f"  WARNING: Could not fetch current ordering: {e}", file=sys.stderr)
            print(f"  Will set ordering with only new rules (existing blocklist ordering may shift)")

    # Policy definitions
    INBOUND_POLICIES = [
        {
            "name": "TURN inbound to media-server",
            "description": (
                "Allow inbound TURN/STUN traffic to CT 120 (media-server) — "
                "ports 3478 (STUN/TURN) and 5349 (TURNS/TLS) from internet"
            ),
            "src_zone": ext_zone_id,
            "dst_zone": dmz_zone_id,
            "dst_ip": DMZ_CT120_IP,
            "dst_ports": "3478,5349",
        },
        {
            "name": "TURN relay inbound to media-server",
            "description": (
                "Allow inbound TURN relay UDP to CT 120 (media-server) — "
                "UDP port range 49160-49200 (coturn relay ports)"
            ),
            "src_zone": ext_zone_id,
            "dst_zone": dmz_zone_id,
            "dst_ip": DMZ_CT120_IP,
            "dst_ports": "49160-49200",
        },
    ]

    # Check existing policies
    existing_policies = client.list_firewall_policies(site_id)
    existing_names = {p.get("name") for p in existing_policies}

    # Pre-seed IDs for existing policies
    new_policy_ids = []
    for ep in existing_policies:
        if ep.get("name") in {p["name"] for p in INBOUND_POLICIES}:
            new_policy_ids.append(ep.get("id") or ep.get("_id"))

    created = 0
    skipped = 0
    errors = 0

    for pol in INBOUND_POLICIES:
        name = pol["name"]
        if name in existing_names:
            print(f"  SKIP: Policy '{name}' already exists")
            skipped += 1
            continue

        # Build payload
        port_items = []
        for p in pol["dst_ports"].split(","):
            p = p.strip()
            if "-" in p:
                start, stop = p.split("-", 1)
                port_items.append({
                    "type": "PORT_NUMBER_RANGE",
                    "start": int(start),
                    "stop": int(stop),
                })
            else:
                port_items.append({"type": "PORT_NUMBER", "value": int(p)})

        payload = {
            "name": name,
            "description": pol["description"],
            "enabled": True,
            "action": {"type": "ALLOW", "allowReturnTraffic": True},
            "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6"},
            "loggingEnabled": True,
            "source": {"zoneId": pol["src_zone"]},
            "destination": {
                "zoneId": pol["dst_zone"],
                "trafficFilter": {
                    "type": "IP_ADDRESS",
                    "ipAddressFilter": {
                        "type": "IP_ADDRESSES",
                        "matchOpposite": False,
                        "items": [{"type": "IP_ADDRESS", "value": pol["dst_ip"]}],
                    },
                    "portFilter": {
                        "type": "PORTS",
                        "matchOpposite": False,
                        "items": port_items,
                    },
                },
            },
        }

        if dry_run:
            print(f"  DRY RUN: '{name}' (ALLOW External→Dmz dst={pol['dst_ip']} "
                  f"ports={pol['dst_ports']})")
        else:
            try:
                result = client.create_firewall_policy(site_id, payload)
                pol_id = result.get("id") or result.get("_id", "?")
                new_policy_ids.append(pol_id)
                print(f"  Created: '{name}' id={pol_id}")
                created += 1
            except Exception as e:
                print(f"  ERROR creating '{name}': {e}", file=sys.stderr)
                errors += 1

    print(f"\n  Summary: {created} created, {skipped} skipped, {errors} errors")

    # Set External→Dmz ordering: existing IP-blocklist + new TURN ALLOW rules
    if not dry_run and new_policy_ids:
        full_before = current_before + [
            pid for pid in new_policy_ids if pid not in current_before
        ]
        print(f"\n  Setting External→Dmz ordering:")
        print(f"    beforeSystemDefined: {len(current_before)} existing + "
              f"{len(new_policy_ids)} TURN = {len(full_before)} total")
        try:
            client.set_firewall_policy_ordering(
                site_id,
                source_zone_id=ext_zone_id,
                dest_zone_id=dmz_zone_id,
                before_system=full_before,
                after_system=[],
            )
            print(f"    Ordering set successfully")
        except Exception as e:
            print(f"    WARNING: Could not set ordering: {e}", file=sys.stderr)

    return errors == 0


def verify_connectivity(label):
    import subprocess
    targets = {
        "pve3 (<INTERNAL_IP>)": "<INTERNAL_IP>",
        "controller (<CONTROLLER_IP>)": "<CONTROLLER_IP>",
        "workstation (<INTERNAL_IP>)": "<INTERNAL_IP>",
    }
    print(f"\n--- Connectivity check: {label} ---")
    failed = []
    for name, ip in targets.items():
        result = subprocess.run(["ping", "-c", "2", "-W", "2", ip], capture_output=True, text=True)
        ok = result.returncode == 0
        print(f"  {'OK' if ok else 'FAIL'}: {name}")
        if not ok:
            failed.append(name)
    if failed:
        print(f"  WARNING: CONNECTIVITY FAILURE: {failed}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Talk-HPB DMZ: Port-forwards + External→Dmz TURN inbound (Step 6)"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done")
    args = parser.parse_args()

    print("=" * 60)
    print("Talk-HPB DMZ: Port-Forward Rules + TURN Inbound (Step 6)")
    print("=" * 60)
    print(f"  Target: {DMZ_CT120_IP} ({DMZ_CT120_NAME})")
    print(f"  Dry-run: {args.dry_run}")
    print()
    print("PREREQUISITES (must be complete before running):")
    print("  [x] 10-dmz-media.py ran (VLAN 20 + Dmz zone + Dmz/Mgmt policies)")
    print("  [ ] Operator created eno1.20 + vmbr20 on pve3")
    print("  [ ] CT 120 net0 bridge=vmbr20, gets DHCP <INTERNAL_IP>")
    print("  [ ] coturn external-ip updated to WAN public IP (07-post-dmz-move.sh)")
    print("  [ ] Team-lead explicit clearance given")
    print()

    api_key = os.environ.get("UNIFI_API_KEY")
    if not api_key:
        import subprocess
        try:
            result = subprocess.run(
                ["vault", "kv", "get", "-field", "api_key", "secret/unifi"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                api_key = result.stdout.strip()
        except Exception:
            pass
    if not api_key:
        print("ERROR: UNIFI_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = UniFiClient.from_env()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        sys.exit(1)
    site_id = sites[0].get("_id") or sites[0].get("id")

    # Verify CT 120 is in VLAN 20 before proceeding
    if not args.dry_run:
        ct120_ok = verify_ct120_in_dmz(client, site_id)
        if not ct120_ok:
            print("\nWARNING: CT 120 does not appear to be on VLAN 20 yet.")
            print("Continue anyway? [y/N]: ", end="", flush=True)
            ans = input().strip().lower()
            if ans != "y":
                print("Aborted.")
                sys.exit(0)

    # STEP 6a: Create WAN port-forward rules
    ok1 = create_portforward_rules(args.dry_run, api_key)

    if not args.dry_run and not verify_connectivity("after port-forwards"):
        print("WARNING: Connectivity check failed after port-forwards!", file=sys.stderr)

    # STEP 6b: Create External→Dmz TURN inbound firewall policies
    ok2 = create_turn_inbound_policies(args.dry_run, client, site_id)

    if not args.dry_run and not verify_connectivity("after External→Dmz TURN rules"):
        print("WARNING: Connectivity check failed after TURN rules!", file=sys.stderr)

    print("\n" + "=" * 60)
    if args.dry_run:
        print("DRY RUN COMPLETE")
    elif ok1 and ok2:
        print("STEP 6 COMPLETE")
        print()
        print("Verify external TURN from outside the LAN:")
        print("  stunclient <WAN_PUBLIC_IP> 3478")
        print("  turnutils_uclient -y -n 1 -u test -w test <WAN_PUBLIC_IP>")
        print("  # Expect: ERROR 401 (auth rejection = server reached, good)")
    else:
        print("COMPLETED WITH ERRORS — check above")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
