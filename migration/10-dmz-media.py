#!/usr/bin/env python3
"""Talk-HPB DMZ: Create VLAN 20 (DMZ-media) + assign to Dmz zone + firewall policies.

Creates the DMZ-media VLAN for CT 120 (media-server) isolation:
  - VLAN 20 named "DMZ-media" on <INTERNAL_IP>/24
  - DHCP reservation: <MAC> → <INTERNAL_IP> (media-server)
  - Assigns VLAN 20 to the existing system "Dmz" zone (2a2373fd)
    NOTE: "Dmz" is the SYSTEM_DEFINED zone. Do NOT use/create the
    user-defined "DMZ" zone (36bff359) — it is empty and should be cleaned up.
  - Trunks UCG-Fiber port 6 (SFP+1 — pve3's eno1 uplink) to carry VLAN 20 tagged
    (additive — keeps VLAN 1 native, does not disturb existing trunk VLANs)
  - Firewall policies (ENABLED immediately — all scoped to 192.168.20.x, safe):

    Dmz→Management:
      ALLOW <INTERNAL_IP>/32 → <INTERNAL_IP>/32 tcp/443  (media-server → NC backend)
      [NO explicit DENY needed — system "Block All Traffic" is default]

    Management→Dmz:
      ALLOW any → <INTERNAL_IP>/32 tcp/22               (SSH management)
      [NO explicit DENY needed — system "Block All Traffic" is default]

    Dmz→External:
      [NO restriction added — system "Allow All Traffic" is default]
      Reason: TURN relay requires unrestricted outbound UDP to arbitrary
      client ports. Restricting to 443/53/123 would break relay entirely.
      The 10 existing IP-blocklist rules on Dmz→External already block
      known bad actors.

    External→Dmz (TURN inbound):
      These are created in Step 6 (11-dmz-portforward.py) together with
      the WAN port-forward rules, after CT 120 is moved to VLAN 20.

pve3-side (operator runs after VLAN trunk is confirmed):
  Do NOT use vmbr0-vlan-aware (risky — reconfigures the main platform bridge).
  Instead use the safe ADDITIVE pattern that matches eno2.30/Storage VLAN:
    On pve3<SERVICE>.example.com:
      Create eno1.20 VLAN subinterface + new vmbr20 bridge
      Attach CT120 net0 to bridge=vmbr20
  See STEP 3 output for exact /etc/network/interfaces stanza.

SAFETY: All rules scoped to 192.168.20.x. No rule touches <INTERNAL_IP>/24.
Operator workstation (<INTERNAL_IP>), pve3 (.57), controller (.1) unaffected.

Usage:
    python3 10-dmz-media.py [--dry-run] [--vlan-id N] [--skip-port-trunk]
"""

import argparse
import json
import os
import sys
import urllib.request
import ssl

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unifi import UniFiClient  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# DMZ network config
DMZ_VLAN_NAME = "DMZ-media"
DMZ_VLAN_ID_DEFAULT = 20
DMZ_SUBNET_HOST = "<INTERNAL_IP>"    # gateway IP
DMZ_SUBNET_PREFIX = 24
DMZ_SUBNET_CIDR = "<INTERNAL_IP>/24"
DMZ_DHCP_START = "<INTERNAL_IP>"
DMZ_DHCP_STOP = "<INTERNAL_IP>"
DMZ_CT120_MAC = "<MAC>"
DMZ_CT120_IP = "<INTERNAL_IP>"
DMZ_CT120_NAME = "media-server"

# Existing "Dmz" system zone — DO NOT CREATE a new zone
# ID confirmed from live API: system-defined, has 20 user IP-blocklist policies
DMZ_ZONE_NAME = "Dmz"
DMZ_ZONE_ID = "2a2373fd-e81a-4399-9c49-5658eb41cab1"

# Target hosts
NC_BACKEND_IP = "<INTERNAL_IP>"    # CT 110 Nextcloud
LAN_SUBNET = "<INTERNAL_IP>/24"      # management LAN

# UCG-Fiber device (classic API _id) + port where pve3's eno1 is connected
# Confirmed via LLDP: eno1 MAC <MAC> = UCG port 6 (SFP+1)
UCG_DEVICE_ID_CLASSIC = "68780ac0fb283555ee7accd2"
UCG_PVE3_PORT_IDX = 6               # SFP+1 confirmed via LLDP

# Classic API base
CLASSIC_BASE = "https://<CONTROLLER_IP>/proxy/network/api/s/default"

# Default VLAN 1 classic networkconf ID (for port_overrides native VLAN)
DEFAULT_NETCONF_CLASSIC_ID = "6743935803b9543f7e31e025"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def classic_api(method, path, data=None, api_key=None):
    """Hit the classic UniFi API (/proxy/network/api/s/default/...)."""
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


def verify_connectivity(label):
    """Quick connectivity check — ping management plane hosts."""
    import subprocess
    targets = {
        "pve3 (<INTERNAL_IP>)": "<INTERNAL_IP>",
        "controller (<CONTROLLER_IP>)": "<CONTROLLER_IP>",
        "workstation (<INTERNAL_IP>)": "<INTERNAL_IP>",
    }
    print(f"\n--- Connectivity check: {label} ---")
    failed = []
    for name, ip in targets.items():
        result = subprocess.run(
            ["ping", "-c", "2", "-W", "2", ip],
            capture_output=True, text=True
        )
        ok = result.returncode == 0
        status = "OK" if ok else "FAIL"
        print(f"  {status}: {name}")
        if not ok:
            failed.append(name)
    if failed:
        print(f"\n  WARNING: CONNECTIVITY FAILURE: {failed}")
        print("  Consider rollback: python3 99-rollback.py <backup-file>")
        return False
    print("  All management hosts reachable.")
    return True


# ---------------------------------------------------------------------------
# Step 1: Create DMZ-media VLAN (classic API for DHCP reservation support)
# ---------------------------------------------------------------------------

def create_dmz_vlan(vlan_id, dry_run, api_key, client, site_id):
    """Create the DMZ-media VLAN network using the classic API.

    Returns the integration API network ID (needed for zone assignment).
    """
    print(f"\n[STEP 1] Create DMZ-media VLAN {vlan_id} ({DMZ_SUBNET_CIDR})")

    # Check if VLAN already exists in the integration API
    networks = client.list_networks(site_id)
    for n in networks:
        if n.get("vlanId") == vlan_id:
            existing_name = n.get("name", "?")
            if existing_name == DMZ_VLAN_NAME:
                net_id = n.get("id") or n.get("_id")
                print(f"  SKIP: VLAN {vlan_id} '{DMZ_VLAN_NAME}' already exists (id={net_id})")
                return net_id
            else:
                print(f"  ERROR: VLAN {vlan_id} already exists as '{existing_name}' — CONFLICT!")
                print(f"  Cannot create '{DMZ_VLAN_NAME}' with same VLAN ID.")
                print(f"  Use --vlan-id to choose a different VLAN ID, or delete the existing network.")
                sys.exit(1)
        if n.get("name") == DMZ_VLAN_NAME:
            net_id = n.get("id") or n.get("_id")
            print(f"  SKIP: Network '{DMZ_VLAN_NAME}' already exists (id={net_id})")
            return net_id

    # Build classic API networkconf payload.
    # NOTE: dhcpd_reservations field is silently IGNORED by this UniFi version.
    # Fixed IP is set separately after creation via set_fixed_ip_reservation().
    payload = {
        "name": DMZ_VLAN_NAME,
        "vlan": vlan_id,
        "vlan_enabled": True,
        "purpose": "corporate",
        "networkgroup": "LAN",
        "ip_subnet": f"{DMZ_SUBNET_HOST}/{DMZ_SUBNET_PREFIX}",
        "dhcpd_enabled": True,
        "dhcpd_start": DMZ_DHCP_START,
        "dhcpd_stop": DMZ_DHCP_STOP,
        "dhcpd_leasetime": 86400,
        "dhcpd_dns_enabled": False,
        "dhcpd_gateway_enabled": False,
    }

    if dry_run:
        print(f"  DRY RUN: Would create VLAN {vlan_id} '{DMZ_VLAN_NAME}'")
        print(f"    Subnet: {DMZ_SUBNET_CIDR}, gateway: {DMZ_SUBNET_HOST}")
        print(f"    DHCP: {DMZ_DHCP_START} - {DMZ_DHCP_STOP}")
        print(f"    Fixed IP (via rest/user): {DMZ_CT120_MAC} → {DMZ_CT120_IP}")
        return "DRY-RUN-NET-ID"

    print(f"  Creating VLAN {vlan_id} '{DMZ_VLAN_NAME}' via classic API...")
    status, resp = classic_api("POST", "rest/networkconf", payload, api_key)
    if status not in (200, 201):
        print(f"  ERROR: status={status} response={resp}", file=sys.stderr)
        sys.exit(1)

    net_data = resp.get("data", [{}])
    if isinstance(net_data, list):
        net_data = net_data[0] if net_data else {}
    net_id_classic = net_data.get("_id", "?")
    print(f"  Created via classic API: classic_id={net_id_classic}")

    # Set fixed IP reservation for CT120 (dhcpd_reservations POST field is ignored)
    set_fixed_ip_reservation(api_key)

    # Fetch integration API ID (needed for zone assignment)
    networks = client.list_networks(site_id)
    for n in networks:
        if n.get("vlanId") == vlan_id and n.get("name") == DMZ_VLAN_NAME:
            net_id_integ = n.get("id") or n.get("_id")
            print(f"  Integration API id: {net_id_integ}")
            return net_id_integ

    print(f"  WARNING: Could not find integration API id; using classic id as fallback.")
    return net_id_classic


def set_fixed_ip_reservation(api_key):
    """Set CT120 fixed IP via rest/user (dhcpd_reservations field is ignored by API).

    UniFi API quirk: dhcpd_reservations in networkconf POST is silently dropped.
    The correct approach: find the existing user record by MAC and set
    use_fixedip=True + fixed_ip. Works even before CT120 has connected to the
    new VLAN (since the MAC already exists in the user DB from prior connections).
    """
    print(f"  [DHCP] Setting fixed IP {DMZ_CT120_IP} for {DMZ_CT120_MAC} via rest/user...")

    # Find user record by MAC
    status, r = classic_api("GET", "rest/user", api_key=api_key)
    user = next(
        (u for u in r.get("data", []) if u.get("mac", "").lower() == DMZ_CT120_MAC.lower()),
        None
    )

    if not user:
        print(f"  WARNING: User record for {DMZ_CT120_MAC} not found — CT120 may not have"
              f" connected to this controller yet.")
        print(f"  Set the fixed IP manually in the UI: Clients → {DMZ_CT120_MAC} → "
              f"Settings → Fixed IP → {DMZ_CT120_IP}")
        return

    uid = user.get("_id")
    if user.get("use_fixedip") and user.get("fixed_ip") == DMZ_CT120_IP:
        print(f"  SKIP: {DMZ_CT120_MAC} already has fixed IP {DMZ_CT120_IP}")
        return

    update = dict(user)
    update["use_fixedip"] = True
    update["fixed_ip"] = DMZ_CT120_IP
    update["name"] = DMZ_CT120_NAME

    status2, r2 = classic_api("PUT", f"rest/user/{uid}", update, api_key=api_key)
    if status2 == 200:
        data = r2.get("data", [{}])
        if isinstance(data, list):
            data = data[0] if data else {}
        print(f"  Fixed IP set: {data.get('mac')} → {data.get('fixed_ip')} "
              f"(use_fixedip={data.get('use_fixedip')})")
    else:
        print(f"  WARNING: Could not set fixed IP: status={status2} resp={r2}",
              file=sys.stderr)


# ---------------------------------------------------------------------------
# Step 2: Assign VLAN 20 to the existing system "Dmz" zone
# ---------------------------------------------------------------------------

def assign_to_dmz_zone(network_id, dry_run, client, site_id):
    """Assign the VLAN 20 network to the existing system 'Dmz' zone.

    API quirk (discovered live 2026-06-08):
    - PATCH /networks/{id} → 405 Method Not Allowed
    - PUT  /networks/{id} with 'id' in body → 400 (unknown property)
    - PATCH /firewall/zones/{id} → 405
    - PUT  /firewall/zones/{id} with only {networkIds: [...]} → 400 (name required)
    - PUT  /firewall/zones/{id} with {name: "Dmz", networkIds: [net_id]} → 200 ✓

    Correct method: update_firewall_zone() with name + networkIds.
    Also need to remove the network from its previous zone (auto-assigned to
    Internal on creation).
    """
    print(f"\n[STEP 2] Assign VLAN 20 network to existing '{DMZ_ZONE_NAME}' zone")

    if dry_run:
        print(f"  DRY RUN: Would PUT firewall/zones/{DMZ_ZONE_ID} "
              f"{{name: '{DMZ_ZONE_NAME}', networkIds: ['{network_id}']}}")
        return DMZ_ZONE_ID

    # Verify the Dmz zone still exists (sanity check)
    zones = client.list_firewall_zones(site_id)
    zone_map_by_name = {z.get("name"): z for z in zones}

    if DMZ_ZONE_NAME not in zone_map_by_name:
        print(f"  ERROR: '{DMZ_ZONE_NAME}' zone not found! Zones: {list(zone_map_by_name.keys())}",
              file=sys.stderr)
        sys.exit(1)

    dmz_zone = zone_map_by_name[DMZ_ZONE_NAME]
    confirmed_zone_id = dmz_zone.get("id") or dmz_zone.get("_id")

    # Check if already assigned
    if network_id in dmz_zone.get("networkIds", []):
        print(f"  SKIP: Network already in '{DMZ_ZONE_NAME}' zone networkIds")
        return confirmed_zone_id

    # Find and update the previous zone: remove this network from its current zone
    for z in zones:
        zid = z.get("id") or z.get("_id")
        nets = z.get("networkIds", [])
        if zid != confirmed_zone_id and network_id in nets:
            updated_nets = [n for n in nets if n != network_id]
            print(f"  Removing network from previous zone '{z.get('name')}' (id={zid[:8]})")
            try:
                client.update_firewall_zone(site_id, zid, {
                    "name": z.get("name"),
                    "networkIds": updated_nets,
                })
            except Exception as e:
                print(f"  WARNING: Could not remove from previous zone: {e}")

    # Assign to Dmz zone
    result = client.update_firewall_zone(site_id, confirmed_zone_id, {
        "name": DMZ_ZONE_NAME,
        "networkIds": [network_id],
    })
    if result.get("id") or result.get("_id"):
        new_nets = result.get("networkIds", [])
        print(f"  Assigned: '{DMZ_ZONE_NAME}' zone networkIds = {new_nets}")
    else:
        print(f"  WARNING: Unexpected response from update_firewall_zone: {result}")

    return confirmed_zone_id


# ---------------------------------------------------------------------------
# Step 3: Trunk UCG-Fiber port 6 (pve3's eno1 uplink) for VLAN 20
# ---------------------------------------------------------------------------

def trunk_pve3_port(dry_run, api_key, vlan_id):
    """Add VLAN 20 as a tagged VLAN on UCG-Fiber port 6 (SFP+1, pve3's eno1 uplink).

    This is ADDITIVE — keeps VLAN 1 as native and preserves any existing
    tagged VLANs. Does not reconfigure the port profile.

    UCG-Fiber port 6 before: native=Default (VLAN 1), tagged=[]
    UCG-Fiber port 6 after:  native=Default (VLAN 1), tagged=[dmz_net_classic_id]
    """
    print(f"\n[STEP 3] Trunk UCG-Fiber port {UCG_PVE3_PORT_IDX} (pve3's eno1/SFP+1) for VLAN {vlan_id}")

    if dry_run:
        print(f"  DRY RUN: Would add VLAN {vlan_id} to UCG port {UCG_PVE3_PORT_IDX} tagged list")
        print(f"  pve3 (operator step): create eno1.{vlan_id} + vmbr{vlan_id} bridge")
        return

    # Look up the classic networkconf ID for DMZ-media
    status2, netconf = classic_api("GET", "rest/networkconf", api_key=api_key)
    if status2 != 200:
        print(f"  ERROR: Could not get networkconf: status={status2}", file=sys.stderr)
        print(f"  FLAG FOR OPERATOR: Manually trunk UCG port {UCG_PVE3_PORT_IDX} for VLAN {vlan_id}")
        return

    dmz_classic_id = None
    for n in netconf.get("data", []):
        if n.get("name") == DMZ_VLAN_NAME and n.get("vlan") == vlan_id:
            dmz_classic_id = n.get("_id")
            break

    if not dmz_classic_id:
        print(f"  ERROR: Could not find classic networkconf id for VLAN {vlan_id} '{DMZ_VLAN_NAME}'",
              file=sys.stderr)
        print(f"  FLAG FOR OPERATOR: Manually trunk UCG port {UCG_PVE3_PORT_IDX} for VLAN {vlan_id}")
        return

    print(f"  DMZ-media classic networkconf id: {dmz_classic_id}")

    # Get current UCG device config
    status, stat = classic_api("GET", "stat/device", api_key=api_key)
    if status != 200:
        print(f"  ERROR: Could not get stat/device: status={status}", file=sys.stderr)
        return

    ucg = next(
        (d for d in stat.get("data", []) if d.get("_id") == UCG_DEVICE_ID_CLASSIC),
        None
    )
    if not ucg:
        print(f"  ERROR: UCG-Fiber device not found (id={UCG_DEVICE_ID_CLASSIC})", file=sys.stderr)
        print(f"  FLAG FOR OPERATOR: Manually trunk UCG port {UCG_PVE3_PORT_IDX} for VLAN {vlan_id}")
        return

    # Find or build port override for port 6
    port_overrides = list(ucg.get("port_overrides", []))
    updated = False

    for po in port_overrides:
        if po.get("port_idx") == UCG_PVE3_PORT_IDX:
            tagged = list(po.get("tagged_networkconf_ids", []))
            if dmz_classic_id in tagged:
                print(f"  SKIP: Port {UCG_PVE3_PORT_IDX} already has VLAN {vlan_id} tagged")
                break
            tagged.append(dmz_classic_id)
            po["tagged_networkconf_ids"] = tagged
            print(f"  Appended {dmz_classic_id} to port {UCG_PVE3_PORT_IDX} tagged list (now: {tagged})")
            updated = True
            break
    else:
        # Port 6 not in overrides yet — add fresh override (additive)
        new_override = {
            "port_idx": UCG_PVE3_PORT_IDX,
            "portconf_id": "",
            "name": "SFP+ 1",
            "native_networkconf_id": DEFAULT_NETCONF_CLASSIC_ID,
            "tagged_networkconf_ids": [dmz_classic_id],
        }
        port_overrides.append(new_override)
        print(f"  Added port {UCG_PVE3_PORT_IDX} override with tagged=[{dmz_classic_id}]")
        updated = True

    if not updated:
        return  # already tagged, nothing to do

    # PUT updated device config
    print(f"  Updating UCG-Fiber device via classic API PUT...")
    status3, resp3 = classic_api(
        "PUT",
        f"rest/device/{UCG_DEVICE_ID_CLASSIC}",
        {"port_overrides": port_overrides},
        api_key=api_key,
    )
    if status3 in (200, 201):
        print(f"  UCG port {UCG_PVE3_PORT_IDX} trunk updated — VLAN {vlan_id} is now tagged.")
        print()
        print(f"  [OPERATOR — pve3 side, safe additive approach]")
        print(f"  Add to /etc/network/interfaces on pve3<SERVICE>.example.com:")
        print(f"")
        print(f"    auto eno1.{vlan_id}")
        print(f"    iface eno1.{vlan_id} inet manual")
        print(f"      vlan-raw-device eno1")
        print(f"")
        print(f"    auto vmbr{vlan_id}")
        print(f"    iface vmbr{vlan_id} inet manual")
        print(f"      bridge-ports eno1.{vlan_id}")
        print(f"      bridge-stp off")
        print(f"      bridge-fd 0")
        print(f"      bridge-vlan-aware no")
        print(f"")
        print(f"  Then bring up: ifup eno1.{vlan_id} && ifup vmbr{vlan_id}")
        print(f"  Then attach CT120: pct set 120 -net0 name=eth0,bridge=vmbr{vlan_id},ip=dhcp,firewall=1")
        print(f"  CT 120 should get DHCP <INTERNAL_IP> (reserved by MAC {DMZ_CT120_MAC})")
    else:
        print(f"  ERROR: status={status3} response={resp3}", file=sys.stderr)
        print(f"  FLAG FOR OPERATOR: Manually trunk UCG port {UCG_PVE3_PORT_IDX} for VLAN {vlan_id}")


# ---------------------------------------------------------------------------
# Step 4: Create firewall policies
# ---------------------------------------------------------------------------

def build_policy(name, description, action, enabled,
                 src_zone_id, dst_zone_id,
                 src_ip=None, dst_ip=None, dst_port=None,
                 logging=False):
    """Build an integration API v1 firewall policy payload.

    Supports single port ("443"), comma-separated ("443,80"), or
    range ("49160-49200") in dst_port.
    """
    action_type = "ALLOW" if action.upper() in ("ALLOW",) else "BLOCK"

    payload = {
        "name": name,
        "description": description,
        "enabled": enabled,
        "action": {"type": action_type},
        "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6"},
        "loggingEnabled": logging,
    }
    if action_type == "ALLOW":
        payload["action"]["allowReturnTraffic"] = True

    # Source
    source = {"zoneId": src_zone_id}
    if src_ip:
        source["trafficFilter"] = {
            "type": "IP_ADDRESS",
            "ipAddressFilter": {
                "type": "IP_ADDRESSES",
                "matchOpposite": False,
                "items": [{"type": "IP_ADDRESS", "value": src_ip}],
            },
        }
    payload["source"] = source

    # Destination
    destination = {"zoneId": dst_zone_id}

    ip_filter = None
    if dst_ip:
        ip_filter = {
            "type": "IP_ADDRESS",
            "ipAddressFilter": {
                "type": "IP_ADDRESSES",
                "matchOpposite": False,
                "items": [{"type": "IP_ADDRESS", "value": dst_ip}],
            },
        }

    port_filter = None
    if dst_port:
        port_items = []
        for p in str(dst_port).split(","):
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
        port_filter = {
            "type": "PORTS",
            "matchOpposite": False,
            "items": port_items,
        }

    if ip_filter or port_filter:
        traffic_filter = {}
        if ip_filter:
            traffic_filter["type"] = ip_filter["type"]
            traffic_filter["ipAddressFilter"] = ip_filter["ipAddressFilter"]
        if port_filter:
            traffic_filter["portFilter"] = port_filter
        destination["trafficFilter"] = traffic_filter

    payload["destination"] = destination
    return payload


def create_firewall_policies(dmz_zone_id, dry_run, client, site_id):
    """Create Dmz-zone firewall policies (2 user-defined ALLOWs).

    System 'Block All Traffic' defaults handle Dmz→Management and
    Management→Dmz deny-all — no explicit DENY user policies needed.

    External→Dmz TURN inbound rules are in 11-dmz-portforward.py (Step 6).
    """
    print(f"\n[STEP 4] Create firewall policies (Dmz zone)")

    zones = client.list_firewall_zones(site_id)
    zone_map = {z.get("name"): (z.get("id") or z.get("_id")) for z in zones}

    mgmt_zone_id = zone_map.get("Management")
    if not mgmt_zone_id:
        print("  ERROR: 'Management' zone not found!", file=sys.stderr)
        sys.exit(1)

    print(f"  Dmz zone:        {dmz_zone_id}")
    print(f"  Management zone: {mgmt_zone_id}")

    POLICIES = [
        # Dmz → Management: only media-server can reach NC backend on 443
        {
            "name": "media-server → NC backend",
            "description": "CT 120 (media-server TURN/signaling) → CT 110 (Nextcloud) backend HTTPS",
            "action": "ALLOW",
            "enabled": True,
            "src_zone": dmz_zone_id,
            "dst_zone": mgmt_zone_id,
            "src_ip": DMZ_CT120_IP,         # <INTERNAL_IP> only
            "dst_ip": NC_BACKEND_IP,         # <INTERNAL_IP> only
            "dst_port": "443",
            "logging": True,
        },
        # Management → Dmz: SSH access to media-server from management LAN
        {
            "name": "LAN SSH to media-server",
            "description": "LAN → CT 120 SSH (operator management + cert push from CT 110)",
            "action": "ALLOW",
            "enabled": True,
            "src_zone": mgmt_zone_id,
            "dst_zone": dmz_zone_id,
            "dst_ip": DMZ_CT120_IP,          # <INTERNAL_IP> only
            "dst_port": "22",
            "logging": False,
        },
    ]

    # Get existing policies to skip already-created ones
    existing_policies = client.list_firewall_policies(site_id)
    existing_names = {p.get("name") for p in existing_policies}

    created_ids = {}
    created = 0
    skipped = 0
    errors = 0

    # Pre-seed IDs for existing policies (for ordering step)
    for ep in existing_policies:
        if ep.get("name") in {p["name"] for p in POLICIES}:
            created_ids[ep.get("name")] = ep.get("id") or ep.get("_id")

    for p in POLICIES:
        name = p["name"]
        if name in existing_names:
            print(f"  SKIP: Policy '{name}' already exists")
            skipped += 1
            continue

        payload = build_policy(
            name=name,
            description=p["description"],
            action=p["action"],
            enabled=p["enabled"],
            src_zone_id=p["src_zone"],
            dst_zone_id=p["dst_zone"],
            src_ip=p.get("src_ip"),
            dst_ip=p.get("dst_ip"),
            dst_port=p.get("dst_port"),
            logging=p.get("logging", False),
        )

        src_label = "Dmz" if p["src_zone"] == dmz_zone_id else "Mgmt"
        dst_label = "Dmz" if p["dst_zone"] == dmz_zone_id else "Mgmt"

        if dry_run:
            port_info = f" :{p.get('dst_port','any')}" if p.get("dst_port") else ""
            src_ip_info = f" src={p['src_ip']}" if p.get("src_ip") else ""
            print(f"  DRY RUN: '{name}' (ALLOW {src_label}→{dst_label}{src_ip_info}{port_info})")
        else:
            try:
                result = client.create_firewall_policy(site_id, payload)
                pol_id = result.get("id") or result.get("_id", "?")
                created_ids[name] = pol_id
                port_info = f" :{p.get('dst_port','any')}" if p.get("dst_port") else ""
                print(f"  Created: '{name}' (ALLOW {src_label}→{dst_label}{port_info}) id={pol_id}")
                created += 1
            except Exception as e:
                print(f"  ERROR creating '{name}': {e}", file=sys.stderr)
                errors += 1

    print(f"\n  Summary: {created} created, {skipped} skipped, {errors} errors")

    if errors > 0:
        print("  WARNING: Some policies failed — check above", file=sys.stderr)
        return created_ids, False

    # Set policy ordering (user ALLOWs before system Block All Traffic)
    if not dry_run and (created > 0 or skipped > 0):
        set_policy_ordering(dmz_zone_id, mgmt_zone_id, created_ids, client, site_id)

    return created_ids, errors == 0


def set_policy_ordering(dmz_zone_id, mgmt_zone_id, policy_ids, client, site_id):
    """Place ALLOW rules in beforeSystemDefined for each zone pair.

    Dmz→Management: [media-server → NC backend] before system "Block All Traffic"
    Management→Dmz: [LAN SSH to media-server] before system "Block All Traffic"

    External→Dmz ordering is handled by 11-dmz-portforward.py (Step 6)
    because it must append after the 10 existing IP-blocklist rules.
    """
    print("\n  Setting policy ordering (beforeSystemDefined)...")

    pairs = [
        (
            dmz_zone_id, mgmt_zone_id, "Dmz→Management",
            ["media-server → NC backend"],
        ),
        (
            mgmt_zone_id, dmz_zone_id, "Management→Dmz",
            ["LAN SSH to media-server"],
        ),
    ]

    for src_z, dst_z, label, names in pairs:
        order = [policy_ids[n] for n in names if n in policy_ids and policy_ids[n]]
        if not order:
            print(f"    {label}: no policy IDs available, skipping")
            continue
        try:
            client.set_firewall_policy_ordering(
                site_id,
                source_zone_id=src_z,
                dest_zone_id=dst_z,
                before_system=order,
                after_system=[],
            )
            print(f"    {label}: beforeSystemDefined={order}")
        except Exception as e:
            print(f"    WARNING: Could not set ordering for {label}: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Talk-HPB DMZ: Create VLAN 20 (DMZ-media) + assign to Dmz zone + firewall"
    )
    parser.add_argument(
        "--vlan-id", type=int, default=DMZ_VLAN_ID_DEFAULT,
        help=f"VLAN ID (default: {DMZ_VLAN_ID_DEFAULT})"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be done without making any changes"
    )
    parser.add_argument(
        "--skip-port-trunk", action="store_true",
        help="Skip UCG-Fiber port 6 trunk update (do manually in UI)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("Talk-HPB DMZ: Create VLAN 20 + Zone Assignment + Firewall")
    print("=" * 60)
    print(f"  VLAN ID: {args.vlan_id}")
    print(f"  Subnet: {DMZ_SUBNET_CIDR}")
    print(f"  CT 120 reservation: {DMZ_CT120_MAC} → {DMZ_CT120_IP}")
    print(f"  Target zone: '{DMZ_ZONE_NAME}' (SYSTEM_DEFINED, existing)")
    print(f"  Dry-run: {args.dry_run}")
    print()

    # Get API key
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
        print("ERROR: UNIFI_API_KEY not set and Vault unavailable", file=sys.stderr)
        sys.exit(1)

    # Build integration API client
    client = UniFiClient.from_env()
    sites = client.list_sites()
    if not sites:
        print("ERROR: No sites found", file=sys.stderr)
        sys.exit(1)
    site_id = sites[0].get("_id") or sites[0].get("id")
    print(f"Site: {site_id}\n")

    # Baseline connectivity check
    if not args.dry_run:
        if not verify_connectivity("baseline — before any changes"):
            print("ERROR: Baseline connectivity check failed. Aborting.", file=sys.stderr)
            sys.exit(1)

    # STEP 1: Create VLAN 20 (classic API — supports DHCP reservations)
    net_id = create_dmz_vlan(args.vlan_id, args.dry_run, api_key, client, site_id)

    if not args.dry_run:
        if not verify_connectivity("after VLAN creation"):
            print("CRITICAL: Connectivity lost after VLAN creation. Investigate.", file=sys.stderr)
            sys.exit(1)

    # STEP 2: Assign VLAN 20 to existing "Dmz" system zone
    zone_id = assign_to_dmz_zone(net_id, args.dry_run, client, site_id)

    # STEP 3: Trunk UCG-Fiber port 6 (pve3's eno1 uplink)
    if not args.skip_port_trunk:
        trunk_pve3_port(args.dry_run, api_key, args.vlan_id)
        if not args.dry_run:
            if not verify_connectivity("after port trunk update"):
                print("CRITICAL: Connectivity lost after port trunk.", file=sys.stderr)
                sys.exit(1)
    else:
        print(f"\n[STEP 3] SKIPPED (--skip-port-trunk)")
        print(f"  Operator must manually trunk UCG port {UCG_PVE3_PORT_IDX} (SFP+1) for VLAN {args.vlan_id}")

    # STEP 4: Create firewall policies
    policy_ids, ok = create_firewall_policies(zone_id, args.dry_run, client, site_id)

    if not args.dry_run:
        if not verify_connectivity("after firewall policies"):
            print("CRITICAL: Connectivity lost after firewall policies!", file=sys.stderr)
            print("  Run: python3 99-rollback.py <backup-file>", file=sys.stderr)
            sys.exit(1)

    # Summary
    print("\n" + "=" * 60)
    if args.dry_run:
        print("DRY RUN COMPLETE — no changes made")
    elif ok:
        print("STEPS 1-4 COMPLETE")
        print(f"  VLAN {args.vlan_id} '{DMZ_VLAN_NAME}' created (<INTERNAL_IP>/24)")
        print(f"  Assigned to '{DMZ_ZONE_NAME}' zone")
        if not args.skip_port_trunk:
            print(f"  UCG-Fiber port {UCG_PVE3_PORT_IDX} trunked for VLAN {args.vlan_id}")
        print(f"  Firewall policies created and enabled")
        print()
        print("NEXT STEPS:")
        print("  [OPERATOR] Complete pve3 eno1.20 + vmbr20 bridge (see STEP 3 output above)")
        print("  [OPERATOR] Attach CT 120: pct set 120 -net0 name=eth0,bridge=vmbr20,ip=dhcp,firewall=1")
        print("  [CHECKPOINT] Verify CT 120 gets <INTERNAL_IP> — report to team-lead")
        print("  [THEN] Run 11-dmz-portforward.py (Step 6) after team-lead clearance")
    else:
        print("COMPLETED WITH ERRORS — check above")
        sys.exit(1)

    return 0


if __name__ == "__main__":
    sys.exit(main())
