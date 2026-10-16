"""Configuration for UniFi VLAN segmentation migration.

Customize this file for your environment before running migration scripts.
All VLAN definitions, client classifications, firewall policy definitions,
and WiFi SSID configs live here. Migration scripts import from this module.

Required setup:
  1. Update VLANS with your desired subnets and DHCP ranges
  2. Update INFRA_CLIENTS / PERSONAL_CLIENTS / IOT_CLIENTS with your devices
  3. Update WIFI_SSIDS with your desired SSID names
  4. Store WiFi PSKs in Vault (or the scripts will generate them)
  5. Update HEALTH_CHECKS with your service URLs
"""

# ---------------------------------------------------------------------------
# VLAN Definitions
# ---------------------------------------------------------------------------

VLANS = {
    "personal": {
        "name": "Personal",
        "vlan_id": 50,
        "subnet": "<INTERNAL_IP>/24",
        "gateway": "<INTERNAL_IP>",
        "dhcp_start": "<INTERNAL_IP>",
        "dhcp_stop": "<INTERNAL_IP>",
        "dns": [],  # Add your DNS server IPs, e.g. ["<INTERNAL_IP>", "<INTERNAL_IP>"]
        "purpose": "Personal devices (laptops, phones, tablets)",
    },
    "iot": {
        "name": "IoT",
        "vlan_id": 100,
        "subnet": "<INTERNAL_IP>/24",
        "gateway": "<INTERNAL_IP>",
        "dhcp_start": "<INTERNAL_IP>",
        "dhcp_stop": "<INTERNAL_IP>",
        "dns": [],  # Empty = use controller's built-in DNS (internet-only, recommended for IoT)
        "purpose": "Smart home, cameras, TVs, IoT devices",
    },
    "guest": {
        "name": "Guest",
        "vlan_id": 200,
        "subnet": "<INTERNAL_IP>/24",
        "gateway": "<INTERNAL_IP>",
        "dhcp_start": "<INTERNAL_IP>",
        "dhcp_stop": "<INTERNAL_IP>",
        "dns": [],  # Empty = use controller's built-in DNS (internet-only)
        "purpose": "Guest WiFi access",
    },
}

# Existing VLANs (do NOT modify — these represent your current network)
# Only VLAN 1 (Default) typically exists as a UniFi network out of the box.
EXISTING_VLANS = {
    "management": {"name": "Default", "vlan_id": 1, "subnet": "<INTERNAL_IP>/24"},
}

# ---------------------------------------------------------------------------
# Client Classification (by current IP on your management subnet)
# ---------------------------------------------------------------------------
# List your devices here so migration scripts know what goes where.
# Infrastructure stays on VLAN 1, personal moves to VLAN 50, IoT to VLAN 100.

# Infrastructure -- stays on VLAN 1 (management), no changes
INFRA_CLIENTS = {
    # "server-name": "<INTERNAL_IP>",
    # "nas": "<INTERNAL_IP>",
    # "gateway": "<INTERNAL_IP>",
    # "switch": "<INTERNAL_IP>",
    # "access-point": "<INTERNAL_IP>",
}

# Personal devices -- will migrate to VLAN 50
PERSONAL_CLIENTS = {
    # "desktop": "<INTERNAL_IP>",
    # "laptop": "<INTERNAL_IP>",
    # "phone": "<INTERNAL_IP>",
}

# IoT devices -- will migrate to VLAN 100
IOT_CLIENTS = {
    # "smart-tv": "<INTERNAL_IP>",
    # "camera": "<INTERNAL_IP>",
    # "smart-speaker": "<INTERNAL_IP>",
}

# ---------------------------------------------------------------------------
# WiFi SSID Definitions
# ---------------------------------------------------------------------------

WIFI_SSIDS = {
    "personal": {
        "name": "my-home",           # Change to your desired SSID name
        "vlan_key": "personal",       # Maps to VLANS["personal"]
        "security": "wpa2",           # wpa3 transitional not all devices support
        "band": "both",               # 2.4 + 5 GHz
        "vault_psk_field": "personal_psk",
    },
    "iot": {
        "name": "my-iot",
        "vlan_key": "iot",
        "security": "wpa2",
        "band": "2.4",                # IoT typically 2.4 GHz only
        "vault_psk_field": "iot_psk",
    },
    "guest": {
        "name": "my-guest",
        "vlan_key": "guest",
        "security": "wpa2",
        "band": "both",
        "vault_psk_field": "guest_psk",
    },
}

# Vault path for WiFi PSKs (optional — scripts generate PSKs if not in Vault)
WIFI_VAULT_PATH = "secret/unifi/wifi"

# ---------------------------------------------------------------------------
# Firewall Zone Definitions
# ---------------------------------------------------------------------------

# Zones to create/ensure exist (maps zone key -> display name)
FIREWALL_ZONES = {
    "management": "Management",
    "personal": "Personal",
    "iot": "IoT",
    "guest": "Guest",
}

# ---------------------------------------------------------------------------
# Firewall Policy Definitions (created DISABLED for safety)
# ---------------------------------------------------------------------------

# UniFi Integration API v1 firewall policy constraints:
#   - action.type: "ALLOW" or "BLOCK" (no "DROP"/"REJECT")
#   - Both source.zoneId and destination.zoneId are REQUIRED
#   - CIDR notation NOT supported in IP filters (single IPs only)
#   - IP filter + port filter nest inside destination.trafficFilter
#   - No "any" zone concept -- rules must specify exact zone pairs
#
# Because of these constraints, "block all internal" rules are expressed
# as individual zone-to-zone rules rather than RFC1918 CIDR blocks.

FIREWALL_POLICIES = [
    # --- Personal: allow DNS + web services, then block rest of management ---
    {
        "name": "Personal-DNS-Allow",
        "description": "Personal devices can reach DNS server",
        "action": "ALLOW",
        "source_zone": "personal",
        "destination_zone": "management",
        "destination_ip": "<INTERNAL_IP>",      # Your DNS server IP
        "destination_port": "53",
    },
    {
        "name": "Personal-Services-Allow",
        "description": "Personal devices can reach reverse proxy for web services",
        "action": "ALLOW",
        "source_zone": "personal",
        "destination_zone": "management",
        "destination_ip": "<INTERNAL_IP>",      # Your reverse proxy IP
        "destination_port": "80,443",
    },
    {
        "name": "Personal-Block-Mgmt",
        "description": "Block personal devices from management network",
        "action": "DROP",
        "source_zone": "personal",
        "destination_zone": "management",
    },
    # --- IoT: block all internal access ---
    {
        "name": "IoT-Block-Mgmt",
        "description": "Block IoT devices from management network",
        "action": "DROP",
        "source_zone": "iot",
        "destination_zone": "management",
    },
    {
        "name": "IoT-Block-Personal",
        "description": "Block IoT devices from personal network",
        "action": "DROP",
        "source_zone": "iot",
        "destination_zone": "personal",
    },
    # --- Guest: block all internal access ---
    {
        "name": "Guest-Block-Mgmt",
        "description": "Block guest devices from management network",
        "action": "DROP",
        "source_zone": "guest",
        "destination_zone": "management",
    },
    {
        "name": "Guest-Block-Personal",
        "description": "Block guest devices from personal network",
        "action": "DROP",
        "source_zone": "guest",
        "destination_zone": "personal",
    },
    {
        "name": "Guest-Block-IoT",
        "description": "Block guest devices from IoT network",
        "action": "DROP",
        "source_zone": "guest",
        "destination_zone": "iot",
    },
]

# Enable order for 05-enable-policies.py (incremental, safest first)
# IoT/Guest blocks first (low risk).
# Personal rules LAST (allow rules before block rule).
POLICY_ENABLE_ORDER = [
    "IoT-Block-Mgmt",
    "IoT-Block-Personal",
    "Guest-Block-Mgmt",
    "Guest-Block-Personal",
    "Guest-Block-IoT",
    "Personal-DNS-Allow",
    "Personal-Services-Allow",
    "Personal-Block-Mgmt",
]

# ---------------------------------------------------------------------------
# MinIO Backup Config (optional — for pre-migration snapshots)
# ---------------------------------------------------------------------------

MINIO_BACKUP_BUCKET = "my-backups"
MINIO_BACKUP_PREFIX = "unifi-migration/"

# ---------------------------------------------------------------------------
# Verification Targets (post-migration health checks)
# ---------------------------------------------------------------------------
# These run from your management network to verify services are still
# reachable after enabling firewall policies.

HEALTH_CHECKS = {
    "dns-server": {
        "host": "<INTERNAL_IP>",
        "port": 53,
    },
    "reverse-proxy": {
        "host": "<INTERNAL_IP>",
        "port": 443,
    },
    # Add your critical services here:
    # "my-app": {
    #     "url": "https://app.example.com/health",
    #     "expect_status": 200,
    # },
}

# NOTE: Health checks run from the management network. They verify
# management-plane services are still reachable but CANNOT validate
# cross-VLAN connectivity from personal/IoT VLANs. After enabling
# allow rules, manually test from a device on the target VLAN before
# enabling the block rule:
#   - DNS:    nslookup myservice.example.com <DNS_SERVER_IP>
#   - Web:    curl -sk https://myservice.example.com
# If those fail, the allow rules have a payload bug and the block rule
# will break all device access from that VLAN.
