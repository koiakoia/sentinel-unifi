#!/usr/bin/env python3
"""UniFi scheduled data collector for Sentinel monitoring.

Runs every 5 minutes via systemd timer. Collects full network state,
compares with previous snapshot, and generates delta events for Wazuh.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unifi import UniFiClient

DATA_DIR = "/var/log/sentinel/unifi"
LATEST_FILE = os.path.join(DATA_DIR, "unifi-latest.json")
PREVIOUS_FILE = os.path.join(DATA_DIR, "unifi-previous.json")
EVENTS_FILE = os.path.join(DATA_DIR, "unifi-events.log")

CPU_THRESHOLD = 80
MEMORY_THRESHOLD = 80

log = logging.getLogger("unifi-collector")


def setup_logging():
    """Configure logging to stderr."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(name)s[%(process)d]: %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    ))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def emit_event(event_type, fields):
    """Write a syslog-style event line to the events log."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pid = os.getpid()
    field_str = "|".join(f"{k}={v}" for k, v in fields.items())
    line = f"{ts} unifi-collector[{pid}]: {event_type}|{field_str}\n"
    with open(EVENTS_FILE, "a") as f:
        f.write(line)


def diff_lists(old_items, new_items, key):
    """Compare two lists of dicts by a key field.

    Returns (added, removed, modified) where modified is a list of
    (old_item, new_item) tuples for items whose content changed.
    """
    old_map = {item.get(key, ""): item for item in old_items}
    new_map = {item.get(key, ""): item for item in new_items}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    added = [new_map[k] for k in (new_keys - old_keys) if k]
    removed = [old_map[k] for k in (old_keys - new_keys) if k]

    modified = []
    for k in old_keys & new_keys:
        if k and diff_dicts(old_map[k], new_map[k]):
            modified.append((old_map[k], new_map[k]))

    return added, removed, modified


def diff_dicts(old, new):
    """Find changed fields between two dicts. Returns dict of changed keys."""
    changes = {}
    all_keys = set(old.keys()) | set(new.keys())
    for k in all_keys:
        old_val = old.get(k)
        new_val = new.get(k)
        if old_val != new_val:
            changes[k] = (old_val, new_val)
    return changes


def get_item_key(item):
    """Get the best identifier key from an item."""
    return item.get("id") or item.get("_id") or item.get("mac", "")


def collect_snapshot(client, site_id):
    """Collect full network state snapshot."""
    snap = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "site_id": site_id,
    }

    collectors = [
        ("devices", lambda: client.list_devices(site_id)),
        ("clients", lambda: client.list_clients(site_id)),
        ("networks", lambda: client.list_networks(site_id)),
        ("wifi", lambda: client.list_wifi(site_id)),
        ("firewall_policies", lambda: client.list_firewall_policies(site_id)),
        ("firewall_zones", lambda: client.list_firewall_zones(site_id)),
        ("dns_policies", lambda: client.list_dns_policies(site_id)),
        ("acl_rules", lambda: client.list_acl_rules(site_id)),
        ("wans", lambda: client.list_wans(site_id)),
        ("pending_devices", lambda: client.list_pending_devices()),
    ]

    for label, fn in collectors:
        try:
            snap[label] = fn()
        except Exception as e:
            log.warning("Failed to collect %s: %s", label, e)
            snap[label] = []

    # Per-device stats
    device_stats = {}
    for dev in snap.get("devices", []):
        dev_id = get_item_key(dev)
        if dev_id:
            try:
                device_stats[dev_id] = client.get_device_stats(site_id, dev_id)
            except Exception as e:
                log.warning("Failed to get stats for device %s: %s", dev_id, e)
                device_stats[dev_id] = {}
    snap["device_stats"] = device_stats

    return snap


def compare_devices(old_snap, new_snap):
    """Compare device lists and emit events."""
    old_devices = old_snap.get("devices", [])
    new_devices = new_snap.get("devices", [])
    key = "macAddress"

    added, removed, modified = diff_lists(old_devices, new_devices, key)

    for dev in added:
        emit_event("DEVICE_STATE_CHANGE", {
            "name": dev.get("name", ""),
            "mac": dev.get("macAddress", ""),
            "state": dev.get("state", "ONLINE"),
            "prev_state": "UNKNOWN",
        })

    for dev in removed:
        emit_event("DEVICE_OFFLINE", {
            "name": dev.get("name", ""),
            "mac": dev.get("macAddress", ""),
            "ip": dev.get("ipAddress", ""),
        })

    for old_dev, new_dev in modified:
        old_state = old_dev.get("state", "")
        new_state = new_dev.get("state", "")
        if old_state != new_state:
            emit_event("DEVICE_STATE_CHANGE", {
                "name": new_dev.get("name", ""),
                "mac": new_dev.get("macAddress", ""),
                "state": new_state,
                "prev_state": old_state,
            })
            if new_state.upper() in ("OFFLINE", "DISCONNECTED"):
                emit_event("DEVICE_OFFLINE", {
                    "name": new_dev.get("name", ""),
                    "mac": new_dev.get("macAddress", ""),
                    "ip": new_dev.get("ipAddress", ""),
                })

        old_fw = old_dev.get("firmwareVersion", "")
        new_fw = new_dev.get("firmwareVersion", "")
        if old_fw and new_fw and old_fw != new_fw:
            emit_event("FIRMWARE_UPDATE", {
                "name": new_dev.get("name", ""),
                "current": new_fw,
                "available": old_fw,
            })


def compare_clients(old_snap, new_snap):
    """Compare client lists and emit events for new clients."""
    old_clients = old_snap.get("clients", [])
    new_clients = new_snap.get("clients", [])

    old_macs = {c.get("macAddress", "") for c in old_clients if c.get("macAddress")}

    for client in new_clients:
        mac = client.get("macAddress", "")
        if mac and mac not in old_macs:
            emit_event("CLIENT_NEW", {
                "name": client.get("name") or client.get("hostname", ""),
                "mac": mac,
                "ip": client.get("ipAddress", ""),
                "type": client.get("type", ""),
            })


def compare_named_list(old_snap, new_snap, snap_key, event_type, name_field):
    """Generic comparator for named list items (networks, wifi, firewall, dns, acl)."""
    old_items = old_snap.get(snap_key, [])
    new_items = new_snap.get(snap_key, [])
    key = name_field

    added, removed, modified = diff_lists(old_items, new_items, key)

    for item in added:
        emit_event(event_type, {
            "action": "added",
            f"{name_field}": item.get(name_field, ""),
        })

    for item in removed:
        emit_event(event_type, {
            "action": "removed",
            f"{name_field}": item.get(name_field, ""),
        })

    for _old, new in modified:
        emit_event(event_type, {
            "action": "modified",
            f"{name_field}": new.get(name_field, ""),
        })


def compare_wans(old_snap, new_snap):
    """Compare WAN interfaces and detect failover."""
    old_wans = {w.get("name", ""): w for w in old_snap.get("wans", []) if w.get("name")}
    new_wans = {w.get("name", ""): w for w in new_snap.get("wans", []) if w.get("name")}

    for name in set(old_wans.keys()) | set(new_wans.keys()):
        old_w = old_wans.get(name, {})
        new_w = new_wans.get(name, {})
        old_up = old_w.get("up")
        new_up = new_w.get("up")
        if old_up is not None and new_up is not None and old_up != new_up:
            emit_event("WAN_FAILOVER", {
                "wan": name,
                "status": "up" if new_up else "down",
            })


def check_thresholds(new_snap):
    """Check device stats against thresholds."""
    device_stats = new_snap.get("device_stats", {})
    devices_by_id = {}
    for dev in new_snap.get("devices", []):
        dev_id = get_item_key(dev)
        if dev_id:
            devices_by_id[dev_id] = dev

    for dev_id, stats in device_stats.items():
        dev = devices_by_id.get(dev_id, {})
        name = dev.get("name", dev_id)

        cpu = stats.get("cpuUtilizationPct", 0)
        if cpu and cpu >= CPU_THRESHOLD:
            emit_event("DEVICE_THRESHOLD", {
                "name": name,
                "metric": "cpu",
                "value": str(round(cpu, 1)),
                "threshold": str(CPU_THRESHOLD),
            })

        mem = stats.get("memoryUtilizationPct", 0)
        if mem and mem >= MEMORY_THRESHOLD:
            emit_event("DEVICE_THRESHOLD", {
                "name": name,
                "metric": "memory",
                "value": str(round(mem, 1)),
                "threshold": str(MEMORY_THRESHOLD),
            })


def check_pending_devices(new_snap):
    """Emit events for pending (unadopted) devices."""
    for dev in new_snap.get("pending_devices", []):
        emit_event("DEVICE_PENDING", {
            "mac": dev.get("mac", ""),
            "model": dev.get("model", ""),
        })


def compare_client_vlans(old_snap, new_snap):
    """Detect clients that changed VLAN/network assignment."""
    old_clients = {c.get("macAddress", ""): c for c in old_snap.get("clients", []) if c.get("macAddress")}
    new_clients = {c.get("macAddress", ""): c for c in new_snap.get("clients", []) if c.get("macAddress")}

    # Build network ID -> name maps for readable events
    old_nets = {n.get("id") or n.get("_id", ""): n.get("name", "")
                for n in old_snap.get("networks", [])}
    new_nets = {n.get("id") or n.get("_id", ""): n.get("name", "")
                for n in new_snap.get("networks", [])}

    for mac in old_clients.keys() & new_clients.keys():
        old_net_id = old_clients[mac].get("networkId", "")
        new_net_id = new_clients[mac].get("networkId", "")
        if old_net_id and new_net_id and old_net_id != new_net_id:
            client_name = new_clients[mac].get("name") or new_clients[mac].get("hostname", mac)
            emit_event("CLIENT_VLAN_CHANGE", {
                "name": client_name,
                "mac": mac,
                "old_network": old_nets.get(old_net_id, old_net_id),
                "new_network": new_nets.get(new_net_id, new_net_id),
            })


def compare_snapshots(old_snap, new_snap):
    """Run all comparison checks between old and new snapshots."""
    compare_devices(old_snap, new_snap)
    compare_clients(old_snap, new_snap)
    compare_client_vlans(old_snap, new_snap)
    compare_named_list(old_snap, new_snap, "networks", "NETWORK_CHANGE", "name")
    compare_named_list(old_snap, new_snap, "wifi", "WIFI_CHANGE", "name")
    compare_named_list(old_snap, new_snap, "firewall_policies", "FIREWALL_CHANGE", "name")
    compare_named_list(old_snap, new_snap, "dns_policies", "DNS_CHANGE", "name")
    compare_named_list(old_snap, new_snap, "acl_rules", "ACL_CHANGE", "name")
    compare_wans(old_snap, new_snap)
    check_thresholds(new_snap)
    check_pending_devices(new_snap)


def load_json(path):
    """Load JSON file, return empty dict on failure."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json(path, data):
    """Atomically write JSON to file."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)


def main():
    setup_logging()
    start_time = time.monotonic()

    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        client = UniFiClient.from_vault()
    except Exception as e:
        log.error("Failed to initialize UniFi client: %s", e)
        return 1

    # Auto-detect site
    try:
        sites = client.list_sites()
        if not sites:
            log.error("No sites found")
            return 1
        site_id = sites[0].get("_id") or sites[0].get("id")
    except Exception as e:
        log.error("Failed to list sites: %s", e)
        return 1

    log.info("Collecting snapshot for site %s", site_id)

    # Collect current state
    try:
        new_snap = collect_snapshot(client, site_id)
    except Exception as e:
        log.error("Failed to collect snapshot: %s", e)
        return 1

    # Load previous snapshot and compare
    old_snap = load_json(LATEST_FILE)
    if old_snap:
        log.info("Comparing with previous snapshot")
        try:
            compare_snapshots(old_snap, new_snap)
        except Exception as e:
            log.warning("Error during snapshot comparison: %s", e)

    # Rotate: current -> previous, write new current
    if os.path.exists(LATEST_FILE):
        try:
            os.replace(LATEST_FILE, PREVIOUS_FILE)
        except OSError as e:
            log.warning("Failed to rotate previous snapshot: %s", e)

    save_json(LATEST_FILE, new_snap)

    duration_ms = int((time.monotonic() - start_time) * 1000)
    # Count clients per VLAN for observability
    net_id_to_vlan = {}
    for n in new_snap.get("networks", []):
        net_id = n.get("id") or n.get("_id", "")
        if net_id:
            net_id_to_vlan[net_id] = str(n.get("vlanId", 1))

    vlan_counts = {}
    for c in new_snap.get("clients", []):
        vlan = net_id_to_vlan.get(c.get("networkId", ""), "1")
        vlan_counts[vlan] = vlan_counts.get(vlan, 0) + 1

    vlan_summary = ";".join(f"vlan{k}={v}" for k, v in sorted(vlan_counts.items()))

    emit_event("COLLECTOR_OK", {
        "devices": str(len(new_snap.get("devices", []))),
        "clients": str(len(new_snap.get("clients", []))),
        "networks": str(len(new_snap.get("networks", []))),
        "vlan_clients": vlan_summary or "vlan1=" + str(len(new_snap.get("clients", []))),
        "duration_ms": str(duration_ms),
    })

    log.info(
        "Collection complete: %d devices, %d clients, %d networks (%dms)",
        len(new_snap.get("devices", [])),
        len(new_snap.get("clients", [])),
        len(new_snap.get("networks", [])),
        duration_ms,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
