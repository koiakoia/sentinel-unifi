#!/usr/bin/env python3
"""UniFi Prometheus metrics exporter for Sentinel monitoring.

Lightweight HTTP server that reads the collector's JSON snapshot
and exposes Prometheus-format metrics at /metrics.
"""

import argparse
import json
import logging
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

SNAPSHOT_PATH = "/var/log/sentinel/unifi/unifi-latest.json"

log = logging.getLogger("unifi-exporter")


def load_snapshot():
    """Load the latest collector snapshot."""
    try:
        with open(SNAPSHOT_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        log.warning("Snapshot file not found: %s", SNAPSHOT_PATH)
        return None
    except json.JSONDecodeError as e:
        log.warning("Invalid JSON in snapshot: %s", e)
        return None


def escape_label(value):
    """Escape a Prometheus label value."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def metric_line(name, labels, value):
    """Format a single Prometheus metric line."""
    if labels:
        label_str = ",".join(
            f'{k}="{escape_label(v)}"' for k, v in labels.items()
        )
        return f"{name}{{{label_str}}} {value}"
    return f"{name} {value}"


def generate_metrics():
    """Read snapshot and generate Prometheus text format metrics."""
    snap = load_snapshot()
    lines = []

    if snap is None:
        # Return empty metrics, not an error
        lines.append("# No snapshot data available")
        return "\n".join(lines) + "\n"

    devices = snap.get("devices", [])
    device_stats = snap.get("device_stats", {})
    clients = snap.get("clients", [])
    networks = snap.get("networks", [])
    wans = snap.get("wans", [])

    # --- Device metrics ---
    lines.append("# HELP unifi_device_uptime_seconds Device uptime in seconds")
    lines.append("# TYPE unifi_device_uptime_seconds gauge")
    for dev in devices:
        dev_id = dev.get("id") or dev.get("_id", "")
        name = dev.get("name", "")
        model = dev.get("model", "")
        mac = dev.get("macAddress", dev.get("mac", ""))
        labels = {"name": name, "model": model, "mac": mac}
        uptime = dev.get("uptime", 0)
        # Also check device_stats for uptimeSeconds
        stats = device_stats.get(dev_id, {})
        if stats.get("uptimeSeconds"):
            uptime = stats["uptimeSeconds"]
        lines.append(metric_line("unifi_device_uptime_seconds", labels, uptime))

    lines.append("")
    lines.append("# HELP unifi_device_cpu_pct Device CPU utilization percentage")
    lines.append("# TYPE unifi_device_cpu_pct gauge")
    for dev in devices:
        dev_id = dev.get("id") or dev.get("_id", "")
        stats = device_stats.get(dev_id, {})
        cpu = stats.get("cpuUtilizationPct", 0)
        lines.append(metric_line("unifi_device_cpu_pct", {"name": dev.get("name", "")}, cpu))

    lines.append("")
    lines.append("# HELP unifi_device_memory_pct Device memory utilization percentage")
    lines.append("# TYPE unifi_device_memory_pct gauge")
    for dev in devices:
        dev_id = dev.get("id") or dev.get("_id", "")
        stats = device_stats.get(dev_id, {})
        mem = stats.get("memoryUtilizationPct", 0)
        lines.append(metric_line("unifi_device_memory_pct", {"name": dev.get("name", "")}, mem))

    lines.append("")
    lines.append("# HELP unifi_device_tx_bps Device transmit bytes per second")
    lines.append("# TYPE unifi_device_tx_bps gauge")
    for dev in devices:
        dev_id = dev.get("id") or dev.get("_id", "")
        stats = device_stats.get(dev_id, {})
        tx = stats.get("txBytes", 0)
        lines.append(metric_line("unifi_device_tx_bps", {"name": dev.get("name", "")}, tx))

    lines.append("")
    lines.append("# HELP unifi_device_rx_bps Device receive bytes per second")
    lines.append("# TYPE unifi_device_rx_bps gauge")
    for dev in devices:
        dev_id = dev.get("id") or dev.get("_id", "")
        stats = device_stats.get(dev_id, {})
        rx = stats.get("rxBytes", 0)
        lines.append(metric_line("unifi_device_rx_bps", {"name": dev.get("name", "")}, rx))

    # --- Client metrics ---
    lines.append("")
    lines.append("# HELP unifi_clients_total Total connected clients by type")
    lines.append("# TYPE unifi_clients_total gauge")
    wired_count = sum(1 for c in clients if c.get("type", "").upper() == "WIRED")
    wireless_count = sum(1 for c in clients if c.get("type", "").upper() == "WIRELESS")
    lines.append(metric_line("unifi_clients_total", {"type": "wired"}, wired_count))
    lines.append(metric_line("unifi_clients_total", {"type": "wireless"}, wireless_count))

    # --- Per-VLAN client counts ---
    lines.append("")
    lines.append("# HELP unifi_clients_by_vlan Connected clients per VLAN")
    lines.append("# TYPE unifi_clients_by_vlan gauge")
    network_id_to_vlan = {}
    for n in networks:
        net_id = n.get("id") or n.get("_id", "")
        vlan_id = n.get("vlanId", 1)
        net_name = n.get("name", "")
        if net_id:
            network_id_to_vlan[net_id] = (vlan_id, net_name)

    vlan_counts = {}
    for c in clients:
        net_id = c.get("networkId", "")
        vlan_id, net_name = network_id_to_vlan.get(net_id, (1, "Default"))
        key = (str(vlan_id), net_name)
        vlan_counts[key] = vlan_counts.get(key, 0) + 1

    for (vlan_id, net_name), count in sorted(vlan_counts.items()):
        lines.append(metric_line("unifi_clients_by_vlan",
                                 {"vlan": vlan_id, "network": net_name}, count))

    # --- WAN metrics ---
    # WAN throughput comes from gateway device uplink stats, not the /wans endpoint
    # which only returns interface metadata (id + name).
    lines.append("")
    lines.append("# HELP unifi_wan_tx_bps WAN transmit bytes per second")
    lines.append("# TYPE unifi_wan_tx_bps gauge")
    lines.append("# HELP unifi_wan_rx_bps WAN receive bytes per second")
    lines.append("# TYPE unifi_wan_rx_bps gauge")
    gateway_types = {"UCG Fiber", "UDM", "UDM Pro", "UDM SE", "UDR", "USG", "USG Pro"}
    for dev in devices:
        dev_type = dev.get("type", dev.get("model", ""))
        if dev_type in gateway_types:
            dev_id = dev.get("id") or dev.get("_id", "")
            stats = device_stats.get(dev_id, {})
            uplink = stats.get("uplink", {})
            name = dev.get("name", dev_type)
            tx = uplink.get("txRateBps", 0)
            rx = uplink.get("rxRateBps", 0)
            lines.append(metric_line("unifi_wan_tx_bps", {"wan": name}, tx))
            lines.append(metric_line("unifi_wan_rx_bps", {"wan": name}, rx))

    # --- Summary metrics ---
    lines.append("")
    lines.append("# HELP unifi_networks_total Total number of networks")
    lines.append("# TYPE unifi_networks_total gauge")
    lines.append(metric_line("unifi_networks_total", {}, len(networks)))

    lines.append("")
    lines.append("# HELP unifi_devices_total Total devices by state")
    lines.append("# TYPE unifi_devices_total gauge")
    state_counts = {}
    for dev in devices:
        state = dev.get("state", "unknown").lower()
        state_counts[state] = state_counts.get(state, 0) + 1
    # Always emit online/offline even if 0
    for state in ("online", "offline"):
        if state not in state_counts:
            state_counts[state] = 0
    for state, count in sorted(state_counts.items()):
        lines.append(metric_line("unifi_devices_total", {"state": state}, count))

    lines.append("")
    return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Prometheus metrics."""

    def do_GET(self):
        if self.path == "/metrics":
            body = generate_metrics().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            snap = load_snapshot()
            if snap is not None:
                body = b'{"status": "ok"}\n'
                self.send_response(200)
            else:
                body = b'{"status": "no_data"}\n'
                self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        """Route access logs through Python logging."""
        log.info(fmt, *args)


def main():
    parser = argparse.ArgumentParser(description="UniFi Prometheus exporter")
    parser.add_argument("--port", type=int, default=9120, help="Listen port (default: 9120)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    server = HTTPServer(("0.0.0.0", args.port), MetricsHandler)
    log.info("UniFi exporter listening on 0.0.0.0:%d", args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
