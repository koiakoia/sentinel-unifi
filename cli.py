#!/usr/bin/env python3
"""UniFi Network CLI — sentinel-unifi"""

import json
import os
import sys

import click

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unifi import UniFiClient


def get_client(ctx):
    """Get or create UniFi client from context."""
    if "client" not in ctx.obj:
        ctx.obj["client"] = UniFiClient.from_vault()
    return ctx.obj["client"]


def get_site_id(ctx):
    """Auto-detect site ID if not provided."""
    if "site_id" not in ctx.obj:
        client = get_client(ctx)
        sites = client.list_sites()
        if not sites:
            click.echo("Error: No sites found", err=True)
            raise SystemExit(1)
        ctx.obj["site_id"] = sites[0].get("_id") or sites[0].get("id")
    return ctx.obj["site_id"]


def output(ctx, data):
    """Output data as JSON or formatted text."""
    if ctx.obj.get("json_output"):
        click.echo(json.dumps(data, indent=2, default=str))
        return True
    return False


def print_table(headers, rows):
    """Print a simple aligned table."""
    if not rows:
        click.echo("  (none)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    click.echo(fmt.format(*headers))
    click.echo(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        click.echo(fmt.format(*(str(c) for c in row)))


def format_uptime(seconds):
    """Format seconds into human-readable uptime."""
    if not seconds:
        return "0s"
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    return " ".join(parts) or "0m"


def format_bytes(b):
    """Format bytes into human-readable."""
    if not b:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# --- Main group ---

@click.group()
@click.option("--site", default=None, help="Site ID (auto-detects first site if omitted)")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON")
@click.pass_context
def unifi(ctx, site, json_output):
    """UniFi Network CLI — sentinel-unifi"""
    ctx.ensure_object(dict)
    ctx.obj["json_output"] = json_output
    if site:
        ctx.obj["site_id"] = site


# --- info ---

@unifi.command()
@click.pass_context
def info(ctx):
    """Show controller version and hostname."""
    client = get_client(ctx)
    data = client.get_info()
    if output(ctx, data):
        return
    click.echo(f"Version: {data.get('applicationVersion', data.get('version', 'N/A'))}")


# --- sites ---

@unifi.group()
@click.pass_context
def sites(ctx):
    """Site management commands."""
    pass


@sites.command("list")
@click.pass_context
def sites_list(ctx):
    """List all sites."""
    client = get_client(ctx)
    data = client.list_sites()
    if output(ctx, data):
        return
    headers = ["ID", "Name", "Description"]
    rows = [
        (
            s.get("_id") or s.get("id", ""),
            s.get("name", ""),
            s.get("desc", s.get("description", "")),
        )
        for s in data
    ]
    print_table(headers, rows)


# --- devices ---

@unifi.group()
@click.pass_context
def devices(ctx):
    """Device management commands."""
    pass


@devices.command("list")
@click.pass_context
def devices_list(ctx):
    """List all devices."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.list_devices(site_id)
    if output(ctx, data):
        return
    headers = ["Name", "Model", "IP", "MAC", "State", "Firmware"]
    rows = [
        (
            d.get("name", ""),
            d.get("model", ""),
            d.get("ipAddress", d.get("ip", "")),
            d.get("macAddress", d.get("mac", "")),
            d.get("state", ""),
            d.get("firmwareVersion", ""),
        )
        for d in data
    ]
    print_table(headers, rows)


@devices.command("show")
@click.argument("device_id")
@click.pass_context
def devices_show(ctx, device_id):
    """Show full details for a device."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.get_device(site_id, device_id)
    if output(ctx, data):
        return
    for key, val in sorted(data.items()):
        click.echo(f"  {key}: {val}")


@devices.command("stats")
@click.argument("device_id")
@click.pass_context
def devices_stats(ctx, device_id):
    """Show CPU, memory, uptime, and throughput for a device."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.get_device_stats(site_id, device_id)
    if output(ctx, data):
        return
    click.echo(f"  CPU:     {data.get('cpuUtilizationPct', 0):.1f}%")
    click.echo(f"  Memory:  {data.get('memoryUtilizationPct', 0):.1f}%")
    click.echo(f"  Uptime:  {format_uptime(data.get('uptimeSeconds', 0))}")
    click.echo(f"  TX:      {format_bytes(data.get('txBytes', 0))}")
    click.echo(f"  RX:      {format_bytes(data.get('rxBytes', 0))}")


@devices.command("restart")
@click.argument("device_id")
@click.option("--confirm", is_flag=True, required=True, help="Confirm device restart")
@click.pass_context
def devices_restart(ctx, device_id, confirm):
    """Restart a device (requires --confirm)."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.restart_device(site_id, device_id)
    if output(ctx, data):
        return
    click.echo(f"Restart initiated for device {device_id}")


@devices.command("port-cycle")
@click.argument("device_id")
@click.argument("port", type=int)
@click.option("--confirm", is_flag=True, required=True, help="Confirm port power cycle")
@click.pass_context
def devices_port_cycle(ctx, device_id, port, confirm):
    """Power-cycle a device port (requires --confirm)."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.port_cycle(site_id, device_id, port)
    if output(ctx, data):
        return
    click.echo(f"Port {port} power-cycled on device {device_id}")


# --- clients ---

@unifi.group()
@click.pass_context
def clients(ctx):
    """Client management commands."""
    pass


@clients.command("list")
@click.option("--type", "client_type", type=click.Choice(["wired", "wireless"]), default=None, help="Filter by type")
@click.pass_context
def clients_list(ctx, client_type):
    """List connected clients."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.list_clients(site_id, type=client_type)
    if output(ctx, data):
        return
    headers = ["Name", "MAC", "IP", "Type"]
    rows = [
        (
            c.get("name") or c.get("hostname", ""),
            c.get("macAddress", c.get("mac", "")),
            c.get("ipAddress", c.get("ip", "")),
            c.get("type", ""),
        )
        for c in data
    ]
    print_table(headers, rows)


# --- networks ---

@unifi.group()
@click.pass_context
def networks(ctx):
    """Network management commands."""
    pass


@networks.command("list")
@click.pass_context
def networks_list(ctx):
    """List all networks."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.list_networks(site_id)
    if output(ctx, data):
        return
    headers = ["Name", "VLAN", "Management", "Enabled"]
    rows = [
        (
            n.get("name", ""),
            str(n.get("vlanId", "")),
            n.get("management", ""),
            "yes" if n.get("enabled") else "no",
        )
        for n in data
    ]
    print_table(headers, rows)


# --- wifi ---

@unifi.group()
@click.pass_context
def wifi(ctx):
    """WiFi management commands."""
    pass


@wifi.command("list")
@click.pass_context
def wifi_list(ctx):
    """List WiFi broadcasts."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.list_wifi(site_id)
    if output(ctx, data):
        return
    headers = ["Name", "Security", "Band", "Enabled"]
    rows = [
        (
            w.get("name", ""),
            w.get("security", ""),
            w.get("band", ""),
            "yes" if w.get("enabled") else "no",
        )
        for w in data
    ]
    print_table(headers, rows)


# --- firewall ---

@unifi.group()
@click.pass_context
def firewall(ctx):
    """Firewall management commands."""
    pass


@firewall.command("zones")
@click.pass_context
def firewall_zones(ctx):
    """List firewall zones."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.list_firewall_zones(site_id)
    if output(ctx, data):
        return
    headers = ["ID", "Name"]
    rows = [
        (z.get("_id") or z.get("id", ""), z.get("name", ""))
        for z in data
    ]
    print_table(headers, rows)


@firewall.command("policies")
@click.pass_context
def firewall_policies(ctx):
    """List firewall policies."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.list_firewall_policies(site_id)
    if output(ctx, data):
        return
    headers = ["Name", "Action", "Enabled"]
    action_label = lambda p: p.get("action", {}).get("type", str(p.get("action", ""))) if isinstance(p.get("action"), dict) else str(p.get("action", ""))
    rows = [
        (
            p.get("name", ""),
            action_label(p),
            "yes" if p.get("enabled", True) else "no",
        )
        for p in data
    ]
    print_table(headers, rows)


# --- dns ---

@unifi.group()
@click.pass_context
def dns(ctx):
    """DNS management commands."""
    pass


@dns.command("list")
@click.pass_context
def dns_list(ctx):
    """List DNS policies."""
    client = get_client(ctx)
    site_id = get_site_id(ctx)
    data = client.list_dns_policies(site_id)
    if output(ctx, data):
        return
    headers = ["ID", "Name", "Enabled"]
    rows = [
        (
            d.get("_id") or d.get("id", ""),
            d.get("name", ""),
            "yes" if d.get("enabled", True) else "no",
        )
        for d in data
    ]
    print_table(headers, rows)


# --- snapshot ---

@unifi.command()
@click.pass_context
def snapshot(ctx):
    """Dump full state to a timestamped JSON file."""
    import datetime

    client = get_client(ctx)
    site_id = get_site_id(ctx)

    click.echo("Collecting full UniFi state snapshot...")

    snap = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "site_id": site_id}

    for label, fn in [
        ("devices", lambda: client.list_devices(site_id)),
        ("clients", lambda: client.list_clients(site_id)),
        ("networks", lambda: client.list_networks(site_id)),
        ("wifi", lambda: client.list_wifi(site_id)),
        ("firewall_zones", lambda: client.list_firewall_zones(site_id)),
        ("firewall_policies", lambda: client.list_firewall_policies(site_id)),
        ("dns_policies", lambda: client.list_dns_policies(site_id)),
        ("acl_rules", lambda: client.list_acl_rules(site_id)),
        ("wans", lambda: client.list_wans(site_id)),
    ]:
        try:
            snap[label] = fn()
            click.echo(f"  {label}: {len(snap[label])} items")
        except Exception as e:
            snap[label] = []
            click.echo(f"  {label}: ERROR - {e}", err=True)

    # Collect per-device stats
    device_stats = {}
    for dev in snap.get("devices", []):
        dev_id = dev.get("id") or dev.get("_id", "")
        if dev_id:
            try:
                device_stats[dev_id] = client.get_device_stats(site_id, dev_id)
            except Exception:
                device_stats[dev_id] = {}
    snap["device_stats"] = device_stats

    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    filename = f"unifi-snapshot-{ts}.json"
    with open(filename, "w") as f:
        json.dump(snap, f, indent=2, default=str)
    click.echo(f"\nSnapshot written to {filename}")


if __name__ == "__main__":
    unifi()
