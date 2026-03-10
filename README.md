# sentinel-unifi

A complete UniFi Network management and observability stack: VLAN segmentation, firewall policy management, Python API client, CLI, Prometheus exporter, Wazuh SIEM integration, and Grafana dashboard.

Built for UniFi controllers running the Integration API (v10+), such as the UCG-Fiber, UDM Pro, and UDM SE.

## What This Does

**Configuration Management** — Define your VLANs, firewall zones, inter-VLAN policies, and WiFi SSIDs in code. Run migration scripts to apply them to your controller via API. Rollback if something breaks.

**Monitoring & Observability** — Collect device/client metrics every 5 minutes, expose them to Prometheus, visualize in Grafana, and alert via Wazuh SIEM rules.

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| **API Client** | `unifi/` | Full CRUD Python client — devices, networks, WiFi, firewall zones & policies |
| **Migration Scripts** | `migration/` | Phased VLAN segmentation: create VLANs, WiFi, zones, policies, rollback |
| **CLI** | `cli.py` | Click-based CLI for interactive network queries |
| **Collector** | `collector.py` | Scheduled data collector with delta detection (systemd timer) |
| **Exporter** | `exporter.py` | Prometheus metrics endpoint (default port 9120) |
| **Wazuh Rules** | `wazuh/` | Custom decoder + alerting rules for network events |
| **Grafana Dashboard** | `grafana/` | Dashboard JSON for UniFi metrics visualization |

## Quick Start

### Prerequisites

```bash
pip install requests click prometheus_client
```

### Authentication

API key is read from (in order):

1. **HashiCorp Vault** at `secret/unifi` (fields: `api_key`, `controller_url`)
2. **Environment variables** `UNIFI_API_KEY` and `UNIFI_CONTROLLER_URL`

```bash
# Option 1: Environment variables (simplest)
export UNIFI_API_KEY="your-api-key-from-unifi-settings"
export UNIFI_CONTROLLER_URL="https://192.168.1.1"

# Option 2: HashiCorp Vault (if you use Vault)
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"
# Store credentials: vault kv put secret/unifi api_key="..." controller_url="https://192.168.1.1"
```

Generate an API key in the UniFi controller UI: **Settings → API → Create API Key**.

### CLI Usage

```bash
python3 cli.py info          # Controller info
python3 cli.py devices       # List all devices
python3 cli.py clients       # List connected clients
python3 cli.py networks      # List networks/VLANs
python3 cli.py wifi          # List WiFi SSIDs
python3 cli.py firewall      # List firewall zones and policies
python3 cli.py dns           # List DNS policies
python3 cli.py snapshot      # Full state snapshot to file
```

## VLAN Segmentation Migration

The `migration/` directory contains a phased approach to segmenting a flat UniFi network into isolated VLANs with firewall policies. Every script supports `--dry-run` and the migration is designed to be incremental and reversible.

### Migration Phases

| Phase | Script | What It Does |
|-------|--------|-------------|
| 0 | `00-snapshot-backup.py` | Full controller state backup (JSON + optional MinIO upload) |
| 1a | `01-create-vlans.py` | Create VLAN networks with DHCP, DNS, gateway config |
| 1b | `02-create-wifi.py` | Create WiFi SSIDs per VLAN (PSKs from Vault or auto-generated) |
| 1c | `03-create-firewall-zones.py` | Create firewall zones mapped to VLANs |
| 1d | `04-create-firewall-policies.py` | Create inter-VLAN policies (all DISABLED initially) |
| 4 | `05-enable-policies.py` | Enable policies one at a time with health checks after each |
| — | `99-rollback.py` | Full rollback using a backup snapshot |

### Setup

1. Copy and customize the config:
   ```bash
   # Edit migration/config.py with your:
   #   - VLAN subnets and DHCP ranges
   #   - Device classifications (which devices go on which VLAN)
   #   - WiFi SSID names
   #   - Firewall policy rules
   #   - Health check endpoints
   ```

2. Run the migration (always start with `--dry-run`):
   ```bash
   cd migration/

   # Backup current state first
   python3 00-snapshot-backup.py --skip-minio

   # Preview changes
   python3 01-create-vlans.py --dry-run
   python3 02-create-wifi.py --dry-run
   python3 03-create-firewall-zones.py --dry-run
   python3 04-create-firewall-policies.py --dry-run

   # Apply (VLANs and WiFi are additive — existing traffic unaffected)
   python3 01-create-vlans.py
   python3 02-create-wifi.py
   python3 03-create-firewall-zones.py
   python3 04-create-firewall-policies.py

   # Enable policies incrementally (interactive, with health checks)
   python3 05-enable-policies.py
   ```

3. If something breaks:
   ```bash
   python3 99-rollback.py migration-backup-*.json
   ```

### Firewall Policy Architecture

Policies are created DISABLED, then enabled one at a time with health checks. The enable order is designed to be safe:

1. **IoT/Guest blocks first** (low risk — these devices don't need internal access)
2. **Personal allow rules** (DNS, web services)
3. **Personal block rule LAST** (only after verifying allows work from VLAN)

The `05-enable-policies.py` script:
- Runs health checks before starting
- Enables one policy at a time
- Runs health checks after each enable
- **Auto-rolls back** if health checks fail
- Requires manual confirmation for the final block rule (can't be automated — need to test from the target VLAN)

### Required Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `UNIFI_API_KEY` | Yes | UniFi controller API key (Settings → API) |
| `UNIFI_CONTROLLER_URL` | Yes | Controller URL, e.g. `https://192.168.1.1` |
| `VAULT_ADDR` | No | HashiCorp Vault URL (alternative to env vars) |
| `VAULT_TOKEN` | No | Vault token for reading secrets |

## Monitoring Stack

### Architecture

```
UniFi Controller API
        │
        ▼
  Collector (5min)  ──→  /var/log/sentinel/unifi/ (snapshots + events)
        │
        ▼
  Exporter (:9120)  ──→  Prometheus  ──→  Grafana Dashboard
        │
        ▼
  Wazuh Rules (100500-100513)  ──→  SIEM Alerts
```

### Prometheus Exporter

```bash
python3 exporter.py
# Metrics available at http://localhost:9120/metrics
```

Key metrics: device uptime, client count per device, port utilization, TX/RX throughput, firmware versions, error rates.

### Wazuh SIEM Integration

| Rule ID | Event |
|---------|-------|
| 100500 | Device offline |
| 100501 | Device recovery |
| 100502 | Firmware change |
| 100503 | New device adopted |
| 100504–100513 | Client anomalies, config changes, port events |

Deploy `wazuh/unifi-api-decoder.xml` and `wazuh/unifi-api-rules.xml` to your Wazuh server's rules directory.

## UniFi API Notes

- **Integration API v1** — field names use camelCase, device types are UPPERCASE (`USW`, `UAP`, `UGW`)
- **Base path**: `/proxy/network/integration/v1/...`
- **Firewall policies**: `ALLOW` or `BLOCK` only (no `DROP`/`REJECT`). Both source and destination zone IDs are required. No CIDR support in IP filters.
- **API key**: Generate in UniFi controller UI → Settings → API

## License

MIT
