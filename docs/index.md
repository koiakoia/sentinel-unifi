# Sentinel UniFi Integration

Python-based CLI and monitoring stack for the UniFi Network controller, providing network visibility, Prometheus metrics, and Wazuh SIEM integration.

## Architecture

```
UCG-Fiber Controller (<CONTROLLER_IP>)
        │
        ▼
  Collector (5min timer)  ──→  /var/log/sentinel/unifi/ (snapshots + events)
        │
        ▼
  Exporter (:9120)  ──→  Prometheus (:9099)  ──→  Grafana Dashboard
        │
        ▼
  Wazuh Rules (100500-100513)  ──→  Alerts (Discord)
```

### Components

| Component | File | Purpose |
|-----------|------|---------|
| CLI | `cli.py` | Interactive command-line tool for network queries |
| Collector | `collector.py` | Systemd timer (5min), snapshots device/client state |
| Exporter | `exporter.py` | Prometheus metrics endpoint on port 9120 |
| Wazuh rules | `wazuh/` | Custom decoder + rules for network event alerting |
| Grafana dashboard | `grafana/` | UniFi network dashboard definition |
| Config | `config/desired-state.yml` | Expected network topology for drift detection |

## CLI Usage

```bash
# On iac-control:
python3 ./cli.py <command>
```

### Commands

| Command | Description |
|---------|-------------|
| `info` | Controller and site information |
| `devices` | List all network devices with status |
| `clients` | List connected clients |
| `networks` | Show configured networks and VLANs |
| `wifi` | WiFi network configuration |
| `firewall` | Firewall rules and traffic policies |
| `dns` | DNS configuration |
| `snapshot` | Take a point-in-time snapshot of all network state |

### Examples

```bash
# Show all network devices
python3 ./cli.py devices

# List connected WiFi clients
python3 ./cli.py clients

# Take a full network snapshot
python3 ./cli.py snapshot
```

## Monitoring Stack

### Collector

Runs as a systemd timer every 5 minutes. Queries the UniFi API and stores:

- Device snapshots (firmware, uptime, port status)
- Client connection data
- Network events (device adoption, disconnects, firmware changes)

Data stored in `/var/log/sentinel/unifi/` on iac-control.

### Prometheus Exporter

Exposes metrics on port 9120, scraped by a dedicated Prometheus instance on port 9099.

Key metrics: device uptime, client count, port utilization, throughput, error rates.

### Grafana Dashboard

Dedicated UniFi dashboard using the UniFi Prometheus datasource (UID `P660CC246A1C19F5F`). Visualizes device health, client distribution, and network performance.

## Wazuh Integration

Custom rules in the 100500-100513 range monitor network events:

| Rule ID | Event |
|---------|-------|
| 100500 | UniFi device offline |
| 100501 | UniFi device online (recovery) |
| 100502 | Firmware change detected |
| 100503 | New device adopted |
| 100504–100513 | Client anomalies, config changes, port events |

Rules use a custom decoder (`wazuh/unifi-api-decoder.xml`) that parses collector JSON output.

## Configuration

### API Access

The UniFi API key is stored in Vault at `secret/unifi`. The controller is a UCG-Fiber at `https://<CONTROLLER_IP>` running API v10.1.84.

### API Notes

- Field names use **camelCase** (not snake_case)
- Device types are **UPPERCASE** (e.g., `USW`, `UAP`, `UGW`)
- Base API path: `/proxy/network/integration/v1/...`
