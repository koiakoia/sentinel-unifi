# Sentinel UniFi Integration

Complete UniFi Network management and observability stack: VLAN segmentation, firewall policy management, Prometheus metrics, and Wazuh SIEM integration.

## Architecture

```
UniFi Controller API
        │
        ├──→  Migration Scripts  ──→  VLANs, WiFi, Zones, Policies
        │
        ▼
  Collector (5min timer)  ──→  Snapshots + Events log
        │
        ▼
  Exporter (:9120)  ──→  Prometheus  ──→  Grafana Dashboard
        │
        ▼
  Wazuh Rules (100500-100513)  ──→  Alerts
```

### Components

| Component | Path | Purpose |
|-----------|------|---------|
| API Client | `unifi/` | Full CRUD client for devices, networks, WiFi, firewall |
| Migration | `migration/` | Phased VLAN segmentation with dry-run and rollback |
| CLI | `cli.py` | Interactive command-line tool for network queries |
| Collector | `collector.py` | Systemd timer (5min), snapshots device/client state |
| Exporter | `exporter.py` | Prometheus metrics endpoint on port 9120 |
| Wazuh rules | `wazuh/` | Custom decoder + rules for network event alerting |
| Grafana dashboard | `grafana/` | UniFi network dashboard definition |

## Configuration

### API Access

Set your UniFi API key via environment variable or HashiCorp Vault:

```bash
export UNIFI_API_KEY="your-key-here"
export UNIFI_CONTROLLER_URL="https://192.168.1.1"
```

Or store in Vault at `secret/unifi` with fields `api_key` and `controller_url`.

### VLAN Migration

Edit `migration/config.py` with your network details, then run the migration scripts in order. See the main README for the full walkthrough.

### API Notes

- Field names use **camelCase** (not snake_case)
- Device types are **UPPERCASE** (e.g., `USW`, `UAP`, `UGW`)
- Base API path: `/proxy/network/integration/v1/...`
