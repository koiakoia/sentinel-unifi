# sentinel-unifi

UniFi Network API integration for Project Sentinel. Provides programmatic access to the UniFi controller (UCG-Fiber at <CONTROLLER_IP>) for monitoring, alerting, and network management.

## Components

- **`unifi/`** — Python API client library wrapping UniFi Network API v10.1.84
- **`cli.py`** — Click-based CLI for interactive network management
- **`collector.py`** — Scheduled data collector (systemd timer, every 5 min)
- **`exporter.py`** — Prometheus metrics exporter (port 9120)
- **`wazuh/`** — Wazuh rules and decoders for network change alerting
- **`grafana/`** — Grafana dashboard definition

## Quick Start

```bash
# Set API key (or store in Vault at secret/unifi)
export UNIFI_API_KEY="your-key-here"

# CLI usage
python3 cli.py info
python3 cli.py devices list
python3 cli.py clients list --type wireless
python3 cli.py snapshot
```

## Authentication

API key is read from (in order):
1. HashiCorp Vault at `secret/unifi` (field: `api_key`)
2. Environment variable `UNIFI_API_KEY`

Controller URL defaults to `https://<CONTROLLER_IP>`, overridable via:
- Vault field `controller_url`
- Environment variable `UNIFI_CONTROLLER_URL`

## Deployment

On iac-control (<HOST_IP>):
- Collector: `systemd` timer runs `collector.py` every 5 minutes
- Exporter: `systemd` service runs `exporter.py` on port 9120
- Data: `/var/log/sentinel/unifi/` (snapshots + events log)
- Wazuh rules deployed to `/var/ossec/etc/rules/` on wazuh server

## CI Pipeline

- yamllint, gitleaks, trivy-fs (matching sentinel-iac pattern)
- Runner tag: `iac`
