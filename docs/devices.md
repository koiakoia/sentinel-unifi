# Network Device Inventory

## Managed Devices

| Device | Type | Model | Role |
|--------|------|-------|------|
| UCG-Fiber | Gateway | UniFi Cloud Gateway Fiber | Primary router, firewall, VPN, controller |
| USW Pro 48 PoE | Switch | UniFi Switch Pro 48 PoE | Core switch, PoE for APs and cameras |
| USW-24-G2 | Switch | UniFi Switch 24 Gen2 | Distribution switch |
| AC Pro | Access Point | UniFi AP AC Pro | WiFi coverage |

## Device Roles

### UCG-Fiber (Gateway)

- Primary internet gateway and router
- Runs the UniFi Network controller (API endpoint)
- Manages firewall rules, traffic policies, VPN
- IP: `<CONTROLLER_IP>`

### USW Pro 48 PoE (Core Switch)

- 48-port PoE+ switch
- Powers access points and IP cameras via PoE
- Provides trunk links to other switches
- VLAN-capable for network segmentation

### USW-24-G2 (Distribution Switch)

- 24-port switch for additional device connectivity
- Uplinked to core switch
- Serves compute and storage infrastructure

### AC Pro (Access Point)

- Dual-band WiFi (2.4GHz + 5GHz)
- Managed via UCG-Fiber controller
- SSID and VLAN configuration via UniFi

## Monitoring

All devices are monitored via the collector → exporter → Prometheus pipeline:

- **Uptime**: Device availability and reboot detection
- **Port status**: Link speed, utilization, error counters
- **Client count**: Per-device connected client tracking
- **Firmware**: Version tracking and change detection
- **Throughput**: Per-port TX/RX bandwidth

Wazuh rules (100500-100513) generate alerts for device offline events, firmware changes, and anomalous client behavior. Level 10+ alerts are forwarded to Discord.

## Network Topology

```
Internet
    │
    ▼
UCG-Fiber (<CONTROLLER_IP>)
    │
    ├── USW Pro 48 PoE ──── AC Pro (WiFi)
    │       │
    │       ├── Proxmox hosts (pve, 208-pve2, pve3)
    │       ├── VMs (iac-control, gitlab, vault, wazuh, pangolin)
    │       └── IP cameras, IoT devices
    │
    └── USW-24-G2
            │
            └── Additional compute/storage
```

## Configuration Drift

The desired network state is defined in `config/desired-state.yml`. The collector compares live state against this definition and logs deviations for Wazuh alerting.
