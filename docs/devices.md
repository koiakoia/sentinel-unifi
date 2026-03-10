# Network Device Inventory

## Supported Devices

The stack supports all UniFi Network devices accessible via the Integration API:

| Type | Examples | Monitored Metrics |
|------|----------|-------------------|
| Gateway | UCG-Fiber, UDM Pro, UDM SE | Uptime, throughput, firewall rules |
| Switch | USW Pro, USW Lite, USW Flex | Port status, PoE usage, error counters |
| Access Point | U6 Pro, U6 Lite, AC Pro | Client count, channel utilization, signal strength |

## Monitoring

All devices are monitored via the collector → exporter → Prometheus pipeline:

- **Uptime**: Device availability and reboot detection
- **Port status**: Link speed, utilization, error counters
- **Client count**: Per-device connected client tracking
- **Firmware**: Version tracking and change detection
- **Throughput**: Per-port TX/RX bandwidth

Wazuh rules (100500-100513) generate alerts for device offline events, firmware changes, and anomalous client behavior.

## Configuration Management

The `migration/` scripts can create and manage:

- **Networks**: VLAN creation with DHCP, DNS, and gateway configuration
- **WiFi**: SSID creation with per-VLAN assignment and WPA2/WPA3 security
- **Firewall Zones**: Zone creation mapped to VLAN networks
- **Firewall Policies**: Inter-VLAN allow/block rules with incremental enablement
