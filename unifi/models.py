"""Dataclasses for structured UniFi API responses."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ControllerInfo:
    version: str
    hostname: str

    @classmethod
    def from_api(cls, data: dict) -> "ControllerInfo":
        return cls(
            version=data.get("version", ""),
            hostname=data.get("hostname", ""),
        )


@dataclass
class DeviceInfo:
    id: str
    name: str
    model: str
    mac: str
    ip: str
    state: str
    firmware_version: str
    uptime: int

    @classmethod
    def from_api(cls, data: dict) -> "DeviceInfo":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            model=data.get("model", ""),
            mac=data.get("mac", ""),
            ip=data.get("ip", ""),
            state=data.get("state", ""),
            firmware_version=data.get("firmwareVersion", ""),
            uptime=data.get("uptime", 0),
        )


@dataclass
class DeviceStats:
    cpu_pct: float
    memory_pct: float
    tx_bytes: int
    rx_bytes: int
    uptime_seconds: int

    @classmethod
    def from_api(cls, data: dict) -> "DeviceStats":
        return cls(
            cpu_pct=data.get("cpuUtilizationPct", 0.0),
            memory_pct=data.get("memoryUtilizationPct", 0.0),
            tx_bytes=data.get("txBytes", 0),
            rx_bytes=data.get("rxBytes", 0),
            uptime_seconds=data.get("uptimeSeconds", 0),
        )


@dataclass
class ClientInfo:
    id: str
    name: str
    mac: str
    ip: str
    type: str
    network: str
    hostname: str
    rx_bytes: int
    tx_bytes: int

    @classmethod
    def from_api(cls, data: dict) -> "ClientInfo":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            mac=data.get("mac", ""),
            ip=data.get("ip", ""),
            type=data.get("type", ""),
            network=data.get("network", ""),
            hostname=data.get("hostname", ""),
            rx_bytes=data.get("rxBytes", 0),
            tx_bytes=data.get("txBytes", 0),
        )


@dataclass
class NetworkInfo:
    id: str
    name: str
    vlan_id: Optional[int]
    subnet: str
    dhcp_enabled: bool
    purpose: str

    @classmethod
    def from_api(cls, data: dict) -> "NetworkInfo":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            vlan_id=data.get("vlanId"),
            subnet=data.get("subnet", ""),
            dhcp_enabled=data.get("dhcpEnabled", False),
            purpose=data.get("purpose", ""),
        )


@dataclass
class WiFiInfo:
    id: str
    name: str
    security: str
    band: str
    enabled: bool

    @classmethod
    def from_api(cls, data: dict) -> "WiFiInfo":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            security=data.get("security", ""),
            band=data.get("band", ""),
            enabled=data.get("enabled", False),
        )


@dataclass
class WanInfo:
    id: str
    name: str
    type: str
    ip: str
    gateway: str
    dns: list
    up: bool

    @classmethod
    def from_api(cls, data: dict) -> "WanInfo":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            type=data.get("type", ""),
            ip=data.get("ip", ""),
            gateway=data.get("gateway", ""),
            dns=data.get("dns", []),
            up=data.get("up", False),
        )
