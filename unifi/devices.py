"""Device management mixin for the UniFi API client."""


class DevicesMixin:
    """Mixin providing device-related API methods."""

    def list_devices(self, site_id: str) -> list:
        """List all devices for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/devices")

    def get_device(self, site_id: str, device_id: str) -> dict:
        """Get a single device by ID."""
        return self._get(f"/sites/{site_id}/devices/{device_id}")

    def get_device_stats(self, site_id: str, device_id: str) -> dict:
        """Get latest statistics for a device."""
        return self._get(f"/sites/{site_id}/devices/{device_id}/statistics/latest")

    def restart_device(self, site_id: str, device_id: str) -> dict:
        """Restart a device."""
        return self._post(f"/sites/{site_id}/devices/{device_id}/actions", json={"action": "restart"})

    def port_cycle(self, site_id: str, device_id: str, port_idx: int) -> dict:
        """Power-cycle a device port."""
        return self._post(
            f"/sites/{site_id}/devices/{device_id}/interfaces/ports/{port_idx}/actions",
            json={"action": "cycle"},
        )

    def list_pending_devices(self) -> list:
        """List devices pending adoption."""
        return self._paginate("/pending-devices")
