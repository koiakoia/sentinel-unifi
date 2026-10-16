"""WiFi broadcast management mixin for the UniFi API client."""


class WiFiMixin:
    """Mixin providing WiFi-related API methods."""

    def list_wifi(self, site_id: str) -> list:
        """List all WiFi broadcasts for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/wifi/broadcasts")

    def get_wifi(self, site_id: str, wifi_id: str) -> dict:
        """Get a single WiFi broadcast by ID."""
        return self._get(f"/sites/{site_id}/wifi/broadcasts/{wifi_id}")

    def create_wifi(self, site_id: str, data: dict) -> dict:
        """Create a new WiFi broadcast."""
        return self._post(f"/sites/{site_id}/wifi/broadcasts", json=data)

    def update_wifi(self, site_id: str, wifi_id: str, data: dict) -> dict:
        """Update an existing WiFi broadcast."""
        return self._put(f"/sites/{site_id}/wifi/broadcasts/{wifi_id}", json=data)

    def delete_wifi(self, site_id: str, wifi_id: str) -> dict:
        """Delete a WiFi broadcast."""
        return self._delete(f"/sites/{site_id}/wifi/broadcasts/{wifi_id}")
