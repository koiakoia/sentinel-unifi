"""Network management mixin for the UniFi API client."""


class NetworksMixin:
    """Mixin providing network-related API methods."""

    def list_networks(self, site_id: str) -> list:
        """List all networks for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/networks")

    def get_network(self, site_id: str, network_id: str) -> dict:
        """Get a single network by ID."""
        return self._get(f"/sites/{site_id}/networks/{network_id}")

    def create_network(self, site_id: str, data: dict) -> dict:
        """Create a new network."""
        return self._post(f"/sites/{site_id}/networks", json=data)

    def update_network(self, site_id: str, network_id: str, data: dict) -> dict:
        """Update an existing network."""
        return self._put(f"/sites/{site_id}/networks/{network_id}", json=data)

    def delete_network(self, site_id: str, network_id: str) -> dict:
        """Delete a network."""
        return self._delete(f"/sites/{site_id}/networks/{network_id}")
