"""Client management mixin for the UniFi API client."""

from typing import Optional


class ClientsMixin:
    """Mixin providing client-related API methods."""

    def list_clients(self, site_id: str, type: Optional[str] = None) -> list:
        """List all clients for a site (auto-paginated).

        Args:
            site_id: The site ID.
            type: Optional filter - 'wired', 'wireless', or 'vpn'.
        """
        params = {}
        if type is not None:
            params["type"] = type
        return self._paginate(f"/sites/{site_id}/clients", params=params)

    def get_client(self, site_id: str, client_id: str) -> dict:
        """Get a single client by ID."""
        return self._get(f"/sites/{site_id}/clients/{client_id}")
