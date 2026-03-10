"""Firewall zone and policy management mixin for the UniFi API client."""


class FirewallMixin:
    """Mixin providing firewall-related API methods."""

    # --- Zones ---

    def list_firewall_zones(self, site_id: str) -> list:
        """List all firewall zones for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/firewall/zones")

    def get_firewall_zone(self, site_id: str, zone_id: str) -> dict:
        """Get a single firewall zone by ID."""
        return self._get(f"/sites/{site_id}/firewall/zones/{zone_id}")

    def create_firewall_zone(self, site_id: str, data: dict) -> dict:
        """Create a new firewall zone."""
        return self._post(f"/sites/{site_id}/firewall/zones", json=data)

    def update_firewall_zone(self, site_id: str, zone_id: str, data: dict) -> dict:
        """Update an existing firewall zone."""
        return self._put(f"/sites/{site_id}/firewall/zones/{zone_id}", json=data)

    def delete_firewall_zone(self, site_id: str, zone_id: str) -> dict:
        """Delete a firewall zone."""
        return self._delete(f"/sites/{site_id}/firewall/zones/{zone_id}")

    # --- Policies ---

    def list_firewall_policies(self, site_id: str) -> list:
        """List all firewall policies for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/firewall/policies")

    def get_firewall_policy(self, site_id: str, policy_id: str) -> dict:
        """Get a single firewall policy by ID."""
        return self._get(f"/sites/{site_id}/firewall/policies/{policy_id}")

    def create_firewall_policy(self, site_id: str, data: dict) -> dict:
        """Create a new firewall policy."""
        return self._post(f"/sites/{site_id}/firewall/policies", json=data)

    def update_firewall_policy(self, site_id: str, policy_id: str, data: dict) -> dict:
        """Update an existing firewall policy."""
        return self._put(f"/sites/{site_id}/firewall/policies/{policy_id}", json=data)

    def delete_firewall_policy(self, site_id: str, policy_id: str) -> dict:
        """Delete a firewall policy."""
        return self._delete(f"/sites/{site_id}/firewall/policies/{policy_id}")
