"""DNS policy management mixin for the UniFi API client."""


class DnsMixin:
    """Mixin providing DNS policy API methods."""

    def list_dns_policies(self, site_id: str) -> list:
        """List all DNS policies for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/dns/policies")

    def get_dns_policy(self, site_id: str, policy_id: str) -> dict:
        """Get a single DNS policy by ID."""
        return self._get(f"/sites/{site_id}/dns/policies/{policy_id}")

    def create_dns_policy(self, site_id: str, data: dict) -> dict:
        """Create a new DNS policy."""
        return self._post(f"/sites/{site_id}/dns/policies", json=data)

    def update_dns_policy(self, site_id: str, policy_id: str, data: dict) -> dict:
        """Update an existing DNS policy."""
        return self._put(f"/sites/{site_id}/dns/policies/{policy_id}", json=data)

    def delete_dns_policy(self, site_id: str, policy_id: str) -> dict:
        """Delete a DNS policy."""
        return self._delete(f"/sites/{site_id}/dns/policies/{policy_id}")
