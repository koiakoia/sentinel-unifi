"""ACL rule management mixin for the UniFi API client."""


class AclMixin:
    """Mixin providing ACL rule API methods."""

    def list_acl_rules(self, site_id: str) -> list:
        """List all ACL rules for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/acl-rules")

    def get_acl_rule(self, site_id: str, rule_id: str) -> dict:
        """Get a single ACL rule by ID."""
        return self._get(f"/sites/{site_id}/acl-rules/{rule_id}")

    def create_acl_rule(self, site_id: str, data: dict) -> dict:
        """Create a new ACL rule."""
        return self._post(f"/sites/{site_id}/acl-rules", json=data)

    def update_acl_rule(self, site_id: str, rule_id: str, data: dict) -> dict:
        """Update an existing ACL rule."""
        return self._put(f"/sites/{site_id}/acl-rules/{rule_id}", json=data)

    def delete_acl_rule(self, site_id: str, rule_id: str) -> dict:
        """Delete an ACL rule."""
        return self._delete(f"/sites/{site_id}/acl-rules/{rule_id}")
