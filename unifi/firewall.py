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
        """Update an existing firewall policy (full replacement via PUT).

        Replaces the entire policy resource. To update individual fields
        without re-submitting the full body, use
        ``patch_firewall_policy()`` (added in a separate PR).

        Args:
            site_id:   UUID of the target site.
            policy_id: UUID of the firewall policy.
            data:      Full policy payload dict.

        Returns:
            Updated firewall policy dict.
        """
        return self._put(f"/sites/{site_id}/firewall/policies/{policy_id}", json=data)

    def delete_firewall_policy(self, site_id: str, policy_id: str) -> dict:
        """Delete a firewall policy."""
        return self._delete(f"/sites/{site_id}/firewall/policies/{policy_id}")

    # -------------------------------------------------------------------------
    # Policy ordering endpoint (v10.1.84+)
    # -------------------------------------------------------------------------

    def get_firewall_policy_ordering(
        self,
        site_id: str,
        source_zone_id: str,
        dest_zone_id: str,
    ) -> dict:
        """Get the user-defined firewall policy evaluation order.

        Retrieves the ordering of user-defined policies for a specific
        source → destination zone pair. System-defined policies are
        separate and can be placed before or after user-defined ones
        via ``beforeSystemDefined`` / ``afterSystemDefined`` keys.

        Args:
            site_id:        UUID of the target site.
            source_zone_id: UUID of the source firewall zone.
            dest_zone_id:   UUID of the destination firewall zone.

        Returns:
            Dict with ``orderedFirewallPolicyIds`` key containing::

                {
                    "orderedFirewallPolicyIds": {
                        "beforeSystemDefined": ["uuid-1", "uuid-2"],
                        "afterSystemDefined":  ["uuid-3"]
                    }
                }
        """
        params = {
            "sourceFirewallZoneId": source_zone_id,
            "destinationFirewallZoneId": dest_zone_id,
        }
        return self._get(f"/sites/{site_id}/firewall/policies/ordering", params=params)

    def set_firewall_policy_ordering(
        self,
        site_id: str,
        source_zone_id: str,
        dest_zone_id: str,
        before_system: list,
        after_system: list,
    ) -> dict:
        """Set the user-defined firewall policy evaluation order.

        Sets ordering for policies matching a specific source → destination
        zone pair. Policies in ``before_system`` are evaluated before
        system-defined policies; policies in ``after_system`` are evaluated
        after.

        The ``index`` field on individual policies is deprecated in
        API v10.1.84 — use this method to control evaluation order.

        Args:
            site_id:        UUID of the target site.
            source_zone_id: UUID of the source firewall zone.
            dest_zone_id:   UUID of the destination firewall zone.
            before_system:  Ordered list of policy UUIDs evaluated BEFORE
                            system-defined policies.
            after_system:   Ordered list of policy UUIDs evaluated AFTER
                            system-defined policies.

        Returns:
            Dict with ``orderedFirewallPolicyIds`` reflecting the saved order.

        Example::

            client.set_firewall_policy_ordering(
                site_id,
                source_zone_id="wan-zone-uuid",
                dest_zone_id="lan-zone-uuid",
                before_system=["block-malware-uuid", "allow-https-uuid"],
                after_system=["log-all-uuid"],
            )
        """
        params = {
            "sourceFirewallZoneId": source_zone_id,
            "destinationFirewallZoneId": dest_zone_id,
        }
        body = {
            "orderedFirewallPolicyIds": {
                "beforeSystemDefined": before_system,
                "afterSystemDefined": after_system,
            }
        }
        return self._put(
            f"/sites/{site_id}/firewall/policies/ordering",
            params=params,
            json=body,
        )

    # -------------------------------------------------------------------------
    # Partial update (PATCH)
    # -------------------------------------------------------------------------

    def patch_firewall_policy(
        self, site_id: str, policy_id: str, fields: dict
    ) -> dict:
        """Partially update a firewall policy (PATCH).

        Unlike :meth:`update_firewall_policy` (PUT, full replacement), PATCH
        applies only the supplied fields without requiring the full policy
        body. Use this to update individual fields — e.g., toggle logging —
        without re-fetching and re-submitting the entire resource.

        Per the OpenAPI spec (v10.1.84), currently supported patch fields:

        - ``loggingEnabled`` (bool) — enable or disable per-policy logging

        The client passes ``fields`` through as-is; additional fields accepted
        by the controller will also work.

        Args:
            site_id:   UUID of the target site.
            policy_id: UUID of the firewall policy to patch.
            fields:    Dict of fields to update (partial payload).

        Returns:
            Full updated firewall policy dict (controller returns the complete
            resource after PATCH).

        Example::

            # Disable logging without touching other fields
            client.patch_firewall_policy(site_id, policy_id, {"loggingEnabled": False})
        """
        return self._patch(
            f"/sites/{site_id}/firewall/policies/{policy_id}", json=fields
        )
