"""ACL rule management mixin for the UniFi API client."""

import warnings


class AclMixin:
    """Mixin providing ACL rule API methods."""

    def list_acl_rules(self, site_id: str) -> list:
        """List all ACL rules for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/acl-rules")

    def get_acl_rule(self, site_id: str, rule_id: str) -> dict:
        """Get a single ACL rule by ID."""
        return self._get(f"/sites/{site_id}/acl-rules/{rule_id}")

    def create_acl_rule(self, site_id: str, data: dict) -> dict:
        """Create a new ACL rule.

        .. deprecated::
            The ``index`` field in ``data`` has no effect in API v10.1.84+.
            Use :meth:`set_acl_rules_ordering` to control rule evaluation order.

        Args:
            site_id: UUID of the target site.
            data:    ACL rule payload dict.

        Returns:
            Created ACL rule dict.
        """
        if "index" in data:
            warnings.warn(
                "The 'index' field in ACL rule payloads is deprecated as of "
                "UniFi Network Integration API v10.1.84 and has no effect. "
                "Use set_acl_rules_ordering() to control rule evaluation order.",
                DeprecationWarning,
                stacklevel=2,
            )
        return self._post(f"/sites/{site_id}/acl-rules", json=data)

    def update_acl_rule(self, site_id: str, rule_id: str, data: dict) -> dict:
        """Update an existing ACL rule.

        .. deprecated::
            The ``index`` field in ``data`` has no effect in API v10.1.84+.
            Use :meth:`set_acl_rules_ordering` to control rule evaluation order.

        Args:
            site_id: UUID of the target site.
            rule_id: UUID of the ACL rule to update.
            data:    ACL rule payload dict.

        Returns:
            Updated ACL rule dict.
        """
        if "index" in data:
            warnings.warn(
                "The 'index' field in ACL rule payloads is deprecated as of "
                "UniFi Network Integration API v10.1.84 and has no effect. "
                "Use set_acl_rules_ordering() to control rule evaluation order.",
                DeprecationWarning,
                stacklevel=2,
            )
        return self._put(f"/sites/{site_id}/acl-rules/{rule_id}", json=data)

    def delete_acl_rule(self, site_id: str, rule_id: str) -> dict:
        """Delete an ACL rule."""
        return self._delete(f"/sites/{site_id}/acl-rules/{rule_id}")

    # -------------------------------------------------------------------------
    # Ordering endpoint (v10.1.84+)
    # -------------------------------------------------------------------------

    def get_acl_rules_ordering(self, site_id: str) -> dict:
        """Get the user-defined ACL rule evaluation order for a site.

        Returns the ordered list of ACL rule UUIDs. Rules are evaluated in
        the order specified by ``orderedAclRuleIds``. Note: the ``index``
        field on individual ACL rules is deprecated — use this endpoint to
        read and set evaluation order.

        Args:
            site_id: UUID of the target site.

        Returns:
            Dict with key ``orderedAclRuleIds`` (list of UUID strings).

            Example::

                {"orderedAclRuleIds": ["uuid-1", "uuid-2", "uuid-3"]}
        """
        return self._get(f"/sites/{site_id}/acl-rules/ordering")

    def set_acl_rules_ordering(self, site_id: str, ordered_ids: list) -> dict:
        """Set the user-defined ACL rule evaluation order for a site.

        Replaces the current ordering with the provided list of rule UUIDs.
        All active rule UUIDs for the site should be included; rules omitted
        from the list may be placed in an undefined position by the controller.

        The ``index`` field on individual ACL rules is deprecated as of
        v10.1.84; use this method to control rule evaluation order instead.

        Args:
            site_id:     UUID of the target site.
            ordered_ids: Ordered list of ACL rule UUID strings. First entry
                         is evaluated first.

        Returns:
            Dict with key ``orderedAclRuleIds`` reflecting the saved order.

        Example::

            client.set_acl_rules_ordering(site_id, [
                "uuid-block-malware",
                "uuid-allow-internal",
                "uuid-default-deny",
            ])
        """
        return self._put(
            f"/sites/{site_id}/acl-rules/ordering",
            json={"orderedAclRuleIds": ordered_ids},
        )
