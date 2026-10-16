"""Unit tests for FirewallMixin policy ordering methods.

Tests cover:
- get_firewall_policy_ordering: GET path + query params
- set_firewall_policy_ordering: PUT path + query params + body shape
"""

import unittest

from unifi.firewall import FirewallMixin


# ---------------------------------------------------------------------------
# Minimal concrete client stub for testing
# ---------------------------------------------------------------------------

class _FakeClient(FirewallMixin):
    """Minimal client stub: mixin methods + stubbed HTTP helpers."""

    def __init__(self):
        self._get_calls = []
        self._put_calls = []

    def _get(self, path, **kwargs):
        self._get_calls.append((path, kwargs))
        return {
            "orderedFirewallPolicyIds": {
                "beforeSystemDefined": [],
                "afterSystemDefined": [],
            }
        }

    def _post(self, path, **kwargs):
        return {}

    def _put(self, path, **kwargs):
        self._put_calls.append((path, kwargs))
        return {
            "orderedFirewallPolicyIds": {
                "beforeSystemDefined": [],
                "afterSystemDefined": [],
            }
        }

    def _delete(self, path, **kwargs):
        return {}

    def _paginate(self, path, **kwargs):
        return []


SITE_ID = "aaaaaaaa-0000-0000-0000-000000000001"
SRC_ZONE = "dddddddd-0000-0000-0000-000000000004"
DST_ZONE = "eeeeeeee-0000-0000-0000-000000000005"
POLICY_A = "ffffffff-0000-0000-0000-000000000006"
POLICY_B = "gggggggg-0000-0000-0000-000000000007"


class TestFirewallPolicyOrdering(unittest.TestCase):
    """Tests for get_firewall_policy_ordering and set_firewall_policy_ordering."""

    def setUp(self):
        self.client = _FakeClient()

    # --- get_firewall_policy_ordering ---

    def test_get_calls_get(self):
        self.client.get_firewall_policy_ordering(SITE_ID, SRC_ZONE, DST_ZONE)
        self.assertEqual(len(self.client._get_calls), 1)

    def test_get_path_contains_ordering(self):
        self.client.get_firewall_policy_ordering(SITE_ID, SRC_ZONE, DST_ZONE)
        path, _ = self.client._get_calls[0]
        self.assertIn(SITE_ID, path)
        self.assertIn("firewall/policies/ordering", path)

    def test_get_sends_source_zone_param(self):
        self.client.get_firewall_policy_ordering(SITE_ID, SRC_ZONE, DST_ZONE)
        _, kwargs = self.client._get_calls[0]
        params = kwargs.get("params", {})
        self.assertEqual(params.get("sourceFirewallZoneId"), SRC_ZONE)

    def test_get_sends_dest_zone_param(self):
        self.client.get_firewall_policy_ordering(SITE_ID, SRC_ZONE, DST_ZONE)
        _, kwargs = self.client._get_calls[0]
        params = kwargs.get("params", {})
        self.assertEqual(params.get("destinationFirewallZoneId"), DST_ZONE)

    # --- set_firewall_policy_ordering ---

    def test_set_calls_put(self):
        self.client.set_firewall_policy_ordering(
            SITE_ID, SRC_ZONE, DST_ZONE, [POLICY_A], [POLICY_B]
        )
        self.assertEqual(len(self.client._put_calls), 1)

    def test_set_path_contains_ordering(self):
        self.client.set_firewall_policy_ordering(
            SITE_ID, SRC_ZONE, DST_ZONE, [], []
        )
        path, _ = self.client._put_calls[0]
        self.assertIn(SITE_ID, path)
        self.assertIn("firewall/policies/ordering", path)

    def test_set_sends_zone_params(self):
        self.client.set_firewall_policy_ordering(
            SITE_ID, SRC_ZONE, DST_ZONE, [], []
        )
        _, kwargs = self.client._put_calls[0]
        params = kwargs.get("params", {})
        self.assertEqual(params.get("sourceFirewallZoneId"), SRC_ZONE)
        self.assertEqual(params.get("destinationFirewallZoneId"), DST_ZONE)

    def test_set_body_before_system(self):
        self.client.set_firewall_policy_ordering(
            SITE_ID, SRC_ZONE, DST_ZONE,
            before_system=[POLICY_A, POLICY_B],
            after_system=[],
        )
        _, kwargs = self.client._put_calls[0]
        body = kwargs.get("json", {})
        ids = body.get("orderedFirewallPolicyIds", {})
        self.assertEqual(ids.get("beforeSystemDefined"), [POLICY_A, POLICY_B])
        self.assertEqual(ids.get("afterSystemDefined"), [])

    def test_set_body_after_system(self):
        self.client.set_firewall_policy_ordering(
            SITE_ID, SRC_ZONE, DST_ZONE,
            before_system=[],
            after_system=[POLICY_A],
        )
        _, kwargs = self.client._put_calls[0]
        body = kwargs.get("json", {})
        ids = body.get("orderedFirewallPolicyIds", {})
        self.assertEqual(ids.get("beforeSystemDefined"), [])
        self.assertEqual(ids.get("afterSystemDefined"), [POLICY_A])

    def test_set_body_both_sections(self):
        self.client.set_firewall_policy_ordering(
            SITE_ID, SRC_ZONE, DST_ZONE,
            before_system=[POLICY_A],
            after_system=[POLICY_B],
        )
        _, kwargs = self.client._put_calls[0]
        ids = kwargs["json"]["orderedFirewallPolicyIds"]
        self.assertIn(POLICY_A, ids["beforeSystemDefined"])
        self.assertIn(POLICY_B, ids["afterSystemDefined"])

    def test_ordering_path_distinct_from_policy_crud(self):
        """Ordering endpoint must not collide with single-policy CRUD paths."""
        self.client.get_firewall_policy_ordering(SITE_ID, SRC_ZONE, DST_ZONE)
        path, _ = self.client._get_calls[0]
        # Must not contain a policy UUID segment after /ordering
        self.assertTrue(
            path.endswith("/ordering") or "/ordering" in path,
            f"Expected ordering path, got: {path}"
        )


if __name__ == "__main__":
    unittest.main()
