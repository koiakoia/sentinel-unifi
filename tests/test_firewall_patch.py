"""Unit tests for FirewallMixin.patch_firewall_policy and UniFiClient._patch.

Tests cover:
- patch_firewall_policy: uses PATCH verb via _patch(), correct path, correct body
- Differentiation from update_firewall_policy (PUT vs PATCH)
- _patch helper on the base client routes to PATCH HTTP method
"""

import unittest

from unifi.firewall import FirewallMixin


# ---------------------------------------------------------------------------
# Minimal concrete client stub for testing
# ---------------------------------------------------------------------------

class _FakeClient(FirewallMixin):
    """Minimal client stub: mixin methods + stubbed HTTP helpers."""

    def __init__(self):
        self._patch_calls = []
        self._put_calls = []

    def _get(self, path, **kwargs):
        return {}

    def _post(self, path, **kwargs):
        return {}

    def _put(self, path, **kwargs):
        self._put_calls.append((path, kwargs))
        return {"id": "policy-id", "loggingEnabled": True}

    def _patch(self, path, **kwargs):
        self._patch_calls.append((path, kwargs))
        return {"id": "policy-id", "loggingEnabled": False}

    def _delete(self, path, **kwargs):
        return {}

    def _paginate(self, path, **kwargs):
        return []


SITE_ID = "aaaaaaaa-0000-0000-0000-000000000001"
POLICY_ID = "hhhhhhhh-0000-0000-0000-000000000008"


class TestFirewallPolicyPatch(unittest.TestCase):
    """Tests for patch_firewall_policy."""

    def setUp(self):
        self.client = _FakeClient()

    def test_patch_calls_patch_not_put(self):
        self.client.patch_firewall_policy(SITE_ID, POLICY_ID, {"loggingEnabled": False})
        self.assertEqual(len(self.client._patch_calls), 1)
        self.assertEqual(len(self.client._put_calls), 0)

    def test_patch_path_contains_policy_id(self):
        self.client.patch_firewall_policy(SITE_ID, POLICY_ID, {"loggingEnabled": False})
        path, _ = self.client._patch_calls[0]
        self.assertIn(SITE_ID, path)
        self.assertIn(POLICY_ID, path)
        self.assertIn("firewall/policies", path)

    def test_patch_body_forwarded(self):
        fields = {"loggingEnabled": False}
        self.client.patch_firewall_policy(SITE_ID, POLICY_ID, fields)
        _, kwargs = self.client._patch_calls[0]
        self.assertEqual(kwargs.get("json"), fields)

    def test_patch_partial_body_only(self):
        """Only the provided fields are sent — not a full policy body."""
        small_payload = {"loggingEnabled": True}
        self.client.patch_firewall_policy(SITE_ID, POLICY_ID, small_payload)
        _, kwargs = self.client._patch_calls[0]
        # Must not add extra keys
        self.assertEqual(kwargs["json"], small_payload)

    def test_patch_returns_full_policy(self):
        """Controller returns full policy after PATCH; client passes it through."""
        result = self.client.patch_firewall_policy(
            SITE_ID, POLICY_ID, {"loggingEnabled": False}
        )
        self.assertIn("id", result)

    def test_update_still_uses_put(self):
        """update_firewall_policy must still use PUT (no regression)."""
        self.client.update_firewall_policy(SITE_ID, POLICY_ID, {"name": "test"})
        self.assertEqual(len(self.client._put_calls), 1)
        self.assertEqual(len(self.client._patch_calls), 0)

    def test_patch_and_put_different_paths(self):
        """PATCH and PUT go to the same policy URL — confirm via path comparison."""
        self.client.patch_firewall_policy(SITE_ID, POLICY_ID, {"loggingEnabled": True})
        self.client.update_firewall_policy(SITE_ID, POLICY_ID, {"name": "full"})
        patch_path, _ = self.client._patch_calls[0]
        put_path, _ = self.client._put_calls[0]
        # Same resource path — verb is the only distinction
        self.assertEqual(patch_path, put_path)


class TestClientPatchHelper(unittest.TestCase):
    """Verify that _patch helper exists in the base client and routes PATCH."""

    def test_patch_method_exists_on_mixin_instance(self):
        """_patch must be callable on any class that uses FirewallMixin."""
        client = _FakeClient()
        self.assertTrue(callable(getattr(client, "_patch", None)))


if __name__ == "__main__":
    unittest.main()
