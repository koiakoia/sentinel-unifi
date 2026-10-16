"""Unit tests for AclMixin ordering methods and deprecation warnings.

Tests cover:
- get_acl_rules_ordering: correct GET path
- set_acl_rules_ordering: correct PUT path + body shape
- create_acl_rule: DeprecationWarning fired when 'index' key present
- update_acl_rule: DeprecationWarning fired when 'index' key present
- create_acl_rule / update_acl_rule: no warning when 'index' absent
"""

import warnings
import unittest

from unifi.acl import AclMixin


# ---------------------------------------------------------------------------
# Minimal concrete client stub for testing
# ---------------------------------------------------------------------------

class _FakeClient(AclMixin):
    """Minimal client stub: mixin methods + stubbed HTTP helpers."""

    def __init__(self):
        self._get_calls = []
        self._post_calls = []
        self._put_calls = []
        self._delete_calls = []
        self._paginate_calls = []

    def _get(self, path, **kwargs):
        self._get_calls.append((path, kwargs))
        return {"orderedAclRuleIds": []}

    def _post(self, path, **kwargs):
        self._post_calls.append((path, kwargs))
        return {"id": "new-rule-id"}

    def _put(self, path, **kwargs):
        self._put_calls.append((path, kwargs))
        return {"orderedAclRuleIds": []}

    def _delete(self, path, **kwargs):
        self._delete_calls.append((path, kwargs))
        return {}

    def _paginate(self, path, **kwargs):
        self._paginate_calls.append((path, kwargs))
        return []


SITE_ID = "aaaaaaaa-0000-0000-0000-000000000001"
RULE_ID = "cccccccc-0000-0000-0000-000000000003"


class TestAclOrdering(unittest.TestCase):
    """Tests for the new get/set ordering methods."""

    def setUp(self):
        self.client = _FakeClient()

    def test_get_ordering_calls_get(self):
        self.client.get_acl_rules_ordering(SITE_ID)
        self.assertEqual(len(self.client._get_calls), 1)
        path, _ = self.client._get_calls[0]
        self.assertIn(SITE_ID, path)
        self.assertIn("acl-rules/ordering", path)

    def test_set_ordering_calls_put(self):
        ordered = ["uuid-1", "uuid-2", "uuid-3"]
        self.client.set_acl_rules_ordering(SITE_ID, ordered)
        self.assertEqual(len(self.client._put_calls), 1)
        path, kwargs = self.client._put_calls[0]
        self.assertIn(SITE_ID, path)
        self.assertIn("acl-rules/ordering", path)
        self.assertEqual(kwargs["json"], {"orderedAclRuleIds": ordered})

    def test_set_ordering_empty_list_accepted(self):
        """Empty list is a valid value — API enforces constraints, not client."""
        self.client.set_acl_rules_ordering(SITE_ID, [])
        path, kwargs = self.client._put_calls[0]
        self.assertEqual(kwargs["json"]["orderedAclRuleIds"], [])

    def test_ordering_path_distinct_from_rule_crud(self):
        """Ordering endpoint path must differ from single-rule path."""
        self.client.get_acl_rules_ordering(SITE_ID)
        path, _ = self.client._get_calls[0]
        self.assertTrue(path.endswith("/ordering"), f"Path should end with /ordering, got: {path}")


class TestAclIndexDeprecationWarning(unittest.TestCase):
    """Tests for DeprecationWarning when 'index' key is passed."""

    def setUp(self):
        self.client = _FakeClient()

    # --- create_acl_rule ---

    def test_create_no_index_no_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.create_acl_rule(SITE_ID, {"name": "rule1", "action": "ALLOW"})
        dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
        self.assertEqual(len(dep_warnings), 0)

    def test_create_with_index_fires_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.create_acl_rule(SITE_ID, {"name": "rule1", "index": 5})
        dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
        self.assertEqual(len(dep_warnings), 1)
        self.assertIn("index", str(dep_warnings[0].message).lower())
        self.assertIn("deprecated", str(dep_warnings[0].message).lower())

    def test_create_with_index_still_sends_request(self):
        """Warning fires but the POST still happens."""
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            self.client.create_acl_rule(SITE_ID, {"name": "rule1", "index": 0})
        self.assertEqual(len(self.client._post_calls), 1)

    # --- update_acl_rule ---

    def test_update_no_index_no_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.update_acl_rule(SITE_ID, RULE_ID, {"name": "rule1"})
        dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
        self.assertEqual(len(dep_warnings), 0)

    def test_update_with_index_fires_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.update_acl_rule(SITE_ID, RULE_ID, {"name": "rule1", "index": 3})
        dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
        self.assertEqual(len(dep_warnings), 1)
        self.assertIn("set_acl_rules_ordering", str(dep_warnings[0].message))

    def test_update_with_index_still_sends_request(self):
        """Warning fires but the PUT still happens."""
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            self.client.update_acl_rule(SITE_ID, RULE_ID, {"name": "rule1", "index": 1})
        self.assertEqual(len(self.client._put_calls), 1)


if __name__ == "__main__":
    unittest.main()
