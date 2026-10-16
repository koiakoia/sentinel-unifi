"""Unit tests for TrafficMatchingMixin (unifi/traffic_matching.py).

Tests cover:
- _validate_tml_payload: valid payloads, missing fields, invalid list type,
  mixed-type item rejection for each list type.
- TrafficMatchingMixin methods: HTTP verb/path routing verified via mock.
"""

import unittest

from unifi.traffic_matching import TrafficMatchingMixin, _validate_tml_payload


# ---------------------------------------------------------------------------
# Minimal concrete class to test the mixin without a full UniFiClient
# ---------------------------------------------------------------------------

class _FakeClient(TrafficMatchingMixin):
    """Minimal client stub: mixin methods + stubbed HTTP helpers."""

    def __init__(self):
        self._get_calls = []
        self._post_calls = []
        self._put_calls = []
        self._delete_calls = []
        self._paginate_calls = []

    def _get(self, path, **kwargs):
        self._get_calls.append((path, kwargs))
        return {"id": "fake-id", "type": "PORTS", "name": "test", "items": []}

    def _post(self, path, **kwargs):
        self._post_calls.append((path, kwargs))
        return {"id": "new-id", "type": "PORTS", "name": "test", "items": []}

    def _put(self, path, **kwargs):
        self._put_calls.append((path, kwargs))
        return {"id": "fake-id", "type": "PORTS", "name": "test", "items": []}

    def _delete(self, path, **kwargs):
        self._delete_calls.append((path, kwargs))
        return {}

    def _paginate(self, path, **kwargs):
        self._paginate_calls.append((path, kwargs))
        return []


SITE_ID = "aaaaaaaa-0000-0000-0000-000000000001"
TML_ID = "bbbbbbbb-0000-0000-0000-000000000002"


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------

class TestValidateTmlPayload(unittest.TestCase):
    """Tests for the _validate_tml_payload helper."""

    # --- Valid payloads ---

    def test_valid_ports_single(self):
        _validate_tml_payload({
            "type": "PORTS",
            "name": "web-ports",
            "items": [{"type": "PORT_NUMBER", "value": 443}],
        })

    def test_valid_ports_range(self):
        _validate_tml_payload({
            "type": "PORTS",
            "name": "ephemeral",
            "items": [{"type": "PORT_NUMBER_RANGE", "start": 1024, "stop": 65535}],
        })

    def test_valid_ports_mixed_subtypes(self):
        """PORT_NUMBER and PORT_NUMBER_RANGE are both valid in a PORTS list."""
        _validate_tml_payload({
            "type": "PORTS",
            "name": "mixed-ports",
            "items": [
                {"type": "PORT_NUMBER", "value": 80},
                {"type": "PORT_NUMBER_RANGE", "start": 8000, "stop": 8010},
            ],
        })

    def test_valid_ipv4_all_subtypes(self):
        _validate_tml_payload({
            "type": "IPV4_ADDRESSES",
            "name": "trusted",
            "items": [
                {"type": "IP_ADDRESS", "value": "<INTERNAL_IP>"},
                {"type": "SUBNET", "value": "<INTERNAL_IP>/8"},
                {"type": "IP_ADDRESS_RANGE", "start": "172.16.0.1", "stop": "172.16.0.50"},
            ],
        })

    def test_valid_ipv6_all_subtypes(self):
        _validate_tml_payload({
            "type": "IPV6_ADDRESSES",
            "name": "ipv6-hosts",
            "items": [
                {"type": "IP_ADDRESS", "value": "2001:db8::1"},
                {"type": "SUBNET", "value": "2001:db8:1::/64"},
            ],
        })

    def test_valid_no_items_key(self):
        """Payload without 'items' key is not rejected client-side (API enforces minItems)."""
        _validate_tml_payload({"type": "PORTS", "name": "no-items-yet"})

    def test_valid_empty_items(self):
        """Empty items list passes client validation (API enforces minItems: 1)."""
        _validate_tml_payload({"type": "IPV4_ADDRESSES", "name": "empty", "items": []})

    # --- Invalid list type ---

    def test_invalid_list_type_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_tml_payload({"type": "FQDN", "name": "bad", "items": []})
        self.assertIn("FQDN", str(ctx.exception))

    def test_missing_type_raises(self):
        with self.assertRaises(ValueError):
            _validate_tml_payload({"name": "no-type", "items": []})

    def test_none_type_raises(self):
        with self.assertRaises(ValueError):
            _validate_tml_payload({"type": None, "name": "no-type", "items": []})

    # --- Missing / empty name ---

    def test_missing_name_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_tml_payload({"type": "PORTS", "items": []})
        self.assertIn("name", str(ctx.exception))

    def test_empty_name_raises(self):
        with self.assertRaises(ValueError):
            _validate_tml_payload({"type": "PORTS", "name": "", "items": []})

    def test_whitespace_name_raises(self):
        with self.assertRaises(ValueError):
            _validate_tml_payload({"type": "PORTS", "name": "   ", "items": []})

    # --- Mixed-type item rejection ---

    def test_port_item_in_ipv4_list_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_tml_payload({
                "type": "IPV4_ADDRESSES",
                "name": "bad-mix",
                "items": [{"type": "PORT_NUMBER", "value": 80}],
            })
        self.assertIn("PORT_NUMBER", str(ctx.exception))

    def test_ipv4_range_item_in_ports_list_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_tml_payload({
                "type": "PORTS",
                "name": "bad-mix",
                "items": [{"type": "IP_ADDRESS_RANGE", "start": "1.2.3.4", "stop": "1.2.3.5"}],
            })
        self.assertIn("IP_ADDRESS_RANGE", str(ctx.exception))

    def test_ipv4_range_item_in_ipv6_list_raises(self):
        """IP_ADDRESS_RANGE is only valid for IPV4_ADDRESSES lists."""
        with self.assertRaises(ValueError) as ctx:
            _validate_tml_payload({
                "type": "IPV6_ADDRESSES",
                "name": "bad-mix",
                "items": [{"type": "IP_ADDRESS_RANGE", "start": "1.2.3.4", "stop": "1.2.3.5"}],
            })
        self.assertIn("IP_ADDRESS_RANGE", str(ctx.exception))

    def test_port_range_in_ipv6_list_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_tml_payload({
                "type": "IPV6_ADDRESSES",
                "name": "bad",
                "items": [{"type": "PORT_NUMBER_RANGE", "start": 80, "stop": 8080}],
            })
        self.assertIn("PORT_NUMBER_RANGE", str(ctx.exception))

    def test_mixed_items_error_lists_all_bad(self):
        """ValueError message should enumerate all invalid items, not just the first."""
        with self.assertRaises(ValueError) as ctx:
            _validate_tml_payload({
                "type": "PORTS",
                "name": "multi-bad",
                "items": [
                    {"type": "PORT_NUMBER", "value": 80},       # valid
                    {"type": "IP_ADDRESS", "value": "<INTERNAL_IP>"},  # invalid
                    {"type": "SUBNET", "value": "<INTERNAL_IP>/24"},  # invalid
                ],
            })
        msg = str(ctx.exception)
        self.assertIn("item[1]", msg)
        self.assertIn("item[2]", msg)


# ---------------------------------------------------------------------------
# Mixin HTTP routing tests
# ---------------------------------------------------------------------------

class TestTrafficMatchingMixinRouting(unittest.TestCase):
    """Verify that mixin methods call the correct HTTP verbs and URL paths."""

    def setUp(self):
        self.client = _FakeClient()

    def test_list_calls_paginate(self):
        self.client.list_traffic_matching_lists(SITE_ID)
        self.assertEqual(len(self.client._paginate_calls), 1)
        path, _ = self.client._paginate_calls[0]
        self.assertIn(SITE_ID, path)
        self.assertIn("traffic-matching-lists", path)

    def test_get_calls_get(self):
        self.client.get_traffic_matching_list(SITE_ID, TML_ID)
        self.assertEqual(len(self.client._get_calls), 1)
        path, _ = self.client._get_calls[0]
        self.assertIn(TML_ID, path)
        self.assertIn("traffic-matching-lists", path)

    def test_create_calls_post(self):
        data = {
            "type": "PORTS",
            "name": "test-list",
            "items": [{"type": "PORT_NUMBER", "value": 443}],
        }
        self.client.create_traffic_matching_list(SITE_ID, data)
        self.assertEqual(len(self.client._post_calls), 1)
        path, kwargs = self.client._post_calls[0]
        self.assertIn(SITE_ID, path)
        self.assertIn("traffic-matching-lists", path)
        self.assertNotIn(TML_ID, path)
        self.assertEqual(kwargs["json"], data)

    def test_create_validation_fires_before_post(self):
        """Invalid payload raises ValueError and no POST is made."""
        with self.assertRaises(ValueError):
            self.client.create_traffic_matching_list(SITE_ID, {"type": "INVALID", "name": "x"})
        self.assertEqual(len(self.client._post_calls), 0)

    def test_update_calls_put(self):
        data = {
            "type": "IPV4_ADDRESSES",
            "name": "updated",
            "items": [{"type": "SUBNET", "value": "<INTERNAL_IP>/8"}],
        }
        self.client.update_traffic_matching_list(SITE_ID, TML_ID, data)
        self.assertEqual(len(self.client._put_calls), 1)
        path, kwargs = self.client._put_calls[0]
        self.assertIn(TML_ID, path)
        self.assertEqual(kwargs["json"], data)

    def test_update_validation_fires_before_put(self):
        bad_data = {
            "type": "PORTS",
            "name": "bad",
            "items": [{"type": "IP_ADDRESS", "value": "1.2.3.4"}],
        }
        with self.assertRaises(ValueError):
            self.client.update_traffic_matching_list(SITE_ID, TML_ID, bad_data)
        self.assertEqual(len(self.client._put_calls), 0)

    def test_delete_calls_delete(self):
        self.client.delete_traffic_matching_list(SITE_ID, TML_ID)
        self.assertEqual(len(self.client._delete_calls), 1)
        path, _ = self.client._delete_calls[0]
        self.assertIn(TML_ID, path)
        self.assertIn("traffic-matching-lists", path)

    def test_delete_no_validation(self):
        """delete does not require a payload — no ValueError possible."""
        self.client.delete_traffic_matching_list(SITE_ID, TML_ID)  # should not raise
        self.assertEqual(len(self.client._delete_calls), 1)


if __name__ == "__main__":
    unittest.main()
