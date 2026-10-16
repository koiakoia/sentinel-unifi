"""Traffic Matching List management mixin for the UniFi API client.

Traffic Matching Lists (TMLs) are named collections of IP addresses, subnets,
IP ranges, or port numbers/ranges. Firewall policies reference TMLs by ID to
define reusable, policy-as-code traffic selectors.

TML types (``type`` discriminator field):

- ``PORTS``          — port numbers and ranges
- ``IPV4_ADDRESSES`` — IPv4 addresses, subnets (CIDR), or address ranges
- ``IPV6_ADDRESSES`` — IPv6 addresses or subnets (CIDR)

Each type has its own valid item subtypes. Mixing item types across list types
is rejected at the client layer before sending to the controller.

Item subtypes by list type
--------------------------

PORTS items:
    - ``{"type": "PORT_NUMBER", "value": <1-65535>}``
    - ``{"type": "PORT_NUMBER_RANGE", "start": <int>, "stop": <int>}``

IPV4_ADDRESSES items:
    - ``{"type": "IP_ADDRESS", "value": "<INTERNAL_IP>"}``
    - ``{"type": "SUBNET", "value": "<INTERNAL_IP>/24"}``
    - ``{"type": "IP_ADDRESS_RANGE", "start": "<INTERNAL_IP>", "stop": "<INTERNAL_IP>"}``

IPV6_ADDRESSES items:
    - ``{"type": "IP_ADDRESS", "value": "2001:db8::1"}``
    - ``{"type": "SUBNET", "value": "2001:db8:1::/64"}``
"""

# Valid item type → expected list type mapping.
# Used to validate that items belong to the declared list type before POST/PUT.
_ITEM_TYPE_TO_LIST_TYPE = {
    # PORTS list item subtypes
    "PORT_NUMBER": "PORTS",
    "PORT_NUMBER_RANGE": "PORTS",
    # IPV4 list item subtypes
    "IP_ADDRESS": None,          # shared between IPV4 and IPV6 — checked via list type
    "SUBNET": None,              # shared between IPV4 and IPV6 — checked via list type
    "IP_ADDRESS_RANGE": "IPV4_ADDRESSES",  # range only in IPv4
}

_VALID_PORTS_ITEM_TYPES = {"PORT_NUMBER", "PORT_NUMBER_RANGE"}
_VALID_IPV4_ITEM_TYPES = {"IP_ADDRESS", "SUBNET", "IP_ADDRESS_RANGE"}
_VALID_IPV6_ITEM_TYPES = {"IP_ADDRESS", "SUBNET"}

_VALID_LIST_TYPES = {"PORTS", "IPV4_ADDRESSES", "IPV6_ADDRESSES"}

_LIST_TYPE_TO_VALID_ITEMS = {
    "PORTS": _VALID_PORTS_ITEM_TYPES,
    "IPV4_ADDRESSES": _VALID_IPV4_ITEM_TYPES,
    "IPV6_ADDRESSES": _VALID_IPV6_ITEM_TYPES,
}


def _validate_tml_payload(data: dict) -> None:
    """Validate a TML create/update payload before sending to the controller.

    Raises ``ValueError`` if:
    - ``type`` is missing or not one of PORTS / IPV4_ADDRESSES / IPV6_ADDRESSES
    - ``name`` is missing or empty
    - ``items`` are present and contain any item whose ``type`` is not valid
      for the declared list ``type`` (mixed-type rejection)

    Args:
        data: Dict payload for create or update request.

    Raises:
        ValueError: If the payload violates TML schema rules.
    """
    list_type = data.get("type")
    if list_type not in _VALID_LIST_TYPES:
        raise ValueError(
            f"Invalid or missing TML type {data.get('type')!r}. "
            f"Must be one of: {', '.join(sorted(_VALID_LIST_TYPES))}"
        )

    name = data.get("name", "")
    if not name or not name.strip():
        raise ValueError("TML 'name' field is required and must be non-empty.")

    items = data.get("items", [])
    if not items:
        # Empty items list; controller enforces minItems: 1 — let API surface that.
        return

    valid_item_types = _LIST_TYPE_TO_VALID_ITEMS[list_type]
    bad = []
    for idx, item in enumerate(items):
        item_type = item.get("type")
        if item_type not in valid_item_types:
            bad.append(f"item[{idx}] type={item_type!r}")

    if bad:
        raise ValueError(
            f"Mixed-type items detected in {list_type!r} TML. "
            f"Valid item types are {sorted(valid_item_types)}. "
            f"Invalid items: {bad}"
        )


class TrafficMatchingMixin:
    """Mixin providing Traffic Matching List (TML) API methods.

    TMLs are referenced by firewall policies via ``trafficMatchingListId``.
    They enable policy-as-code patterns for reusable traffic selectors.
    """

    # -------------------------------------------------------------------------
    # List / Collection endpoints
    # -------------------------------------------------------------------------

    def list_traffic_matching_lists(self, site_id: str) -> list:
        """List all Traffic Matching Lists for a site (auto-paginated).

        Args:
            site_id: UUID of the target site.

        Returns:
            List of TML dicts. Each dict has at minimum: ``id``, ``name``,
            ``type``, and ``items``.
        """
        return self._paginate(f"/sites/{site_id}/traffic-matching-lists")

    def get_traffic_matching_list(self, site_id: str, tml_id: str) -> dict:
        """Get a single Traffic Matching List by ID.

        Args:
            site_id: UUID of the target site.
            tml_id:  UUID of the Traffic Matching List.

        Returns:
            TML dict with ``id``, ``name``, ``type``, and ``items``.
        """
        return self._get(f"/sites/{site_id}/traffic-matching-lists/{tml_id}")

    def create_traffic_matching_list(self, site_id: str, data: dict) -> dict:
        """Create a new Traffic Matching List.

        The ``data`` payload must include:
        - ``type``  (str)  — ``PORTS``, ``IPV4_ADDRESSES``, or ``IPV6_ADDRESSES``
        - ``name``  (str)  — non-empty human-readable name
        - ``items`` (list) — at least one item dict; all items must be valid
          for the declared ``type`` (mixed-type items are rejected client-side)

        Example — port list::

            client.create_traffic_matching_list(site_id, {
                "type": "PORTS",
                "name": "web-ports",
                "items": [
                    {"type": "PORT_NUMBER", "value": 80},
                    {"type": "PORT_NUMBER", "value": 443},
                    {"type": "PORT_NUMBER_RANGE", "start": 8080, "stop": 8090},
                ],
            })

        Example — IPv4 list::

            client.create_traffic_matching_list(site_id, {
                "type": "IPV4_ADDRESSES",
                "name": "trusted-hosts",
                "items": [
                    {"type": "IP_ADDRESS", "value": "<INTERNAL_IP>"},
                    {"type": "SUBNET", "value": "<INTERNAL_IP>/8"},
                    {"type": "IP_ADDRESS_RANGE", "start": "172.16.0.1", "stop": "172.16.0.50"},
                ],
            })

        Args:
            site_id: UUID of the target site.
            data:    TML payload dict (see above).

        Returns:
            Created TML dict with ``id`` assigned by the controller.

        Raises:
            ValueError: If ``type``, ``name``, or item types are invalid.
        """
        _validate_tml_payload(data)
        return self._post(f"/sites/{site_id}/traffic-matching-lists", json=data)

    def update_traffic_matching_list(self, site_id: str, tml_id: str, data: dict) -> dict:
        """Replace an existing Traffic Matching List (full PUT replacement).

        The ``data`` payload follows the same rules as
        :meth:`create_traffic_matching_list`.

        Args:
            site_id: UUID of the target site.
            tml_id:  UUID of the Traffic Matching List to update.
            data:    Full TML payload dict (``type``, ``name``, ``items``).

        Returns:
            Updated TML dict.

        Raises:
            ValueError: If ``type``, ``name``, or item types are invalid.
        """
        _validate_tml_payload(data)
        return self._put(
            f"/sites/{site_id}/traffic-matching-lists/{tml_id}", json=data
        )

    def delete_traffic_matching_list(self, site_id: str, tml_id: str) -> dict:
        """Delete a Traffic Matching List.

        .. warning::
            Deleting a TML that is referenced by active firewall policies will
            leave those policies with a dangling reference. Check policy
            references before deletion.

        Args:
            site_id: UUID of the target site.
            tml_id:  UUID of the Traffic Matching List to delete.

        Returns:
            Empty dict (204 / no-content response).
        """
        return self._delete(
            f"/sites/{site_id}/traffic-matching-lists/{tml_id}"
        )
