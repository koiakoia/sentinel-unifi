"""Hotspot voucher management mixin for the UniFi API client."""


class HotspotMixin:
    """Mixin providing hotspot voucher API methods."""

    def list_vouchers(self, site_id: str) -> list:
        """List all hotspot vouchers for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/hotspot/vouchers")

    def create_vouchers(self, site_id: str, data: dict) -> dict:
        """Create new hotspot vouchers."""
        return self._post(f"/sites/{site_id}/hotspot/vouchers", json=data)

    def delete_voucher(self, site_id: str, voucher_id: str) -> dict:
        """Delete a hotspot voucher."""
        return self._delete(f"/sites/{site_id}/hotspot/vouchers/{voucher_id}")
