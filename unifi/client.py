"""Core UniFi API client with auto-pagination and mixin composition."""

import os
import subprocess

import requests
import urllib3

from .acl import AclMixin
from .clients import ClientsMixin
from .devices import DevicesMixin
from .dns import DnsMixin
from .firewall import FirewallMixin
from .hotspot import HotspotMixin
from .networks import NetworksMixin
from .wifi import WiFiMixin

# Suppress warnings for self-signed certs on UCG-Fiber
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_BASE_URL = "https://192.168.1.1"
BASE_PATH = "/proxy/network/integration/v1"
DEFAULT_LIMIT = 200


class UniFiClient(
    DevicesMixin,
    ClientsMixin,
    NetworksMixin,
    WiFiMixin,
    FirewallMixin,
    DnsMixin,
    AclMixin,
    HotspotMixin,
):
    """UniFi Network Integration API client.

    Connects to the UniFi controller's integration API (v1) with API key auth.
    All list methods auto-paginate to return complete results.

    Usage:
        client = UniFiClient(api_key="your-key")
        sites = client.list_sites()
        devices = client.list_devices(sites[0]["id"])
    """

    def __init__(self, api_key: str, base_url: str = DEFAULT_BASE_URL, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.headers.update({
            "X-API-Key": api_key,
            "Accept": "application/json",
        })
        self._session.verify = self.verify_ssl

    @classmethod
    def from_env(cls) -> "UniFiClient":
        """Create a client from environment variables.

        Reads UNIFI_API_KEY (required) and UNIFI_CONTROLLER_URL (optional).
        """
        api_key = os.environ.get("UNIFI_API_KEY")
        if not api_key:
            raise ValueError("UNIFI_API_KEY environment variable is not set")
        base_url = os.environ.get("UNIFI_CONTROLLER_URL", DEFAULT_BASE_URL)
        return cls(api_key=api_key, base_url=base_url)

    @classmethod
    def from_vault(cls, vault_path: str = "secret/unifi", field: str = "api_key") -> "UniFiClient":
        """Create a client using an API key from HashiCorp Vault.

        Falls back to UNIFI_API_KEY env var if vault lookup fails.
        """
        api_key = None
        try:
            result = subprocess.run(
                ["vault", "kv", "get", "-field", field, vault_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                api_key = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if not api_key:
            api_key = os.environ.get("UNIFI_API_KEY")
        if not api_key:
            raise ValueError(f"Could not get API key from vault ({vault_path}) or UNIFI_API_KEY env var")

        base_url = os.environ.get("UNIFI_CONTROLLER_URL")
        if not base_url:
            try:
                result = subprocess.run(
                    ["vault", "kv", "get", "-field", "controller_url", vault_path],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    base_url = result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if not base_url:
            base_url = DEFAULT_BASE_URL
        return cls(api_key=api_key, base_url=base_url)

    def _url(self, path: str) -> str:
        """Build full URL from a path relative to the API version root."""
        return f"{self.base_url}{BASE_PATH}{path}"

    def _request(self, method: str, path: str, **kwargs) -> dict:
        """Make an authenticated API request and return the JSON response."""
        resp = self._session.request(method, self._url(path), **kwargs)
        resp.raise_for_status()
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    def _get(self, path: str, **kwargs) -> dict:
        """HTTP GET."""
        return self._request("GET", path, **kwargs)

    def _post(self, path: str, **kwargs) -> dict:
        """HTTP POST."""
        return self._request("POST", path, **kwargs)

    def _put(self, path: str, **kwargs) -> dict:
        """HTTP PUT."""
        return self._request("PUT", path, **kwargs)

    def _delete(self, path: str, **kwargs) -> dict:
        """HTTP DELETE."""
        return self._request("DELETE", path, **kwargs)

    def _paginate(self, path: str, **kwargs) -> list:
        """Auto-paginate a GET endpoint and return all items.

        Uses offset/limit query params. Iterates until a page returns
        fewer items than the limit (indicating the last page).
        """
        all_items = []
        offset = 0
        params = kwargs.pop("params", {})

        while True:
            page_params = {**params, "offset": offset, "limit": DEFAULT_LIMIT}
            resp = self._get(path, params=page_params, **kwargs)

            # API returns {"data": [...], "offset": N, "limit": N, "totalCount": N}
            items = resp.get("data", [])
            all_items.extend(items)

            if len(items) < DEFAULT_LIMIT:
                break
            offset += DEFAULT_LIMIT

        return all_items

    # --- Top-level endpoints (not site-scoped) ---

    def get_info(self) -> dict:
        """Get application/controller info."""
        return self._get("/info")

    def list_sites(self) -> list:
        """List all sites (auto-paginated)."""
        return self._paginate("/sites")

    # --- Site-scoped convenience: WANs & VPN ---

    def list_wans(self, site_id: str) -> list:
        """List WAN interfaces for a site (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/wans")

    def list_vpn_tunnels(self, site_id: str) -> list:
        """List site-to-site VPN tunnels (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/vpn/site-to-site-tunnels")

    def list_vpn_servers(self, site_id: str) -> list:
        """List VPN servers (auto-paginated)."""
        return self._paginate(f"/sites/{site_id}/vpn/servers")

    def client_action(self, site_id: str, client_id: str, data: dict) -> dict:
        """Perform an action on a client (e.g., reconnect, block)."""
        return self._post(f"/sites/{site_id}/clients/{client_id}/actions", json=data)
