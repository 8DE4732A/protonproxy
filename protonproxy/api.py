"""Proton API client with session management and automatic token refresh."""

import json
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests

# Configuration
BASE_URL = "https://account.proton.me/api/"
APP_VERSION = "browser-vpn@1.2.13"
CONFIG_FILE = Path.home() / ".protonproxy" / "session.json"


class ProtonAPIError(Exception):
    """Proton API error with code and message."""

    def __init__(self, code: int, message: str, http_status: int = 0):
        self.code = code
        self.message = message
        self.http_status = http_status
        super().__init__(f"[{code}] {message}")


class ProtonAPI:
    """Proton API client with session management."""

    def __init__(self):
        self.session = requests.Session()
        self.uid: Optional[str] = None
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self._load_session()

    def _load_session(self) -> None:
        """Load saved session from disk."""
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text())
                self.uid = data.get("uid")
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
            except (json.JSONDecodeError, KeyError):
                pass

    def save_session(self) -> None:
        """Save session to disk."""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(
            json.dumps(
                {
                    "uid": self.uid,
                    "access_token": self.access_token,
                    "refresh_token": self.refresh_token,
                }
            )
        )

    def clear_session(self) -> None:
        """Clear saved session."""
        self.uid = None
        self.access_token = None
        self.refresh_token = None
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()

    def is_logged_in(self) -> bool:
        """Check if user is logged in."""
        return bool(self.uid and self.access_token)

    def _get_headers(self, include_auth: bool = True) -> dict[str, str]:
        """Get request headers."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-pm-appversion": APP_VERSION,
        }
        if include_auth and self.uid and self.access_token:
            headers["x-pm-uid"] = self.uid
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    def request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
        include_auth: bool = True,
        retry_on_401: bool = True,
    ) -> dict[str, Any]:
        """Make API request with automatic token refresh."""
        url = urljoin(BASE_URL, endpoint)
        headers = self._get_headers(include_auth)

        if method.upper() == "GET":
            response = self.session.get(url, headers=headers, params=data)
        else:
            response = self.session.request(
                method, url, headers=headers, json=data
            )

        # Handle 401 - try token refresh
        if response.status_code == 401 and retry_on_401 and self.refresh_token:
            if self._refresh_access_token():
                return self.request(
                    method, endpoint, data, include_auth, retry_on_401=False
                )

        # Parse response
        try:
            result = response.json()
        except json.JSONDecodeError:
            raise ProtonAPIError(
                0, f"Invalid JSON response: {response.text[:200]}", response.status_code
            )

        # Check for API errors
        if response.status_code >= 400 or result.get("Code", 1000) != 1000:
            raise ProtonAPIError(
                result.get("Code", response.status_code),
                result.get("Error", response.reason),
                response.status_code,
            )

        return result

    def get(self, endpoint: str, **kwargs) -> dict[str, Any]:
        """GET request."""
        return self.request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, data: dict, **kwargs) -> dict[str, Any]:
        """POST request."""
        return self.request("POST", endpoint, data=data, **kwargs)

    def _refresh_access_token(self) -> bool:
        """Refresh access token using refresh token."""
        if not self.uid or not self.refresh_token:
            return False

        try:
            result = self.post(
                "auth/refresh",
                {
                    "UID": self.uid,
                    "ResponseType": "token",
                    "GrantType": "refresh_token",
                    "RefreshToken": self.refresh_token,
                    "RedirectURI": "https://protonvpn.com",
                },
                include_auth=False,
                retry_on_401=False,
            )
            self.access_token = result["AccessToken"]
            self.refresh_token = result["RefreshToken"]
            self.save_session()
            return True
        except ProtonAPIError:
            return False

    def set_session(self, uid: str, access_token: str, refresh_token: str) -> None:
        """Set session from login result."""
        self.uid = uid
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.save_session()


# Global API instance
api = ProtonAPI()
