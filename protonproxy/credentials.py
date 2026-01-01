"""Proxy credentials management - fetch and cache browser proxy tokens."""

import time
from dataclasses import dataclass
from typing import Optional

from .api import api, ProtonAPIError

# Token duration in seconds (20 minutes, matching extension)
TOKEN_DURATION = 1200


@dataclass
class Credentials:
    """Proxy authentication credentials."""

    username: str
    password: str
    expires_at: float  # Unix timestamp

    def is_expired(self) -> bool:
        """Check if credentials are expired."""
        return time.time() >= self.expires_at

    def is_expiring_soon(self, margin_seconds: int = 60) -> bool:
        """Check if credentials will expire soon."""
        return time.time() >= self.expires_at - margin_seconds


# Cached credentials
_cached_credentials: Optional[Credentials] = None


def fetch_credentials() -> Credentials:
    """Fetch new proxy credentials from API."""
    global _cached_credentials

    result = api.get(f"vpn/v1/browser/token?Duration={TOKEN_DURATION}")

    expire_seconds = result.get("Expire", TOKEN_DURATION)
    credentials = Credentials(
        username=result["Username"],
        password=result["Password"],
        expires_at=time.time() + expire_seconds,
    )

    _cached_credentials = credentials
    return credentials


def get_credentials(force_refresh: bool = False) -> Credentials:
    """
    Get valid proxy credentials.

    Returns cached credentials if still valid, otherwise fetches new ones.
    """
    global _cached_credentials

    if force_refresh or _cached_credentials is None or _cached_credentials.is_expired():
        return fetch_credentials()

    # If expiring soon, refresh in background
    if _cached_credentials.is_expiring_soon():
        try:
            return fetch_credentials()
        except ProtonAPIError:
            # Return cached if refresh fails but not yet expired
            if not _cached_credentials.is_expired():
                return _cached_credentials
            raise

    return _cached_credentials


def clear_credentials() -> None:
    """Clear cached credentials."""
    global _cached_credentials
    _cached_credentials = None
