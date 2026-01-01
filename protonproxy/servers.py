"""Server list management and selection logic."""

from dataclasses import dataclass
from typing import Optional

from .api import api


# Feature flags (bitmap)
class Feature:
    SECURE_CORE = 1
    TOR = 2
    P2P = 4
    STREAMING = 8
    IPV6 = 16


@dataclass
class Server:
    """Physical server information."""

    id: str
    domain: str
    entry_ip: str
    exit_ip: str
    label: Optional[str]
    status: int
    load: Optional[int]

    def is_online(self) -> bool:
        """Check if server is online."""
        return self.status > 0


@dataclass
class Logical:
    """Logical server (group of physical servers)."""

    id: str
    name: str
    domain: str
    entry_country: str
    exit_country: str
    city: Optional[str]
    tier: int
    features: int
    load: Optional[int]
    score: float
    status: int
    servers: list[Server]

    def is_online(self) -> bool:
        """Check if logical has at least one online server."""
        return self.status > 0 and any(s.is_online() for s in self.servers)

    def is_free(self) -> bool:
        """Check if server is available for free users."""
        return self.tier == 0

    def is_secure_core(self) -> bool:
        """Check if this is a Secure Core server."""
        return bool(self.features & Feature.SECURE_CORE)

    def get_best_server(self) -> Optional[Server]:
        """Get the best available physical server."""
        online_servers = [s for s in self.servers if s.is_online()]
        if not online_servers:
            return None
        # Prefer servers with label (indicates specific port routing)
        labeled = [s for s in online_servers if s.label]
        return labeled[0] if labeled else online_servers[0]

    @property
    def proxy_port(self) -> int:
        """Get proxy port based on server type."""
        if self.is_secure_core():
            return 443
        # Base port + label offset if available
        base_port = 4443
        best = self.get_best_server()
        if best and best.label and best.label.isdigit():
            return base_port + int(best.label)
        return base_port


# Cached server list
_cached_logicals: list[Logical] = []


def _parse_server(data: dict) -> Server:
    """Parse server from API response."""
    return Server(
        id=str(data.get("ID", "")),
        domain=data["Domain"],
        entry_ip=data["EntryIP"],
        exit_ip=data["ExitIP"],
        label=data.get("Label"),
        status=data.get("Status", 0),
        load=data.get("Load"),
    )


def _parse_logical(data: dict) -> Logical:
    """Parse logical from API response."""
    servers = [_parse_server(s) for s in data.get("Servers", [])]
    return Logical(
        id=str(data["ID"]),
        name=data["Name"],
        domain=data["Domain"],
        entry_country=data["EntryCountry"],
        exit_country=data["ExitCountry"],
        city=data.get("City"),
        tier=data.get("Tier", 0),
        features=data.get("Features", 0),
        load=data.get("Load"),
        score=data.get("Score", 0),
        status=data.get("Status", 0),
        servers=servers,
    )


def fetch_servers(force_refresh: bool = False) -> list[Logical]:
    """Fetch server list from API."""
    global _cached_logicals

    if not force_refresh and _cached_logicals:
        return _cached_logicals

    result = api.get("vpn/v1/logicals")
    logicals = [_parse_logical(l) for l in result.get("LogicalServers", [])]

    # Filter to only online servers
    logicals = [l for l in logicals if l.is_online()]

    # Sort by score (lower is better)
    logicals.sort(key=lambda l: l.score)

    _cached_logicals = logicals
    return logicals


def get_servers(
    country: Optional[str] = None,
    free_only: bool = True,
    secure_core: bool = False,
) -> list[Logical]:
    """
    Get filtered list of servers.

    Args:
        country: Filter by exit country code (e.g., 'US', 'JP')
        free_only: Only show free tier servers
        secure_core: Include Secure Core servers
    """
    logicals = fetch_servers()

    if free_only:
        logicals = [l for l in logicals if l.is_free()]

    if not secure_core:
        logicals = [l for l in logicals if not l.is_secure_core()]

    if country:
        country = country.upper()
        logicals = [l for l in logicals if l.exit_country == country]

    return logicals


def get_countries(free_only: bool = True) -> list[str]:
    """Get list of available countries."""
    logicals = get_servers(free_only=free_only)
    countries = sorted(set(l.exit_country for l in logicals))
    return countries


def get_best_server(country: Optional[str] = None, free_only: bool = True) -> Optional[Logical]:
    """Get the best server based on score/load."""
    servers = get_servers(country=country, free_only=free_only)
    if not servers:
        return None
    # Already sorted by score
    return servers[0]


def get_server_by_name(name: str) -> Optional[Logical]:
    """Get server by name (e.g., 'JP#9')."""
    logicals = fetch_servers()
    for logical in logicals:
        if logical.name.lower() == name.lower():
            return logical
    return None
