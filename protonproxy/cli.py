"""Command-line interface for ProtonVPN proxy."""

import argparse
import sys

from rich.console import Console
from rich.table import Table

from . import __version__
from .api import api, ProtonAPIError
from .auth import login_interactive, logout, check_login
from .credentials import clear_credentials
from .proxy import LocalProxy, UpstreamProxy, set_upstream_proxy
from .servers import (
    get_servers,
    get_countries,
    get_best_server,
    get_server_by_name,
    fetch_servers,
)

console = Console()


def cmd_login(args) -> int:
    """Handle login command."""
    if check_login():
        console.print("[green]✓ Already logged in[/green]")
        if not args.force:
            return 0
        console.print("  Forcing re-login...")

    if login_interactive():
        return 0
    return 1


def cmd_logout(args) -> int:
    """Handle logout command."""
    logout()
    clear_credentials()
    return 0


def cmd_status(args) -> int:
    """Handle status command."""
    if check_login():
        console.print("[green]✓ Logged in[/green]")
        return 0
    else:
        console.print("[red]✗ Not logged in[/red]")
        console.print("  Run: protonproxy login")
        return 1


def cmd_servers(args) -> int:
    """Handle servers command."""
    if not check_login():
        console.print("[red]✗ Not logged in. Run: protonproxy login[/red]")
        return 1

    try:
        servers = get_servers(
            country=args.country,
            free_only=not args.all,
        )

        if not servers:
            console.print("[yellow]No servers found[/yellow]")
            return 0

        table = Table(title=f"ProtonVPN Servers ({len(servers)} total)")
        table.add_column("Name", style="cyan")
        table.add_column("Country")
        table.add_column("City")
        table.add_column("Tier")
        table.add_column("Load", justify="right")
        table.add_column("Status")

        for s in servers[:50]:  # Limit display
            tier = "Free" if s.is_free() else "Plus"
            load = f"{s.load}%" if s.load is not None else "-"
            status = "[green]●[/green]" if s.is_online() else "[red]●[/red]"
            table.add_row(s.name, s.exit_country, s.city or "-", tier, load, status)

        console.print(table)

        if len(servers) > 50:
            console.print(f"[dim]... and {len(servers) - 50} more[/dim]")

        return 0
    except ProtonAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1


def cmd_countries(args) -> int:
    """Handle countries command."""
    if not check_login():
        console.print("[red]✗ Not logged in. Run: protonproxy login[/red]")
        return 1

    try:
        countries = get_countries(free_only=not args.all)
        console.print(f"[bold]Available countries ({len(countries)}):[/bold]")
        console.print("  " + "  ".join(countries))
        return 0
    except ProtonAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1


def cmd_connect(args) -> int:
    """Handle connect command."""
    if not check_login():
        console.print("[red]✗ Not logged in. Run: protonproxy login[/red]")
        return 1

    try:
        # Find server
        if args.server:
            # Connect to specific server
            server = get_server_by_name(args.server)
            if not server:
                console.print(f"[red]Server not found: {args.server}[/red]")
                return 1
        elif args.country:
            # Connect to best server in country
            server = get_best_server(country=args.country, free_only=not args.all)
            if not server:
                console.print(f"[red]No servers in country: {args.country}[/red]")
                return 1
        else:
            # Connect to best overall server
            server = get_best_server(free_only=not args.all)
            if not server:
                console.print("[red]No servers available[/red]")
                return 1

        # Configure upstream proxy if specified
        if args.upstream:
            try:
                upstream = UpstreamProxy.from_url(args.upstream)
                set_upstream_proxy(upstream)
                console.print(f"[cyan]🔗 Using upstream proxy: {args.upstream}[/cyan]")
            except ValueError as e:
                console.print(f"[red]Invalid upstream proxy: {e}[/red]")
                return 1

        # Start proxy
        proxy = LocalProxy(host=args.host, port=args.port)
        proxy.start(server)
        return 0

    except ProtonAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    except KeyboardInterrupt:
        return 0


def cmd_gui(args) -> int:
    """Handle gui command."""
    try:
        from .gui import main as gui_main
        gui_main()
        return 0
    except ImportError as e:
        console.print(f"[red]Error: Could not import GUI modules. {e}[/red]")
        console.print("[yellow]Hint: Make sure tkinter is installed (e.g., sudo apt-get install python3-tk)[/yellow]")
        return 1
    except Exception as e:
        console.print(f"[red]Error launching GUI: {e}[/red]")
        return 1


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="protonproxy",
        description="ProtonVPN browser extension proxy for global use",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # login
    login_parser = subparsers.add_parser("login", help="Log in to ProtonVPN")
    login_parser.add_argument(
        "-f", "--force", action="store_true", help="Force re-login"
    )
    login_parser.set_defaults(func=cmd_login)

    # logout
    logout_parser = subparsers.add_parser("logout", help="Log out")
    logout_parser.set_defaults(func=cmd_logout)

    # status
    status_parser = subparsers.add_parser("status", help="Check login status")
    status_parser.set_defaults(func=cmd_status)

    # servers
    servers_parser = subparsers.add_parser("servers", help="List available servers")
    servers_parser.add_argument(
        "-c", "--country", help="Filter by country code (e.g., US, JP)"
    )
    servers_parser.add_argument(
        "-a", "--all", action="store_true", help="Show all tiers (not just free)"
    )
    servers_parser.set_defaults(func=cmd_servers)

    # countries
    countries_parser = subparsers.add_parser("countries", help="List available countries")
    countries_parser.add_argument(
        "-a", "--all", action="store_true", help="Show all tiers (not just free)"
    )
    countries_parser.set_defaults(func=cmd_countries)

    # connect
    connect_parser = subparsers.add_parser("connect", help="Start proxy connection")
    connect_parser.add_argument(
        "-c", "--country", help="Connect to best server in country"
    )
    connect_parser.add_argument(
        "-s", "--server", help="Connect to specific server (e.g., JP#9)"
    )
    connect_parser.add_argument(
        "-a", "--all", action="store_true", help="Allow all tiers (not just free)"
    )
    connect_parser.add_argument(
        "--host", default="127.0.0.1", help="Local proxy host (default: 127.0.0.1)"
    )
    connect_parser.add_argument(
        "--port", type=int, default=8080, help="Local proxy port (default: 8080)"
    )
    connect_parser.add_argument(
        "--upstream", "-u",
        help="Upstream proxy URL (e.g., socks5://127.0.0.1:1080 or http://proxy:8080)"
    )
    connect_parser.set_defaults(func=cmd_connect)

    # gui
    gui_parser = subparsers.add_parser("gui", help="Launch graphical user interface")
    gui_parser.set_defaults(func=cmd_gui)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
