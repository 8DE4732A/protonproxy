"""Local HTTP proxy server that forwards traffic through ProtonVPN."""

import base64
import os
import select
import socket
import ssl
import sys
import threading
from typing import Optional
from urllib.parse import urlparse

from .credentials import get_credentials, Credentials
from .servers import Logical

# Enable debug mode via environment variable
DEBUG = os.environ.get("PROTONPROXY_DEBUG", "").lower() in ("1", "true", "yes")


def debug_log(*args):
    """Print debug message if DEBUG is enabled."""
    if DEBUG:
        print("[DEBUG]", *args, file=sys.stderr)


class ProxyHandler:
    """Handle a single proxy connection."""

    def __init__(
        self,
        client_socket: socket.socket,
        proton_server: Logical,
        credentials: Credentials,
    ):
        self.client = client_socket
        self.server = proton_server
        self.credentials = credentials
        self.proton_socket: Optional[socket.socket] = None

    def _get_proxy_auth_header(self) -> str:
        """Generate Proxy-Authorization header value."""
        auth = f"{self.credentials.username}:{self.credentials.password}"
        encoded = base64.b64encode(auth.encode()).decode()
        return f"Basic {encoded}"

    def _connect_to_proton(self) -> socket.socket:
        """Establish SSL connection to Proton proxy server."""
        best = self.server.get_best_server()
        if not best:
            raise ConnectionError(f"No available server in {self.server.name}")

        host = best.domain
        port = self.server.proxy_port

        debug_log(f"Connecting to {host}:{port}")

        # Create SSL socket
        context = ssl.create_default_context()
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(30)
        
        try:
            ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
            ssl_socket.connect((host, port))
            debug_log(f"SSL connection established to {host}:{port}")
            return ssl_socket
        except ssl.SSLError as e:
            debug_log(f"SSL Error: {e}")
            raise
        except Exception as e:
            debug_log(f"Connection error: {e}")
            raise

    def _handle_connect(self, request: bytes) -> None:
        """Handle HTTPS CONNECT request."""
        # Parse target from CONNECT request
        first_line = request.split(b"\r\n")[0].decode()
        _, target, _ = first_line.split(" ")
        debug_log(f"CONNECT request for {target}")

        # Connect to Proton proxy
        self.proton_socket = self._connect_to_proton()

        # Forward CONNECT with proxy auth
        modified_request = self._add_proxy_auth(request)
        debug_log(f"Sending to Proton:\n{modified_request[:500]}")
        self.proton_socket.sendall(modified_request)

        # Read response from Proton proxy
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.proton_socket.recv(4096)
            if not chunk:
                break
            response += chunk

        debug_log(f"Proton response:\n{response[:500]}")

        # Forward response to client
        self.client.sendall(response)

        # Check if connection established
        status_line = response.split(b"\r\n")[0]
        if b"200" in status_line:
            debug_log("Tunnel established, relaying data")
            # Tunnel established, relay data
            self._relay_data()
        else:
            debug_log(f"Tunnel failed: {status_line}")

    def _handle_http(self, request: bytes) -> None:
        """Handle plain HTTP request."""
        first_line = request.split(b"\r\n")[0].decode()
        debug_log(f"HTTP request: {first_line}")
        
        # Connect to Proton proxy
        self.proton_socket = self._connect_to_proton()

        # Forward request with proxy auth
        modified_request = self._add_proxy_auth(request)
        self.proton_socket.sendall(modified_request)

        # Relay response
        self._relay_data()

    def _add_proxy_auth(self, request: bytes) -> bytes:
        """Add Proxy-Authorization header to request."""
        # Don't include \r\n here - the join() will add it
        auth_header = f"Proxy-Authorization: {self._get_proxy_auth_header()}"

        # Split request into lines, insert auth after first line
        lines = request.split(b"\r\n")
        lines.insert(1, auth_header.encode())
        return b"\r\n".join(lines)

    def _relay_data(self) -> None:
        """Relay data between client and Proton proxy."""
        self.client.setblocking(False)
        self.proton_socket.setblocking(False)

        sockets = [self.client, self.proton_socket]
        
        try:
            while True:
                try:
                    readable, _, _ = select.select(sockets, [], [], 60)
                except (ValueError, OSError):
                    # Socket closed
                    break

                if not readable:
                    debug_log("Relay timeout")
                    break  # Timeout

                for sock in readable:
                    try:
                        data = sock.recv(65536)
                        if not data:
                            debug_log("Remote closed connection")
                            return

                        if sock is self.client:
                            self._send_all(self.proton_socket, data)
                        else:
                            self._send_all(self.client, data)
                    except ssl.SSLWantReadError:
                        # SSL needs more data, continue waiting
                        continue
                    except ssl.SSLWantWriteError:
                        # SSL buffer full, continue
                        continue
                    except ssl.SSLError as e:
                        if "WANT_READ" in str(e) or "WANT_WRITE" in str(e):
                            continue
                        debug_log(f"SSL error in relay: {e}")
                        return
                    except (ConnectionError, BrokenPipeError, OSError) as e:
                        debug_log(f"Connection error: {e}")
                        return
        except Exception as e:
            debug_log(f"Relay exception: {e}")

    def _send_all(self, sock: socket.socket, data: bytes) -> None:
        """Send all data, handling SSL non-blocking."""
        total_sent = 0
        while total_sent < len(data):
            try:
                sent = sock.send(data[total_sent:])
                if sent == 0:
                    raise ConnectionError("Socket closed")
                total_sent += sent
            except ssl.SSLWantWriteError:
                # Wait for socket to be writable
                select.select([], [sock], [], 1)
            except ssl.SSLWantReadError:
                # SSL needs to read first
                select.select([sock], [], [], 1)

    def handle(self) -> None:
        """Handle the proxy request."""
        try:
            # Read request
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = self.client.recv(4096)
                if not chunk:
                    return
                request += chunk

            first_line = request.split(b"\r\n")[0].decode()
            method = first_line.split(" ")[0]

            if method == "CONNECT":
                self._handle_connect(request)
            else:
                self._handle_http(request)

        except Exception as e:
            debug_log(f"Handler error: {e}")
            # Send error response
            try:
                error_response = f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nProxy Error: {e}"
                self.client.sendall(error_response.encode())
            except:
                pass
        finally:
            self._cleanup()

    def _cleanup(self) -> None:
        """Clean up sockets."""
        try:
            self.client.close()
        except:
            pass
        try:
            if self.proton_socket:
                self.proton_socket.close()
        except:
            pass


class LocalProxy:
    """Local HTTP proxy server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.current_server: Optional[Logical] = None

    def set_server(self, server: Logical) -> None:
        """Set the ProtonVPN server to use."""
        self.current_server = server

    def start(self, server: Logical) -> None:
        """Start the proxy server."""
        self.current_server = server
        self.running = True

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.server_socket.settimeout(1)  # Allow checking running flag

        print(f"🌐 Proxy server listening on {self.host}:{self.port}")
        print(f"📡 Connected to {server.name} ({server.exit_country})")
        print(f"   Upstream: {server.domain}:{server.proxy_port}")
        print("\n   Configure your app to use:")
        print(f"   HTTP Proxy: {self.host}:{self.port}")
        print("\n   Press Ctrl+C to stop\n")

        try:
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    # Get fresh credentials for each connection
                    credentials = get_credentials()
                    handler = ProxyHandler(client_socket, self.current_server, credentials)
                    thread = threading.Thread(target=handler.handle, daemon=True)
                    thread.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\n⏹️  Stopping proxy server...")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the proxy server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        print("✅ Proxy server stopped")
