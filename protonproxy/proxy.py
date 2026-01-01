"""Local HTTP proxy server that forwards traffic through ProtonVPN."""

import struct
import base64
import os
import select
import socket
import ssl
import sys
import threading
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import socks

from .credentials import get_credentials, Credentials
from .servers import Logical

# Enable debug mode via environment variable
DEBUG = os.environ.get("PROTONPROXY_DEBUG", "").lower() in ("1", "true", "yes")

# Global upstream proxy configuration
_upstream_proxy: Optional["UpstreamProxy"] = None


def debug_log(*args):
    """Print debug message if DEBUG is enabled."""
    if DEBUG:
        print("[DEBUG]", *args, file=sys.stderr)


@dataclass
class UpstreamProxy:
    """Upstream proxy configuration."""
    
    type: str  # "socks5", "socks4", "http"
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    
    @classmethod
    def from_url(cls, url: str) -> "UpstreamProxy":
        """Parse proxy URL like socks5://user:pass@host:port or http://host:port"""
        parsed = urlparse(url)
        
        proxy_type = parsed.scheme.lower()
        if proxy_type not in ("socks5", "socks4", "http", "https"):
            raise ValueError(f"Unsupported proxy type: {proxy_type}")
        
        host = parsed.hostname
        port = parsed.port
        
        if not host or not port:
            raise ValueError(f"Invalid proxy URL: {url}")
        
        return cls(
            type=proxy_type,
            host=host,
            port=port,
            username=parsed.username,
            password=parsed.password,
        )


def set_upstream_proxy(proxy: Optional[UpstreamProxy]) -> None:
    """Set global upstream proxy configuration."""
    global _upstream_proxy
    _upstream_proxy = proxy
    if proxy:
        debug_log(f"Upstream proxy set: {proxy.type}://{proxy.host}:{proxy.port}")


def get_upstream_proxy() -> Optional[UpstreamProxy]:
    """Get current upstream proxy configuration."""
    return _upstream_proxy


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

    def _create_upstream_socket(self, target_host: str, target_port: int) -> socket.socket:
        """Create socket, optionally through upstream proxy."""
        upstream = get_upstream_proxy()
        
        if upstream is None:
            # Direct connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((target_host, target_port))
            return sock
        
        debug_log(f"Connecting via upstream {upstream.type}://{upstream.host}:{upstream.port}")
        
        if upstream.type in ("socks5", "socks4"):
            # Use PySocks for SOCKS proxy
            proxy_type = socks.SOCKS5 if upstream.type == "socks5" else socks.SOCKS4
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(
                proxy_type,
                upstream.host,
                upstream.port,
                username=upstream.username,
                password=upstream.password,
            )
            sock.settimeout(30)
            sock.connect((target_host, target_port))
            return sock
        
        elif upstream.type in ("http", "https"):
            # HTTP CONNECT tunnel
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((upstream.host, upstream.port))
            
            # Send CONNECT request
            connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            connect_req += f"Host: {target_host}:{target_port}\r\n"
            
            if upstream.username and upstream.password:
                auth = base64.b64encode(
                    f"{upstream.username}:{upstream.password}".encode()
                ).decode()
                connect_req += f"Proxy-Authorization: Basic {auth}\r\n"
            
            connect_req += "\r\n"
            sock.sendall(connect_req.encode())
            
            # Read response
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("Upstream proxy closed connection")
                response += chunk
            
            # Check status
            status_line = response.split(b"\r\n")[0].decode()
            if "200" not in status_line:
                raise ConnectionError(f"Upstream proxy error: {status_line}")
            
            debug_log(f"Upstream tunnel established: {status_line}")
            return sock
        
        else:
            raise ValueError(f"Unsupported upstream proxy type: {upstream.type}")

    def _connect_to_proton(self) -> socket.socket:
        """Establish SSL connection to Proton proxy server."""
        best = self.server.get_best_server()
        if not best:
            raise ConnectionError(f"No available server in {self.server.name}")

        host = best.domain
        port = self.server.proxy_port

        debug_log(f"Connecting to {host}:{port}")

        # Create socket (direct or through upstream proxy)
        raw_socket = self._create_upstream_socket(host, port)
        
        # Wrap with SSL
        context = ssl.create_default_context()
        
        try:
            ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
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

    def _handle_socks5(self) -> None:
        """Handle SOCKS5 request."""
        # 1. Negotiation
        # Ver, NMethods, Methods
        header = self.client.recv(2)
        if not header or header[0] != 0x05:
            return
        
        n_methods = header[1]
        methods = self.client.recv(n_methods)
        
        # We don't require auth for local SOCKS5 proxy
        # Respond: Ver(05) Method(00 - No auth)
        self.client.sendall(b"\x05\x00")
        
        # 2. Request
        # Ver(05) Cmd(01=Connect) Rsv(00) Atyp(01=IPv4, 03=Domain, 04=IPv6) DstAddr DstPort
        request = self.client.recv(4)
        if not request or request[0] != 0x05 or request[1] != 0x01: # Only CONNECT
            # Unsupported or invalid
            return
            
        atyp = request[3]
        if atyp == 0x01: # IPv4
            addr = self.client.recv(4)
            host = socket.inet_ntoa(addr)
        elif atyp == 0x03: # Domain
            addr_len = self.client.recv(1)[0]
            host = self.client.recv(addr_len).decode()
        elif atyp == 0x04: # IPv6
            # Not fully supported for now, but parse it
            addr = self.client.recv(16)
            host = socket.inet_ntop(socket.AF_INET6, addr)
        else:
            # Bad ATYP
            return
            
        port_bytes = self.client.recv(2)
        port = struct.unpack("!H", port_bytes)[0]
        
        debug_log(f"SOCKS5 Connect to {host}:{port}")
        
        try:
            # Connect to upstream via Proton
            self.proton_socket = self._connect_to_proton()
            
            # Since _connect_to_proton creates a tunnel to the proton server,
            # we now need to tell the proton server where to go? 
            # WAIT. _connect_to_proton connects to the Proton Proxy Server (Exit Node).
            # The Proton Proxy accepts HTTP CONNECT methods.
            # So even if our client speaks SOCKS5, we must translate that to HTTP CONNECT 
            # when talking to the Proton Proxy.
            
            # Send CONNECT to Proton Proxy
            connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\n"
            connect_req += f"Host: {host}:{port}\r\n"
            
            # Auth
            auth_header = f"Proxy-Authorization: {self._get_proxy_auth_header()}\r\n"
            connect_req += auth_header
            connect_req += "\r\n"
            
            self.proton_socket.sendall(connect_req.encode())
            
            # Read response from Proton
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = self.proton_socket.recv(4096)
                if not chunk:
                    raise ConnectionError("Proton proxy closed connection")
                response += chunk
                
            status_line = response.split(b"\r\n")[0].decode()
            if "200" in status_line:
                # Success. Reply to SOCKS5 client.
                # Ver(05) Rep(00=Success) Rsv(00) Atyp(01) BindAddr(0.0.0.0) BindPort(0)
                reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                self.client.sendall(reply)
                debug_log(f"SOCKS5 tunnel established to {host}:{port}")
                self._relay_data()
            else:
                # Failure
                debug_log(f"Proton handshake failed: {status_line}")
                # Reply generic failure (01)
                reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                self.client.sendall(reply)
                
        except Exception as e:
            debug_log(f"SOCKS5 error: {e}")
            try:
                # Connection refused (05) or just failure (01)
                self.client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except:
                pass

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
            # Peek first byte to detect protocol
            # SOCKS5 starts with 0x05, HTTP starts with ASCII method (GET, POST, CONNECT, etc.)
            first_byte = self.client.recv(1, socket.MSG_PEEK)
            if not first_byte:
                return
            
            if first_byte[0] == 0x05:
                # SOCKS5 protocol
                debug_log("Detected SOCKS5 protocol")
                self._handle_socks5()
                return

            # HTTP protocol - read full request
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
    """Local HTTP/SOCKS5 proxy server (auto-detect protocol)."""

    def __init__(
        self, 
        host: str = "127.0.0.1", 
        port: int = 8080,
    ):
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

        print(f"🌐 Proxy server listening on {self.host}:{self.port} (HTTP + SOCKS5)")
        print(f"📡 Connected to {server.name} ({server.exit_country})")
        print(f"   Upstream: {server.domain}:{server.proxy_port}")
        print("\n   Configure your app to use:")
        print(f"   HTTP Proxy:   {self.host}:{self.port}")
        print(f"   SOCKS5 Proxy: {self.host}:{self.port}")
        print("\n   Press Ctrl+C to stop\n")

        try:
            while self.running:
                if not self.server_socket:
                    break

                try:
                    readable, _, _ = select.select([self.server_socket], [], [], 1.0)
                except (ValueError, OSError):
                    continue
                    
                for ready_sock in readable:
                    try:
                        client_socket, addr = ready_sock.accept()
                        # Get fresh credentials for each connection
                        credentials = get_credentials()
                        handler = ProxyHandler(client_socket, self.current_server, credentials)
                        thread = threading.Thread(target=handler.handle, daemon=True)
                        thread.start()
                    except socket.timeout:
                        pass
                    except OSError:
                        pass
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
