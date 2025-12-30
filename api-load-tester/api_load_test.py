#!/usr/bin/env python3
"""
API Load Tester

A comprehensive API load testing and benchmarking tool that measures detailed
timing metrics including DNS resolution, TCP connection, TLS handshake,
time to first byte (TTFB), and total request time.
"""

import argparse
import json
import os
import socket
import ssl
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Graph characters
BLOCK_FULL = "█"
BLOCK_EMPTY = "░"


class RateLimiter:
    """Token bucket rate limiter for controlling QPS."""

    def __init__(self, qps: float):
        """
        Initialize rate limiter.

        Args:
            qps: Target queries per second (0 = unlimited)
        """
        self.qps = qps
        self.tokens = qps
        self.last_update = time.perf_counter()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        """Wait until a token is available."""
        if self.qps <= 0:
            return

        while True:
            with self.lock:
                now = time.perf_counter()
                elapsed = now - self.last_update
                self.tokens = min(self.qps, self.tokens + elapsed * self.qps)
                self.last_update = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return

            # Wait a bit before checking again
            time.sleep(0.001)


class LoadPattern:
    """
    Manages load testing patterns for controlling virtual user spawning over time.

    Supported patterns:
    - constant: All users start immediately and stay constant
    - ramp-up: Gradually increase users from 1 to max over ramp_duration
    - step: Increase users in steps (step_users every step_duration)
    - spike: Normal load with sudden spike to spike_users for spike_duration
    - soak: Same as constant but intended for long duration tests
    """

    PATTERNS = ["constant", "ramp-up", "step", "spike", "soak"]

    def __init__(
        self,
        pattern: str,
        max_users: int,
        duration: float,
        ramp_duration: float = 0,
        step_users: int = 1,
        step_duration: float = 10,
        spike_users: int = 0,
        spike_duration: float = 10,
        spike_delay: float = 0
    ):
        """
        Initialize load pattern.

        Args:
            pattern: Pattern type (constant, ramp-up, step, spike, soak)
            max_users: Maximum number of virtual users
            duration: Total test duration in seconds
            ramp_duration: Time to ramp up to max users (for ramp-up pattern)
            step_users: Users to add per step (for step pattern)
            step_duration: Duration of each step in seconds (for step pattern)
            spike_users: Number of users during spike (for spike pattern)
            spike_duration: Duration of spike in seconds (for spike pattern)
            spike_delay: Delay before spike starts (for spike pattern)
        """
        self.pattern = pattern.lower()
        self.max_users = max_users
        self.duration = duration
        self.ramp_duration = ramp_duration or duration * 0.5  # Default: 50% of duration
        self.step_users = step_users
        self.step_duration = step_duration
        self.spike_users = spike_users or max_users * 2  # Default: 2x normal
        self.spike_duration = spike_duration
        self.spike_delay = spike_delay or duration * 0.3  # Default: spike at 30%
        self.start_time = None
        self.user_timeline = []  # Track (timestamp, active_users) for graphing
        self._lock = threading.Lock()

    def start(self):
        """Mark the start of the test."""
        self.start_time = time.time()

    def get_elapsed(self) -> float:
        """Get elapsed time since start."""
        if self.start_time is None:
            return 0
        return time.time() - self.start_time

    def get_target_users(self, elapsed: float = None) -> int:
        """
        Get the target number of active users at the given elapsed time.

        Args:
            elapsed: Elapsed time in seconds (None = current time)

        Returns:
            Target number of active users
        """
        if elapsed is None:
            elapsed = self.get_elapsed()

        if self.pattern == "constant" or self.pattern == "soak":
            return self.max_users

        elif self.pattern == "ramp-up":
            if elapsed >= self.ramp_duration:
                return self.max_users
            # Linear ramp from 1 to max_users
            progress = elapsed / self.ramp_duration
            return max(1, int(1 + (self.max_users - 1) * progress))

        elif self.pattern == "step":
            # Calculate which step we're on
            current_step = int(elapsed / self.step_duration)
            users = min(self.max_users, self.step_users * (current_step + 1))
            return max(1, users)

        elif self.pattern == "spike":
            # Normal load, then spike, then back to normal
            if elapsed < self.spike_delay:
                return self.max_users
            elif elapsed < self.spike_delay + self.spike_duration:
                return self.spike_users
            else:
                return self.max_users

        return self.max_users

    def record_users(self, active_users: int):
        """Record active users for timeline graph."""
        with self._lock:
            elapsed = self.get_elapsed()
            self.user_timeline.append((round(elapsed, 2), active_users))

    def get_user_timeline(self) -> List[Tuple[float, int]]:
        """Get the recorded user timeline."""
        with self._lock:
            return list(self.user_timeline)

    def get_pattern_description(self) -> str:
        """Get a description of the current pattern configuration."""
        if self.pattern == "constant":
            return f"Constant: {self.max_users} users"
        elif self.pattern == "ramp-up":
            return f"Ramp-up: 1→{self.max_users} users over {self.ramp_duration:.0f}s"
        elif self.pattern == "step":
            steps = (self.max_users + self.step_users - 1) // self.step_users
            return f"Step: +{self.step_users} users every {self.step_duration:.0f}s ({steps} steps)"
        elif self.pattern == "spike":
            return f"Spike: {self.max_users}→{self.spike_users} users at {self.spike_delay:.0f}s for {self.spike_duration:.0f}s"
        elif self.pattern == "soak":
            return f"Soak: {self.max_users} users for {self.duration:.0f}s"
        return f"{self.pattern}: {self.max_users} users"


class ConnectionPool:
    """Thread-safe connection pool for keep-alive connections."""

    def __init__(self, hostname: str, port: int, is_https: bool, max_size: int = 100):
        """
        Initialize connection pool.

        Args:
            hostname: Target hostname
            port: Target port
            is_https: Whether to use TLS
            max_size: Maximum pool size
        """
        self.hostname = hostname
        self.port = port
        self.is_https = is_https
        self.max_size = max_size
        self.pool: List[socket.socket] = []
        self.lock = threading.Lock()
        self.ssl_context = ssl.create_default_context() if is_https else None

    def get_connection(self) -> Tuple[socket.socket, bool, float, float, float]:
        """
        Get a connection from pool or create new one.

        Returns:
            Tuple of (socket, is_reused, dns_ms, tcp_ms, tls_ms)
        """
        # Try to get existing connection
        with self.lock:
            if self.pool:
                conn = self.pool.pop()
                try:
                    # Test if connection is still alive by checking socket state
                    conn.settimeout(0.001)
                    try:
                        # For SSL sockets, we can't use MSG_PEEK, so just check fileno
                        if conn.fileno() == -1:
                            raise ConnectionError("Connection closed")
                        # Try a non-blocking peek for regular sockets
                        if not isinstance(conn, ssl.SSLSocket):
                            conn.setblocking(False)
                            data = conn.recv(1, socket.MSG_PEEK)
                            if data == b'':
                                raise ConnectionError("Connection closed")
                    except BlockingIOError:
                        pass  # No data available, connection is good
                    except ssl.SSLWantReadError:
                        pass  # SSL socket is fine
                    conn.setblocking(True)
                    conn.settimeout(10)
                    return conn, True, 0, 0, 0
                except (socket.error, ConnectionError, OSError):
                    try:
                        conn.close()
                    except Exception:
                        pass

        # Create new connection
        dns_start = time.perf_counter()
        try:
            result = socket.getaddrinfo(self.hostname, None, socket.AF_INET)
            ip = result[0][4][0] if result else None
        except socket.gaierror:
            raise ConnectionError("DNS resolution failed")
        dns_ms = (time.perf_counter() - dns_start) * 1000

        tcp_start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((ip, self.port))
        except (socket.error, socket.timeout):
            sock.close()
            raise ConnectionError("TCP connection failed")
        tcp_ms = (time.perf_counter() - tcp_start) * 1000

        tls_ms = 0
        if self.is_https:
            tls_start = time.perf_counter()
            try:
                sock = self.ssl_context.wrap_socket(sock, server_hostname=self.hostname)
            except ssl.SSLError:
                sock.close()
                raise ConnectionError("TLS handshake failed")
            tls_ms = (time.perf_counter() - tls_start) * 1000

        return sock, False, dns_ms, tcp_ms, tls_ms

    def return_connection(self, conn: socket.socket) -> None:
        """Return a connection to the pool."""
        with self.lock:
            if len(self.pool) < self.max_size:
                self.pool.append(conn)
            else:
                try:
                    conn.close()
                except Exception:
                    pass

    def close_all(self) -> None:
        """Close all connections in the pool."""
        with self.lock:
            for conn in self.pool:
                try:
                    conn.close()
                except Exception:
                    pass
            self.pool.clear()


def measure_dns_resolution(hostname: str) -> Tuple[float, str]:
    """
    Measure DNS resolution time.

    Args:
        hostname: The hostname to resolve

    Returns:
        Tuple of (time_ms, resolved_ip)
    """
    start = time.perf_counter()
    try:
        result = socket.getaddrinfo(hostname, None, socket.AF_INET)
        end = time.perf_counter()
        ip = result[0][4][0] if result else "N/A"
        return (end - start) * 1000, ip
    except socket.gaierror as e:
        return -1, f"DNS Error: {e}"


def measure_tcp_connection(ip: str, port: int) -> Tuple[float, Optional[socket.socket]]:
    """
    Measure TCP connection establishment time.

    Args:
        ip: IP address to connect to
        port: Port number

    Returns:
        Tuple of (time_ms, socket_object or None)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    start = time.perf_counter()
    try:
        sock.connect((ip, port))
        end = time.perf_counter()
        return (end - start) * 1000, sock
    except (socket.error, socket.timeout):
        sock.close()
        return -1, None


def measure_tls_handshake(sock: socket.socket, hostname: str) -> Tuple[float, Optional[ssl.SSLSocket]]:
    """
    Measure TLS handshake time.

    Args:
        sock: Connected TCP socket
        hostname: Hostname for SNI

    Returns:
        Tuple of (time_ms, ssl_socket or None)
    """
    context = ssl.create_default_context()

    start = time.perf_counter()
    try:
        ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
        end = time.perf_counter()
        return (end - start) * 1000, ssl_sock
    except ssl.SSLError:
        return -1, None


def build_http_request(
    method: str,
    path: str,
    hostname: str,
    headers: Optional[Dict] = None,
    data: Optional[str] = None,
    keep_alive: bool = False
) -> bytes:
    """
    Build a raw HTTP request.

    Args:
        method: HTTP method
        path: Request path
        hostname: Host header value
        headers: Additional headers
        data: Request body
        keep_alive: Use keep-alive connection

    Returns:
        Bytes of the HTTP request
    """
    path = path or "/"
    lines = [f"{method} {path} HTTP/1.1"]
    lines.append(f"Host: {hostname}")
    lines.append(f"Connection: {'keep-alive' if keep_alive else 'close'}")
    lines.append("Accept: */*")
    lines.append("User-Agent: API-Load-Tester/1.0")

    if headers:
        for key, value in headers.items():
            lines.append(f"{key}: {value}")

    if data:
        lines.append(f"Content-Length: {len(data)}")
        if "Content-Type" not in (headers or {}):
            lines.append("Content-Type: application/json")

    lines.append("")  # Empty line before body
    lines.append(data or "")

    return "\r\n".join(lines).encode()


def parse_http_response(data: bytes) -> Tuple[int, Dict[str, str], bytes, str]:
    """
    Parse HTTP response.

    Args:
        data: Raw response bytes

    Returns:
        Tuple of (status_code, headers_dict, body_bytes, error_detail)
    """
    if not data:
        return -1, {}, b"", "empty response"

    try:
        # Split headers and body
        if b"\r\n\r\n" in data:
            header_part, body = data.split(b"\r\n\r\n", 1)
        elif b"\n\n" in data:
            # Some servers use just \n
            header_part, body = data.split(b"\n\n", 1)
        else:
            # No header/body separator found - might be incomplete
            return -1, {}, data, f"no header separator in {len(data)} bytes"

        lines = header_part.decode("utf-8", errors="replace").split("\r\n")
        if len(lines) == 1 and "\n" in lines[0]:
            lines = header_part.decode("utf-8", errors="replace").split("\n")

        # Parse status line
        status_line = lines[0].strip()
        if not status_line:
            return -1, {}, body, "empty status line"

        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            return -1, {}, body, f"invalid status line: {status_line[:50]}"

        try:
            status_code = int(parts[1])
        except ValueError:
            return -1, {}, body, f"invalid status code: {parts[1]}"

        # Parse headers
        headers = {}
        for line in lines[1:]:
            line = line.strip()
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.lower()] = value
            elif ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower().strip()] = value.strip()

        return status_code, headers, body, ""

    except Exception as e:
        return -1, {}, b"", f"parse error: {e}"


def read_http_response(sock: socket.socket, timeout: int = 30) -> bytes:
    """
    Read complete HTTP response handling chunked encoding and content-length.

    Args:
        sock: Socket to read from
        timeout: Read timeout

    Returns:
        Raw response bytes
    """
    sock.settimeout(timeout)
    response_data = b""

    # Read headers first
    while b"\r\n\r\n" not in response_data:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
        except socket.timeout:
            break

    if b"\r\n\r\n" not in response_data:
        return response_data

    header_end = response_data.index(b"\r\n\r\n") + 4
    headers_raw = response_data[:header_end].decode("utf-8", errors="replace").lower()

    # Check for content-length
    content_length = None
    for line in headers_raw.split("\r\n"):
        if line.startswith("content-length:"):
            try:
                content_length = int(line.split(":")[1].strip())
            except ValueError:
                pass
            break

    # Check for chunked encoding
    is_chunked = "transfer-encoding: chunked" in headers_raw

    if content_length is not None:
        # Read exact content length
        body_so_far = len(response_data) - header_end
        remaining = content_length - body_so_far
        while remaining > 0:
            try:
                chunk = sock.recv(min(4096, remaining))
                if not chunk:
                    break
                response_data += chunk
                remaining -= len(chunk)
            except socket.timeout:
                break
    elif is_chunked:
        # Read chunked response
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b"0\r\n\r\n" in response_data:
                    break
            except socket.timeout:
                break
    else:
        # Read until connection closes or timeout
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break

    return response_data


def measure_http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    data: Optional[str] = None,
    timeout: int = 30,
    pool: Optional[ConnectionPool] = None,
    expect_status: Optional[int] = None,
    expect_body: Optional[str] = None,
    _retry: bool = False
) -> Dict:
    """
    Measure full HTTP request with detailed timing.

    Args:
        url: Target URL
        method: HTTP method
        headers: Request headers
        data: Request body
        timeout: Request timeout in seconds
        pool: Connection pool for keep-alive (None = new connection each time)
        expect_status: Expected status code for validation
        expect_body: Expected body substring for validation
        _retry: Internal flag to prevent infinite retry loops

    Returns:
        Dictionary with timing metrics and response info
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    result = {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "dns_ms": 0,
        "tcp_ms": 0,
        "tls_ms": 0,
        "ttfb_ms": -1,
        "total_ms": -1,
        "status_code": -1,
        "response_size": 0,
        "error": None,
        "resolved_ip": "N/A",
        "connection_reused": False,
        "validation_error": None,
        "stale_retry": _retry  # True if this request was retried due to stale connection
    }

    total_start = time.perf_counter()
    sock = None
    use_keepalive = pool is not None
    was_reused = False

    try:
        if pool:
            # Use connection pool
            sock, reused, dns_ms, tcp_ms, tls_ms = pool.get_connection()
            was_reused = reused
            result["connection_reused"] = reused
            result["dns_ms"] = dns_ms
            result["tcp_ms"] = tcp_ms
            result["tls_ms"] = tls_ms
        else:
            # Create new connection with timing
            dns_time, ip = measure_dns_resolution(hostname)
            result["dns_ms"] = dns_time
            result["resolved_ip"] = ip

            if dns_time < 0:
                result["error"] = ip
                return result

            tcp_time, sock = measure_tcp_connection(ip, port)
            result["tcp_ms"] = tcp_time

            if tcp_time < 0 or sock is None:
                result["error"] = "TCP connection failed"
                return result

            if is_https:
                tls_time, ssl_sock = measure_tls_handshake(sock, hostname)
                result["tls_ms"] = tls_time

                if tls_time < 0 or ssl_sock is None:
                    result["error"] = "TLS handshake failed"
                    sock.close()
                    return result
                sock = ssl_sock
            else:
                result["tls_ms"] = 0

        # Send HTTP request and measure TTFB
        sock.settimeout(timeout)
        request_bytes = build_http_request(method, path, hostname, headers, data, use_keepalive)
        ttfb_start = time.perf_counter()

        # Try to send - if this fails on reused connection, retry with fresh one
        try:
            sock.sendall(request_bytes)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
            # Send failed - connection was definitely dead, request didn't reach server
            if was_reused and not _retry:
                try:
                    sock.close()
                except Exception:
                    pass
                return measure_http_request(
                    url, method, headers, data, timeout,
                    pool, expect_status, expect_body, _retry=True
                )
            raise

        # Read first chunk (for TTFB)
        # After sendall succeeds, request may have reached server, so be careful about retrying
        first_chunk = sock.recv(4096)

        # Check if connection was closed by server (empty response on reused connection)
        if not first_chunk:
            # Connection closed immediately after send - this is ambiguous
            # For reused connections, this likely means stale connection detected by recv
            # The request might or might not have reached the server
            if was_reused and not _retry:
                # Only retry if we got empty response very quickly (< 50ms suggests stale, not slow server)
                ttfb_elapsed = (time.perf_counter() - ttfb_start) * 1000
                if ttfb_elapsed < 50:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return measure_http_request(
                        url, method, headers, data, timeout,
                        pool, expect_status, expect_body, _retry=True
                    )
            raise ConnectionError("Server closed connection (empty response)")

        ttfb_end = time.perf_counter()
        result["ttfb_ms"] = (ttfb_end - ttfb_start) * 1000

        # Read rest of response
        response_data = first_chunk
        if use_keepalive:
            # Need to read complete response for keep-alive
            # First, ensure we have all headers
            while b"\r\n\r\n" not in response_data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk

            if b"\r\n\r\n" in response_data:
                header_end = response_data.index(b"\r\n\r\n") + 4
                headers_raw = response_data[:header_end].decode("utf-8", errors="replace").lower()

                # Check for content-length
                content_length = None
                is_chunked = "transfer-encoding: chunked" in headers_raw

                for line in headers_raw.split("\r\n"):
                    if line.startswith("content-length:"):
                        try:
                            content_length = int(line.split(":")[1].strip())
                        except ValueError:
                            pass
                        break

                if content_length is not None:
                    # Read exact content length
                    body_so_far = len(response_data) - header_end
                    remaining = content_length - body_so_far
                    while remaining > 0:
                        try:
                            chunk = sock.recv(min(4096, remaining))
                            if not chunk:
                                break
                            response_data += chunk
                            remaining -= len(chunk)
                        except socket.timeout:
                            break
                elif is_chunked:
                    # Read chunked response until we see the final chunk (0\r\n\r\n)
                    # The terminator might be 0\r\n\r\n or 0\r\n followed by trailers and \r\n
                    max_reads = 1000  # Prevent infinite loop
                    reads = 0
                    while reads < max_reads:
                        # Check for chunked terminator patterns
                        if b"\r\n0\r\n\r\n" in response_data or response_data.endswith(b"0\r\n\r\n"):
                            break
                        # Also check for terminator with trailing headers
                        if b"\r\n0\r\n" in response_data and response_data.endswith(b"\r\n"):
                            # Might be end of chunked with no trailers
                            last_chunk_pos = response_data.rfind(b"\r\n0\r\n")
                            after_zero = response_data[last_chunk_pos + 5:]
                            if after_zero == b"\r\n" or after_zero == b"":
                                break
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response_data += chunk
                            reads += 1
                        except socket.timeout:
                            break
                # else: no content-length and not chunked - likely HTTP/1.0 or empty body
        else:
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break

        # Parse response
        status_code, resp_headers, body, parse_error = parse_http_response(response_data)
        result["status_code"] = status_code
        result["response_size"] = len(body)

        # Set error for failed parsing
        # Don't retry on parsing failure - we received data, so server processed the request
        if status_code == -1:
            result["error"] = f"Parse failed: {parse_error} ({len(response_data)} bytes)"

        # Validation
        if expect_status is not None and status_code != expect_status:
            result["validation_error"] = f"Expected status {expect_status}, got {status_code}"

        if expect_body is not None:
            body_str = body.decode("utf-8", errors="replace")
            if expect_body not in body_str:
                result["validation_error"] = f"Body missing expected: '{expect_body}'"

        # Return connection to pool only if request was fully successful
        # Don't return connections with errors or invalid responses
        if pool and result["error"] is None and status_code > 0:
            pool.return_connection(sock)
            sock = None
        elif sock:
            try:
                sock.close()
            except Exception:
                pass
            sock = None

    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
        # Connection was clearly dead - safe to retry on reused connection
        if was_reused and not _retry:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            return measure_http_request(
                url, method, headers, data, timeout,
                pool, expect_status, expect_body, _retry=True
            )

        result["error"] = f"Connection error: {e}"
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    except socket.timeout as e:
        # Timeout - server may have received and processed the request
        # Don't retry to avoid duplicate processing
        result["error"] = f"Request timeout: {e}"
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    except (socket.error, ConnectionError, OSError) as e:
        # Other socket errors - ambiguous whether server received request
        # Don't retry to avoid potential duplicate processing
        result["error"] = f"Request failed: {e}"
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    total_end = time.perf_counter()
    result["total_ms"] = (total_end - total_start) * 1000

    return result


def run_load_test(
    url: str,
    num_requests: Optional[int] = None,
    duration_seconds: Optional[int] = None,
    method: str = "GET",
    headers: Optional[Dict] = None,
    data: Optional[str] = None,
    concurrency: int = 1,
    delay_ms: int = 0,
    verbose: bool = False,
    keep_alive: bool = True,
    target_qps: float = 0,
    expect_status: Optional[int] = None,
    expect_body: Optional[str] = None,
    pattern: str = "constant",
    ramp_duration: float = 0,
    step_users: int = 1,
    step_duration: float = 10,
    spike_users: int = 0,
    spike_duration: float = 10,
    spike_delay: float = 0
) -> Tuple[List[Dict], float, List[Tuple[float, int]]]:
    """
    Run load test with specified parameters and load pattern.

    Args:
        url: Target URL
        num_requests: Number of requests to make
        duration_seconds: Duration to run test (overrides num_requests)
        method: HTTP method
        headers: Request headers
        data: Request body
        concurrency: Number of concurrent virtual users (max for patterns)
        delay_ms: Delay between requests in milliseconds
        verbose: Print each request result
        keep_alive: Use keep-alive connections
        target_qps: Target queries per second (0 = unlimited)
        expect_status: Expected status code for validation
        expect_body: Expected body substring for validation
        pattern: Load pattern (constant, ramp-up, step, spike, soak)
        ramp_duration: Duration for ramp-up pattern
        step_users: Users per step for step pattern
        step_duration: Duration of each step for step pattern
        spike_users: Peak users during spike
        spike_duration: Duration of spike
        spike_delay: Delay before spike starts

    Returns:
        Tuple of (list of result dictionaries, total_duration_seconds, user_timeline)
    """
    results = []
    results_lock = threading.Lock()
    request_counter = [0]
    counter_lock = threading.Lock()
    stop_event = threading.Event()
    worker_stop_events = {}  # Per-worker stop events for pattern control
    active_workers = [0]  # Track active worker count
    workers_lock = threading.Lock()
    start_time = time.time()

    # Parse URL for connection pool
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"

    # Create connection pool if keep-alive is enabled
    max_pool_size = max(concurrency * 2, spike_users * 2 if spike_users else concurrency * 2)
    pool = ConnectionPool(hostname, port, is_https, max_size=max_pool_size) if keep_alive else None

    # Create rate limiter
    rate_limiter = RateLimiter(target_qps)

    # Create load pattern
    effective_duration = duration_seconds or 60  # Default duration for patterns
    load_pattern = LoadPattern(
        pattern=pattern,
        max_users=concurrency,
        duration=effective_duration,
        ramp_duration=ramp_duration,
        step_users=step_users,
        step_duration=step_duration,
        spike_users=spike_users,
        spike_duration=spike_duration,
        spike_delay=spike_delay
    )

    print(f"\n{BOLD}Starting load test...{RESET}")
    print(f"Target: {CYAN}{url}{RESET}")
    print(f"Method: {method}")
    print(f"Pattern: {MAGENTA}{load_pattern.get_pattern_description()}{RESET}")
    print(f"Keep-Alive: {GREEN if keep_alive else YELLOW}{'enabled' if keep_alive else 'disabled'}{RESET}")

    if target_qps > 0:
        print(f"Target QPS: {CYAN}{target_qps}{RESET}")

    if expect_status:
        print(f"Expect Status: {expect_status}")
    if expect_body:
        print(f"Expect Body: '{expect_body[:30]}{'...' if len(expect_body) > 30 else ''}'")

    if duration_seconds:
        print(f"Duration: {duration_seconds} seconds")
    elif num_requests:
        print(f"Requests: {num_requests}")

    print("-" * 60)

    def worker(worker_id: int, worker_stop: threading.Event):
        """Worker function for each virtual user."""
        with workers_lock:
            active_workers[0] += 1

        try:
            while not stop_event.is_set() and not worker_stop.is_set():
                # Check if we should stop (request count reached)
                if num_requests:
                    with counter_lock:
                        if request_counter[0] >= num_requests:
                            return
                        request_counter[0] += 1
                        current_count = request_counter[0]
                else:
                    with counter_lock:
                        request_counter[0] += 1
                        current_count = request_counter[0]

                # Rate limiting
                rate_limiter.acquire()

                # Check again after rate limiting wait
                if stop_event.is_set() or worker_stop.is_set():
                    return

                # Make request
                result = measure_http_request(
                    url, method, headers, data,
                    pool=pool,
                    expect_status=expect_status,
                    expect_body=expect_body
                )

                with results_lock:
                    results.append(result)

                if verbose:
                    status_color = GREEN if 200 <= result["status_code"] < 300 else RED
                    reused = f"{GREEN}↺{RESET}" if result["connection_reused"] else f"{YELLOW}●{RESET}"
                    validation = f" {RED}✗{RESET}" if result["validation_error"] else ""
                    error_info = ""
                    if result.get("error"):
                        error_info = f" | {RED}{result['error'][:40]}{RESET}"
                    print(f"[{current_count}] {reused} {status_color}{result['status_code']}{RESET}{validation} | "
                          f"DNS: {result['dns_ms']:.1f}ms | "
                          f"TCP: {result['tcp_ms']:.1f}ms | "
                          f"TLS: {result['tls_ms']:.1f}ms | "
                          f"TTFB: {result['ttfb_ms']:.1f}ms | "
                          f"Total: {result['total_ms']:.1f}ms{error_info}")

                if delay_ms > 0:
                    time.sleep(delay_ms / 1000)
        finally:
            with workers_lock:
                active_workers[0] -= 1

    def progress_reporter():
        """Report progress periodically."""
        while not stop_event.is_set():
            time.sleep(0.5)
            elapsed = time.time() - start_time
            with results_lock:
                completed = len(results)
                reused = sum(1 for r in results if r.get("connection_reused", False))
                validation_errors = sum(1 for r in results if r.get("validation_error"))
                stale_retries = sum(1 for r in results if r.get("stale_retry", False))
                failed = sum(1 for r in results if r.get("error"))
            with workers_lock:
                current_users = active_workers[0]
            qps = completed / elapsed if elapsed > 0 else 0

            # Record user timeline
            load_pattern.record_users(current_users)

            if not verbose:
                extra = ""
                if keep_alive and completed > 0:
                    reuse_pct = (reused / completed) * 100
                    extra = f" | Reused: {reuse_pct:.0f}%"
                if stale_retries > 0:
                    extra += f" | {YELLOW}Retried: {stale_retries}{RESET}"
                if failed > 0:
                    extra += f" | {RED}Failed: {failed}{RESET}"
                if validation_errors > 0:
                    extra += f" | {RED}Validation Errors: {validation_errors}{RESET}"

                print(f"\r  VUs: {CYAN}{current_users}{RESET}/{concurrency} | "
                      f"Requests: {completed} | "
                      f"Elapsed: {elapsed:.1f}s | "
                      f"QPS: {qps:.1f}{extra}    ", end="", flush=True)

    # Start load pattern
    load_pattern.start()

    # Start progress reporter thread
    progress_thread = threading.Thread(target=progress_reporter, daemon=True)
    progress_thread.start()

    # Dynamic worker management based on pattern
    executor = ThreadPoolExecutor(max_workers=max(concurrency, spike_users or concurrency))
    futures = []
    next_worker_id = 0

    try:
        if duration_seconds:
            # Duration-based test with dynamic pattern
            end_time_target = time.time() + duration_seconds

            while time.time() < end_time_target and not stop_event.is_set():
                # Get target users for current time
                target_users = load_pattern.get_target_users()

                with workers_lock:
                    current_users = active_workers[0]

                # Spawn more workers if needed
                while current_users < target_users:
                    worker_stop = threading.Event()
                    worker_stop_events[next_worker_id] = worker_stop
                    future = executor.submit(worker, next_worker_id, worker_stop)
                    futures.append((next_worker_id, future))
                    next_worker_id += 1
                    current_users += 1

                # Stop excess workers if needed (for spike pattern returning to normal)
                if current_users > target_users:
                    workers_to_stop = current_users - target_users
                    for wid in sorted(worker_stop_events.keys(), reverse=True)[:workers_to_stop]:
                        if wid in worker_stop_events:
                            worker_stop_events[wid].set()

                time.sleep(0.1)  # Check every 100ms

            stop_event.set()
        else:
            # Request-based test - start all workers immediately (constant pattern)
            for i in range(concurrency):
                worker_stop = threading.Event()
                worker_stop_events[i] = worker_stop
                future = executor.submit(worker, i, worker_stop)
                futures.append((i, future))

            # Wait for all requests to complete
            while True:
                with counter_lock:
                    if request_counter[0] >= num_requests:
                        break
                with workers_lock:
                    if active_workers[0] == 0:
                        break
                time.sleep(0.1)

            stop_event.set()

        # Wait for all workers to finish
        for wid, future in futures:
            try:
                future.result(timeout=5)
            except Exception:
                pass

    finally:
        stop_event.set()
        for worker_stop in worker_stop_events.values():
            worker_stop.set()
        executor.shutdown(wait=False)

    end_time = time.time()
    total_duration = end_time - start_time

    # Close connection pool
    if pool:
        pool.close_all()

    print("\n")
    return results, total_duration, load_pattern.get_user_timeline()


def calculate_statistics(results: List[Dict], duration_seconds: float, concurrency: int) -> Dict:
    """
    Calculate statistics from test results.

    Args:
        results: List of result dictionaries
        duration_seconds: Total test duration in seconds
        concurrency: Number of virtual users

    Returns:
        Dictionary with statistical summaries
    """
    # A request is successful only if no error AND valid status code (not -1)
    successful = [r for r in results if r["error"] is None and r["status_code"] != -1]
    failed = [r for r in results if r["error"] is not None or r["status_code"] == -1]
    validation_errors = [r for r in results if r.get("validation_error")]
    connection_reused = [r for r in results if r.get("connection_reused", False)]
    stale_retries = [r for r in results if r.get("stale_retry", False)]

    metrics = ["dns_ms", "tcp_ms", "tls_ms", "ttfb_ms", "total_ms"]

    # Calculate throughput metrics
    qps = len(results) / duration_seconds if duration_seconds > 0 else 0
    successful_qps = len(successful) / duration_seconds if duration_seconds > 0 else 0

    # Total connection attempts = requests + retries
    # Note: With conservative retry logic, retries only happen when connection was dead
    # before sending, so retries don't cause duplicate server-side processing
    total_connection_attempts = len(results) + len(stale_retries)

    stats = {
        "total_requests": len(results),
        "total_connection_attempts": total_connection_attempts,
        "successful": len(successful),
        "failed": len(failed),
        "validation_errors": len(validation_errors),
        "success_rate": len(successful) / len(results) * 100 if results else 0,
        "duration_seconds": duration_seconds,
        "virtual_users": concurrency,
        "qps": qps,
        "successful_qps": successful_qps,
        "connections_reused": len(connection_reused),
        "connection_reuse_rate": len(connection_reused) / len(results) * 100 if results else 0,
        "stale_connection_retries": len(stale_retries),
        "status_codes": {},
        "metrics": {}
    }

    # Count status codes
    for r in results:
        code = str(r["status_code"])
        stats["status_codes"][code] = stats["status_codes"].get(code, 0) + 1

    # Calculate metrics statistics
    for metric in metrics:
        values = [r[metric] for r in successful if r[metric] >= 0]
        if values:
            sorted_values = sorted(values)
            stats["metrics"][metric] = {
                "min": min(values),
                "max": max(values),
                "avg": statistics.mean(values),
                "median": statistics.median(values),
                "p50": sorted_values[int(len(values) * 0.5)],
                "p90": sorted_values[int(len(values) * 0.9)] if len(values) >= 10 else max(values),
                "p95": sorted_values[int(len(values) * 0.95)] if len(values) >= 20 else max(values),
                "p99": sorted_values[int(len(values) * 0.99)] if len(values) >= 100 else max(values),
                "stddev": statistics.stdev(values) if len(values) > 1 else 0
            }
        else:
            stats["metrics"][metric] = None

    return stats


def draw_histogram(values: List[float], width: int = 50, height: int = 10, title: str = "") -> str:
    """Draw an ASCII histogram."""
    if not values:
        return "  No data available"

    min_val = min(values)
    max_val = max(values)

    if min_val == max_val:
        max_val = min_val + 1

    num_buckets = min(width, 40)
    bucket_size = (max_val - min_val) / num_buckets
    buckets = [0] * num_buckets

    for v in values:
        idx = min(int((v - min_val) / bucket_size), num_buckets - 1)
        buckets[idx] += 1

    max_count = max(buckets)

    lines = []
    if title:
        lines.append(f"  {BOLD}{title}{RESET}")

    for row in range(height, 0, -1):
        threshold = (row / height) * max_count
        line = "  │"
        for count in buckets:
            if count >= threshold:
                line += CYAN + BLOCK_FULL + RESET
            else:
                line += " "
        lines.append(line)

    lines.append("  └" + "─" * num_buckets)
    lines.append(f"  {min_val:.0f}ms{' ' * (num_buckets - 10)}{max_val:.0f}ms")

    return "\n".join(lines)


def draw_timeline(results: List[Dict], width: int = 60) -> str:
    """Draw a timeline graph showing request latencies over time."""
    if not results:
        return "  No data available"

    if len(results) > width:
        step = len(results) / width
        sampled = [results[int(i * step)] for i in range(width)]
    else:
        sampled = results

    total_times = [r["total_ms"] for r in sampled if r["total_ms"] >= 0]

    if not total_times:
        return "  No successful requests"

    max_time = max(total_times)
    min_time = min(total_times)
    height = 8

    lines = []
    lines.append(f"  {BOLD}Response Time Over Time{RESET}")
    lines.append(f"  {max_time:.0f}ms ┤")

    for row in range(height - 1, -1, -1):
        threshold_low = min_time + (row / height) * (max_time - min_time)
        threshold_high = min_time + ((row + 1) / height) * (max_time - min_time)

        line = "       │" if row > 0 else f"  {min_time:.0f}ms ┤"

        for t in total_times:
            if threshold_low <= t < threshold_high:
                line += GREEN + "•" + RESET
            elif t >= threshold_high:
                line += YELLOW + "│" + RESET
            else:
                line += " "

        lines.append(line)

    lines.append("       └" + "─" * len(total_times))
    lines.append(f"        1{' ' * (len(total_times) - 5)}{len(results)}")
    lines.append("        Request Number →")

    return "\n".join(lines)


def draw_breakdown_bar(stats: Dict, width: int = 50) -> str:
    """Draw a stacked bar showing timing breakdown."""
    metrics = stats.get("metrics", {})

    components = [
        ("DNS", "dns_ms", BLUE),
        ("TCP", "tcp_ms", GREEN),
        ("TLS", "tls_ms", YELLOW),
        ("TTFB", "ttfb_ms", MAGENTA),
    ]

    lines = []
    lines.append(f"\n  {BOLD}Average Timing Breakdown{RESET}")

    total_avg = 0
    values = []

    for name, key, color in components:
        if metrics.get(key) and metrics[key].get("avg"):
            val = metrics[key]["avg"]
            values.append((name, val, color))
            total_avg += val

    if total_avg == 0:
        return "  No timing data available"

    bar = "  ["
    for name, val, color in values:
        bar_width = int((val / total_avg) * width)
        bar += color + BLOCK_FULL * bar_width + RESET
    bar += "]"
    lines.append(bar)

    legend = "  "
    for name, val, color in values:
        pct = (val / total_avg) * 100
        legend += f"{color}■{RESET} {name}: {val:.1f}ms ({pct:.0f}%)  "
    lines.append(legend)

    return "\n".join(lines)


def print_report(results: List[Dict], stats: Dict) -> None:
    """Print formatted report with statistics and graphs (Locust-style)."""

    # Header
    print()
    print(f"{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                       🚀 LOAD TEST REPORT                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════════╝{RESET}")

    # Quick Stats Bar (Locust-style)
    success_rate = stats['success_rate']
    rate_color = GREEN if success_rate >= 99 else YELLOW if success_rate >= 95 else RED
    metrics = stats.get("metrics", {})
    median_ms = metrics.get("total_ms", {}).get("median", 0) or 0
    p95_ms = metrics.get("total_ms", {}).get("p95", 0) or 0

    print()
    print(f"  {BOLD}Reqs:{RESET} {stats['total_requests']:,}  "
          f"{BOLD}OK:{RESET} {GREEN}{stats['successful']:,}{RESET}  "
          f"{BOLD}Fail:{RESET} {RED if stats['failed'] > 0 else ''}{stats['failed']:,}{RESET if stats['failed'] > 0 else ''}  "
          f"{BOLD}Rate:{RESET} {rate_color}{success_rate:.1f}%{RESET}  "
          f"{BOLD}RPS:{RESET} {CYAN}{stats['qps']:.1f}{RESET}  "
          f"{BOLD}Median:{RESET} {median_ms:.0f}ms  "
          f"{BOLD}P95:{RESET} {p95_ms:.0f}ms")

    # Locust-style Statistics Table
    print()
    print(f"{BOLD}┌─────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐{RESET}")
    print(f"{BOLD}│ Metric  │    Min   │    Avg   │   Med    │   P90    │   P95    │   P99    │    Max   │{RESET}")
    print(f"{BOLD}├─────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤{RESET}")

    metric_labels = [
        ("DNS", "dns_ms", BLUE),
        ("TCP", "tcp_ms", GREEN),
        ("TLS", "tls_ms", YELLOW),
        ("TTFB", "ttfb_ms", MAGENTA),
        ("Total", "total_ms", CYAN),
    ]

    for label, key, color in metric_labels:
        m = stats["metrics"].get(key)
        if m:
            print(f"│ {color}{label:<7}{RESET} │ {m['min']:>7.1f}ms │ {m['avg']:>7.1f}ms │ "
                  f"{m['median']:>7.1f}ms │ {m['p90']:>7.1f}ms │ {m['p95']:>7.1f}ms │ "
                  f"{m['p99']:>7.1f}ms │ {m['max']:>7.1f}ms │")
        else:
            print(f"│ {label:<7} │ {'N/A':>8} │ {'N/A':>8} │ {'N/A':>8} │ {'N/A':>8} │ {'N/A':>8} │ {'N/A':>8} │ {'N/A':>8} │")

    print(f"{BOLD}└─────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘{RESET}")

    # Percentile Distribution Bar
    if metrics.get("total_ms"):
        m = metrics["total_ms"]
        max_val = m.get("max", 1) or 1
        print()
        print(f"  {BOLD}Response Time Distribution:{RESET}")
        print(f"  0ms {BLOCK_EMPTY * 60} {max_val:.0f}ms")

        # Draw percentile markers
        bar = list(" " * 60)
        for pct, val, marker in [(50, m.get("median", 0), "▼"), (90, m.get("p90", 0), "▼"), (95, m.get("p95", 0), "▼"), (99, m.get("p99", 0), "▼")]:
            if val and max_val > 0:
                pos = min(59, int((val / max_val) * 59))
                bar[pos] = marker
        print(f"      {''.join(bar)}")
        print(f"      {GREEN}P50{RESET}{'':>15}{YELLOW}P90{RESET}{'':>5}{RED}P95{RESET}{'':>3}{MAGENTA}P99{RESET}")

    # Status Codes
    print()
    print(f"  {BOLD}Status Codes:{RESET}")
    for code, count in sorted(stats["status_codes"].items()):
        color = GREEN if code.startswith("2") else YELLOW if code.startswith("3") else RED
        pct = (count / stats["total_requests"]) * 100
        bar_len = int(pct / 2)
        print(f"    {color}{code}{RESET} │{BLOCK_FULL * bar_len}{BLOCK_EMPTY * (50 - bar_len)}│ {count:,} ({pct:.1f}%)")

    # Error summary if there are failures
    if stats['failed'] > 0:
        print()
        print(f"  {BOLD}{RED}Errors:{RESET}")
        error_counts: Dict[str, int] = {}
        for r in results:
            if r.get("error"):
                err = r["error"][:50]
                error_counts[err] = error_counts.get(err, 0) + 1
        for err, count in sorted(error_counts.items(), key=lambda x: -x[1])[:5]:
            print(f"    {RED}✗{RESET} {count}x {err}")

    # Connection info
    if stats['connections_reused'] > 0:
        print()
        print(f"  {BOLD}Connections:{RESET} {stats['connections_reused']:,} reused ({stats['connection_reuse_rate']:.0f}%)"
              + (f" │ {YELLOW}{stats.get('stale_connection_retries', 0)} retries{RESET}" if stats.get('stale_connection_retries', 0) > 0 else ""))

    # Graphs
    print()
    print(f"{BOLD}{'─' * 74}{RESET}")
    print(f"{BOLD}                           VISUALIZATIONS{RESET}")
    print(f"{BOLD}{'─' * 74}{RESET}")

    print(draw_breakdown_bar(stats))
    print()
    print(draw_timeline(results))

    total_times = [r["total_ms"] for r in results if r["total_ms"] >= 0]
    print()
    print(draw_histogram(total_times, title="Response Time Distribution"))

    print()
    print(f"{BOLD}{CYAN}{'═' * 74}{RESET}")


def export_results(results: List[Dict], stats: Dict, filepath: str) -> None:
    """Export results to JSON file."""
    output = {
        "timestamp": datetime.now().isoformat(),
        "summary": stats,
        "requests": results
    }

    with open(filepath, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"{GREEN}Results exported to: {filepath}{RESET}")


def export_html_report(results: List[Dict], stats: Dict, url: str, filepath: str,
                       user_timeline: List[Tuple[float, int]] = None, pattern: str = "constant") -> None:
    """Export results to interactive HTML report with charts (like Locust)."""
    import html as html_module  # For escaping

    # Escape URL for safe HTML insertion
    safe_url = html_module.escape(url)
    user_timeline = user_timeline or []

    # Prepare data for charts
    timestamps = []
    response_times = []
    successful_times = []

    start_time = None
    for r in results:
        try:
            ts = datetime.fromisoformat(r["timestamp"])
            if start_time is None:
                start_time = ts
            elapsed = (ts - start_time).total_seconds()
            timestamps.append(round(elapsed, 2))
            response_times.append(round(r["total_ms"], 2) if r["total_ms"] >= 0 else None)
            if r["status_code"] > 0 and r["error"] is None:
                successful_times.append(r["total_ms"])
        except (ValueError, KeyError):
            pass

    # Calculate RPS over time (1-second buckets)
    max_time = max(timestamps) if timestamps else 0
    rps_data = []
    rps_labels = []
    for i in range(int(max_time) + 1):
        count = sum(1 for t in timestamps if i <= t < i + 1)
        rps_labels.append(i)
        rps_data.append(count)

    # Response time distribution buckets
    if successful_times:
        min_rt = min(successful_times)
        max_rt = max(successful_times)
        bucket_count = 20
        bucket_size = (max_rt - min_rt) / bucket_count if max_rt > min_rt else 1
        dist_labels = []
        dist_data = []
        for i in range(bucket_count):
            low = min_rt + i * bucket_size
            high = low + bucket_size
            count = sum(1 for t in successful_times if low <= t < high)
            dist_labels.append(f"{low:.0f}")
            dist_data.append(count)
    else:
        dist_labels = []
        dist_data = []

    # Error summary (with HTML escaping)
    error_counts: Dict[str, int] = {}
    for r in results:
        if r.get("error"):
            err = html_module.escape(r["error"][:60])
            error_counts[err] = error_counts.get(err, 0) + 1

    # Metrics for timing breakdown
    metrics = stats.get("metrics", {})
    timing_labels = ["DNS", "TCP", "TLS", "TTFB"]
    timing_avg = [
        metrics.get("dns_ms", {}).get("avg", 0) or 0,
        metrics.get("tcp_ms", {}).get("avg", 0) or 0,
        metrics.get("tls_ms", {}).get("avg", 0) or 0,
        metrics.get("ttfb_ms", {}).get("avg", 0) or 0,
    ]

    # User timeline data for users graph
    user_times = [t[0] for t in user_timeline] if user_timeline else []
    user_counts = [t[1] for t in user_timeline] if user_timeline else []

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Load Test Report - {safe_url}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{
            color: #00d4aa;
            margin-bottom: 10px;
            font-size: 28px;
        }}
        .subtitle {{
            color: #888;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            color: #00d4aa;
        }}
        .stat-value.error {{ color: #ff6b6b; }}
        .stat-value.warning {{ color: #ffd93d; }}
        .stat-label {{
            color: #888;
            font-size: 14px;
            margin-top: 5px;
        }}
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(600px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .chart-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
        }}
        .chart-title {{
            color: #00d4aa;
            margin-bottom: 15px;
            font-size: 18px;
        }}
        .chart-container {{
            position: relative;
            height: 300px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #2a2a4a;
        }}
        th {{
            background: #1a1a2e;
            color: #00d4aa;
            font-weight: 600;
        }}
        tr:hover {{ background: #1f1f3a; }}
        .success {{ color: #00d4aa; }}
        .error {{ color: #ff6b6b; }}
        .metric-bar {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .metric-bar-fill {{
            height: 8px;
            border-radius: 4px;
            background: linear-gradient(90deg, #00d4aa, #00a8cc);
        }}
        .timing-table td:nth-child(n+2) {{ text-align: right; font-family: monospace; }}
        .timing-table th:nth-child(n+2) {{ text-align: right; }}
        .error-list {{
            background: #2a1a1a;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }}
        .error-item {{
            padding: 8px 0;
            border-bottom: 1px solid #3a2a2a;
            font-family: monospace;
            font-size: 13px;
        }}
        .error-count {{
            color: #ff6b6b;
            font-weight: bold;
            margin-right: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Load Test Report</h1>
        <div class="subtitle">
            Target: <strong>{safe_url}</strong> |
            Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
            Duration: {stats.get("duration_seconds", 0):.2f}s
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats.get("total_requests", 0)}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value success">{stats.get("successful", 0)}</div>
                <div class="stat-label">Successful</div>
            </div>
            <div class="stat-card">
                <div class="stat-value {"error" if stats.get("failed", 0) > 0 else ""}">{stats.get("failed", 0)}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value {"error" if stats.get("success_rate", 0) < 95 else "warning" if stats.get("success_rate", 0) < 100 else ""}">{stats.get("success_rate", 0):.1f}%</div>
                <div class="stat-label">Success Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get("qps", 0):.2f}</div>
                <div class="stat-label">Requests/sec</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get("virtual_users", 1)}</div>
                <div class="stat-label">Virtual Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{metrics.get("total_ms", {}).get("median", 0) or 0:.0f}ms</div>
                <div class="stat-label">Median Response</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{metrics.get("total_ms", {}).get("p95", 0) or 0:.0f}ms</div>
                <div class="stat-label">95th Percentile</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <h3 class="chart-title">📈 Response Time Over Time</h3>
                <div class="chart-container">
                    <canvas id="responseTimeChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">📊 Requests Per Second</h3>
                <div class="chart-container">
                    <canvas id="rpsChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">📉 Response Time Distribution</h3>
                <div class="chart-container">
                    <canvas id="distributionChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">⏱️ Timing Breakdown (Avg)</h3>
                <div class="chart-container">
                    <canvas id="timingChart"></canvas>
                </div>
            </div>
            {"" if not user_timeline else f'''<div class="chart-card">
                <h3 class="chart-title">👥 Virtual Users Over Time ({pattern})</h3>
                <div class="chart-container">
                    <canvas id="usersChart"></canvas>
                </div>
            </div>'''}
        </div>

        <div class="chart-card">
            <h3 class="chart-title">📋 Timing Statistics (milliseconds)</h3>
            <table class="timing-table">
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Min</th>
                        <th>Avg</th>
                        <th>Median</th>
                        <th>P90</th>
                        <th>P95</th>
                        <th>P99</th>
                        <th>Max</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''<tr>
                        <td><strong>{name}</strong></td>
                        <td>{metrics.get(key, {}).get("min", 0) or 0:.1f}</td>
                        <td>{metrics.get(key, {}).get("avg", 0) or 0:.1f}</td>
                        <td>{metrics.get(key, {}).get("median", 0) or 0:.1f}</td>
                        <td>{metrics.get(key, {}).get("p90", 0) or 0:.1f}</td>
                        <td>{metrics.get(key, {}).get("p95", 0) or 0:.1f}</td>
                        <td>{metrics.get(key, {}).get("p99", 0) or 0:.1f}</td>
                        <td>{metrics.get(key, {}).get("max", 0) or 0:.1f}</td>
                    </tr>''' for name, key in [("DNS", "dns_ms"), ("TCP", "tcp_ms"), ("TLS", "tls_ms"), ("TTFB", "ttfb_ms"), ("Total", "total_ms")])}
                </tbody>
            </table>
        </div>

        {"" if not error_counts else f'''
        <div class="chart-card" style="margin-top: 20px;">
            <h3 class="chart-title">❌ Error Summary</h3>
            <div class="error-list">
                {"".join(f'<div class="error-item"><span class="error-count">{count}x</span>{err}</div>' for err, count in sorted(error_counts.items(), key=lambda x: -x[1]))}
            </div>
        </div>
        '''}
    </div>

    <script>
        // Response Time Over Time
        new Chart(document.getElementById('responseTimeChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(timestamps)},
                datasets: [{{
                    label: 'Response Time (ms)',
                    data: {json.dumps(response_times)},
                    borderColor: '#00d4aa',
                    backgroundColor: 'rgba(0, 212, 170, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: {0 if len(timestamps) > 100 else 3}
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{
                        grid: {{ color: '#2a2a4a' }},
                        ticks: {{ color: '#888' }},
                        title: {{ display: true, text: 'Time (s)', color: '#888' }}
                    }},
                    y: {{
                        grid: {{ color: '#2a2a4a' }},
                        ticks: {{ color: '#888' }},
                        title: {{ display: true, text: 'Response Time (ms)', color: '#888' }}
                    }}
                }}
            }}
        }});

        // RPS Chart
        new Chart(document.getElementById('rpsChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(rps_labels)},
                datasets: [{{
                    label: 'Requests/sec',
                    data: {json.dumps(rps_data)},
                    backgroundColor: '#00a8cc',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{
                        grid: {{ color: '#2a2a4a' }},
                        ticks: {{ color: '#888' }},
                        title: {{ display: true, text: 'Time (s)', color: '#888' }}
                    }},
                    y: {{
                        grid: {{ color: '#2a2a4a' }},
                        ticks: {{ color: '#888' }},
                        title: {{ display: true, text: 'Requests', color: '#888' }},
                        beginAtZero: true
                    }}
                }}
            }}
        }});

        // Distribution Chart
        new Chart(document.getElementById('distributionChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(dist_labels)},
                datasets: [{{
                    label: 'Count',
                    data: {json.dumps(dist_data)},
                    backgroundColor: '#6c5ce7',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{
                        grid: {{ color: '#2a2a4a' }},
                        ticks: {{ color: '#888' }},
                        title: {{ display: true, text: 'Response Time (ms)', color: '#888' }}
                    }},
                    y: {{
                        grid: {{ color: '#2a2a4a' }},
                        ticks: {{ color: '#888' }},
                        title: {{ display: true, text: 'Count', color: '#888' }},
                        beginAtZero: true
                    }}
                }}
            }}
        }});

        // Timing Breakdown Chart
        new Chart(document.getElementById('timingChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(timing_labels)},
                datasets: [{{
                    data: {json.dumps(timing_avg)},
                    backgroundColor: ['#00d4aa', '#00a8cc', '#6c5ce7', '#fd79a8'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: true,
                        position: 'right',
                        labels: {{ color: '#888' }}
                    }}
                }}
            }}
        }});

        // Virtual Users Over Time Chart
        {"" if not user_timeline else f'''
        new Chart(document.getElementById('usersChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(user_times)},
                datasets: [{{
                    label: 'Active Users',
                    data: {json.dumps(user_counts)},
                    borderColor: '#fd79a8',
                    backgroundColor: 'rgba(253, 121, 168, 0.1)',
                    fill: true,
                    stepped: true,
                    tension: 0,
                    pointRadius: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{
                        grid: {{ color: '#2a2a4a' }},
                        ticks: {{ color: '#888' }},
                        title: {{ display: true, text: 'Time (s)', color: '#888' }}
                    }},
                    y: {{
                        grid: {{ color: '#2a2a4a' }},
                        ticks: {{ color: '#888', stepSize: 1 }},
                        title: {{ display: true, text: 'Active Users', color: '#888' }},
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        '''}
    </script>
</body>
</html>'''

    with open(filepath, "w") as f:
        f.write(html)

    print(f"{GREEN}HTML report exported to: {filepath}{RESET}")


def load_headers_from_env() -> Dict[str, str]:
    """Load custom headers from environment variables."""
    headers = {}

    api_key = os.getenv("API_KEY")
    bearer_token = os.getenv("BEARER_TOKEN")

    if api_key:
        headers["X-API-Key"] = api_key
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    custom = os.getenv("CUSTOM_HEADERS")
    if custom:
        try:
            headers.update(json.loads(custom))
        except json.JSONDecodeError:
            print(f"{YELLOW}Warning: CUSTOM_HEADERS is not valid JSON{RESET}")

    return headers


def main():
    parser = argparse.ArgumentParser(
        description="API Load Tester - Benchmark API endpoints with detailed timing metrics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://api.example.com/health
  %(prog)s https://api.example.com/users -n 100
  %(prog)s https://api.example.com/data -d 60 -v
  %(prog)s https://api.example.com/test -n 50 -o results.json
  %(prog)s https://api.example.com/post -m POST --data '{"key":"value"}'
  %(prog)s https://api.example.com/stress -n 100 -c 10   (10 virtual users)
  %(prog)s https://api.example.com/load -d 30 -c 5      (5 VUs for 30 seconds)
  %(prog)s https://api.example.com/api -n 100 -q 50     (target 50 QPS)
  %(prog)s https://api.example.com/api --expect-status 200 --expect-body '"ok"'
        """
    )

    parser.add_argument("url", help="Target URL to test")
    parser.add_argument("-n", "--requests", type=int, default=10,
                        help="Number of requests to make (default: 10)")
    parser.add_argument("-d", "--duration", type=int,
                        help="Duration in seconds (overrides --requests)")
    parser.add_argument("-m", "--method", default="GET",
                        choices=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
                        help="HTTP method (default: GET)")
    parser.add_argument("--data", help="Request body data (for POST/PUT/PATCH)")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                        help="Custom header (format: 'Key: Value'). Can be used multiple times")
    parser.add_argument("-c", "--concurrency", type=int, default=1,
                        help="Number of concurrent virtual users (default: 1)")
    parser.add_argument("-q", "--qps", type=float, default=0,
                        help="Target queries per second, 0 = unlimited (default: 0)")
    parser.add_argument("--delay", type=int, default=0,
                        help="Delay between requests in milliseconds (default: 0)")
    parser.add_argument("--no-keepalive", action="store_true",
                        help="Disable HTTP keep-alive connections")
    parser.add_argument("--expect-status", type=int,
                        help="Expected HTTP status code for validation")
    parser.add_argument("--expect-body", type=str,
                        help="Expected substring in response body for validation")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output for each request")
    parser.add_argument("-o", "--output", help="Export results to JSON file")
    parser.add_argument("--html", help="Export interactive HTML report with charts")
    parser.add_argument("--no-graph", action="store_true",
                        help="Disable graphical output")

    # Load pattern arguments
    parser.add_argument("--pattern", type=str, default="constant",
                        choices=["constant", "ramp-up", "step", "spike", "soak"],
                        help="Load pattern: constant (default), ramp-up, step, spike, soak")
    parser.add_argument("--ramp-duration", type=float, default=0,
                        help="Ramp-up duration in seconds (for ramp-up pattern, default: 50%% of duration)")
    parser.add_argument("--step-users", type=int, default=1,
                        help="Users to add per step (for step pattern, default: 1)")
    parser.add_argument("--step-duration", type=float, default=10,
                        help="Duration of each step in seconds (for step pattern, default: 10)")
    parser.add_argument("--spike-users", type=int, default=0,
                        help="Peak users during spike (for spike pattern, default: 2x concurrency)")
    parser.add_argument("--spike-duration", type=float, default=10,
                        help="Duration of spike in seconds (for spike pattern, default: 10)")
    parser.add_argument("--spike-delay", type=float, default=0,
                        help="Delay before spike starts in seconds (for spike pattern, default: 30%% of duration)")

    args = parser.parse_args()

    # Validate URL
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.hostname:
        print(f"{RED}Error: Invalid URL. Please include scheme (http/https){RESET}")
        sys.exit(1)

    # Build headers
    headers = load_headers_from_env()

    if args.headers:
        for h in args.headers:
            if ": " in h:
                key, value = h.split(": ", 1)
                headers[key] = value
            else:
                print(f"{YELLOW}Warning: Invalid header format '{h}'. Use 'Key: Value'{RESET}")

    # Validate concurrency
    if args.concurrency < 1:
        print(f"{RED}Error: Concurrency must be at least 1{RESET}")
        sys.exit(1)

    # Run load test
    try:
        results, duration, user_timeline = run_load_test(
            url=args.url,
            num_requests=args.requests if not args.duration else None,
            duration_seconds=args.duration,
            method=args.method,
            headers=headers if headers else None,
            data=args.data,
            concurrency=args.concurrency,
            delay_ms=args.delay,
            verbose=args.verbose,
            keep_alive=not args.no_keepalive,
            target_qps=args.qps,
            expect_status=args.expect_status,
            expect_body=args.expect_body,
            pattern=args.pattern,
            ramp_duration=args.ramp_duration,
            step_users=args.step_users,
            step_duration=args.step_duration,
            spike_users=args.spike_users,
            spike_duration=args.spike_duration,
            spike_delay=args.spike_delay
        )
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Test interrupted by user{RESET}")
        sys.exit(0)

    if not results:
        print(f"{RED}No results collected{RESET}")
        sys.exit(1)

    # Calculate statistics
    stats = calculate_statistics(results, duration, args.concurrency)

    # Print report
    if not args.no_graph:
        print_report(results, stats)
    else:
        print(f"\nTotal: {stats['total_requests']} | "
              f"Success: {stats['successful']} | "
              f"Failed: {stats['failed']}")
        print(f"VUs: {stats['virtual_users']} | "
              f"Duration: {stats['duration_seconds']:.2f}s | "
              f"QPS: {stats['qps']:.2f}")
        if stats["metrics"].get("total_ms"):
            m = stats["metrics"]["total_ms"]
            print(f"Avg: {m['avg']:.1f}ms | P95: {m['p95']:.1f}ms | Max: {m['max']:.1f}ms")

    # Export if requested
    if args.output:
        export_results(results, stats, args.output)

    if args.html:
        export_html_report(results, stats, args.url, args.html, user_timeline, args.pattern)

    # Exit with error if validation failures
    if stats['validation_errors'] > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
