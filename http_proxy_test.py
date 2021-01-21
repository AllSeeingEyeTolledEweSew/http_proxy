# The author disclaims copyright to this source code. Please see the
# accompanying UNLICENSE file.
"""Tests for http_proxy."""

import base64
import collections
import contextlib
import email.message
import http.client
import http.server
import json
import socket
import threading
import time
from typing import BinaryIO
from typing import cast
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import Tuple
from typing import Union
import unittest
import unittest.mock
import urllib.parse

import http_proxy

LEN = 9000
CHUNK = 1013
DATA = bytes(i % 256 for i in range(LEN))


def get_chunks() -> Iterator[bytes]:
    """Yields fixture data in arbitrary-sized chunks."""
    for i in range(0, LEN, CHUNK):
        yield DATA[i : i + CHUNK]


def parse_headers(fp: BinaryIO) -> http.client.HTTPMessage:
    # mypy 0.790's typeshed is missing this function
    return http.client.parse_headers(fp)  # type: ignore


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    """Handler class for HTTP server test cases."""

    # pylint: disable=too-many-public-methods

    def path_empty(self) -> None:
        """Send an empty response with Content-Length: 0"""
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def path_empty_no_length(self) -> None:
        """Send an empty response with no Content-Length"""
        self.send_response(200)
        self.send_header("Connection", "close")
        self.end_headers()

    def path_empty_with_hop_by_hop(self) -> None:
        """Send an empty response with a nonstandard hop-by-hop header"""
        self.send_response(200)
        self.send_header("Connection", "close, X-Magic")
        self.send_header("X-Magic", "abcd1234")
        self.end_headers()

    def path_bad_status_line(self) -> None:
        """Send a bad HTTP response status line"""
        self.wfile.write(b"HTTP/1.1 whoopsie\r\n")

    def path_data(self) -> None:
        """Send some data with Content-Length"""
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(LEN))
        self.end_headers()
        self.wfile.write(DATA)

    def path_data_short(self) -> None:
        """Send some data, truncated according to its Content-Length"""
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(LEN))
        self.end_headers()
        self.wfile.write(DATA[: LEN // 2])

    def path_data_no_length(self) -> None:
        """Send some data with no Content-Length"""
        self.send_response(200)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(DATA)

    def path_data_with_invalid_length(self) -> None:
        """Send some data with a garbage Content-Length"""
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "whoopsie")
        self.end_headers()
        self.wfile.write(DATA)

    def path_data_chunked(self) -> None:
        """Send some data using chunked encoding"""
        self.send_response(200)
        self.send_header("Connection", "close, Transfer-Encoding")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for chunk in get_chunks():
            self.wfile.write(b"%x\r\n" % len(chunk))
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    def path_data_chunked_invalid(self) -> None:
        """Send some chunked encoding with an invalid chunk size"""
        self.send_response(200)
        self.send_header("Connection", "close, Transfer-Encoding")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.write(b"whoopsie\r\n")

    def path_data_chunked_short(self) -> None:
        """Send some truncated chunked encoding"""
        self.send_response(200)
        self.send_header("Connection", "close, Transfer-Encoding")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.write(b"123\r\n")

    def path_trailers(self) -> None:
        """Send some data using chunked encoding with HTTP trailers"""
        self.send_response(200)
        self.send_header("Connection", "close, Transfer-Encoding")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Trailer", "Checksum")
        self.end_headers()
        for chunk in get_chunks():
            self.wfile.write(b"%x\r\n" % len(chunk))
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")
        self.wfile.write(b"0\r\n")
        self.wfile.write(b"Checksum: abc123\r\n")
        self.wfile.write(b"\r\n")

    def path_reflect_headers(self) -> None:
        """Send the received headers and status line as JSON"""
        data_dict = dict(
            requestline=self.requestline, headers=dict(self.headers.items())
        )
        data = json.dumps(data_dict).encode()
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def path_reflect_data(self) -> None:
        """Send the received request body, transforming chunked encoding"""
        data = b""
        if self.headers.get("Transfer-Encoding", "identity") != "identity":
            while True:
                length = int(self.rfile.readline(), 16)
                if length == 0:
                    while True:
                        line = self.rfile.readline()
                        if line in (b"\r\n", b"", b"\n"):
                            break
                    break
                data += self.rfile.read(length)
                self.rfile.read(2)
        elif "Content-Length" in self.headers:
            length = int(self.headers["Content-Length"])
            data = self.rfile.read(length)
        else:
            data = self.rfile.read()
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def path_forbidden(self) -> None:
        """Send a 403 response"""
        self.send_response(403)
        self.send_header("Connection", "close")
        self.end_headers()

    def dispatch(self) -> None:
        """Generic implementation for the do_* handler methods"""
        path = self.path[1:]
        handler = getattr(self, "path_" + path, None)
        if handler:
            handler()
        else:
            self.send_error(404)

    # pylint: disable=invalid-name
    def do_GET(self) -> None:
        """Handle a test GET request"""
        self.dispatch()

    # pylint: disable=invalid-name
    def do_PUT(self) -> None:
        """Handle a test PUT request"""
        self.dispatch()

    # pylint: disable=invalid-name
    def do_PATCH(self) -> None:
        """Handle a test PATCH request"""
        self.dispatch()

    # pylint: disable=invalid-name
    def do_POST(self) -> None:
        """Handle a test POST request"""
        self.dispatch()

    # pylint: disable=invalid-name
    def do_HEAD(self) -> None:
        """Handle a test HEAD request"""
        self.dispatch()

    # pylint: disable=invalid-name
    def do_OPTIONS(self) -> None:
        """Handle a test OPTIONS request"""
        self.dispatch()

    # pylint: disable=invalid-name
    def do_TRACE(self) -> None:
        """Handle a test TRACE request"""
        self.dispatch()


class BaseTest(unittest.TestCase):
    """Base class with common utility functions"""

    def setUp(self) -> None:
        self.proxy = http.server.HTTPServer(
            ("localhost", 0), http_proxy.Handler
        )
        self.proxy_thread = threading.Thread(
            name="proxy", target=self.proxy.serve_forever, daemon=True
        )
        self.httpd = http.server.HTTPServer(("localhost", 0), FixtureHandler)
        self.httpd_thread = threading.Thread(
            name="httpd", target=self.httpd.serve_forever, daemon=True
        )

    def get_conn(self) -> http.client.HTTPConnection:
        """Returns a HTTPConnection to the proxy"""
        host, port = self.proxy.socket.getsockname()
        return http.client.HTTPConnection(host, port=port)

    def putrequest_proxy_to_httpd(
        self, conn: http.client.HTTPConnection, method: str, path: str
    ) -> None:
        host, port = self.httpd.socket.getsockname()
        url = urllib.parse.urlunsplit(
            ("http", "%s:%d" % (host, port), path, None, None)
        )
        conn.putrequest(method, url)

    def check_header_sanity(self, headers: email.message.Message) -> None:
        """Checks response headers for sanity.

        Args:
            headers: A multi-valued dict (email.message.Message subclass) of
                response headers
        """
        counter = collections.Counter(headers.keys())
        duplicates = {
            name: value for name, value in counter.items() if value > 1
        }
        self.assertEqual(duplicates, {})


class HTTPProxyTest(BaseTest):
    """Tests for normal HTTP methods (not CONNECT)."""

    # pylint: disable=too-many-public-methods

    def setUp(self) -> None:
        super().setUp()
        self.proxy_thread.start()
        self.httpd_thread.start()

    def tearDown(self) -> None:
        super().tearDown()
        self.proxy.shutdown()
        self.httpd.shutdown()

    def do_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str] = None,
        message_body: Union[bytes, Iterable[bytes], BinaryIO] = None,
        encode_chunked: bool = False,
    ) -> http.client.HTTPConnection:
        """Execute a proxied request to the test webserver.

        Args:
            method: The HTTP method string to use
            path: The relative path on the test webserver
            headers: A dict of headers to send
            message_body: An iterable of bytes, or file-like, or bytes.
            encode_chunked: Whether to write message_body using chunked
                encoding.

        Returns:
            An HTTPConnection, with the given request already sent
        """
        conn = self.get_conn()
        self.putrequest_proxy_to_httpd(conn, method, path)
        headers = dict(headers or {})
        connection_header = "close"
        if "Connection" in headers:
            connection_header += ", " + headers["Connection"]
        headers["Connection"] = connection_header
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        conn.endheaders(
            message_body=message_body, encode_chunked=encode_chunked
        )
        return conn

    def test_get_bad_status_line(self) -> None:
        response = self.do_request("GET", "/bad_status_line").getresponse()
        self.assertEqual(response.status, 502)
        self.check_header_sanity(response.headers)

    def test_get_forbidden(self) -> None:
        response = self.do_request("GET", "/forbidden").getresponse()
        self.assertEqual(response.status, 403)
        self.check_header_sanity(response.headers)

    def test_nonexistent_gateway(self) -> None:
        conn = self.get_conn()
        conn.putrequest("GET", "http://does-not-exist/")
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 502)
        self.check_header_sanity(response.headers)

    def test_gateway_timeout(self) -> None:
        # Create a listening socket that sends nothing
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.settimeout(10)
        server.bind(("localhost", 0))
        host, port = server.getsockname()
        server.listen(10)

        # Set a low timeout
        http_proxy.Handler.timeout = 1

        with unittest.mock.patch("http_proxy.Handler.timeout", 1):
            conn = self.get_conn()
            conn.putrequest("GET", "http://%s:%d/" % (host, port))
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 504)
            self.check_header_sanity(response.headers)

    def test_non_http_url(self) -> None:
        conn = self.get_conn()
        conn.putrequest("GET", "https://example.com/")
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 400)
        self.check_header_sanity(response.headers)

    def test_invalid_http_url(self) -> None:
        conn = self.get_conn()
        conn.putrequest("GET", "http://example.com:whoopsie/")
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 400)
        self.check_header_sanity(response.headers)

    def test_get_empty(self) -> None:
        response = self.do_request("GET", "/empty").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), "0")
        self.assertEqual(response.read(), b"")

    def test_get_empty_no_length(self) -> None:
        response = self.do_request("GET", "/empty_no_length").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        self.assertEqual(response.read(), b"")

    def test_get_empty_with_hop_by_hop(self) -> None:
        response = self.do_request(
            "GET", "/empty_with_hop_by_hop"
        ).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        # HTTPMessage not a Container in mypy 0.790
        self.assertNotIn("X-Magic", response.headers)  # type: ignore

    def test_get_data(self) -> None:
        response = self.do_request("GET", "/data").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), str(LEN))
        self.assertEqual(response.read(), DATA)

    def test_get_data_with_invalid_length(self) -> None:
        response = self.do_request(
            "GET", "/data_with_invalid_length"
        ).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.read(), DATA)

    def test_get_data_short(self) -> None:
        response = self.do_request("GET", "/data_short").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), str(LEN))
        with self.assertRaises(http.client.IncompleteRead):
            response.read()

    def test_get_data_no_length(self) -> None:
        response = self.do_request("GET", "/data_no_length").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        self.assertEqual(response.read(), DATA)

    def test_get_data_chunked(self) -> None:
        response = self.do_request("GET", "/data_chunked").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        self.assertEqual(response.read(), DATA)

    def test_get_data_chunked_invalid(self) -> None:
        response = self.do_request(
            "GET", "/data_chunked_invalid"
        ).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        with self.assertRaises(http.client.IncompleteRead):
            response.read()

    def test_get_data_chunked_short(self) -> None:
        response = self.do_request("GET", "/data_chunked_short").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        with self.assertRaises(http.client.IncompleteRead):
            response.read()

    def test_basic_auth(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Basic secret"}
            response = self.do_request(
                "GET", "/data", headers=headers
            ).getresponse()
            self.assertEqual(response.status, 200)
            self.check_header_sanity(response.headers)
            self.assertEqual(response.getheader("Content-Length"), str(LEN))
            self.assertEqual(response.read(), DATA)

    def test_basic_auth_fail(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Basic wrong"}
            response = self.do_request(
                "GET", "/data", headers=headers
            ).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_absent(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            response = self.do_request("GET", "/data").getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_malformed(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "malformed"}
            response = self.do_request(
                "GET", "/data", headers=headers
            ).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_wrong_scheme(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Digest secret"}
            response = self.do_request(
                "GET", "/data", headers=headers
            ).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_trailers(self) -> None:
        response = self.do_request("GET", "/trailers").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        # http.client doesn't actually parse trailers, but at least test
        # they're processed correctly
        self.assertNotEqual(response.getheader("Trailer"), None)
        self.assertEqual(response.read(), DATA)

    def test_reflect_headers(self) -> None:
        headers = {
            "X-End-To-End": "foo",
            "X-Hop-By-Hop": "bar",
            "Connection": "close, X-Hop-By-Hop",
        }
        response = self.do_request(
            "GET", "/reflect_headers", headers=headers
        ).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        data = json.loads(response.read().decode())
        seen_headers = data["headers"]
        self.assertEqual(
            seen_headers.get("X-End-To-End"), headers.get("X-End-To-End")
        )
        self.assertNotIn("X-Hop-By-Hop", seen_headers)

    def test_reflect_data(self) -> None:
        response = self.do_request(
            "POST",
            "/reflect_data",
            headers={"Content-Length": str(LEN)},
            message_body=DATA,
        ).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        data = response.read()
        self.assertEqual(data, DATA)

    def test_reflect_data_chunked(self) -> None:
        response = self.do_request(
            "POST",
            "/reflect_data",
            headers={"Transfer-Encoding": "chunked"},
            message_body=get_chunks(),
            encode_chunked=True,
        ).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        data = response.read()
        self.assertEqual(data, DATA)

    def test_body_bad_length(self) -> None:
        response = self.do_request(
            "POST", "/empty", headers={"Content-Length": "whoopsie"}
        ).getresponse()
        self.assertEqual(response.status, 411)
        self.check_header_sanity(response.headers)

    def test_body_required(self) -> None:
        response = self.do_request("POST", "/empty").getresponse()
        self.assertEqual(response.status, 411)
        self.check_header_sanity(response.headers)

    def test_body_invalid_chunk(self) -> None:
        response = self.do_request(
            "POST",
            "/empty",
            headers={"Transfer-Encoding": "chunked"},
            message_body=b"whoopsie\r\n",
        ).getresponse()
        self.assertEqual(response.status, 400)
        self.check_header_sanity(response.headers)

    def test_pipelining(self) -> None:
        # python's http.client doesn't support pipelining!
        # NB: this could hang depending on socket buffer sizes.
        proxy_address = self.proxy.socket.getsockname()
        sock = socket.create_connection(proxy_address, 30)
        rfile = sock.makefile("rb")
        httpd_host = ("%s:%d" % self.httpd.socket.getsockname()).encode()
        sock.sendall(b"GET http://%s/data HTTP/1.1\r\n" % httpd_host)
        sock.sendall(b"\r\n")
        sock.sendall(b"POST http://%s/reflect_data HTTP/1.1\r\n" % httpd_host)
        sock.sendall(b"Content-Length: %d\r\n" % LEN)
        sock.sendall(b"\r\n")
        sock.sendall(DATA)
        sock.sendall(b"PUT http://%s/reflect_data HTTP/1.1\r\n" % httpd_host)
        sock.sendall(b"Transfer-Encoding: chunked\r\n")
        sock.sendall(b"Connection: Transfer-Encoding\r\n")
        sock.sendall(b"\r\n")
        for chunk in get_chunks():
            sock.sendall(b"%x\r\n" % len(chunk))
            sock.sendall(chunk)
            sock.sendall(b"\r\n")
        sock.sendall(b"0\r\n")
        sock.sendall(b"\r\n")
        sock.sendall(b"GET http://%s/data_chunked HTTP/1.1\r\n" % httpd_host)
        sock.sendall(b"\r\n")
        sock.sendall(b"HEAD http://%s/forbidden HTTP/1.1\r\n" % httpd_host)
        sock.sendall(b"Connection: close\r\n")
        sock.sendall(b"\r\n")

        def read_status(file_like: BinaryIO) -> Tuple[str, int, str]:
            line = file_like.readline().decode()
            version, status, reason = line.split(None, 2)
            return version, int(status), reason

        def read_chunks_discard_trailer(
            file_like: BinaryIO,
        ) -> Iterator[bytes]:
            while True:
                size_line = file_like.readline()
                size = int(size_line, 16)
                if size == 0:
                    while True:
                        line = file_like.readline()
                        if line in (b"\r\n", b"", b"\n"):
                            return
                chunk = file_like.read(size)
                self.assertEqual(len(chunk), size)
                yield chunk
                file_like.read(2)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 200)
        headers = parse_headers(rfile)
        self.check_header_sanity(headers)
        self.assertEqual(headers["Content-Length"], str(LEN))
        data = rfile.read(LEN)
        self.assertEqual(data, DATA)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 200)
        headers = parse_headers(rfile)
        self.check_header_sanity(headers)
        self.assertEqual(headers["Content-Length"], str(LEN))
        data = rfile.read(LEN)
        self.assertEqual(data, DATA)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 200)
        headers = parse_headers(rfile)
        self.check_header_sanity(headers)
        self.assertEqual(headers["Content-Length"], str(LEN))
        data = rfile.read(LEN)
        self.assertEqual(data, DATA)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 200)
        headers = parse_headers(rfile)
        self.check_header_sanity(headers)
        self.assertEqual(headers["Transfer-Encoding"], "chunked")
        data = b"".join(read_chunks_discard_trailer(rfile))
        self.assertEqual(data, DATA)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 403)
        headers = parse_headers(rfile)
        self.check_header_sanity(headers)

        # Test the socket gets closed
        self.assertEqual(rfile.read(), b"")


class ConnectMethodTest(BaseTest):
    """Tests for the CONNECT method"""

    def do_connect_obj(
        self, path: str, headers: Dict[str, str] = None
    ) -> http.client.HTTPConnection:
        """Execute a proxied CONNECT request.

        Args:
            path: The CONNECT method target (normally host:port)
            headers: A dict of headers to send

        Returns:
            An HTTPConnection with the given request already sent
        """
        # http.client doesn't actually support bidirectional CONNECT streaming,
        # but it's nice for testing headers
        conn = self.get_conn()
        conn.putrequest("CONNECT", path)
        headers = dict(headers or {})
        connection_header = "close"
        if "Connection" in headers:
            connection_header += ", " + headers["Connection"]
        headers["Connection"] = connection_header
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        conn.endheaders()
        return conn

    def do_connect_obj_to_server(
        self, headers: Dict[str, str] = None
    ) -> http.client.HTTPConnection:
        """Execute a proxied CONNECT request to the fixture server socket.

        Args:
            headers: A dict of headers to send

        Returns:
            An HTTPConnection with the given request already sent
        """
        return self.do_connect_obj(
            "%s:%d" % self.server.getsockname(), headers=headers
        )

    def make_connected_pair(self) -> Tuple[socket.socket, socket.socket]:
        """Establish a proxied pair of connected sockets.

        Executes a CONNECT request to the proxy, to the fixture server socket.
        We will assert that the request was successful and the response was
        valid, then return the sockets on either end of the connection.

        Returns:
            A tuple of socket objects; the first is the client connection to
                the proxy, and the second is the server-side incoming
                connection.
        """
        proxy_address = self.proxy.socket.getsockname()
        c_to_s = socket.create_connection(proxy_address, 30)
        server_host, server_port = self.server.getsockname()
        c_to_s.sendall(
            b"CONNECT %s:%d HTTP/1.1\r\n" % (server_host.encode(), server_port)
        )
        c_to_s.sendall(b"\r\n")

        s_to_c, _ = self.server.accept()

        with c_to_s.makefile("rb") as c_rfile:
            version, status_str, _ = c_rfile.readline().decode().split(None, 2)
            status = int(status_str)
            self.assertEqual(version, "HTTP/1.1")
            self.assertGreaterEqual(status, 200)
            self.assertLess(status, 300)
            headers = parse_headers(c_rfile)
            self.check_header_sanity(headers)
            self.assertEqual(headers["Connection"], "close")

        return c_to_s, s_to_c

    def setUp(self) -> None:
        super().setUp()
        self.proxy_thread.start()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("localhost", 0))
        self.server.listen()

    def tearDown(self) -> None:
        super().tearDown()
        self.proxy.shutdown()
        self.server.close()

    def test_basic_auth(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Basic secret"}
            response = self.do_connect_obj_to_server(
                headers=headers
            ).getresponse()
            self.assertEqual(response.status, 200)
            self.check_header_sanity(response.headers)

    def test_basic_auth_fail(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Basic wrong"}
            response = self.do_connect_obj_to_server(
                headers=headers
            ).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_malformed(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "malformed"}
            response = self.do_connect_obj_to_server(
                headers=headers
            ).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_wrong_scheme(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Digest secret"}
            response = self.do_connect_obj_to_server(
                headers=headers
            ).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_malformed(self) -> None:
        response = self.do_connect_obj("malformed").getresponse()
        self.assertGreaterEqual(response.status, 400)
        self.assertLess(response.status, 500)
        self.check_header_sanity(response.headers)

    def test_nonexistent_gateway(self) -> None:
        response = self.do_connect_obj("does-not-exist:80").getresponse()
        self.assertEqual(response.status, 502)
        self.check_header_sanity(response.headers)

    def test_gateway_timeout(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.timeout", 1):
            response = self.do_connect_obj("0.0.0.1:80").getresponse()
            self.assertEqual(response.status, 504)
            self.check_header_sanity(response.headers)

    def test_shutdown_on_read_timeout(self) -> None:
        with unittest.mock.patch("http_proxy.Handler.timeout", 1):
            c_to_s, s_to_c = self.make_connected_pair()
            # Client and server send greetings, then get closed due to
            # inactivity
            s_to_c.sendall(b"abcd")
            c_to_s.sendall(b"1234")
            with s_to_c.makefile("rb") as s_rfile:
                self.assertEqual(s_rfile.read(), b"1234")
            with c_to_s.makefile("rb") as c_rfile:
                self.assertEqual(c_rfile.read(), b"abcd")

    def test_connect_and_close_upstream(self) -> None:
        c_to_s, s_to_c = self.make_connected_pair()
        c_rfile = c_to_s.makefile("rb")
        s_rfile = s_to_c.makefile("rb")

        s_to_c.sendall(b"abcd")
        self.assertEqual(c_rfile.read(4), b"abcd")

        c_to_s.sendall(b"1234")
        self.assertEqual(s_rfile.read(4), b"1234")

        s_to_c.sendall(b"goodbye")
        # Note: must close socket *and* makefile()s
        s_to_c.close()
        s_rfile.close()
        self.assertEqual(c_rfile.read(), b"goodbye")

    def test_connect_and_close_client(self) -> None:
        c_to_s, s_to_c = self.make_connected_pair()
        c_rfile = c_to_s.makefile("rb")
        s_rfile = s_to_c.makefile("rb")

        s_to_c.sendall(b"abcd")
        self.assertEqual(c_rfile.read(4), b"abcd")

        c_to_s.sendall(b"1234")
        self.assertEqual(s_rfile.read(4), b"1234")

        c_to_s.sendall(b"goodbye")
        # Note: must close socket *and* makefile()s
        c_to_s.close()
        c_rfile.close()
        self.assertEqual(s_rfile.read(), b"goodbye")


class MainTest(BaseTest):
    def setUp(self) -> None:
        super().setUp()
        self.httpd_thread.start()
        self.main = http_proxy.Main()
        self.main_thread = threading.Thread(
            name="main", target=self.main.run, daemon=True
        )

    def tearDown(self) -> None:
        super().tearDown()
        self.httpd.shutdown()
        self.main.shutdown()

    def get_unused_address(self) -> Tuple[str, int]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("localhost", 0))
            return cast(Tuple[str, int], sock.getsockname())

    @contextlib.contextmanager
    def start_and_connect(
        self, *args: str
    ) -> Iterator[http.client.HTTPConnection]:
        host, port = self.get_unused_address()
        argv = ["http_proxy", "--bind-host", host, "--port", str(port)]
        argv += args
        with unittest.mock.patch("sys.argv", argv):
            self.main_thread.start()
            deadline = time.time() + 5
            while True:
                try:
                    sock = socket.create_connection((host, port))
                    sock.close()
                    break
                except OSError:
                    pass
                self.assertLess(time.time(), deadline, msg="startup timed out")
                time.sleep(0.1)
            yield http.client.HTTPConnection(host, port=port)

    def test_normal_startup(self) -> None:
        with self.start_and_connect() as conn:
            self.putrequest_proxy_to_httpd(conn, "GET", "/empty")
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.check_header_sanity(response.headers)
            self.assertEqual(response.getheader("Content-Length"), "0")
            self.assertEqual(response.read(), b"")

    def test_auth_fail(self) -> None:
        with self.start_and_connect("--basic-auth", "test:test") as conn:
            self.putrequest_proxy_to_httpd(conn, "GET", "/empty")
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_auth_pass(self) -> None:
        with self.start_and_connect("--basic-auth", "test:test") as conn:
            self.putrequest_proxy_to_httpd(conn, "GET", "/empty")
            conn.putheader(
                "Proxy-Authorization",
                "Basic %s" % base64.b64encode("test:test".encode()).decode(),
            )
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.check_header_sanity(response.headers)
            self.assertEqual(response.getheader("Content-Length"), "0")
            self.assertEqual(response.read(), b"")
