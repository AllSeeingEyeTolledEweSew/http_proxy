# The author disclaims copyright to this source code. Please see the
# accompanying UNLICENSE file.

import time
import unittest
import unittest.mock
import logging
import tempfile
import socket
import os
import os.path
import collections
import logging
import random
import http.server
import http.client
import threading
import urllib.parse
import json

import http_proxy


LEN = 9000
CHUNK = 1013
DATA = bytes(i % 256 for i in range(LEN))


def get_chunks():
    for i in range(0, LEN, CHUNK):
        yield DATA[i:i + CHUNK]


class FixtureHandler(http.server.BaseHTTPRequestHandler):

    def path_empty(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def path_empty_no_length(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self.end_headers()

    def path_empty_with_hop_by_hop(self):
        self.send_response(200)
        self.send_header("Connection", "close, X-Magic")
        self.send_header("X-Magic", "abcd1234")
        self.end_headers()

    def path_bad_status_line(self):
        self.wfile.write(b"HTTP/1.1 whoopsie\r\n")

    def path_data(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(LEN))
        self.end_headers()
        self.wfile.write(DATA)

    def path_data_short(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(LEN))
        self.end_headers()
        self.wfile.write(DATA[:LEN // 2])

    def path_data_no_length(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(DATA)

    def path_data_with_invalid_length(self):
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "whoopsie")
        self.end_headers()
        self.wfile.write(DATA)

    def path_data_chunked(self):
        self.send_response(200)
        self.send_header("Connection", "close, Transfer-Encoding")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for chunk in get_chunks():
            self.wfile.write(b"%x\r\n" % len(chunk))
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    def path_data_chunked_invalid(self):
        self.send_response(200)
        self.send_header("Connection", "close, Transfer-Encoding")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.write(b"whoopsie\r\n")

    def path_data_chunked_short(self):
        self.send_response(200)
        self.send_header("Connection", "close, Transfer-Encoding")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.write(b"123\r\n")

    def path_trailers(self):
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

    def path_reflect_headers(self):
        data = dict(
                requestline=self.requestline,
        headers=dict(self.headers.items()))
        data = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def path_reflect_data(self):
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

    def path_forbidden(self):
        self.send_response(403)
        self.send_header("Connection", "close")
        self.end_headers()

    def dispatch(self):
        path = self.path[1:]
        handler = getattr(self, "path_" + path, None)
        if handler:
            handler()
        else:
            self.send_error(404)

    def do_GET(self):
        self.dispatch()

    def do_PUT(self):
        self.dispatch()

    def do_PATCH(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_HEAD(self):
        self.dispatch()

    def do_OPTIONS(self):
        self.dispatch()

    def do_TRACE(self):
        self.dispatch()


class BaseTest(unittest.TestCase):

    def setUp(self):
        self.proxy = http.server.HTTPServer(("localhost", 0),
                http_proxy.Handler)
        self.proxy_thread = threading.Thread(name="proxy",
                target=self.proxy.serve_forever, daemon=True)
        self.proxy_thread.start()

    def tearDown(self):
        self.proxy.shutdown()

    def get_conn(self):
        host, port = self.proxy.socket.getsockname()
        return http.client.HTTPConnection(host, port=port)

    def check_header_sanity(self, headers):
        counter = collections.Counter(headers.keys())
        duplicates = {name: value for name, value in counter.items() if value > 1}
        self.assertEqual(duplicates, {})


class HTTPProxyTest(BaseTest):
    """Tests for tvaf.dal.create_schema()."""

    def setUp(self):
        super().setUp()
        self.httpd = http.server.HTTPServer(("localhost", 0), FixtureHandler)
        self.httpd_thread = threading.Thread(name="httpd",
                target=self.httpd.serve_forever, daemon=True)
        self.httpd_thread.start()

    def tearDown(self):
        super().tearDown()
        self.httpd.shutdown()

    def do_request(self, method, path, headers=None, message_body=None,
            encode_chunked=False):
        conn = self.get_conn()
        self.putrequest_proxy_to_httpd(conn, method, path)
        headers = dict(headers or {})
        connection_header = "close"
        if "Connection" in headers:
            connection_header += ", " + headers["Connection"]
        headers["Connection"] = connection_header
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        conn.endheaders(message_body=message_body,
                encode_chunked=encode_chunked)
        return conn

    def putrequest_proxy_to_httpd(self, conn, method, path):
        host, port = self.httpd.socket.getsockname()
        url = urllib.parse.urlunsplit(("http", "%s:%d" % (host, port), path,
            None, None))
        conn.putrequest(method, url)

    def test_get_bad_status_line(self):
        response = self.do_request("GET", "/bad_status_line").getresponse()
        self.assertEqual(response.status, 502)
        self.check_header_sanity(response.headers)

    def test_get_forbidden(self):
        response = self.do_request("GET", "/forbidden").getresponse()
        self.assertEqual(response.status, 403)
        self.check_header_sanity(response.headers)

    def test_nonexistent_gateway(self):
        conn = self.get_conn()
        conn.putrequest("GET", "http://does-not-exist/")
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 502)
        self.check_header_sanity(response.headers)

    def test_gateway_timeout(self):
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
            data = response.read()
            self.assertEqual(response.status, 504)
            self.check_header_sanity(response.headers)

    def test_non_http_url(self):
        conn = self.get_conn()
        conn.putrequest("GET", "https://example.com/")
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 400)
        self.check_header_sanity(response.headers)

    def test_invalid_http_url(self):
        conn = self.get_conn()
        conn.putrequest("GET", "http://example.com:whoopsie/")
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 400)
        self.check_header_sanity(response.headers)

    def test_get_empty(self):
        response = self.do_request("GET", "/empty").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), "0")
        self.assertEqual(response.read(), b"")

    def test_get_empty_no_length(self):
        response = self.do_request("GET", "/empty_no_length").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        self.assertEqual(response.read(), b"")

    def test_get_empty_with_hop_by_hop(self):
        response = self.do_request("GET", "/empty_with_hop_by_hop").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertNotIn("X-Magic", response.headers)

    def test_get_data(self):
        response = self.do_request("GET", "/data").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), str(LEN))
        self.assertEqual(response.read(), DATA)

    def test_get_data_with_invalid_length(self):
        response = self.do_request("GET", "/data_with_invalid_length").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.read(), DATA)

    def test_get_data_short(self):
        response = self.do_request("GET", "/data_short").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), str(LEN))
        with self.assertRaises(http.client.IncompleteRead):
            response.read()

    def test_get_data_no_length(self):
        response = self.do_request("GET", "/data_no_length").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        self.assertEqual(response.read(), DATA)

    def test_get_data_chunked(self):
        response = self.do_request("GET", "/data_chunked").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        self.assertEqual(response.read(), DATA)

    def test_get_data_chunked_invalid(self):
        response = self.do_request("GET", "/data_chunked_invalid").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        with self.assertRaises(http.client.IncompleteRead):
            response.read()

    def test_get_data_chunked_short(self):
        response = self.do_request("GET", "/data_chunked_short").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        with self.assertRaises(http.client.IncompleteRead):
            response.read()

    def test_basic_auth(self):
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Basic secret"}
            response = self.do_request("GET", "/data", headers=headers).getresponse()
            self.assertEqual(response.status, 200)
            self.check_header_sanity(response.headers)
            self.assertEqual(response.getheader("Content-Length"), str(LEN))
            self.assertEqual(response.read(), DATA)

    def test_basic_auth_fail(self):
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Basic wrong"}
            response = self.do_request("GET", "/data", headers=headers).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_malformed(self):
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "malformed"}
            response = self.do_request("GET", "/data", headers=headers).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_wrong_scheme(self):
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Digest secret"}
            response = self.do_request("GET", "/data", headers=headers).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_trailers(self):
        response = self.do_request("GET", "/trailers").getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        self.assertEqual(response.getheader("Content-Length"), None)
        # http.client doesn't actually parse trailers, but at least test
        # they're processed correctly
        self.assertNotEqual(response.getheader("Trailer"), None)
        self.assertEqual(response.read(), DATA)

    def test_reflect_headers(self):
        headers = {"X-End-To-End": "foo", "X-Hop-By-Hop": "bar", "Connection":
                "close, X-Hop-By-Hop"}
        response = self.do_request("GET", "/reflect_headers", headers=headers).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        data = json.loads(response.read().decode())
        seen_headers = data["headers"]
        self.assertEqual(seen_headers.get("X-End-To-End"), headers.get("X-End-To-End"))
        self.assertNotIn("X-Hop-By-Hop", seen_headers)

    def test_reflect_data(self):
        response = self.do_request("POST", "/reflect_data",
                headers={"Content-Length": str(LEN)}, message_body=DATA).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        data = response.read()
        self.assertEqual(data, DATA)

    def test_reflect_data_chunked(self):
        response = self.do_request("POST", "/reflect_data",
                headers={"Transfer-Encoding": "chunked"},
                message_body=get_chunks(), encode_chunked=True).getresponse()
        self.assertEqual(response.status, 200)
        self.check_header_sanity(response.headers)
        data = response.read()
        self.assertEqual(data, DATA)

    def test_body_bad_length(self):
        response = self.do_request("POST", "/empty",
                headers={"Content-Length": "whoopsie"}).getresponse()
        self.assertEqual(response.status, 411)
        self.check_header_sanity(response.headers)

    def test_body_required(self):
        response = self.do_request("POST", "/empty").getresponse()
        self.assertEqual(response.status, 411)
        self.check_header_sanity(response.headers)

    def test_body_invalid_chunk(self):
        response = self.do_request("POST", "/empty",
                headers={"Transfer-Encoding": "chunked"},
                message_body=b"whoopsie\r\n").getresponse()
        self.assertEqual(response.status, 400)
        self.check_header_sanity(response.headers)

    def test_pipelining(self):
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

        def read_status(file_like):
            line = file_like.readline().decode()
            version, status, reason = line.split(None, 2)
            return version, int(status), reason

        def read_chunks_discard_trailer(file_like):
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
        headers = http.client.parse_headers(rfile)
        self.check_header_sanity(headers)
        self.assertEqual(headers["Content-Length"], str(LEN))
        data = rfile.read(LEN)
        self.assertEqual(data, DATA)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 200)
        headers = http.client.parse_headers(rfile)
        self.check_header_sanity(headers)
        self.assertEqual(headers["Content-Length"], str(LEN))
        data = rfile.read(LEN)
        self.assertEqual(data, DATA)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 200)
        headers = http.client.parse_headers(rfile)
        self.check_header_sanity(headers)
        self.assertEqual(headers["Content-Length"], str(LEN))
        data = rfile.read(LEN)
        self.assertEqual(data, DATA)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 200)
        headers = http.client.parse_headers(rfile)
        self.check_header_sanity(headers)
        self.assertEqual(headers["Transfer-Encoding"], "chunked")
        data = b"".join(read_chunks_discard_trailer(rfile))
        self.assertEqual(data, DATA)

        version, status, _ = read_status(rfile)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(status, 403)
        headers = http.client.parse_headers(rfile)
        self.check_header_sanity(headers)

        # Test the socket gets closed
        self.assertEqual(rfile.read(), b"")


class ConnectMethodTest(BaseTest):

    def do_connect_obj(self, path, headers=None):
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

    def do_connect_obj_to_server(self, headers=None):
        return self.do_connect_obj("%s:%d" % self.server.getsockname(),
                headers=headers)

    def make_connected_pair(self):
        proxy_address = self.proxy.socket.getsockname()
        c_to_s = socket.create_connection(proxy_address, 30)
        server_host, server_port = self.server.getsockname()
        c_to_s.sendall(b"CONNECT %s:%d HTTP/1.1\r\n" % (server_host.encode(), server_port))
        c_to_s.sendall(b"\r\n")

        s_to_c, _ = self.server.accept()

        with c_to_s.makefile("rb") as c_rfile:
            version, status, _ = c_rfile.readline().decode().split(None, 2)
            status = int(status)
            self.assertEqual(version, "HTTP/1.1")
            self.assertGreaterEqual(status, 200)
            self.assertLess(status, 300)
            headers = http.client.parse_headers(c_rfile)
            self.check_header_sanity(headers)
            self.assertEqual(headers["Connection"], "close")

        return c_to_s, s_to_c

    def setUp(self):
        super().setUp()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("localhost", 0))
        self.server.listen()

    def test_basic_auth(self):
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Basic secret"}
            response = self.do_connect_obj_to_server(headers=headers).getresponse()
            self.assertEqual(response.status, 200)
            self.check_header_sanity(response.headers)

    def test_basic_auth_fail(self):
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Basic wrong"}
            response = self.do_connect_obj_to_server(headers=headers).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_malformed(self):
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "malformed"}
            response = self.do_connect_obj_to_server(headers=headers).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_basic_auth_wrong_scheme(self):
        with unittest.mock.patch("http_proxy.Handler.basic_auth", "secret"):
            headers = {"Proxy-Authorization": "Digest secret"}
            response = self.do_connect_obj_to_server(headers=headers).getresponse()
            self.assertEqual(response.status, 407)
            self.check_header_sanity(response.headers)

    def test_malformed(self):
        response = self.do_connect_obj("malformed").getresponse()
        self.assertGreaterEqual(response.status, 400)
        self.assertLess(response.status, 500)
        self.check_header_sanity(response.headers)

    def test_nonexistent_gateway(self):
        response = self.do_connect_obj("does-not-exist:80").getresponse()
        self.assertEqual(response.status, 502)
        self.check_header_sanity(response.headers)

    def test_gateway_timeout(self):
        with unittest.mock.patch("http_proxy.Handler.timeout", 1):
            response = self.do_connect_obj("0.0.0.1:80").getresponse()
            self.assertEqual(response.status, 504)
            self.check_header_sanity(response.headers)

    def test_shutdown_on_read_timeout(self):
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

    def test_connect_and_close_upstream(self):
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

    def test_connect_and_close_client(self):
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