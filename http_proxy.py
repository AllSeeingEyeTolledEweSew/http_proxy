#!/usr/bin/env python3

# The author disclaims copyright to this source code. Please see the
# accompanying UNLICENSE file.

import argparse
import base64
import http.client
import http.server
import select
import socket
import traceback
import urllib.parse


class ChunkError(Exception):

    pass


class _HTTPError(Exception):

    def __init__(self, code, message=None, explain=None):
        super().__init__()
        self.code = code
        self.message = message
        self.explain = explain


def read_to_end_of_chunks(file_like):

    def inner():
        while True:
            size_line = file_like.readline()
            yield size_line
            try:
                size = int(size_line, 16)
            except ValueError:
                raise ChunkError("Invalid chunk size: %r" % size_line)
            if size < 0:
                raise ChunkError("Invalid chunk size: %d" % size)
            if size == 0:
                # Allow trailers, if any
                while True:
                    line = file_like.readline()
                    yield line
                    if line in (b"\r\n", b"", b"\n"):
                        return
            # Chunk size + crlf
            chunk = file_like.read(size + 2)
            yield chunk

    # Interpret any empty read as a closed connection, and stop
    for chunk in inner():
        if not chunk:
            return
        yield chunk


def read_to_limit(file_like, limit, buffer_size):
    offset = 0
    while offset < limit:
        amount = min(limit - offset, buffer_size)
        buf = file_like.read(amount)
        if not buf:
            return
        yield buf
        offset += len(buf)


def read_all(file_like, buffer_size):
    while True:
        buf = file_like.read(buffer_size)
        if not buf:
            return
        yield buf


class Handler(http.server.BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"

    BUFLEN = 8192

    close_connection = True
    timeout = 30
    basic_auth = None

    def authorize(self):
        if not self.basic_auth:
            return True

        header = self.headers.get("Proxy-Authorization")
        split = header.split(None, 1)
        if len(split) != 2:
            return False
        scheme, credentials = split
        if scheme.lower() != "basic":
            return False
        return credentials == self.basic_auth

    def do_auth(self):
        if self.authorize():
            return True

        # send_error doesn't let us send headers, so do it by hand
        self.log_error("code %d, message %s", 407,
                       "Proxy authorization required")
        self.send_response(407, "Proxy authorization required")
        self.send_header("Connection", "close")
        self.send_header("Proxy-Authenticate", "Basic")
        self.end_headers()
        return False

    def connect_request(self):
        split = self.path.split(":")
        if len(split) != 2:
            raise _HTTPError(400, explain="Target must be host:port")
        host, port = split

        try:
            return socket.create_connection((host, port), self.timeout)
        except socket.timeout:
            raise _HTTPError(504, explain=traceback.format_exc())
        except OSError:
            raise _HTTPError(502, explain=traceback.format_exc())

    def bidirectional_proxy(self, upstream):
        socks = (upstream, self.request)
        while True:
            (rlist, _, xlist) = select.select(socks, (), socks, self.timeout)
            if xlist:
                return
            if not rlist:
                return
            for sock in rlist:
                data = sock.recv(self.BUFLEN)
                if not data:
                    return
                if sock is upstream:
                    self.request.sendall(data)
                else:
                    upstream.sendall(data)

    # pylint:disable=invalid-name
    def do_CONNECT(self):
        upstream = None
        try:
            if not self.do_auth():
                return

            upstream = self.connect_request()
        except _HTTPError as err:
            self.send_error(err.code, message=err.message, explain=err.explain)
        except:  # pylint:disable=bare-except
            self.log_error("%s", traceback.format_exc())
            self.send_error(500, explain=traceback.format_exc())

        if upstream is None:
            return

        self.send_response(200)
        self.send_header("Connection", "close")
        self.end_headers()

        try:
            self.bidirectional_proxy(upstream)
        except:  # pylint:disable=bare-except
            self.log_error("%s", traceback.format_exc())
            self.close_connection = True

        upstream.close()

    def proxy_request(self):
        url = urllib.parse.urlsplit(self.path)

        if url.scheme != "http":
            raise _HTTPError(400, message="Target scheme is not http")

        # We need to read only the expected amount from the client
        # https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
        if self.headers.get("Transfer-Encoding", "identity") != "identity":
            # BaseHTTPHandler never parses chunked encoding itself
            message_body = read_to_end_of_chunks(self.rfile)
        elif "Content-Length" in self.headers:
            try:
                length = int(self.headers["Content-Length"])
            except ValueError:
                raise _HTTPError(411)
            message_body = read_to_limit(self.rfile, length, self.BUFLEN)
        elif self.command not in ("PATCH", "POST", "PUT"):
            # Not expecting a body
            message_body = None
        else:
            raise _HTTPError(411)

        try:
            upstream = http.client.HTTPConnection(url.netloc,
                                                  timeout=self.timeout)
        except http.client.InvalidURL as exc:
            raise _HTTPError(400,
                             message=str(exc),
                             explain=traceback.format_exc())

        path = urllib.parse.urlunsplit(("", "", url.path, url.query, ""))
        upstream.putrequest(self.command,
                            path,
                            skip_host=True,
                            skip_accept_encoding=True)

        connection_tokens = []
        filter_headers = set(
            ("proxy-authorization", "connection", "keep-alive"))
        pass_headers = set(("transfer-encoding", "te", "trailer"))
        if "Connection" in self.headers:
            request_connection_tokens = [
                token.strip() for token in self.headers["Connection"].split(",")
            ]
        else:
            request_connection_tokens = []
        for token in request_connection_tokens:
            # Better parsing than base class, I think
            if token.lower() == "keep-alive":
                self.close_connection = False
                filter_headers.add(token.lower())
            elif token.lower() == "close":
                self.close_connection = True
            elif token.lower() in pass_headers:
                connection_tokens.append(token)
            else:
                filter_headers.add(token.lower())

        for name, value in self.headers.items():
            if name.lower() in filter_headers:
                continue
            upstream.putheader(name, value)

        # No pipelineing to upstream
        if "close" not in connection_tokens:
            connection_tokens.append("close")

        upstream.putheader("Connection", ", ".join(connection_tokens))

        try:
            # Never use encode_chunked here, as we pass through
            # transfer-encoding from the client.
            # Calls socket.create_connection, so catch socket exceptions here.
            upstream.endheaders(message_body=message_body)
            # This parses the upstream response line and headers
            return (upstream, upstream.getresponse())
        except socket.timeout:
            raise _HTTPError(504, explain=traceback.format_exc())
        except (OSError, http.client.HTTPException):
            upstream.close()
            raise _HTTPError(502, explain=traceback.format_exc())
        except ChunkError as exc:
            upstream.close()
            raise _HTTPError(400,
                             message=str(exc),
                             explain=traceback.format_exc())

    def proxy_response(self, response):
        # send_response supplies some headers unconditionally
        self.log_request(response.code)
        self.send_response_only(response.code, response.reason)

        connection_tokens = []
        filter_headers = set(
            ("proxy-authorization", "connection", "keep-alive"))
        pass_headers = set(("transfer-encoding", "te", "trailer"))
        if response.getheader("Connection"):
            response_connection_tokens = [
                token.strip()
                for token in response.getheader("Connection").split(",")
            ]
        else:
            response_connection_tokens = []
        for token in response_connection_tokens:
            if token.lower() == "close":
                continue
            if token.lower() in pass_headers:
                connection_tokens.append(token)
            else:
                filter_headers.add(token.lower())
        # Close the connection if the client requested it
        if self.close_connection:
            connection_tokens.append("close")
        for name, value in response.getheaders():
            if name.lower() in filter_headers:
                continue
            self.send_header(name, value)
        if connection_tokens:
            self.send_header("Connection", ", ".join(connection_tokens))

        self.end_headers()

        # HTTPResponse.read() will decode chunks, but we want to pass them
        # through. Use this "hack" to pass through the encoding, and just use
        # our own reader. Field is undocumented, but public.
        response.chunked = False

        # https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
        if response.getheader("Transfer-Encoding", "identity") != "identity":
            body = read_to_end_of_chunks(response)
        elif response.getheader("Content-Length"):
            try:
                length = int(response.getheader("Content-Length"))
            except ValueError:
                body = read_all(response, self.BUFLEN)
            else:
                body = read_to_limit(response, length, self.BUFLEN)
        else:
            # May hang if the server wrongly keeps the connection alive
            body = read_all(response, self.BUFLEN)

        for chunk in body:
            self.wfile.write(chunk)

    def do_proxy(self):
        upstream = None
        response = None
        try:
            if not self.do_auth():
                return

            upstream, response = self.proxy_request()
        except _HTTPError as exc:
            self.send_error(exc.code, message=exc.message, explain=exc.explain)
        except:  # pylint:disable=bare-except
            self.log_error("%s", traceback.format_exc())
            self.send_error(500, explain=traceback.format_exc())

        if not response:
            return

        try:
            self.proxy_response(response)
        except:  # pylint:disable=bare-except
            self.log_error("%s", traceback.format_exc())
            self.close_connection = True

        upstream.close()

    # pylint:disable=invalid-name
    def do_GET(self):
        self.do_proxy()

    # pylint:disable=invalid-name
    def do_POST(self):
        self.do_proxy()

    # pylint:disable=invalid-name
    def do_PUT(self):
        self.do_proxy()

    # pylint:disable=invalid-name
    def do_PATCH(self):
        self.do_proxy()

    # pylint:disable=invalid-name
    def do_HEAD(self):
        self.do_proxy()

    # pylint:disable=invalid-name
    def do_OPTIONS(self):
        self.do_proxy()

    # pylint:disable=invalid-name
    def do_DELETE(self):
        self.do_proxy()

    # pylint:disable=invalid-name
    def do_TRACE(self):
        self.do_proxy()


def main():
    parser = argparse.ArgumentParser("Simple HTTP proxy")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--basic-auth")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--bind-host", default="localhost")

    args = parser.parse_args()

    address = (args.bind_host, args.port)

    if args.basic_auth:
        Handler.basic_auth = base64.b64encode(args.basic_auth.encode()).decode()

    http.server.ThreadingHTTPServer(address, Handler)


if __name__ == "__main__":
    main()
