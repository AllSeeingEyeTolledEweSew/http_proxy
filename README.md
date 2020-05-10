# http_proxy

This is a python HTTP proxy. It was developed as a testing utility for [libtorrent](http://github.com/arvidn/libtorrent), and has limited feature support.

## goals

* single python file, suitable for direct execution
* no third-party dependencies
* suitable for testing http clients that may make calls through a proxy
* compatible with the oldest currently-supported python3 (3.6 as of writing)

## non-goals

* efficiency
* scalability
* production-grade security

## features

* connection reuse and pipelining requests from the client
  * does not pipeline requests to upstream server
* correct handling of `Transfer-Encoding: chunked`
  * chunked encoding is passed through, both client-to-upstream and upstream-to-client
  * actually used whenever `Content-Length` is absent and `Transfer-Encoding` is not `identity`, per the HTTP/1.1 spec
* correct handling of HTTP/1.1 `Connection:` header
  * `close` is detected as a distinct token (`Connection: close, Transfer-Encoding` is recognized as including `Connection: close`)
  * `close` is passed through, and taken into account for connection reuse
  * standard hop-by-hop headers, and those marked by `Connection:`, are not passed through
    * except `Transfer-Encoding`, as above
* accurate error handling and mapping of HTTP status codes
* optional Basic authentication
* configurable timeout
* the `CONNECT` method
  * the timeout applies to inactivity on the connection
