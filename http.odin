package sakura

import "core:strconv"
import "core:sys/linux"

// HTTP/1.1 request parser and response writer. Parsing allocates nothing:
// header keys and values are slices into the connection's read buffer.
// Responses are appended to the connection's output buffer, which the event
// loop flushes with one send per batch (see loop.odin).

Header :: struct {
	key, value: string,
}

MAX_HEADERS :: 48
MAX_HEADER_BYTES :: 64 * 1024

Request :: struct {
	method:         string,
	target:         string,
	path:           string,
	query:          string,
	headers:        [MAX_HEADERS]Header,
	n_headers:      int,
	content_length: int,
	keep_alive:     bool,
	head_end:       int, // offset in conn.in_buf just past CRLFCRLF
}

// Header names are ASCII case-insensitive; `name` must be lowercase.
header_get :: proc "contextless" (req: ^Request, name: string) -> (string, bool) {
	for &h in req.headers[:req.n_headers] {
		if ascii_ieq_lower(h.key, name) {
			return h.value, true
		}
	}
	return "", false
}

@(private = "file")
ascii_ieq_lower :: #force_inline proc "contextless" (s, lower: string) -> bool {
	if len(s) != len(lower) {
		return false
	}
	for i in 0 ..< len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

Parse_Result :: enum u8 {
	Ok,
	Incomplete,
	Bad,
}

// Returns the absolute index just past the terminating CRLFCRLF, or -1.
// Resumes scanning from c.scan so a slowly arriving header block is scanned
// once.
@(private = "file")
find_headers_end :: proc "contextless" (c: ^Conn) -> int {
	buf := c.in_buf[:]
	from := max(c.start, c.scan - 3)
	#no_bounds_check for i := from; i + 3 < len(buf); i += 1 {
		if buf[i + 3] != '\n' {
			continue
		}
		if buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' {
			return i + 4
		}
	}
	c.scan = len(buf)
	return -1
}

// Parse one request line + headers starting at c.start into `req`. The body
// stays in the buffer; `req.head_end` marks where it begins.
parse_request :: proc(c: ^Conn, req: ^Request) -> Parse_Result {
	head_end := find_headers_end(c)
	if head_end < 0 {
		return len(c.in_buf) - c.start > MAX_HEADER_BYTES ? .Bad : .Incomplete
	}
	head := string(c.in_buf[c.start:head_end - 2])
	req^ = {}
	req.head_end = head_end

	line, rest := cut_line(head)
	sp1 := index_byte(line, ' ')
	if sp1 < 0 {
		return .Bad
	}
	req.method = line[:sp1]
	line = line[sp1 + 1:]
	sp2 := index_byte(line, ' ')
	if sp2 < 0 {
		return .Bad
	}
	req.target = line[:sp2]
	version := line[sp2 + 1:]

	req.path = req.target
	if q := index_byte(req.target, '?'); q >= 0 {
		req.path = req.target[:q]
		req.query = req.target[q + 1:]
	}

	conn_hdr := ""
	for len(rest) > 0 {
		line, rest = cut_line(rest)
		colon := index_byte(line, ':')
		if colon <= 0 {
			continue
		}
		if req.n_headers == MAX_HEADERS {
			return .Bad
		}
		key := trim_ows(line[:colon])
		val := trim_ows(line[colon + 1:])
		req.headers[req.n_headers] = {key, val}
		req.n_headers += 1
		if ascii_ieq_lower(key, "content-length") {
			n, ok := strconv.parse_int(val, 10)
			if !ok || n < 0 {
				return .Bad
			}
			req.content_length = n
		} else if ascii_ieq_lower(key, "connection") {
			conn_hdr = val
		}
	}

	if version == "HTTP/1.0" {
		req.keep_alive = ascii_ieq_lower(conn_hdr, "keep-alive")
	} else {
		req.keep_alive = !ascii_ieq_lower(conn_hdr, "close")
	}
	return .Ok
}

@(private = "file")
cut_line :: #force_inline proc "contextless" (s: string) -> (line, rest: string) {
	nl := index_byte(s, '\n')
	if nl < 0 {
		return s, ""
	}
	line = s[:nl]
	if len(line) > 0 && line[len(line) - 1] == '\r' {
		line = line[:len(line) - 1]
	}
	return line, s[nl + 1:]
}

@(private = "file")
trim_ows :: #force_inline proc "contextless" (s: string) -> string {
	a, b := 0, len(s)
	for a < b && (s[a] == ' ' || s[a] == '\t') {
		a += 1
	}
	for b > a && (s[b - 1] == ' ' || s[b - 1] == '\t') {
		b -= 1
	}
	return s[a:b]
}

index_byte :: #force_inline proc "contextless" (s: string, b: u8) -> int {
	#no_bounds_check for i in 0 ..< len(s) {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// --- responses ------------------------------------------------------------

@(private = "file")
status_line :: proc "contextless" (code: int) -> string {
	switch code {
	case 200:
		return "HTTP/1.1 200 OK\r\n"
	case 201:
		return "HTTP/1.1 201 Created\r\n"
	case 204:
		return "HTTP/1.1 204 No Content\r\n"
	case 206:
		return "HTTP/1.1 206 Partial Content\r\n"
	case 304:
		return "HTTP/1.1 304 Not Modified\r\n"
	case 400:
		return "HTTP/1.1 400 Bad Request\r\n"
	case 401:
		return "HTTP/1.1 401 Unauthorized\r\n"
	case 403:
		return "HTTP/1.1 403 Forbidden\r\n"
	case 404:
		return "HTTP/1.1 404 Not Found\r\n"
	case 405:
		return "HTTP/1.1 405 Method Not Allowed\r\n"
	case 409:
		return "HTTP/1.1 409 Conflict\r\n"
	case 411:
		return "HTTP/1.1 411 Length Required\r\n"
	case 413:
		return "HTTP/1.1 413 Content Too Large\r\n"
	case 415:
		return "HTTP/1.1 415 Unsupported Media Type\r\n"
	case 416:
		return "HTTP/1.1 416 Range Not Satisfiable\r\n"
	case 500:
		return "HTTP/1.1 500 Internal Server Error\r\n"
	case 502:
		return "HTTP/1.1 502 Bad Gateway\r\n"
	case 503:
		return "HTTP/1.1 503 Service Unavailable\r\n"
	}
	return "HTTP/1.1 200 OK\r\n"
}

// CORS headers required by BUD-01 on every response.
COMMON_HEADERS ::
	"Access-Control-Allow-Origin: *\r\n" +
	"Access-Control-Allow-Headers: Authorization, *\r\n" +
	"Access-Control-Allow-Methods: GET, HEAD, PUT, DELETE\r\n" +
	"Server: sakura\r\n"

// Terminates every header block; the Connection header always comes last so
// cached header prefixes can be reused for both.
connection_tail :: #force_inline proc "contextless" (keep_alive: bool) -> string {
	return keep_alive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n"
}

out_str :: #force_inline proc(c: ^Conn, s: string) {
	append(&c.out, s)
}

out_int :: proc(c: ^Conn, v: i64) {
	buf: [24]u8
	append(&c.out, strconv.write_int(buf[:], v, 10))
}

// Status line, common headers, Content-Type and extras: everything up to
// Content-Length.
@(private = "file")
write_head :: proc(c: ^Conn, code: int, content_type: string, extra: []Header) {
	out_str(c, status_line(code))
	out_str(c, COMMON_HEADERS)
	if content_type != "" {
		out_str(c, "Content-Type: ")
		out_str(c, content_type)
		out_str(c, "\r\n")
	}
	for h in extra {
		out_str(c, h.key)
		out_str(c, ": ")
		out_str(c, h.value)
		out_str(c, "\r\n")
	}
}

// Queue a complete response with an in-memory body.
respond :: proc(
	c: ^Conn,
	code: int,
	content_type: string,
	body: []u8,
	keep_alive: bool,
	extra: []Header = {},
) {
	write_head(c, code, content_type, extra)
	out_str(c, "Content-Length: ")
	out_int(c, i64(len(body)))
	out_str(c, "\r\n")
	out_str(c, connection_tail(keep_alive))
	append(&c.out, ..body)
	if !keep_alive {
		c.close_after = true
	}
}

// Queue just a header block with an explicit Content-Length; the caller then
// queues the body (bytes or a file range).
respond_headers :: proc(
	c: ^Conn,
	code: int,
	content_type: string,
	content_length: i64,
	keep_alive: bool,
	extra: []Header = {},
) {
	write_head(c, code, content_type, extra)
	out_str(c, "Content-Length: ")
	out_int(c, content_length)
	out_str(c, "\r\n")
	out_str(c, connection_tail(keep_alive))
	if !keep_alive {
		c.close_after = true
	}
}

// Plain-text error with an X-Reason header (BUD diagnostic).
respond_error :: proc(c: ^Conn, code: int, reason: string, keep_alive: bool) {
	respond(c, code, "text/plain", transmute([]u8)reason, keep_alive, {{"X-Reason", reason}})
}

// Blocking send of everything; used only off the event loop (mirror thread).
send_blocking :: proc(fd: linux.Fd, data: []u8) -> bool {
	sent := 0
	for sent < len(data) {
		n, err := linux.send(fd, data[sent:], {.NOSIGNAL})
		if err == .EINTR {
			continue
		}
		if err != .NONE || n == 0 {
			return false
		}
		sent += n
	}
	return true
}
