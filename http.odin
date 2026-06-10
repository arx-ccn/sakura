package sakura

import "core:net"
import "core:strconv"
import "core:strings"

// A tiny HTTP/1.1 server core: buffered connection reader, request parser, and
// response writer. No allocations beyond the per-request arena; header values
// are slices into the connection's read buffer.

Header :: struct {
	key, value: string,
}

Request :: struct {
	method:         string,
	target:         string,
	path:           string,
	query:          string,
	headers:        [dynamic]Header, // keys lowercased; arena-allocated
	content_length: int,
	keep_alive:     bool,
	// Streaming body bookkeeping. `body_start` is the absolute offset in
	// `conn.buf` where the body begins; `body_consumed` tracks how much of the
	// declared content_length has been read so far via the streaming reader.
	body_start:     int,
	body_consumed:  int,
}

// Case-insensitive (keys already lowercased at parse time) linear header lookup.
header_get :: proc(req: ^Request, name: string) -> (string, bool) {
	for h in req.headers {
		if h.key == name {
			return h.value, true
		}
	}
	return "", false
}

// A connection's read buffer persists across keep-alive requests. `start` marks
// how much has been consumed; the buffer is compacted between requests.
// `scan` tracks how far find_headers_end has scanned to avoid O(n^2) rescans.
Conn :: struct {
	sock:  net.TCP_Socket,
	buf:   [dynamic]u8,
	start: int,
	scan:  int,
}

// recv directly into the dynamic buffer's tail (no stack bounce-copy).
@(private = "file")
conn_fill :: proc(c: ^Conn) -> bool {
	old_len := len(c.buf)
	resize(&c.buf, old_len + 16384)
	n, err := net.recv_tcp(c.sock, c.buf[old_len:])
	if err != nil || n == 0 {
		resize(&c.buf, old_len)
		return false
	}
	resize(&c.buf, old_len + n)
	return true
}

// Returns the absolute index just past the terminating CRLFCRLF, or -1.
// Resumes scanning from c.scan (relative to c.start) each call.
@(private = "file")
find_headers_end :: proc(c: ^Conn) -> int {
	buf := c.buf
	// Start scanning a few bytes before the previously scanned tail so a CRLF
	// pair straddling two fills is not missed.
	from := c.scan
	if from < c.start {
		from = c.start
	} else if from > 3 {
		from -= 3
	}
	if len(buf) >= 4 {
		#no_bounds_check for i in from ..= len(buf) - 4 {
			if buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n' {
				return i + 4
			}
		}
	}
	c.scan = len(buf)
	return -1
}

MAX_HEADER_BYTES :: 64 * 1024

// Read and parse one request's line + headers ONLY. The body is NOT read here;
// callers access it explicitly via read_full_body or body_read_chunk.
// ok=false means the connection should close.
read_request :: proc(c: ^Conn, max_body: int) -> (req: Request, ok: bool) {
	// Accumulate until the header block is complete.
	head_end := -1
	for {
		head_end = find_headers_end(c)
		if head_end >= 0 {
			break
		}
		if len(c.buf) - c.start > MAX_HEADER_BYTES {
			return {}, false
		}
		if !conn_fill(c) {
			return {}, false
		}
	}
	head_abs := head_end
	head := string(c.buf[c.start:head_abs - 4])

	// Request line.
	lines := strings.split(head, "\r\n")
	if len(lines) == 0 {
		return {}, false
	}
	parts := strings.split(lines[0], " ")
	if len(parts) < 3 {
		return {}, false
	}
	req.method = parts[0]
	req.target = parts[1]
	version := parts[2]

	// Split target into path and query.
	if q := strings.index_byte(req.target, '?'); q >= 0 {
		req.path = req.target[:q]
		req.query = req.target[q + 1:]
	} else {
		req.path = req.target
		req.query = ""
	}

	// Headers: small arena-allocated dynamic array, linear lookup.
	req.headers = make([dynamic]Header, context.allocator)
	content_length := 0
	for i in 1 ..< len(lines) {
		line := lines[i]
		colon := strings.index_byte(line, ':')
		if colon < 0 {
			continue
		}
		key := ascii_lower(strings.trim_space(line[:colon]))
		val := strings.trim_space(line[colon + 1:])
		append(&req.headers, Header{key, val})
		if key == "content-length" {
			content_length, _ = strconv.parse_int(val)
		}
	}

	req.content_length = content_length
	req.body_start = head_abs
	req.body_consumed = 0

	// Consume the header block now; the body remains in the buffer (or arrives
	// later) and is read on demand.
	c.start = head_abs

	if content_length < 0 {
		return {}, false
	}
	if content_length > max_body {
		// Oversized: cannot drain a huge body, so close after the 413.
		req.method = "__TOOLARGE__"
		req.keep_alive = false
		return req, true
	}

	// Keep-alive policy.
	conn_hdr_val, _ := header_get(&req, "connection")
	conn_hdr := ascii_lower(conn_hdr_val)
	if version == "HTTP/1.0" {
		req.keep_alive = conn_hdr == "keep-alive"
	} else {
		req.keep_alive = conn_hdr != "close"
	}

	return req, true
}

// --- body access ----------------------------------------------------------

// Read the entire body into a single arena-allocated slice, preserving the old
// buffered-body semantics. `cap` bounds the acceptable size (e.g. 1MB for
// /mirror's tiny JSON). Returns ok=false if content_length exceeds `cap`.
// On success the body is fully consumed.
read_full_body :: proc(c: ^Conn, req: ^Request, cap: int) -> ([]u8, bool) {
	if req.content_length > cap {
		return nil, false
	}
	body_end := req.body_start + req.content_length
	for len(c.buf) < body_end {
		if !conn_fill(c) {
			return nil, false
		}
	}
	out := c.buf[req.body_start:body_end]
	req.body_consumed = req.content_length
	c.start = body_end
	return out, true
}

// Streaming body reader: copies up to len(dst) bytes of the remaining body into
// dst, serving first from already-buffered bytes then recv'ing more directly.
// Returns the number of bytes read (0 at clean end-of-body), and ok=false on a
// connection error before the body completed.
body_read_chunk :: proc(c: ^Conn, req: ^Request, dst: []u8) -> (n: int, ok: bool) {
	remaining := req.content_length - req.body_consumed
	if remaining <= 0 {
		return 0, true
	}
	want := min(len(dst), remaining)

	// Serve any already-buffered bytes first.
	avail := len(c.buf) - c.start
	if avail > 0 {
		take := min(avail, want)
		copy(dst[:take], c.buf[c.start:c.start + take])
		c.start += take
		req.body_consumed += take
		return take, true
	}

	// Buffer drained: recv straight into dst.
	got, err := net.recv_tcp(c.sock, dst[:want])
	if err != nil || got == 0 {
		return 0, false
	}
	req.body_consumed += got
	return got, true
}

// True once the full declared body has been consumed.
body_done :: proc(req: ^Request) -> bool {
	return req.body_consumed >= req.content_length
}

// Move any unconsumed bytes (pipelined next request) to the front. If the
// buffer capacity has ballooned on a long-lived keep-alive connection, shrink
// it back down so we don't retain a huge allocation.
conn_compact :: proc(c: ^Conn) {
	rem := len(c.buf) - c.start
	if c.start > 0 {
		if rem > 0 {
			copy(c.buf[:rem], c.buf[c.start:])
		}
		resize(&c.buf, rem)
		c.start = 0
	}
	c.scan = 0
	if cap(c.buf) > 256 * 1024 && rem <= 16 * 1024 {
		// Free the oversized backing store and reallocate small.
		old := c.buf
		c.buf = make([dynamic]u8, rem, 16 * 1024)
		if rem > 0 {
			copy(c.buf[:rem], old[:rem])
		}
		delete(old)
	}
}

// --- responses ------------------------------------------------------------

@(private = "file")
status_text :: proc(code: int) -> string {
	switch code {
	case 200: return "OK"
	case 201: return "Created"
	case 204: return "No Content"
	case 206: return "Partial Content"
	case 304: return "Not Modified"
	case 400: return "Bad Request"
	case 401: return "Unauthorized"
	case 403: return "Forbidden"
	case 404: return "Not Found"
	case 405: return "Method Not Allowed"
	case 409: return "Conflict"
	case 411: return "Length Required"
	case 413: return "Content Too Large"
	case 415: return "Unsupported Media Type"
	case 416: return "Range Not Satisfiable"
	case 500: return "Internal Server Error"
	case 502: return "Bad Gateway"
	case 503: return "Service Unavailable"
	}
	return "OK"
}

// Standard CORS headers required by BUD-01 on every response.
@(private = "file")
write_common_headers :: proc(b: ^strings.Builder, keep_alive: bool) {
	strings.write_string(b, "Access-Control-Allow-Origin: *\r\n")
	strings.write_string(b, "Access-Control-Allow-Headers: Authorization, *\r\n")
	strings.write_string(b, "Access-Control-Allow-Methods: GET, HEAD, PUT, DELETE\r\n")
	strings.write_string(b, "Server: sakura\r\n")
	if keep_alive {
		strings.write_string(b, "Connection: keep-alive\r\n")
	} else {
		strings.write_string(b, "Connection: close\r\n")
	}
}

@(private = "file")
write_status_line :: proc(b: ^strings.Builder, code: int) {
	buf: [8]u8
	strings.write_string(b, "HTTP/1.1 ")
	strings.write_string(b, strconv.itoa(buf[:], code))
	strings.write_byte(b, ' ')
	strings.write_string(b, status_text(code))
	strings.write_string(b, "\r\n")
}

send_all :: proc(c: ^Conn, data: []u8) -> bool {
	sent := 0
	for sent < len(data) {
		n, err := net.send_tcp(c.sock, data[sent:])
		if err != nil || n == 0 {
			return false
		}
		sent += n
	}
	return true
}

// Send a complete response with a body held in memory. Header block and body
// are coalesced into a single send.
respond :: proc(
	c: ^Conn,
	code: int,
	content_type: string,
	body: []u8,
	keep_alive: bool,
	extra: []Header = {},
) -> bool {
	b := strings.builder_make(context.temp_allocator)
	write_status_line(&b, code)
	write_common_headers(&b, keep_alive)
	if content_type != "" {
		strings.write_string(&b, "Content-Type: ")
		strings.write_string(&b, content_type)
		strings.write_string(&b, "\r\n")
	}
	for h in extra {
		strings.write_string(&b, h.key)
		strings.write_string(&b, ": ")
		strings.write_string(&b, h.value)
		strings.write_string(&b, "\r\n")
	}
	lenbuf: [20]u8
	strings.write_string(&b, "Content-Length: ")
	strings.write_string(&b, strconv.itoa(lenbuf[:], len(body)))
	strings.write_string(&b, "\r\n\r\n")
	// Coalesce body into the same buffer for a single send.
	if len(body) > 0 {
		strings.write_bytes(&b, body)
	}
	return send_all(c, transmute([]u8)strings.to_string(b))
}

// Send just the header block with an explicit Content-Length; the caller then
// streams the body itself (used for serving blob files off disk).
respond_headers :: proc(
	c: ^Conn,
	code: int,
	content_type: string,
	content_length: i64,
	keep_alive: bool,
	extra: []Header = {},
) -> bool {
	b := strings.builder_make(context.temp_allocator)
	write_status_line(&b, code)
	write_common_headers(&b, keep_alive)
	if content_type != "" {
		strings.write_string(&b, "Content-Type: ")
		strings.write_string(&b, content_type)
		strings.write_string(&b, "\r\n")
	}
	for h in extra {
		strings.write_string(&b, h.key)
		strings.write_string(&b, ": ")
		strings.write_string(&b, h.value)
		strings.write_string(&b, "\r\n")
	}
	lenbuf: [20]u8
	strings.write_string(&b, "Content-Length: ")
	strings.write_string(&b, strconv.itoa(lenbuf[:], int(content_length)))
	strings.write_string(&b, "\r\n\r\n")
	return send_all(c, transmute([]u8)strings.to_string(b))
}

// Convenience: plain-text error with an X-Reason header (BUD diagnostic).
respond_error :: proc(c: ^Conn, code: int, reason: string, keep_alive: bool) -> bool {
	return respond(c, code, "text/plain", transmute([]u8)reason, keep_alive, {{"X-Reason", reason}})
}

@(private = "file")
ascii_lower :: proc(s: string) -> string {
	// Allocates in the temp arena; fine for header keys.
	buf := make([]u8, len(s), context.temp_allocator)
	for i in 0 ..< len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		buf[i] = c
	}
	return string(buf)
}
