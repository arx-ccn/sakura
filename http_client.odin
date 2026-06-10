package sakura

import "core:net"
import "core:strconv"
import "core:strings"

// Minimal HTTP client used only by PUT /mirror. Supports plain http:// — TLS is
// out of scope for a dependency-free build, so https:// sources are rejected
// (the caller maps that to 502 with an explanatory X-Reason).

http_get :: proc(url: string, max_body: int) -> (status: int, content_type: string, body: []u8, ok: bool) {
	if strings.has_prefix(url, "https://") {
		return 0, "", nil, false // TLS unsupported
	}
	rest := url
	if strings.has_prefix(rest, "http://") {
		rest = rest[7:]
	} else {
		return 0, "", nil, false
	}

	slash := strings.index_byte(rest, '/')
	hostport := rest
	path := "/"
	if slash >= 0 {
		hostport = rest[:slash]
		path = rest[slash:]
	}

	host := hostport
	port := 80
	if colon := strings.index_byte(hostport, ':'); colon >= 0 {
		host = hostport[:colon]
		if p, pok := strconv.parse_int(hostport[colon + 1:]); pok {
			port = p
		}
	}

	ep, rerr := net.resolve_ip4(strings.concatenate({host, ":", itoa_int(port)}, context.temp_allocator))
	if rerr != nil {
		return 0, "", nil, false
	}
	sock, derr := net.dial_tcp(ep)
	if derr != nil {
		return 0, "", nil, false
	}
	defer net.close(sock)

	// Send the request.
	rb := strings.builder_make(context.temp_allocator)
	strings.write_string(&rb, "GET ")
	strings.write_string(&rb, path)
	strings.write_string(&rb, " HTTP/1.1\r\nHost: ")
	strings.write_string(&rb, host)
	strings.write_string(&rb, "\r\nUser-Agent: sakura\r\nAccept: */*\r\nConnection: close\r\n\r\n")
	req_bytes := transmute([]u8)strings.to_string(rb)
	sent := 0
	for sent < len(req_bytes) {
		n, serr := net.send_tcp(sock, req_bytes[sent:])
		if serr != nil || n == 0 {
			return 0, "", nil, false
		}
		sent += n
	}

	// Read the whole response (Connection: close).
	resp := make([dynamic]u8, context.temp_allocator)
	tmp: [16384]u8 = ---
	for {
		n, err := net.recv_tcp(sock, tmp[:])
		if n > 0 {
			append(&resp, ..tmp[:n])
		}
		if err != nil || n == 0 {
			break
		}
		if len(resp) > max_body + 1024*1024 {
			break // guard against unbounded responses
		}
	}

	// Split headers/body.
	head_end := -1
	#no_bounds_check for i in 0 ..= len(resp) - 4 {
		if resp[i] == '\r' && resp[i + 1] == '\n' && resp[i + 2] == '\r' && resp[i + 3] == '\n' {
			head_end = i + 4
			break
		}
	}
	if head_end < 0 {
		return 0, "", nil, false
	}

	head := string(resp[:head_end - 4])
	lines := strings.split(head, "\r\n")
	if len(lines) == 0 {
		return 0, "", nil, false
	}
	// Status line: HTTP/1.1 200 OK
	sparts := strings.split(lines[0], " ")
	if len(sparts) < 2 {
		return 0, "", nil, false
	}
	status, _ = strconv.parse_int(sparts[1])

	ctype := ""
	chunked := false
	clen := -1
	for i in 1 ..< len(lines) {
		colon := strings.index_byte(lines[i], ':')
		if colon < 0 {
			continue
		}
		key := ascii_lower_s(strings.trim_space(lines[i][:colon]))
		val := strings.trim_space(lines[i][colon + 1:])
		switch key {
		case "content-type":
			ctype = val
		case "content-length":
			clen, _ = strconv.parse_int(val)
		case "transfer-encoding":
			if strings.contains(ascii_lower_s(val), "chunked") {
				chunked = true
			}
		}
	}

	raw := resp[head_end:]
	out: []u8
	if chunked {
		out = dechunk(raw[:], context.temp_allocator)
	} else if clen >= 0 {
		if clen > len(raw) {
			clen = len(raw)
		}
		out = raw[:clen]
	} else {
		out = raw[:]
	}
	if len(out) > max_body {
		return 0, "", nil, false
	}
	return status, ctype, out, true
}

@(private = "file")
dechunk :: proc(data: []u8, allocator := context.allocator) -> []u8 {
	out := make([dynamic]u8, allocator)
	i := 0
	for i < len(data) {
		// chunk size line (hex) up to CRLF
		line_end := -1
		for j in i ..< len(data) - 1 {
			if data[j] == '\r' && data[j + 1] == '\n' {
				line_end = j
				break
			}
		}
		if line_end < 0 {
			break
		}
		size_str := string(data[i:line_end])
		// strip any chunk extensions after ';'
		if semi := strings.index_byte(size_str, ';'); semi >= 0 {
			size_str = size_str[:semi]
		}
		size, ok := strconv.parse_int(strings.trim_space(size_str), 16)
		if !ok || size == 0 {
			break
		}
		start := line_end + 2
		if start + size > len(data) {
			break
		}
		append(&out, ..data[start:start + size])
		i = start + size + 2 // skip data + trailing CRLF
	}
	return out[:]
}

@(private = "file")
ascii_lower_s :: proc(s: string) -> string {
	buf := make([]u8, len(s), context.temp_allocator)
	for i in 0 ..< len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {c += 32}
		buf[i] = c
	}
	return string(buf)
}

@(private = "file")
itoa_int :: proc(v: int) -> string {
	buf := make([]u8, 24, context.temp_allocator)
	return strconv.itoa(buf, v)
}
