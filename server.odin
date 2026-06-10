package sakura

import "core:io"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/linux"

Config :: struct {
	host:         string,
	port:         int,
	data_dir:     string,
	domain:       string, // for BUD-11 `server` tag scoping; "" disables
	public_url:   string, // base URL for descriptors; "" => derive from Host
	max_body:     int,
	workers:      int,
	require_auth: bool, // require auth for upload/delete/mirror
}

// Process-wide handles. Workers are stateless and share these.
g_config: ^Config
g_store: ^Store

// Mirror request bodies are tiny JSON; cap them well below the blob limit.
MIRROR_BODY_CAP :: 1024 * 1024

// Entry point for every request once parsed. Returns ok=false when the
// connection must be closed.
handle_request :: proc(req: ^Request, c: ^Conn) -> bool {
	now := unix_now()

	if req.method == "__TOOLARGE__" {
		respond_error(c, 413, "blob exceeds maximum size", false)
		return false // body was never consumed; close.
	}

	switch req.method {
	case "OPTIONS":
		return respond(c, 204, "", {}, req.keep_alive, {{"Access-Control-Max-Age", "86400"}})
	case "GET", "HEAD":
		return handle_read(req, c, req.method == "HEAD", now)
	case "PUT":
		switch req.path {
		case "/upload":
			return handle_upload(req, c, now)
		case "/mirror":
			return handle_mirror(req, c, now)
		}
		// Unknown PUT endpoint: drain the body to keep the connection usable.
		if !drain_body(req, c) {
			respond_error(c, 404, "unknown endpoint", false)
			return false
		}
		return respond_error(c, 404, "unknown endpoint", req.keep_alive)
	case "DELETE":
		return handle_delete(req, c, now)
	}
	return respond_error(c, 405, "method not allowed", req.keep_alive)
}

// Discard any unread request body so the connection stays keep-alive correct.
// Returns false if the connection broke mid-drain (caller should close).
@(private = "file")
drain_body :: proc(req: ^Request, c: ^Conn) -> bool {
	buf: [65536]u8 = ---
	for !body_done(req) {
		n, ok := body_read_chunk(c, req, buf[:])
		if !ok {
			return false
		}
		if n == 0 {
			break
		}
	}
	return true
}

@(private = "file")
handle_read :: proc(req: ^Request, c: ^Conn, head_only: bool, now: i64) -> bool {
	// HEAD /upload is BUD-06 upload-requirements, not a blob fetch.
	if head_only && req.path == "/upload" {
		return handle_upload_head(req, c, now)
	}
	if req.path == "/" {
		body := "sakura 🌸 a Blossom server\n"
		return respond(c, 200, "text/plain; charset=utf-8", transmute([]u8)body, req.keep_alive)
	}
	if strings.has_prefix(req.path, "/list/") {
		return handle_list(req, c, req.path[6:])
	}
	return handle_get(req, c, head_only)
}

// Extract the sha256 (64 lowercase hex) from a path like "/<hash>.png".
@(private = "file")
path_hash :: proc(path: string) -> (string, bool) {
	s := path
	if len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	if dot := strings.index_byte(s, '.'); dot >= 0 {
		s = s[:dot]
	}
	if !is_lower_hex(s, 64) {
		return "", false
	}
	return s, true
}

@(private = "file")
url_base :: proc(req: ^Request) -> string {
	if g_config.public_url != "" {
		return g_config.public_url
	}
	host, ok := header_get(req, "host")
	if !ok {
		host = "localhost"
	}
	return strings.concatenate({"http://", host}, context.temp_allocator)
}

// --- GET / HEAD /<sha256> -------------------------------------------------

@(private = "file")
handle_get :: proc(req: ^Request, c: ^Conn, head_only: bool) -> bool {
	hash, ok := path_hash(req.path)
	if !ok {
		return respond_error(c, 404, "not found", req.keep_alive)
	}
	path := blob_path(g_store, hash, context.temp_allocator)

	fh, oerr := os.open(path, os.O_RDONLY)
	if oerr != nil {
		return respond_error(c, 404, "blob not found", req.keep_alive)
	}
	defer os.close(fh)
	size, _ := os.file_size(fh)

	// Determine content type: stored metadata, else sniff, else octet-stream.
	mime := "application/octet-stream"
	if _, m, has := store_meta(g_store, hash); has && m != "" {
		mime = m
	} else {
		sniff: [16]u8
		n, _ := os.read(fh, sniff[:])
		os.seek(fh, 0, io.Seek_From.Start)
		if t := sniff_mime(sniff[:n]); t != "" {
			mime = t
		}
	}

	// Range handling (single range only).
	off: i64 = 0
	length := size
	is_range := false
	if rng, has := header_get(req, "range"); has {
		if s, e, rok := parse_range(rng, size); rok {
			off = s
			length = e - s + 1
			is_range = true
		} else {
			return respond(c, 416, "", {}, req.keep_alive, {{"Content-Range", strings.concatenate({"bytes */", itoa(size)}, context.temp_allocator)}})
		}
	}

	extra := make([dynamic]Header, context.temp_allocator)
	append(&extra, Header{"Accept-Ranges", "bytes"})
	code := 200
	if is_range {
		code = 206
		cr := strings.concatenate({"bytes ", itoa(off), "-", itoa(off + length - 1), "/", itoa(size)}, context.temp_allocator)
		append(&extra, Header{"Content-Range", cr})
	}

	if !respond_headers(c, code, mime, length, req.keep_alive, extra[:]) {
		return false
	}
	if head_only {
		return true
	}
	return stream_file(c, fh, off, length)
}

// Stream `length` bytes from `fh` at `off` to the socket. Uses sendfile(2) on
// Linux (zero-copy), falling back to a read/send loop on error or other OSes.
@(private = "file")
stream_file :: proc(c: ^Conn, fh: ^os.File, off: i64, length: i64) -> bool {
	when ODIN_OS == .Linux {
		out_fd := linux.Fd(i32(c.sock))
		in_fd := linux.Fd(i32(os.fd(fh)))
		offset := off
		remaining := length
		for remaining > 0 {
			count := uint(min(remaining, 1 << 30))
			n, errno := linux.sendfile(out_fd, in_fd, &offset, count)
			if errno == .EINTR || errno == .EAGAIN {
				continue
			}
			if errno != .NONE {
				// Fall back to the portable loop for the remainder.
				return stream_file_rw(c, fh, offset, remaining)
			}
			if n == 0 {
				return false
			}
			remaining -= i64(n)
		}
		return true
	} else {
		return stream_file_rw(c, fh, off, length)
	}
}

@(private = "file")
stream_file_rw :: proc(c: ^Conn, fh: ^os.File, off: i64, length: i64) -> bool {
	if off > 0 {
		os.seek(fh, off, io.Seek_From.Start)
	}
	buf: [65536]u8 = ---
	remaining := length
	for remaining > 0 {
		want := min(i64(len(buf)), remaining)
		n, rerr := os.read(fh, buf[:want])
		if rerr != nil || n == 0 {
			return false
		}
		if !send_all(c, buf[:n]) {
			return false
		}
		remaining -= i64(n)
	}
	return true
}

// --- PUT /upload ----------------------------------------------------------

@(private = "file")
handle_upload :: proc(req: ^Request, c: ^Conn, now: i64) -> bool {
	if req.content_length == 0 {
		return respond_error(c, 400, "empty body", req.keep_alive)
	}

	// Stream the body: hash it AND write it to a temp file, in 64KB chunks.
	tmp := tmp_path(g_store, context.temp_allocator)
	fh, oerr := os.open(tmp, os.O_WRONLY | os.O_CREATE | os.O_TRUNC)
	if oerr != nil {
		// Can't open temp; still drain so keep-alive survives.
		if !drain_body(req, c) {
			respond_error(c, 500, "failed to store blob", false)
			return false
		}
		return respond_error(c, 500, "failed to store blob", req.keep_alive)
	}

	ctx: Sha256_Ctx
	sha256_init(&ctx)

	// Sniff mime from the first chunk.
	sniffed := ""
	first := true
	buf: [65536]u8 = ---
	total: i64 = 0
	broke := false
	for !body_done(req) {
		n, rok := body_read_chunk(c, req, buf[:])
		if !rok {
			broke = true
			break
		}
		if n == 0 {
			break
		}
		chunk := buf[:n]
		sha256_update(&ctx, chunk)
		if _, werr := os.write(fh, chunk); werr != nil {
			os.close(fh)
			os.remove(tmp)
			// Body partially consumed and write failed: try to drain rest.
			if !drain_body(req, c) {
				respond_error(c, 500, "failed to store blob", false)
				return false
			}
			return respond_error(c, 500, "failed to store blob", req.keep_alive)
		}
		if first {
			if t := sniff_mime(chunk); t != "" {
				sniffed = t
			}
			first = false
		}
		total += i64(n)
	}
	os.close(fh)

	if broke {
		// Connection died mid-body; clean up and close.
		os.remove(tmp)
		return false
	}

	digest := sha256_final(&ctx)
	hash := hex_string(digest[:], context.temp_allocator)

	// At this point the entire body is consumed, so failures below can keep the
	// connection alive.

	// Optional client-asserted hash must match.
	if xs, has := header_get(req, "x-sha-256"); has && xs != hash {
		os.remove(tmp)
		return respond_error(c, 400, "x-sha-256 does not match body", req.keep_alive)
	}

	pubkey := ""
	if g_config.require_auth {
		auth, _ := header_get(req, "authorization")
		res := validate_auth(auth, "upload", hash, false, now, g_config.domain)
		if !res.ok {
			os.remove(tmp)
			return respond_error(c, 401, res.reason, req.keep_alive)
		}
		pubkey = res.pubkey
	}

	// Content type: client header, else sniff, else octet-stream.
	mime := "application/octet-stream"
	if ct, has := header_get(req, "content-type"); has && ct != "" {
		mime = ct
	} else if sniffed != "" {
		mime = sniffed
	}

	size, uploaded, stored_mime, created, ok := store_put_file(g_store, hash, tmp, total, pubkey, mime, now)
	if !ok {
		return respond_error(c, 500, "failed to store blob", req.keep_alive)
	}

	desc := blob_descriptor(url_base(req), hash, size, stored_mime, uploaded)
	code := created ? 201 : 200
	return respond(c, code, "application/json", transmute([]u8)desc, req.keep_alive)
}

// --- HEAD /upload (BUD-06) ------------------------------------------------

@(private = "file")
handle_upload_head :: proc(req: ^Request, c: ^Conn, now: i64) -> bool {
	xhash, _ := header_get(req, "x-sha-256")
	if g_config.require_auth {
		auth, _ := header_get(req, "authorization")
		res := validate_auth(auth, "upload", xhash, false, now, g_config.domain)
		if !res.ok {
			return respond_error(c, 401, res.reason, req.keep_alive)
		}
	}
	clen, has_len := header_get(req, "x-content-length")
	if !has_len {
		return respond_error(c, 411, "missing X-Content-Length", req.keep_alive)
	}
	n, ok := strconv.parse_int(clen)
	if !ok || n < 0 {
		return respond_error(c, 400, "invalid X-Content-Length", req.keep_alive)
	}
	if n > g_config.max_body {
		return respond_error(c, 413, "blob exceeds maximum size", req.keep_alive)
	}
	return respond(c, 200, "", {}, req.keep_alive)
}

// --- GET /list/<pubkey> ---------------------------------------------------

@(private = "file")
handle_list :: proc(req: ^Request, c: ^Conn, pubkey: string) -> bool {
	if !is_lower_hex(pubkey, 64) {
		return respond_error(c, 400, "invalid pubkey", req.keep_alive)
	}
	records := store_list(g_store, pubkey, context.temp_allocator)
	base := url_base(req)

	b := strings.builder_make(context.temp_allocator)
	strings.write_byte(&b, '[')
	for r, i in records {
		if i > 0 {
			strings.write_byte(&b, ',')
		}
		write_descriptor(&b, base, r.sha256, r.size, r.mime, r.uploaded)
	}
	strings.write_byte(&b, ']')
	return respond(c, 200, "application/json", transmute([]u8)strings.to_string(b), req.keep_alive)
}

// --- DELETE /<sha256> -----------------------------------------------------

@(private = "file")
handle_delete :: proc(req: ^Request, c: ^Conn, now: i64) -> bool {
	hash, ok := path_hash(req.path)
	if !ok {
		return respond_error(c, 404, "not found", req.keep_alive)
	}
	auth, _ := header_get(req, "authorization")
	res := validate_auth(auth, "delete", hash, true, now, g_config.domain)
	if !res.ok {
		return respond_error(c, 401, res.reason, req.keep_alive)
	}
	if !store_delete(g_store, hash, res.pubkey) {
		return respond_error(c, 404, "blob not found or not owned", req.keep_alive)
	}
	return respond(c, 200, "", {}, req.keep_alive)
}

// --- PUT /mirror (BUD-04) -------------------------------------------------

@(private = "file")
handle_mirror :: proc(req: ^Request, c: ^Conn, now: i64) -> bool {
	// Mirror bodies are tiny JSON; read the whole thing (capped).
	body, bok := read_full_body(c, req, MIRROR_BODY_CAP)
	if !bok {
		respond_error(c, 413, "mirror request too large", false)
		return false
	}

	j, jok := json_parse(string(body), context.temp_allocator)
	if !jok {
		return respond_error(c, 400, "invalid request body", req.keep_alive)
	}
	obj, is_obj := j.(map[string]Json)
	if !is_obj {
		return respond_error(c, 400, "invalid request body", req.keep_alive)
	}
	url_val, has_url := obj["url"]
	url, is_str := url_val.(string)
	if !has_url || !is_str {
		return respond_error(c, 400, "missing url", req.keep_alive)
	}

	// Cheap structural pre-auth BEFORE fetching the remote blob (no signature
	// check yet — that needs the hash). Rejects obviously bad tokens early so a
	// large download is never performed for an unauthorized request.
	if g_config.require_auth {
		auth, _ := header_get(req, "authorization")
		if reason, ok := auth_precheck(auth, "upload", now, g_config.domain); !ok {
			return respond_error(c, 401, reason, req.keep_alive)
		}
	}

	status, ctype, data, fok := http_get(url, g_config.max_body)
	if !fok {
		return respond_error(c, 502, "failed to fetch source blob", req.keep_alive)
	}
	if status != 200 {
		return respond_error(c, 502, "source returned non-200", req.keep_alive)
	}

	digest := sha256(data)
	hash := hex_string(digest[:], context.temp_allocator)

	pubkey := ""
	if g_config.require_auth {
		auth, _ := header_get(req, "authorization")
		// Mirror reuses the upload authorization; the x tag must match.
		res := validate_auth(auth, "upload", hash, true, now, g_config.domain)
		if !res.ok {
			return respond_error(c, 401, res.reason, req.keep_alive)
		}
		pubkey = res.pubkey
	}

	mime := "application/octet-stream"
	if ctype != "" {
		mime = ctype
	} else if t := sniff_mime(data); t != "" {
		mime = t
	}

	size, uploaded, stored_mime, created, ok := store_put(g_store, hash, data, pubkey, mime, now)
	if !ok {
		return respond_error(c, 500, "failed to store blob", req.keep_alive)
	}
	desc := blob_descriptor(url_base(req), hash, size, stored_mime, uploaded)
	code := created ? 201 : 200
	return respond(c, code, "application/json", transmute([]u8)desc, req.keep_alive)
}

// --- helpers --------------------------------------------------------------

@(private = "file")
write_descriptor :: proc(b: ^strings.Builder, base, hash: string, size: i64, mime: string, uploaded: i64) {
	strings.write_string(b, "{\"url\":")
	json_write_string(b, strings.concatenate({base, "/", hash}, context.temp_allocator))
	strings.write_string(b, ",\"sha256\":")
	json_write_string(b, hash)
	strings.write_string(b, ",\"size\":")
	strings.write_string(b, itoa(size))
	strings.write_string(b, ",\"type\":")
	json_write_string(b, mime)
	strings.write_string(b, ",\"uploaded\":")
	strings.write_string(b, itoa(uploaded))
	strings.write_byte(b, '}')
}

@(private = "file")
blob_descriptor :: proc(base, hash: string, size: i64, mime: string, uploaded: i64) -> string {
	b := strings.builder_make(context.temp_allocator)
	write_descriptor(&b, base, hash, size, mime, uploaded)
	return strings.to_string(b)
}

@(private = "file")
itoa :: proc(v: i64) -> string {
	buf := make([]u8, 24, context.temp_allocator)
	return strconv.itoa(buf, int(v))
}

// Parse "bytes=start-end" against a known total size. Supports "a-b", "a-",
// and "-suffix". Returns inclusive [start, end].
@(private = "file")
parse_range :: proc(h: string, size: i64) -> (start: i64, end: i64, ok: bool) {
	if !strings.has_prefix(h, "bytes=") {
		return 0, 0, false
	}
	spec := h[6:]
	if comma := strings.index_byte(spec, ','); comma >= 0 {
		spec = spec[:comma] // only the first range
	}
	dash := strings.index_byte(spec, '-')
	if dash < 0 {
		return 0, 0, false
	}
	lhs := spec[:dash]
	rhs := spec[dash + 1:]

	if lhs == "" {
		// suffix range: last N bytes
		n, pok := strconv.parse_i64(rhs)
		if !pok || n <= 0 {
			return 0, 0, false
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true
	}

	s, pok := strconv.parse_i64(lhs)
	if !pok || s < 0 || s >= size {
		return 0, 0, false
	}
	e := size - 1
	if rhs != "" {
		ev, eok := strconv.parse_i64(rhs)
		if !eok {
			return 0, 0, false
		}
		e = ev
	}
	if e >= size {
		e = size - 1
	}
	if e < s {
		return 0, 0, false
	}
	return s, e, true
}

// Minimal magic-number content sniffing for common blob types.
@(private = "file")
sniff_mime :: proc(d: []u8) -> string {
	if len(d) >= 8 && d[0] == 0x89 && d[1] == 'P' && d[2] == 'N' && d[3] == 'G' {
		return "image/png"
	}
	if len(d) >= 3 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF {
		return "image/jpeg"
	}
	if len(d) >= 6 && string(d[:6]) == "GIF89a" {
		return "image/gif"
	}
	if len(d) >= 6 && string(d[:6]) == "GIF87a" {
		return "image/gif"
	}
	if len(d) >= 12 && string(d[:4]) == "RIFF" && string(d[8:12]) == "WEBP" {
		return "image/webp"
	}
	if len(d) >= 4 && string(d[:4]) == "%PDF" {
		return "application/pdf"
	}
	if len(d) >= 12 && string(d[4:8]) == "ftyp" {
		return "video/mp4"
	}
	if len(d) >= 4 && d[0] == 0x1A && d[1] == 0x45 && d[2] == 0xDF && d[3] == 0xA3 {
		return "video/webm"
	}
	if len(d) >= 2 && d[0] == 'P' && d[1] == 'K' {
		return "application/zip"
	}
	return ""
}
