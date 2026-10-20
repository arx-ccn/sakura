package sakura

import "base:runtime"
import "core:mem/virtual"
import "core:strconv"
import "core:strings"
import "core:sys/linux"
import "core:thread"

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

// Process-wide handles. Workers share these.
g_config: ^Config
g_store: ^Store

// Entry point for every request whose body (if any) is fully buffered.
// Responses are queued on `c`; returns .Detached when the connection was
// handed to another thread.
handle_request :: proc(c: ^Conn, req: ^Request, body: []u8) -> Conn_End {
	switch req.method {
	case "GET":
		handle_read(c, req, false)
	case "HEAD":
		handle_read(c, req, true)
	case "PUT":
		switch req.path {
		case "/upload":
			handle_upload(c, req, body)
		case "/mirror":
			return mirror_start(c, req, body)
		case:
			respond_error(c, 404, "unknown endpoint", req.keep_alive)
		}
	case "DELETE":
		handle_delete(c, req)
	case "OPTIONS":
		respond(c, 204, "", {}, req.keep_alive, {{"Access-Control-Max-Age", "86400"}})
	case:
		respond_error(c, 405, "method not allowed", req.keep_alive)
	}
	return .Keep
}

@(private = "file")
handle_read :: proc(c: ^Conn, req: ^Request, head_only: bool) {
	// HEAD /upload is BUD-06 upload-requirements, not a blob fetch.
	if head_only && req.path == "/upload" {
		handle_upload_head(c, req)
		return
	}
	if req.path == "/" {
		body := "sakura 🌸 a Blossom server\n"
		respond(c, 200, "text/plain; charset=utf-8", transmute([]u8)body, req.keep_alive)
		return
	}
	if strings.has_prefix(req.path, "/list/") {
		handle_list(c, req, req.path[6:])
		return
	}
	handle_get(c, req, head_only)
}

// Extract the sha256 (64 lowercase hex) from a path like "/<hash>.png".
@(private = "file")
path_hash :: proc "contextless" (path: string) -> (hash: [32]u8, ok: bool) {
	s := path
	if len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	if dot := index_byte(s, '.'); dot >= 0 {
		s = s[:dot]
	}
	if !is_lower_hex(s, 64) {
		return {}, false
	}
	return hash_bin(s)
}

@(private = "file")
url_base :: proc(host: string) -> string {
	if g_config.public_url != "" {
		return g_config.public_url
	}
	return strings.concatenate({"http://", host == "" ? "localhost" : host})
}

// --- GET / HEAD /<sha256> -------------------------------------------------

@(private = "file")
handle_get :: proc(c: ^Conn, req: ^Request, head_only: bool) {
	hash, ok := path_hash(req.path)
	if !ok {
		respond_error(c, 404, "not found", req.keep_alive)
		return
	}
	blob := cache_get(&c.w.cache, hash)
	if blob == nil {
		respond_error(c, 404, "blob not found", req.keep_alive)
		return
	}

	// Whole blob: the cached header block, then bytes or a sendfile.
	rng, has_range := header_get(req, "range")
	if !has_range {
		append(&c.out, ..blob.head)
		out_str(c, connection_tail(req.keep_alive))
		c.close_after = !req.keep_alive
		if !head_only {
			queue_body(c, blob, 0, blob.size)
		}
		return
	}

	// Single byte range.
	start, end, rok := parse_range(rng, blob.size)
	if !rok {
		respond(
			c,
			416,
			"",
			{},
			req.keep_alive,
			{{"Content-Range", strings.concatenate({"bytes */", itoa(blob.size)})}},
		)
		return
	}
	length := end - start + 1
	cr := strings.concatenate({"bytes ", itoa(start), "-", itoa(end), "/", itoa(blob.size)})
	respond_headers(
		c,
		206,
		blob.mime,
		length,
		req.keep_alive,
		{{"Accept-Ranges", "bytes"}, {"Content-Range", cr}},
	)
	if !head_only {
		queue_body(c, blob, start, length)
	}
}

// Queue `length` bytes of the blob from `off`: copied when inlined, else a
// sendfile from the cached fd (which the connection keeps a reference to).
@(private = "file")
queue_body :: proc(c: ^Conn, blob: ^Cached_Blob, off, length: i64) {
	if length == 0 {
		return
	}
	if blob.body != nil {
		append(&c.out, ..blob.body[off:][:length])
		return
	}
	blob.file.refs += 1
	c.file = blob.file
	c.file_off = off
	c.file_left = length
}

// --- PUT /upload ----------------------------------------------------------

// A body small enough to have been buffered whole.
@(private = "file")
handle_upload :: proc(c: ^Conn, req: ^Request, body: []u8) {
	if len(body) == 0 {
		respond_error(c, 400, "empty body", req.keep_alive)
		return
	}
	upload_store(c, req, sha256(body), sniff_mime(body), body, nil, i64(len(body)))
}

// A streamed body, now complete in `tmp` (see loop.odin).
upload_finish_file :: proc(
	c: ^Conn,
	req: ^Request,
	digest: [32]u8,
	tmp: cstring,
	size: i64,
	sniffed: string,
) {
	upload_store(c, req, digest, sniffed, nil, tmp, size)
}

// Admission checks and storage, once the body's hash is known. Exactly one of
// `data` (in memory) and `tmp` (temp file, always consumed) is set.
@(private = "file")
upload_store :: proc(
	c: ^Conn,
	req: ^Request,
	digest: [32]u8,
	sniffed: string,
	data: []u8,
	tmp: cstring,
	size: i64,
) {
	d := digest
	hash := hex_string(d[:])

	refuse :: proc(c: ^Conn, req: ^Request, tmp: cstring, code: int, reason: string) {
		if tmp != nil {
			linux.unlink(tmp)
		}
		respond_error(c, code, reason, req.keep_alive)
	}

	// Optional client-asserted hash must match.
	if xs, has := header_get(req, "x-sha-256"); has && xs != hash {
		refuse(c, req, tmp, 400, "x-sha-256 does not match body")
		return
	}

	now := unix_now()
	pubkey: [32]u8
	if g_config.require_auth {
		auth, _ := header_get(req, "authorization")
		res := validate_auth(auth, "upload", hash, false, now, g_config.domain)
		if !res.ok {
			refuse(c, req, tmp, 401, res.reason)
			return
		}
		pubkey, _ = hash_bin(res.pubkey)
	}

	// Content type: client header, else sniff, else octet-stream.
	mime := "application/octet-stream"
	if ct, has := header_get(req, "content-type"); has && ct != "" {
		mime = ct
	} else if sniffed != "" {
		mime = sniffed
	}

	stored_size, uploaded: i64
	stored_mime: string
	created, ok: bool
	if tmp != nil {
		stored_size, uploaded, stored_mime, created, ok = store_put_file(
			g_store,
			digest,
			tmp,
			size,
			pubkey,
			mime,
			now,
		)
	} else {
		stored_size, uploaded, stored_mime, created, ok = store_put(
			g_store,
			digest,
			data,
			pubkey,
			mime,
			now,
		)
	}
	if !ok {
		respond_error(c, 500, "failed to store blob", req.keep_alive)
		return
	}

	host, _ := header_get(req, "host")
	desc := blob_descriptor(url_base(host), hash, stored_size, stored_mime, uploaded)
	respond(c, created ? 201 : 200, "application/json", transmute([]u8)desc, req.keep_alive)
}

// --- HEAD /upload (BUD-06) ------------------------------------------------

@(private = "file")
handle_upload_head :: proc(c: ^Conn, req: ^Request) {
	xhash, _ := header_get(req, "x-sha-256")
	if g_config.require_auth {
		auth, _ := header_get(req, "authorization")
		res := validate_auth(auth, "upload", xhash, false, unix_now(), g_config.domain)
		if !res.ok {
			respond_error(c, 401, res.reason, req.keep_alive)
			return
		}
	}
	clen, has_len := header_get(req, "x-content-length")
	if !has_len {
		respond_error(c, 411, "missing X-Content-Length", req.keep_alive)
		return
	}
	n, ok := strconv.parse_int(clen)
	if !ok || n < 0 {
		respond_error(c, 400, "invalid X-Content-Length", req.keep_alive)
		return
	}
	if n > g_config.max_body {
		respond_error(c, 413, "blob exceeds maximum size", req.keep_alive)
		return
	}
	respond(c, 200, "", {}, req.keep_alive)
}

// --- GET /list/<pubkey> ---------------------------------------------------

@(private = "file")
handle_list :: proc(c: ^Conn, req: ^Request, pubkey: string) {
	pb, ok := hash_bin(pubkey)
	if !ok || !is_lower_hex(pubkey, 64) {
		respond_error(c, 400, "invalid pubkey", req.keep_alive)
		return
	}
	records := store_list(g_store, pb)
	host, _ := header_get(req, "host")
	base := url_base(host)

	b := strings.builder_make()
	strings.write_byte(&b, '[')
	for r, i in records {
		if i > 0 {
			strings.write_byte(&b, ',')
		}
		write_descriptor(&b, base, r.sha256, r.size, r.mime, r.uploaded)
	}
	strings.write_byte(&b, ']')
	respond(c, 200, "application/json", transmute([]u8)strings.to_string(b), req.keep_alive)
}

// --- DELETE /<sha256> -----------------------------------------------------

@(private = "file")
handle_delete :: proc(c: ^Conn, req: ^Request) {
	hash, ok := path_hash(req.path)
	if !ok {
		respond_error(c, 404, "not found", req.keep_alive)
		return
	}
	auth, _ := header_get(req, "authorization")
	hk := hash
	res := validate_auth(auth, "delete", hex_string(hk[:]), true, unix_now(), g_config.domain)
	if !res.ok {
		respond_error(c, 401, res.reason, req.keep_alive)
		return
	}
	pubkey, _ := hash_bin(res.pubkey)
	if !store_delete(g_store, hash, pubkey) {
		respond_error(c, 404, "blob not found or not owned", req.keep_alive)
		return
	}
	respond(c, 200, "", {}, req.keep_alive)
}

// --- PUT /mirror (BUD-04) -------------------------------------------------

// What the mirror thread needs once the connection's buffers are gone.
@(private = "file")
Mirror_Job :: struct {
	fd:   linux.Fd,
	body: []u8,
	auth: string,
	host: string,
}

// Mirroring blocks on an outbound fetch, so it runs on its own thread with the
// socket handed over; the response always closes the connection.
@(private = "file")
mirror_start :: proc(c: ^Conn, req: ^Request, body: []u8) -> Conn_End {
	heap := runtime.heap_allocator()
	auth, _ := header_get(req, "authorization")
	host, _ := header_get(req, "host")
	job := new(Mirror_Job, heap)
	job.fd = c.fd
	job.body = clone_bytes(body, heap)
	job.auth = string(clone_bytes(transmute([]u8)auth, heap))
	job.host = string(clone_bytes(transmute([]u8)host, heap))
	conn_detach(c)
	thread.create_and_start_with_poly_data(job, mirror_main, self_cleanup = true)
	return .Detached
}

@(private = "file")
clone_bytes :: proc(b: []u8, allocator: runtime.Allocator) -> []u8 {
	out := make([]u8, len(b), allocator)
	copy(out, b)
	return out
}

@(private = "file")
mirror_main :: proc(job: ^Mirror_Job) {
	heap := runtime.heap_allocator()
	arena: virtual.Arena
	if virtual.arena_init_growing(&arena) != nil {
		linux.close(job.fd)
		return
	}
	context.allocator = virtual.arena_allocator(&arena)
	context.temp_allocator = context.allocator

	c: Conn
	c.fd = job.fd
	c.out = make([dynamic]u8, heap)
	mirror_handle(&c, job)
	send_blocking(c.fd, c.out[:])
	linux.close(c.fd)

	delete(c.out)
	delete(job.body, heap)
	delete(job.auth, heap)
	delete(job.host, heap)
	free(job, heap)
	virtual.arena_destroy(&arena)
}

@(private = "file")
mirror_handle :: proc(c: ^Conn, job: ^Mirror_Job) {
	now := unix_now()
	j, jok := json_parse(string(job.body))
	if !jok {
		respond_error(c, 400, "invalid request body", false)
		return
	}
	obj, is_obj := j.(map[string]Json)
	if !is_obj {
		respond_error(c, 400, "invalid request body", false)
		return
	}
	url_val, has_url := obj["url"]
	url, is_str := url_val.(string)
	if !has_url || !is_str {
		respond_error(c, 400, "missing url", false)
		return
	}

	// Cheap structural pre-auth BEFORE fetching the remote blob (no signature
	// check yet — that needs the hash). Rejects obviously bad tokens early so a
	// large download is never performed for an unauthorized request.
	if g_config.require_auth {
		if reason, ok := auth_precheck(job.auth, "upload", now, g_config.domain); !ok {
			respond_error(c, 401, reason, false)
			return
		}
	}

	status, ctype, data, fok := http_get(url, g_config.max_body)
	if !fok {
		respond_error(c, 502, "failed to fetch source blob", false)
		return
	}
	if status != 200 {
		respond_error(c, 502, "source returned non-200", false)
		return
	}

	digest := sha256(data)
	hash := hex_string(digest[:])

	pubkey: [32]u8
	if g_config.require_auth {
		// Mirror reuses the upload authorization; the x tag must match.
		res := validate_auth(job.auth, "upload", hash, true, now, g_config.domain)
		if !res.ok {
			respond_error(c, 401, res.reason, false)
			return
		}
		pubkey, _ = hash_bin(res.pubkey)
	}

	mime := "application/octet-stream"
	if ctype != "" {
		mime = ctype
	} else if t := sniff_mime(data); t != "" {
		mime = t
	}

	size, uploaded, stored_mime, created, ok := store_put(g_store, digest, data, pubkey, mime, now)
	if !ok {
		respond_error(c, 500, "failed to store blob", false)
		return
	}
	desc := blob_descriptor(url_base(job.host), hash, size, stored_mime, uploaded)
	respond(c, created ? 201 : 200, "application/json", transmute([]u8)desc, false)
}

// --- helpers --------------------------------------------------------------

@(private = "file")
write_descriptor :: proc(
	b: ^strings.Builder,
	base, hash: string,
	size: i64,
	mime: string,
	uploaded: i64,
) {
	strings.write_string(b, "{\"url\":")
	json_write_string(b, strings.concatenate({base, "/", hash}))
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
	b := strings.builder_make()
	write_descriptor(&b, base, hash, size, mime, uploaded)
	return strings.to_string(b)
}

@(private = "file")
itoa :: proc(v: i64) -> string {
	buf := make([]u8, 24)
	return strconv.write_int(buf, v, 10)
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
