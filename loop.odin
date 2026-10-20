package sakura

import "base:runtime"
import "core:fmt"
import "core:mem/virtual"
import "core:net"
import "core:os"
import "core:sync"
import "core:sys/linux"
import "core:thread"

// Event loop. The main thread accepts; each worker owns an epoll set and every
// connection it is handed, so requests never cross threads or take locks:
//
//   acceptor ── accept ──► conn ── epoll_ctl(ADD) round-robin ──► worker[i]
//   worker:  epoll_wait ─► recv ─► parse ─► handler appends to conn.out
//                                        ─► send (+ sendfile for big blobs)
//
// Sockets are non-blocking and level-triggered. A connection that can't take
// more output arms EPOLLOUT until it drains; idle connections cost only their
// buffers, so any number can stay open without starving others.

// Request bodies other than uploads (e.g. /mirror JSON) are buffered whole.
BODY_CAP :: 1024 * 1024
// Uploads up to this size are buffered and hashed in one go; larger ones
// stream through the worker's scratch buffer into a temp file.
UPLOAD_MEM_MAX :: 256 * 1024
SCRATCH_SIZE :: 256 * 1024
MAX_EVENTS :: 512

Worker :: struct {
	epfd:    linux.Fd,
	arena:   virtual.Arena,
	cache:   Blob_Cache,
	scratch: []u8,
	epoch:   u64,
}

Conn_State :: enum u8 {
	Head, // reading/handling requests
	Upload, // streaming a large upload body into c.up
}

// A large upload in flight.
Upload :: struct {
	fd:      linux.Fd,
	tmp:     cstring, // heap
	sha:     Sha256_Ctx,
	left:    int,
	total:   i64,
	sniffed: string,
	failed:  bool, // a write failed; keep draining, then answer 500
}

Conn :: struct {
	fd:          linux.Fd,
	w:           ^Worker,
	state:       Conn_State,
	close_after: bool, // close once `out` drains
	out_armed:   bool, // EPOLLOUT registered
	corked:      bool, // TCP_CORK on while a file goes out
	in_buf:      [dynamic]u8, // heap; requests (and small bodies)
	start:       int, // first unconsumed byte of in_buf
	scan:        int, // find_headers_end resume point
	out:         [dynamic]u8, // heap; queued response bytes
	out_off:     int,
	file:        ^Blob_File, // queued sendfile source, after `out`
	file_off:    i64,
	file_left:   i64,
	req:         Request,
	up:          Upload,
}

g_workers: []Worker

workers_start :: proc(n: int) {
	g_workers = make([]Worker, n)
	for &w in g_workers {
		fd, err := linux.epoll_create()
		if err != .NONE {
			fmt.eprintln("fatal: epoll_create:", err)
			os.exit(1)
		}
		w.epfd = fd
		thread.create_and_start_with_poly_data(&w, worker_main)
	}
}

// Accept forever on the main thread, dealing connections round-robin.
acceptor_run :: proc(listen: net.TCP_Socket) {
	heap := runtime.heap_allocator()
	next := 0
	for {
		client, _, err := net.accept_tcp(listen)
		if err != nil {
			continue
		}
		net.set_blocking(client, false)
		w := &g_workers[next]
		next = (next + 1) % len(g_workers)

		c := new(Conn, heap)
		c.fd = linux.Fd(client)
		c.w = w
		c.in_buf = make([dynamic]u8, 0, 4096, heap)
		c.out = make([dynamic]u8, 0, 4096, heap)
		ev := linux.EPoll_Event {
			events = {.IN, .RDHUP},
			data = {ptr = c},
		}
		if linux.epoll_ctl(w.epfd, .ADD, c.fd, &ev) != .NONE {
			conn_free(c, .Close)
		}
	}
}

@(private = "file")
worker_main :: proc(w: ^Worker) {
	if virtual.arena_init_growing(&w.arena) != nil {
		fmt.eprintln("fatal: worker arena")
		os.exit(1)
	}
	context.allocator = virtual.arena_allocator(&w.arena)
	context.temp_allocator = context.allocator
	cache_init(&w.cache)
	w.scratch = make([]u8, SCRATCH_SIZE, runtime.heap_allocator())

	events: [MAX_EVENTS]linux.EPoll_Event
	for {
		n, err := linux.epoll_wait(w.epfd, &events[0], MAX_EVENTS, -1)
		if err != .NONE {
			continue
		}
		if epoch := sync.atomic_load(&g_delete_epoch); epoch != w.epoch {
			cache_clear(&w.cache)
			w.epoch = epoch
		}
		for &ev in events[:n] {
			c := (^Conn)(ev.data.ptr)
			if end := conn_event(c, ev.events); end != .Keep {
				conn_free(c, end)
			}
		}
	}
}

Conn_End :: enum u8 {
	Keep,
	Close,
	Detached, // the fd now belongs to someone else (mirror thread)
}

@(private = "file")
conn_event :: proc(c: ^Conn, events: linux.EPoll_Event_Set) -> Conn_End {
	if events & {.IN, .RDHUP, .HUP, .ERR} != {} {
		ok := c.state == .Upload ? upload_read(c) : conn_read(c)
		if !ok {
			return .Close
		}
	}
	return conn_run(c)
}

// Flush output, then handle buffered requests until input runs dry or output
// backs up.
@(private = "file")
conn_run :: proc(c: ^Conn) -> Conn_End {
	for {
		switch conn_flush(c) {
		case .Blocked:
			arm_out(c, true)
			return .Keep
		case .Error:
			return .Close
		case .Done:
		}
		if c.close_after {
			return .Close
		}
		if c.state == .Upload {
			arm_out(c, false)
			return .Keep
		}
		switch next_request(c) {
		case .Need_Input:
			arm_out(c, false)
			return .Keep
		case .Progress:
		case .Detached:
			return .Detached
		}
	}
}

@(private = "file")
arm_out :: proc(c: ^Conn, want: bool) {
	if c.out_armed == want {
		return
	}
	c.out_armed = want
	ev := linux.EPoll_Event {
		events = {.IN, .RDHUP},
		data = {ptr = c},
	}
	if want {
		ev.events += {.OUT}
	}
	linux.epoll_ctl(c.w.epfd, .MOD, c.fd, &ev)
}

// recv into in_buf until the socket is drained. false: peer closed or error.
@(private = "file")
conn_read :: proc(c: ^Conn) -> bool {
	for {
		if cap(c.in_buf) - len(c.in_buf) < 4096 {
			reserve(&c.in_buf, max(2 * cap(c.in_buf), 16384))
		}
		old := len(c.in_buf)
		space := cap(c.in_buf) - old
		n, err := linux.recv(c.fd, raw_data(c.in_buf)[old:][:space], {})
		if err == .EAGAIN {
			return true
		}
		if err == .EINTR {
			continue
		}
		if err != .NONE || n == 0 {
			return false
		}
		(^runtime.Raw_Dynamic_Array)(&c.in_buf).len = old + n
		if n < space || len(c.in_buf) - c.start > MAX_HEADER_BYTES + BODY_CAP {
			return true
		}
	}
}

Flush :: enum u8 {
	Done,
	Blocked,
	Error,
}

@(private = "file")
conn_flush :: proc(c: ^Conn) -> Flush {
	// Corked, the header and the file go out in full segments (nginx's
	// tcp_nopush). Without it sendfile pushes a partial segment at every 64 KiB
	// of pipe it fills: GET 1 MiB measured 62k/s at 129 us of CPU each,
	// against 70k/s at 113 us corked. Uncorking pushes the final partial one.
	if c.file != nil && !c.corked {
		set_cork(c, true)
	}
	for c.out_off < len(c.out) {
		n, err := linux.send(c.fd, c.out[c.out_off:], {.NOSIGNAL})
		if err == .EAGAIN {
			return .Blocked
		}
		if err == .EINTR {
			continue
		}
		if err != .NONE {
			return .Error
		}
		c.out_off += n
	}
	clear(&c.out)
	c.out_off = 0
	if cap(c.out) > 1 << 20 {
		shrink(&c.out, 4096)
	}

	for c.file != nil {
		n, err := linux.sendfile(c.fd, c.file.fd, &c.file_off, uint(min(c.file_left, 1 << 30)))
		if err == .EAGAIN {
			return .Blocked
		}
		if err == .EINTR {
			continue
		}
		if err != .NONE || n == 0 {
			return .Error
		}
		c.file_left -= i64(n)
		if c.file_left == 0 {
			file_unref(c.file)
			c.file = nil
			set_cork(c, false)
		}
	}
	return .Done
}

@(private = "file")
set_cork :: proc(c: ^Conn, on: bool) {
	c.corked = on
	v := i32(on ? 1 : 0)
	linux.setsockopt_tcp(c.fd, linux.SOL_TCP, .CORK, &v)
}

Next :: enum u8 {
	Need_Input,
	Progress,
	Detached,
}

// Parse and dispatch the next buffered request.
@(private = "file")
next_request :: proc(c: ^Conn) -> Next {
	// Drop consumed bytes; the previous request's slices are dead by now.
	if c.start > 0 {
		rem := len(c.in_buf) - c.start
		copy(c.in_buf[:rem], c.in_buf[c.start:])
		resize(&c.in_buf, rem)
		c.start = 0
		c.scan = 0
		if cap(c.in_buf) > 1 << 20 && rem < 16384 {
			shrink(&c.in_buf, 16384)
		}
	}
	if c.w.arena.total_used > 0 {
		virtual.arena_free_all(&c.w.arena)
	}

	req := &c.req
	switch parse_request(c, req) {
	case .Incomplete:
		return .Need_Input
	case .Bad:
		respond_error(c, 400, "malformed request", false)
		return .Progress
	case .Ok:
	}

	if req.content_length > g_config.max_body {
		respond_error(c, 413, "blob exceeds maximum size", false)
		return .Progress
	}
	is_upload := req.method == "PUT" && req.path == "/upload"
	if is_upload && req.content_length > UPLOAD_MEM_MAX {
		c.start = req.head_end
		upload_begin(c)
		return .Progress
	}
	if req.content_length > BODY_CAP {
		respond_error(c, 413, "request body too large", false)
		return .Progress
	}
	if len(c.in_buf) - req.head_end < req.content_length {
		return .Need_Input
	}
	body := c.in_buf[req.head_end:][:req.content_length]
	c.start = req.head_end + req.content_length
	c.scan = c.start
	if handle_request(c, req, body) == .Detached {
		return .Detached
	}
	return .Progress
}

// --- streaming uploads ------------------------------------------------------

@(private = "file")
upload_begin :: proc(c: ^Conn) {
	up := &c.up
	up^ = {}
	up.tmp = tmp_path(g_store, runtime.heap_allocator())
	fd, err := linux.open(up.tmp, {.WRONLY, .CREAT, .EXCL, .CLOEXEC}, FILE_MODE)
	up.fd = err == .NONE ? fd : -1
	up.failed = err != .NONE
	up.left = c.req.content_length
	sha256_init(&up.sha)
	c.state = .Upload

	take := min(len(c.in_buf) - c.start, up.left)
	upload_chunk(c, c.in_buf[c.start:][:take])
	c.start += take
	if up.left == 0 {
		upload_end(c)
	}
}

@(private = "file")
upload_chunk :: proc(c: ^Conn, chunk: []u8) {
	up := &c.up
	if len(chunk) == 0 {
		return
	}
	if up.total == 0 {
		up.sniffed = sniff_mime(chunk)
	}
	up.left -= len(chunk)
	up.total += i64(len(chunk))
	if up.failed {
		return
	}
	sha256_update(&up.sha, chunk)
	for done := 0; done < len(chunk); {
		n, err := linux.write(up.fd, chunk[done:])
		if err == .EINTR {
			continue
		}
		if err != .NONE || n == 0 {
			up.failed = true
			return
		}
		done += n
	}
}

// recv body bytes straight into the worker's scratch buffer.
@(private = "file")
upload_read :: proc(c: ^Conn) -> bool {
	up := &c.up
	scratch := c.w.scratch
	for up.left > 0 {
		want := min(up.left, len(scratch))
		n, err := linux.recv(c.fd, scratch[:want], {})
		if err == .EAGAIN {
			return true
		}
		if err == .EINTR {
			continue
		}
		if err != .NONE || n == 0 {
			return false
		}
		upload_chunk(c, scratch[:n])
		if n < want {
			break
		}
	}
	if up.left == 0 {
		upload_end(c)
	}
	return true
}

@(private = "file")
upload_end :: proc(c: ^Conn) {
	up := &c.up
	c.state = .Head
	c.scan = c.start
	if up.fd >= 0 {
		linux.close(up.fd)
		up.fd = -1
	}
	if up.failed {
		linux.unlink(up.tmp)
		respond_error(c, 500, "failed to store blob", c.req.keep_alive)
	} else {
		digest := sha256_final(&up.sha)
		upload_finish_file(c, &c.req, digest, up.tmp, up.total, up.sniffed)
	}
	delete(up.tmp, runtime.heap_allocator())
	up.tmp = nil
}

// Release a connection. `.Detached` leaves the fd open: its new owner closes it.
conn_free :: proc(c: ^Conn, end: Conn_End) {
	heap := runtime.heap_allocator()
	if end == .Close {
		linux.close(c.fd)
	}
	if c.state == .Upload {
		if c.up.fd >= 0 {
			linux.close(c.up.fd)
		}
		linux.unlink(c.up.tmp)
		delete(c.up.tmp, heap)
	}
	if c.file != nil {
		file_unref(c.file)
	}
	delete(c.in_buf)
	delete(c.out)
	free(c, heap)
}

// Hand the connection's socket to another thread: off epoll, back to blocking.
conn_detach :: proc(c: ^Conn) {
	linux.epoll_ctl(c.w.epfd, .DEL, c.fd, nil)
	net.set_blocking(net.TCP_Socket(c.fd), true)
}
