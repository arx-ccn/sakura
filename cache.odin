package sakura

import "base:runtime"
import "core:strconv"
import "core:sys/linux"

// Per-worker cache of the blobs being served, so a GET costs one send (small
// blobs) or one send + one sendfile (large ones) and no open/fstat/close.
//
// Blobs are content-addressed and immutable, so an entry can only go stale by
// deletion: store_delete bumps g_delete_epoch and every worker drops its whole
// cache before handling its next batch of events.
//
//   slot = hash[0..1] & (CACHE_SLOTS-1)        direct-mapped, evict on collision
//   size <= INLINE_MAX   -> head + body bytes  (one append into conn.out)
//   larger               -> head + open fd     (sendfile, fd refcounted so an
//                                               eviction can't close it under a
//                                               transfer in flight)

CACHE_SLOTS :: 8192
INLINE_MAX :: 16 * 1024
INLINE_BUDGET :: 32 * 1024 * 1024 // per worker

Blob_File :: struct {
	fd:   linux.Fd,
	refs: int,
}

Cached_Blob :: struct {
	hash: [32]u8,
	used: bool,
	size: i64,
	mime: string, // heap copy
	head: []u8, // 200 header block up to, not including, the Connection line
	body: []u8, // the whole blob when inlined
	file: ^Blob_File, // the open blob otherwise
}

Blob_Cache :: struct {
	slots:        []Cached_Blob,
	inline_bytes: int,
}

file_unref :: proc(f: ^Blob_File) {
	f.refs -= 1
	if f.refs > 0 {
		return
	}
	linux.close(f.fd)
	free(f, runtime.heap_allocator())
}

cache_init :: proc(bc: ^Blob_Cache) {
	bc.slots = make([]Cached_Blob, CACHE_SLOTS, runtime.heap_allocator())
}

@(private = "file")
slot_evict :: proc(bc: ^Blob_Cache, e: ^Cached_Blob) {
	if !e.used {
		return
	}
	heap := runtime.heap_allocator()
	delete(e.head, heap)
	delete(e.mime, heap)
	if e.body != nil {
		bc.inline_bytes -= len(e.body)
		delete(e.body, heap)
	}
	if e.file != nil {
		file_unref(e.file)
	}
	e^ = {}
}

cache_clear :: proc(bc: ^Blob_Cache) {
	for &e in bc.slots {
		slot_evict(bc, &e)
	}
}

// The cached blob for `hash`, loading it on a miss. nil when the blob isn't
// stored (or its file is gone).
cache_get :: proc(bc: ^Blob_Cache, hash: [32]u8) -> ^Cached_Blob {
	e := &bc.slots[(int(hash[0]) | int(hash[1]) << 8) & (CACHE_SLOTS - 1)]
	if e.used && e.hash == hash {
		return e
	}

	_, mime, has := store_meta(g_store, hash)
	if !has {
		return nil
	}
	hk := hash
	fd, oerr := linux.open(blob_path(g_store, hex_string(hk[:])), {.CLOEXEC})
	if oerr != .NONE {
		return nil
	}
	st: linux.Stat
	if linux.fstat(fd, &st) != .NONE {
		linux.close(fd)
		return nil
	}
	size := i64(st.size)

	if mime == "" {
		sniff: [16]u8
		n, _ := linux.pread(fd, sniff[:], 0)
		mime = sniff_mime(sniff[:max(n, 0)])
		if mime == "" {
			mime = "application/octet-stream"
		}
	}

	slot_evict(bc, e)
	heap := runtime.heap_allocator()
	e.hash = hash
	e.used = true
	e.size = size
	e.mime = clone_str(mime, heap)
	e.head = build_head(mime, size, heap)

	if size <= INLINE_MAX && bc.inline_bytes + int(size) <= INLINE_BUDGET {
		body := make([]u8, int(size), heap)
		if read_all_at(fd, body) {
			e.body = body
			bc.inline_bytes += len(body)
			linux.close(fd)
			return e
		}
		delete(body, heap)
	}
	e.file = new(Blob_File, heap)
	e.file^ = {fd, 1}
	return e
}

@(private = "file")
read_all_at :: proc(fd: linux.Fd, dst: []u8) -> bool {
	got := 0
	for got < len(dst) {
		n, err := linux.pread(fd, dst[got:], i64(got))
		if err == .EINTR {
			continue
		}
		if err != .NONE || n == 0 {
			return false
		}
		got += n
	}
	return true
}

// "HTTP/1.1 200 OK" through Content-Length, ready to be followed by
// connection_tail().
@(private = "file")
build_head :: proc(mime: string, size: i64, allocator: runtime.Allocator) -> []u8 {
	b := make([dynamic]u8, 0, 320, allocator)
	append(&b, "HTTP/1.1 200 OK\r\n")
	append(&b, COMMON_HEADERS)
	append(&b, "Content-Type: ")
	append(&b, mime)
	append(&b, "\r\nAccept-Ranges: bytes\r\nContent-Length: ")
	buf: [24]u8
	append(&b, strconv.write_int(buf[:], size, 10))
	append(&b, "\r\n")
	return b[:]
}

@(private = "file")
clone_str :: proc(s: string, allocator: runtime.Allocator) -> string {
	b := make([]u8, len(s), allocator)
	copy(b, s)
	return string(b)
}
