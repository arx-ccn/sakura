package sakura

import "core:mem"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:sys/linux"

// Content-addressed blob store.
//
// Blobs live on disk at <data>/blobs/<xx>/<sha256>, sharded by the first hash
// byte to keep directory sizes sane. A compact append-only log (<data>/index.log)
// records ownership so the in-memory index can be rebuilt at startup. The index
// answers existence, metadata and /list, and tracks owners so a blob file is
// removed only once no pubkey claims it.
//
// The index is split into 256 shards by the first hash byte, each with its own
// lock on its own cache line, so lookups of different blobs never contend:
//
//   by_hash:   shards[hash[0]].by_hash      (shard lock)
//   by_pubkey: owners.by_pubkey + log append (owners lock)
//
// Lock order is always shard, then owners.
//
// Index keys are BINARY: hashes are [32]u8 and pubkeys are [32]u8. The on-disk
// index.log format stays hex text (decoded to binary on replay, encoded to hex
// on write) for backward compatibility.

Blob_Meta :: struct {
	size:     i64,
	mime:     string,
	uploaded: i64, // first upload time
	owners:   map[[32]u8]i64, // pubkey -> that owner's upload time
}

Blob_Record :: struct {
	sha256:   string, // hex, encoded into the caller's allocator at list time
	size:     i64,
	mime:     string,
	uploaded: i64,
}

STORE_SHARDS :: 256

Store_Shard :: struct #align (64) {
	mu:      sync.RW_Mutex,
	by_hash: map[[32]u8]^Blob_Meta,
}

Store :: struct {
	shards:    [STORE_SHARDS]Store_Shard,
	owners_mu: sync.RW_Mutex,
	by_pubkey: map[[32]u8]^Owner_List,
	log:       linux.Fd,
	persist:   mem.Allocator,
	data_dir:  string,
	blobs_dir: string,
	tmp_dir:   string,
}

// The blobs one pubkey has stored, for /list. Append-only in chunks that
// double in size (16, 32, 64, ... hashes), so adding never rehashes or copies:
// a hash set here stalled every upload for tens of ms whenever it grew.
// Deletes leave dead entries behind (and a re-add after a delete a duplicate);
// store_list filters both against the shard index and compacts the list once
// dead entries outnumber live ones.
Owner_List :: struct {
	chunks: [dynamic][][32]u8,
	fill:   int, // entries used in the last chunk
	total:  int, // entries appended, live or dead
	live:   int,
	gen:    int, // bumped by each compaction
}

// Bumped after every delete. Workers cache immutable blobs and drop their
// caches when this changes (see cache.odin).
g_delete_epoch: u64

store_init :: proc(st: ^Store, data_dir: string) -> bool {
	st.persist = context.allocator
	st.data_dir = strings.clone(data_dir)
	st.blobs_dir = strings.concatenate({data_dir, "/blobs"})
	st.tmp_dir = strings.concatenate({data_dir, "/tmp"})
	for &sh in st.shards {
		sh.by_hash = make(map[[32]u8]^Blob_Meta)
	}
	st.by_pubkey = make(map[[32]u8]^Owner_List)

	os.make_directory(data_dir)
	os.make_directory(st.blobs_dir)
	os.make_directory(st.tmp_dir)

	// Every shard directory exists up front, so uploads never mkdir.
	hex: [2]u8
	for i in 0 ..< 256 {
		b := [1]u8{u8(i)}
		hex_encode(hex[:], b[:])
		os.make_directory(
			strings.concatenate({st.blobs_dir, "/", string(hex[:])}, context.temp_allocator),
		)
	}

	// Replay the index log.
	log_path := strings.concatenate({data_dir, "/index.log"})
	if contents, rerr := os.read_entire_file_from_path(log_path, context.allocator); rerr == nil {
		replay_log(st, string(contents))
		delete(contents)
	}

	fd, err := linux.open(
		strings.clone_to_cstring(log_path, context.temp_allocator),
		{.WRONLY, .CREAT, .APPEND, .CLOEXEC},
		FILE_MODE,
	)
	if err != .NONE {
		return false
	}
	st.log = fd
	return true
}

FILE_MODE :: linux.Mode{.IRUSR, .IWUSR, .IRGRP, .IROTH}

@(private = "file")
shard_of :: #force_inline proc "contextless" (st: ^Store, hash: [32]u8) -> ^Store_Shard {
	return &st.shards[hash[0]]
}

// Decode 64-char lowercase hex into a [32]u8. Returns ok=false on bad input.
hash_bin :: proc "contextless" (s: string) -> (out: [32]u8, ok: bool) {
	if len(s) != 64 {
		return {}, false
	}
	if !hex_decode(out[:], s) {
		return {}, false
	}
	return out, true
}

@(private = "file")
replay_log :: proc(st: ^Store, contents: string) {
	context.allocator = st.persist
	it := contents
	for line in strings.split_lines_iterator(&it) {
		if len(line) == 0 {
			continue
		}
		fields := strings.fields(line)
		defer delete(fields)
		switch fields[0] {
		case "A":
			if len(fields) == 6 {
				h, hok := hash_bin(fields[1])
				p, pok := hash_bin(fields[2])
				if !hok || !pok {
					continue
				}
				size, _ := strconv.parse_i64(fields[3])
				uploaded, _ := strconv.parse_i64(fields[5])
				if apply_add(st, h, p, size, fields[4], uploaded) {
					owner_add(st, h, p)
				}
			}
		case "D":
			if len(fields) == 3 {
				h, hok := hash_bin(fields[1])
				p, pok := hash_bin(fields[2])
				if !hok || !pok {
					continue
				}
				if apply_del(st, h, p) {
					owner_del(st, p)
				}
			}
		}
	}
}

// Insert ownership into a shard's index (no disk write). Caller holds the shard
// lock. Returns whether `pubkey` newly owns the blob.
@(private = "file")
apply_add :: proc(
	st: ^Store,
	hash: [32]u8,
	pubkey: [32]u8,
	size: i64,
	mime: string,
	uploaded: i64,
) -> bool {
	context.allocator = st.persist
	sh := shard_of(st, hash)
	meta, has := sh.by_hash[hash]
	if !has {
		meta = new(Blob_Meta)
		meta.size = size
		meta.mime = strings.clone(mime)
		meta.uploaded = uploaded
		meta.owners = make(map[[32]u8]i64)
		sh.by_hash[hash] = meta
	}
	if _, owned := meta.owners[pubkey]; owned {
		return false
	}
	meta.owners[pubkey] = uploaded
	return true
}

// Record that `pubkey` newly owns `hash`. Caller holds the owners lock.
@(private = "file")
owner_add :: proc(st: ^Store, hash: [32]u8, pubkey: [32]u8) {
	context.allocator = st.persist
	ol := st.by_pubkey[pubkey]
	if ol == nil {
		ol = new(Owner_List)
		st.by_pubkey[pubkey] = ol
	}
	if len(ol.chunks) == 0 || ol.fill == len(ol.chunks[len(ol.chunks) - 1]) {
		append(&ol.chunks, make([][32]u8, 16 << uint(len(ol.chunks))))
		ol.fill = 0
	}
	ol.chunks[len(ol.chunks) - 1][ol.fill] = hash
	ol.fill += 1
	ol.total += 1
	ol.live += 1
}

// The entry stays in the list; store_list skips it. Caller holds owners.
@(private = "file")
owner_del :: proc(st: ^Store, pubkey: [32]u8) {
	if ol := st.by_pubkey[pubkey]; ol != nil {
		ol.live -= 1
	}
}

// Copy out the first `n` entries of an owner list.
@(private = "file")
owner_entries :: proc(ol: ^Owner_List, n: int, dst: ^[dynamic][32]u8) {
	for chunk in ol.chunks {
		take := min(len(chunk), n - len(dst))
		if take <= 0 {
			return
		}
		append(dst, ..chunk[:take])
	}
}

// Remove ownership from a shard's index. Caller holds the shard lock. Returns
// false when `pubkey` didn't own the blob.
@(private = "file")
apply_del :: proc(st: ^Store, hash: [32]u8, pubkey: [32]u8) -> bool {
	sh := shard_of(st, hash)
	meta, has := sh.by_hash[hash]
	if !has {
		return false
	}
	if _, owned := meta.owners[pubkey]; !owned {
		return false
	}
	delete_key(&meta.owners, pubkey)
	if len(meta.owners) == 0 {
		delete_key(&sh.by_hash, hash)
	}
	return true
}

// Build the on-disk path for a hex hash: <blobs>/<first two hex chars>/<hash>.
blob_path :: proc(st: ^Store, hash: string, allocator := context.allocator) -> cstring {
	return strings.clone_to_cstring(
		strings.concatenate({st.blobs_dir, "/", hash[:2], "/", hash}, context.temp_allocator),
		allocator,
	)
}

// Append an "A" record to the index log (hex-encoded). Caller holds owners.
@(private = "file")
log_add :: proc(st: ^Store, hash: [32]u8, pubkey: [32]u8, size: i64, mime: string, now: i64) {
	line: [512]u8
	n := 0
	put :: proc(line: ^[512]u8, n: ^int, s: string) {
		n^ += copy(line[n^:], s)
	}
	hk, pk := hash, pubkey
	put(&line, &n, "A ")
	hex_encode(line[n:][:64], hk[:])
	n += 64
	put(&line, &n, " ")
	hex_encode(line[n:][:64], pk[:])
	n += 64
	buf: [32]u8
	put(&line, &n, " ")
	put(&line, &n, strconv.write_int(buf[:], size, 10))
	put(&line, &n, " ")
	put(&line, &n, mime[:min(len(mime), 256)])
	put(&line, &n, " ")
	put(&line, &n, strconv.write_int(buf[:], now, 10))
	put(&line, &n, "\n")
	linux.write(st.log, line[:n])
}

// Record ownership + persist. `size` and `mime` only apply when the blob is
// new to the index. Caller must already have placed the file on disk.
@(private = "file")
commit_owner :: proc(
	st: ^Store,
	hash: [32]u8,
	pubkey: [32]u8,
	size: i64,
	mime: string,
	now: i64,
) -> (
	out_size: i64,
	uploaded: i64,
	mime_out: string,
	created: bool,
) {
	sh := shard_of(st, hash)
	sync.rw_mutex_lock(&sh.mu)
	defer sync.rw_mutex_unlock(&sh.mu)

	created = apply_add(st, hash, pubkey, size, mime, now)
	meta := sh.by_hash[hash]
	out_size, uploaded, mime_out = meta.size, meta.owners[pubkey], meta.mime
	if !created {
		return
	}

	sync.rw_mutex_lock(&st.owners_mu)
	defer sync.rw_mutex_unlock(&st.owners_mu)
	owner_add(st, hash, pubkey)
	log_add(st, hash, pubkey, meta.size, meta.mime, now)
	return
}

// Write `data` to a temp file and rename it into place. Readers never see a
// partial blob. The temp file sits in the blob's own shard directory: a rename
// within one directory locks only it, while a cross-directory rename takes the
// filesystem-wide rename mutex and would serialize every upload.
@(private = "file")
write_blob_file :: proc(st: ^Store, hash: string, data: []u8) -> bool {
	n := sync.atomic_add(&g_tmp_counter, 1)
	buf: [24]u8
	shard := strings.concatenate({st.blobs_dir, "/", hash[:2], "/"}, context.temp_allocator)
	tmp := strings.clone_to_cstring(
		strings.concatenate(
			{shard, ".up-", strconv.write_uint(buf[:], n, 10)},
			context.temp_allocator,
		),
	)
	path := strings.clone_to_cstring(strings.concatenate({shard, hash}, context.temp_allocator))
	fd, err := linux.open(tmp, {.WRONLY, .CREAT, .EXCL, .CLOEXEC}, FILE_MODE)
	if err != .NONE {
		return false
	}
	written := 0
	for written < len(data) {
		n, werr := linux.write(fd, data[written:])
		if werr == .EINTR {
			continue
		}
		if werr != .NONE || n == 0 {
			linux.close(fd)
			linux.unlink(tmp)
			return false
		}
		written += n
	}
	linux.close(fd)
	if linux.rename(tmp, path) != .NONE {
		linux.unlink(tmp)
		return false
	}
	return true
}

// Store a blob whose bytes are in memory (small uploads and /mirror). The file
// is only written when the index doesn't already have the blob.
store_put :: proc(
	st: ^Store,
	hash: [32]u8,
	data: []u8,
	pubkey: [32]u8,
	mime: string,
	now: i64,
) -> (
	size: i64,
	uploaded: i64,
	mime_out: string,
	created: bool,
	ok: bool,
) {
	if _, _, has := store_meta(st, hash); !has {
		hk := hash
		if !write_blob_file(st, hex_string(hk[:]), data) {
			return 0, 0, "", false, false
		}
	}
	sz, up, mo, cr := commit_owner(st, hash, pubkey, i64(len(data)), mime, now)
	return sz, up, mo, cr, true
}

// Store a blob whose bytes already sit in `temp_path` (the streaming upload
// path). Renames temp into place, then records ownership. The temp file is
// always consumed.
store_put_file :: proc(
	st: ^Store,
	hash: [32]u8,
	temp_path: cstring,
	size: i64,
	pubkey: [32]u8,
	mime: string,
	now: i64,
) -> (
	out_size: i64,
	uploaded: i64,
	mime_out: string,
	created: bool,
	ok: bool,
) {
	if _, _, has := store_meta(st, hash); has {
		linux.unlink(temp_path)
	} else {
		hk := hash
		if linux.rename(temp_path, blob_path(st, hex_string(hk[:]))) != .NONE {
			linux.unlink(temp_path)
			return 0, 0, "", false, false
		}
	}
	sz, up, mo, cr := commit_owner(st, hash, pubkey, size, mime, now)
	return sz, up, mo, cr, true
}

store_delete :: proc(st: ^Store, hash: [32]u8, pubkey: [32]u8) -> bool {
	sh := shard_of(st, hash)
	sync.rw_mutex_lock(&sh.mu)
	defer sync.rw_mutex_unlock(&sh.mu)

	if !apply_del(st, hash, pubkey) {
		return false
	}
	hk, pk := hash, pubkey
	if _, still := sh.by_hash[hash]; !still {
		linux.unlink(blob_path(st, hex_string(hk[:])))
		sync.atomic_add(&g_delete_epoch, 1)
	}

	sync.rw_mutex_lock(&st.owners_mu)
	defer sync.rw_mutex_unlock(&st.owners_mu)
	owner_del(st, pubkey)
	line: [2 + 64 + 1 + 64 + 1]u8
	line[0], line[1] = 'D', ' '
	hex_encode(line[2:66], hk[:])
	line[66] = ' '
	hex_encode(line[67:131], pk[:])
	line[131] = '\n'
	linux.write(st.log, line[:])
	return true
}

// Look up stored metadata (size + mime). The mime string is owned by the
// store and lives as long as the blob. Shared shard lock.
store_meta :: proc(st: ^Store, hash: [32]u8) -> (size: i64, mime: string, ok: bool) {
	sh := shard_of(st, hash)
	sync.rw_mutex_shared_lock(&sh.mu)
	defer sync.rw_mutex_shared_unlock(&sh.mu)
	meta, has := sh.by_hash[hash]
	if !has {
		return 0, "", false
	}
	return meta.size, meta.mime, true
}

// List all blobs owned by a pubkey, newest first. The sha256 hex and mime are
// copied into the caller's allocator.
store_list :: proc(st: ^Store, pubkey: [32]u8, allocator := context.allocator) -> []Blob_Record {
	hashes: [dynamic][32]u8
	hashes.allocator = allocator
	n, gen := 0, 0
	{
		sync.rw_mutex_shared_lock(&st.owners_mu)
		defer sync.rw_mutex_shared_unlock(&st.owners_mu)
		ol := st.by_pubkey[pubkey]
		if ol == nil {
			return {}
		}
		n = ol.total
		gen = ol.gen
		reserve(&hashes, n)
		owner_entries(ol, n, &hashes)
	}

	// Keep entries the pubkey still owns, once each.
	seen := make(map[[32]u8]bool, len(hashes), allocator)
	records := make([dynamic]Blob_Record, allocator)
	live := make([dynamic][32]u8, allocator)
	for &hash in hashes {
		if hash in seen {
			continue
		}
		seen[hash] = true
		sh := shard_of(st, hash)
		sync.rw_mutex_shared_lock(&sh.mu)
		if meta, ok := sh.by_hash[hash]; ok {
			if uploaded, owned := meta.owners[pubkey]; owned {
				append(&live, hash)
				append(
					&records,
					Blob_Record {
						sha256 = hex_string(hash[:], allocator),
						size = meta.size,
						mime = strings.clone(meta.mime, allocator),
						uploaded = uploaded,
					},
				)
			}
		}
		sync.rw_mutex_shared_unlock(&sh.mu)
	}

	if n > 2 * len(live) + 64 {
		owner_compact(st, pubkey, live[:], n, gen)
	}
	slice.sort_by(records[:], proc(a, b: Blob_Record) -> bool {
		return a.uploaded > b.uploaded
	})
	return records[:]
}

// Rebuild an owner list from `live` (what its first `n` entries came to) plus
// whatever was appended since. Deletes after the snapshot just leave dead
// entries again, which the next list skips. Skipped if another compaction
// ran since the snapshot (generation `gen`), as positions no longer line up.
@(private = "file")
owner_compact :: proc(st: ^Store, pubkey: [32]u8, live: [][32]u8, n, gen: int) {
	sync.rw_mutex_lock(&st.owners_mu)
	defer sync.rw_mutex_unlock(&st.owners_mu)
	ol := st.by_pubkey[pubkey]
	if ol == nil || ol.gen != gen {
		return
	}
	all := make([dynamic][32]u8, 0, ol.total, context.temp_allocator)
	owner_entries(ol, ol.total, &all)

	context.allocator = st.persist
	for chunk in ol.chunks {
		delete(chunk)
	}
	clear(&ol.chunks)
	keep_live := ol.live
	ol.fill, ol.total = 0, 0
	for &h in live {
		owner_add(st, h, pubkey)
	}
	for &h in all[n:] {
		owner_add(st, h, pubkey)
	}
	ol.live = keep_live
	ol.gen = gen + 1
}

// Generate a unique temp file path under <data>/tmp. Uniqueness comes from a
// process-wide atomic counter.
@(private = "file")
g_tmp_counter: u64

tmp_path :: proc(st: ^Store, allocator := context.allocator) -> cstring {
	n := sync.atomic_add(&g_tmp_counter, 1)
	buf: [24]u8
	id := strconv.write_uint(buf[:], n, 10)
	return strings.clone_to_cstring(
		strings.concatenate({st.tmp_dir, "/up-", id}, context.temp_allocator),
		allocator,
	)
}
