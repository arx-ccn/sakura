package sakura

import "core:mem"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:sync"

// Content-addressed blob store.
//
// Blobs live on disk at <data>/blobs/<xx>/<sha256>, sharded by the first hash
// byte to keep directory sizes sane. A compact append-only log (<data>/index.log)
// records ownership so the in-memory index can be rebuilt at startup. The index
// itself answers /list and tracks reference counts so a blob file is removed
// only once no pubkey claims it.
//
// The GET/HEAD hot path does NOT touch the write lock: it stats and streams the
// file directly off disk. store_meta / store_list take a shared (read) lock;
// mutations take the exclusive (write) lock.
//
// Index keys are BINARY: hashes are [32]u8 and pubkeys are [32]u8. The on-disk
// index.log format stays hex text (decoded to binary on replay, encoded to hex
// on write) for backward compatibility.

Blob_Meta :: struct {
	size:     i64,
	mime:     string,
	uploaded: i64,                // first upload time
	owners:   map[[32]u8]i64,     // pubkey -> that owner's upload time
}

Blob_Record :: struct {
	sha256:   string, // hex, encoded into the caller's allocator at list time
	size:     i64,
	mime:     string,
	uploaded: i64,
}

Store :: struct {
	mu:        sync.RW_Mutex,
	data_dir:  string,
	blobs_dir: string,
	tmp_dir:   string,
	log:       ^os.File,
	persist:   mem.Allocator,
	by_hash:   map[[32]u8]^Blob_Meta,
	by_pubkey: map[[32]u8]map[[32]u8]bool,
}

store_init :: proc(st: ^Store, data_dir: string) -> bool {
	st.persist = context.allocator
	st.data_dir = strings.clone(data_dir)
	st.blobs_dir = strings.concatenate({data_dir, "/blobs"})
	st.tmp_dir = strings.concatenate({data_dir, "/tmp"})
	st.by_hash = make(map[[32]u8]^Blob_Meta)
	st.by_pubkey = make(map[[32]u8]map[[32]u8]bool)

	os.make_directory(data_dir)
	os.make_directory(st.blobs_dir)
	os.make_directory(st.tmp_dir)

	// Replay the index log.
	log_path := strings.concatenate({data_dir, "/index.log"})
	if contents, rerr := os.read_entire_file_from_path(log_path, context.allocator); rerr == nil {
		replay_log(st, string(contents))
		delete(contents)
	}

	h, err := os.open(log_path, os.O_WRONLY | os.O_CREATE | os.O_APPEND)
	if err != nil {
		return false
	}
	st.log = h
	return true
}

// Decode 64-char lowercase hex into a [32]u8. Returns ok=false on bad input.
@(private = "file")
hash_bin :: proc(s: string) -> (out: [32]u8, ok: bool) {
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
				apply_add(st, h, p, size, fields[4], uploaded)
			}
		case "D":
			if len(fields) == 3 {
				h, hok := hash_bin(fields[1])
				p, pok := hash_bin(fields[2])
				if !hok || !pok {
					continue
				}
				apply_del(st, h, p, false)
			}
		}
	}
}

// Insert ownership into the in-memory index (no disk write). Retained strings
// (just the mime) are cloned into the persistent allocator; keys are binary.
@(private = "file")
apply_add :: proc(st: ^Store, hash: [32]u8, pubkey: [32]u8, size: i64, mime: string, uploaded: i64) {
	context.allocator = st.persist
	meta, has := st.by_hash[hash]
	if !has {
		meta = new(Blob_Meta)
		meta.size = size
		meta.mime = strings.clone(mime)
		meta.uploaded = uploaded
		meta.owners = make(map[[32]u8]i64)
		st.by_hash[hash] = meta
	}
	if _, owned := meta.owners[pubkey]; !owned {
		meta.owners[pubkey] = uploaded
	}

	set, has_set := st.by_pubkey[pubkey]
	if !has_set {
		set = make(map[[32]u8]bool)
		st.by_pubkey[pubkey] = set
	}
	set[hash] = true
	st.by_pubkey[pubkey] = set
}

// Remove ownership. When `remove_file` and the last owner is gone, the blob
// file is unlinked.
@(private = "file")
apply_del :: proc(st: ^Store, hash: [32]u8, pubkey: [32]u8, remove_file: bool) -> bool {
	meta, has := st.by_hash[hash]
	if !has {
		return false
	}
	if _, owned := meta.owners[pubkey]; !owned {
		return false
	}
	delete_key(&meta.owners, pubkey)
	if set, ok := st.by_pubkey[pubkey]; ok {
		delete_key(&set, hash)
	}
	if len(meta.owners) == 0 {
		if remove_file {
			hk := hash
			os.remove(blob_path(st, hex_string(hk[:], context.temp_allocator), context.temp_allocator))
		}
		delete_key(&st.by_hash, hash)
	}
	return true
}

// Build the on-disk path for a hash: <blobs>/<first two hex chars>/<hash>.
blob_path :: proc(st: ^Store, hash: string, allocator := context.allocator) -> string {
	return strings.concatenate({st.blobs_dir, "/", hash[:2], "/", hash}, allocator)
}

@(private = "file")
log_line :: proc(st: ^Store, line: string) {
	os.write(st.log, transmute([]u8)line)
}

// Append an "A" record to the index log (hex-encoded).
@(private = "file")
log_add :: proc(st: ^Store, hash, pubkey: string, size: i64, mime: string, now: i64) {
	b := strings.builder_make(context.temp_allocator)
	buf: [32]u8
	strings.write_string(&b, "A ")
	strings.write_string(&b, hash)
	strings.write_byte(&b, ' ')
	strings.write_string(&b, pubkey)
	strings.write_byte(&b, ' ')
	strings.write_string(&b, strconv.itoa(buf[:], int(size)))
	strings.write_byte(&b, ' ')
	strings.write_string(&b, mime)
	strings.write_byte(&b, ' ')
	strings.write_string(&b, strconv.itoa(buf[:], int(now)))
	strings.write_byte(&b, '\n')
	log_line(st, strings.to_string(b))
}

// Ensure the shard directory for a hash exists.
@(private = "file")
ensure_shard :: proc(st: ^Store, hash: string) {
	shard := strings.concatenate({st.blobs_dir, "/", hash[:2]}, context.temp_allocator)
	os.make_directory(shard)
}

// Record ownership + persist, under the write lock. `data_size` and `mime` are
// only used when the blob is new to the index. Returns the same tuple as
// store_put. Caller must already have placed the file on disk.
@(private = "file")
commit_owner :: proc(
	st: ^Store,
	hash_hex: string,
	hash_bin_v: [32]u8,
	pubkey_hex: string,
	pubkey_bin: [32]u8,
	size: i64,
	mime: string,
	now: i64,
) -> (out_size: i64, uploaded: i64, mime_out: string, created: bool) {
	sync.rw_mutex_lock(&st.mu)
	defer sync.rw_mutex_unlock(&st.mu)

	newly_owned := true
	if meta, has := st.by_hash[hash_bin_v]; has {
		if _, owned := meta.owners[pubkey_bin]; owned {
			newly_owned = false
		}
	}

	apply_add(st, hash_bin_v, pubkey_bin, size, mime, now)
	meta := st.by_hash[hash_bin_v]

	log_add(st, hash_hex, pubkey_hex, size, meta.mime, now)

	return meta.size, meta.owners[pubkey_bin], meta.mime, newly_owned
}

// Store a blob whose bytes are already in memory (used by /mirror). Writes to a
// temp file and renames into place OUTSIDE the lock; only the index update and
// log append take the write lock.
store_put :: proc(
	st: ^Store,
	hash: string,
	data: []u8,
	pubkey: string,
	mime: string,
	now: i64,
) -> (size: i64, uploaded: i64, mime_out: string, created: bool, ok: bool) {
	hb, hok := hash_bin(hash)
	if !hok {
		return 0, 0, "", false, false
	}
	pb, pok := hash_bin(pubkey)
	if pubkey != "" && !pok {
		return 0, 0, "", false, false
	}

	path := blob_path(st, hash, context.temp_allocator)
	if !os.exists(path) {
		ensure_shard(st, hash)
		tmp := tmp_path(st, context.temp_allocator)
		if werr := os.write_entire_file(tmp, data); werr != nil {
			os.remove(tmp)
			return 0, 0, "", false, false
		}
		if rerr := os.rename(tmp, path); rerr != nil {
			// Lost a race or rename failed; if the blob now exists, that's fine.
			os.remove(tmp)
			if !os.exists(path) {
				return 0, 0, "", false, false
			}
		}
	}

	sz, up, mo, cr := commit_owner(st, hash, hb, pubkey, pb, i64(len(data)), mime, now)
	return sz, up, mo, cr, true
}

// Store a blob whose bytes already sit in `temp_path` (the streaming upload
// path). Renames temp into place, then records ownership under the write lock.
// On any failure the temp file is removed.
store_put_file :: proc(
	st: ^Store,
	hash: string,
	temp_path: string,
	size: i64,
	pubkey: string,
	mime: string,
	now: i64,
) -> (out_size: i64, uploaded: i64, mime_out: string, created: bool, ok: bool) {
	hb, hok := hash_bin(hash)
	if !hok {
		os.remove(temp_path)
		return 0, 0, "", false, false
	}
	pb, pok := hash_bin(pubkey)
	if pubkey != "" && !pok {
		os.remove(temp_path)
		return 0, 0, "", false, false
	}

	path := blob_path(st, hash, context.temp_allocator)
	if os.exists(path) {
		// Already have it; discard the temp upload.
		os.remove(temp_path)
	} else {
		ensure_shard(st, hash)
		if rerr := os.rename(temp_path, path); rerr != nil {
			os.remove(temp_path)
			if !os.exists(path) {
				return 0, 0, "", false, false
			}
		}
	}

	sz, up, mo, cr := commit_owner(st, hash, hb, pubkey, pb, size, mime, now)
	return sz, up, mo, cr, true
}

store_delete :: proc(st: ^Store, hash, pubkey: string) -> bool {
	hb, hok := hash_bin(hash)
	pb, pok := hash_bin(pubkey)
	if !hok || !pok {
		return false
	}
	sync.rw_mutex_lock(&st.mu)
	defer sync.rw_mutex_unlock(&st.mu)

	if !apply_del(st, hb, pb, true) {
		return false
	}
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "D ")
	strings.write_string(&b, hash)
	strings.write_byte(&b, ' ')
	strings.write_string(&b, pubkey)
	strings.write_byte(&b, '\n')
	log_line(st, strings.to_string(b))
	return true
}

// Look up stored metadata for the GET/HEAD path (mime + size). Shared lock.
store_meta :: proc(st: ^Store, hash: string) -> (size: i64, mime: string, ok: bool) {
	hb, hok := hash_bin(hash)
	if !hok {
		return 0, "", false
	}
	sync.rw_mutex_shared_lock(&st.mu)
	defer sync.rw_mutex_shared_unlock(&st.mu)
	meta, has := st.by_hash[hb]
	if !has {
		return 0, "", false
	}
	return meta.size, meta.mime, true
}

// List all blobs owned by a pubkey, newest first. Shared lock. The sha256 hex
// is encoded into the caller's allocator.
store_list :: proc(st: ^Store, pubkey: string, allocator := context.allocator) -> []Blob_Record {
	pb, pok := hash_bin(pubkey)
	if !pok {
		return {}
	}
	sync.rw_mutex_shared_lock(&st.mu)
	defer sync.rw_mutex_shared_unlock(&st.mu)

	set, has := st.by_pubkey[pb]
	if !has {
		return {}
	}
	records := make([dynamic]Blob_Record, allocator)
	for hash in set {
		meta, ok := st.by_hash[hash]
		if !ok {
			continue
		}
		uploaded := meta.uploaded
		if t, ok2 := meta.owners[pb]; ok2 {
			uploaded = t
		}
		key := hash
		append(&records, Blob_Record{
			sha256 = hex_string(key[:], allocator),
			size = meta.size,
			mime = strings.clone(meta.mime, allocator),
			uploaded = uploaded,
		})
	}
	slice.sort_by(records[:], proc(a, b: Blob_Record) -> bool {
		return a.uploaded > b.uploaded
	})
	return records[:]
}

// Generate a unique temp file path under <data>/tmp. Uniqueness comes from a
// process-wide atomic counter.
@(private = "file")
g_tmp_counter: u64

tmp_path :: proc(st: ^Store, allocator := context.allocator) -> string {
	n := sync.atomic_add(&g_tmp_counter, 1)
	buf: [24]u8
	id := strconv.itoa(buf[:], int(n))
	return strings.concatenate({st.tmp_dir, "/up-", id}, allocator)
}
