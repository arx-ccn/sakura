package sakura

import "base:intrinsics"
import "core:simd"
import "core:strconv"
import "core:strings"

// Nostr event handling and BUD-11 authorization validation.

Event :: struct {
	id:         string, // hex
	pubkey:     string, // hex
	sig:        string, // hex
	created_at: i64,
	kind:       i64,
	content:    string,
	tags:       [][]string,
}

// --- parsing ----------------------------------------------------------------

// Why event_parse rejected its input.
@(private = "file")
Parse_Error :: enum u8 {
	None,
	Json, // not well-formed JSON
	Malformed, // JSON, but not an event: missing field or wrong type
}

@(private = "file")
Field :: enum u8 {
	Id,
	Pubkey,
	Sig,
	Content,
	Created_At,
	Kind,
	Tags,
}

@(private = "file")
Fields :: bit_set[Field]

@(private = "file")
ALL_FIELDS :: Fields{.Id, .Pubkey, .Sig, .Content, .Created_At, .Kind, .Tags}

// Caller-owned storage for an event's tags, so a typical event parses without
// allocating; bigger tag sets spill to context.allocator. The parsed Event
// may point into it, so it must outlive the Event.
@(private = "file")
Tag_Scratch :: struct {
	items: [48]string,
	ends:  [24]int,
	rows:  [24][]string,
}

// A slice that starts on scratch memory and moves to the allocator when full.
@(private = "file")
Grow :: struct($T: typeid) {
	data: []T,
	n:    int,
}

@(private = "file")
grow_push :: proc(g: ^Grow($T), v: T) {
	if g.n == len(g.data) {
		bigger := make([]T, 2 * len(g.data))
		copy(bigger, g.data)
		g.data = bigger
	}
	#no_bounds_check g.data[g.n] = v
	g.n += 1
}

// Parse an event straight from JSON text, without a JSON tree or maps. String
// fields alias s unless they contain escapes; tags live in scratch while they
// fit. Accepts exactly what json_parse plus field extraction did: unknown
// keys are skipped, the last duplicate key wins (so a mistyped field only
// counts if no later duplicate fixes it), trailing text is ignored.
@(private = "file")
event_parse :: proc(s: string, scratch: ^Tag_Scratch) -> (ev: Event, err: Parse_Error) {
	c := Json_Cursor{s, 0}
	json_skip_ws(&c)
	if peek(&c) != '{' {
		_, ok := json_value(&c)
		return {}, ok ? .Malformed : .Json
	}
	c.pos += 1
	have: Fields
	json_skip_ws(&c)
	if peek(&c) == '}' {
		return {}, .Malformed
	}
	for {
		json_skip_ws(&c)
		if peek(&c) != '"' {
			return {}, .Json
		}
		key, kok := json_string(&c)
		json_skip_ws(&c)
		if !kok || peek(&c) != ':' {
			return {}, .Json
		}
		c.pos += 1
		json_skip_ws(&c)
		ok: bool
		switch key {
		case "id":         ok = read_str(&c, &ev.id, .Id, &have)
		case "pubkey":     ok = read_str(&c, &ev.pubkey, .Pubkey, &have)
		case "sig":        ok = read_str(&c, &ev.sig, .Sig, &have)
		case "content":    ok = read_str(&c, &ev.content, .Content, &have)
		case "created_at": ok = read_int(&c, &ev.created_at, .Created_At, &have)
		case "kind":       ok = read_int(&c, &ev.kind, .Kind, &have)
		case "tags":       ok = read_tags(&c, &ev.tags, &have, scratch)
		case:              _, ok = json_value(&c)
		}
		if !ok {
			return {}, .Json
		}
		json_skip_ws(&c)
		switch peek(&c) {
		case ',':
			c.pos += 1
		case '}':
			return ev, have == ALL_FIELDS ? .None : .Malformed
		case:
			return {}, .Json
		}
	}
}

// Next byte, or 0 at the end (0 never matches the bytes callers look for).
@(private = "file")
peek :: #force_inline proc(c: ^Json_Cursor) -> u8 {
	return c.pos < len(c.s) ? c.s[c.pos] : 0
}

// A string field; any other value type is consumed and marks it missing.
@(private = "file")
read_str :: proc(c: ^Json_Cursor, dst: ^string, f: Field, have: ^Fields) -> bool {
	if peek(c) != '"' {
		have^ -= {f}
		_, ok := json_value(c)
		return ok
	}
	dst^ = json_string(c) or_return
	have^ += {f}
	return true
}

// A number field (truncated to i64); other value types mark it missing.
@(private = "file")
read_int :: proc(c: ^Json_Cursor, dst: ^i64, f: Field, have: ^Fields) -> bool {
	switch peek(c) {
	case '"', '{', '[', 't', 'f', 'n':
		have^ -= {f}
		_, ok := json_value(c)
		return ok
	}
	dst^ = json_int(c) or_return
	have^ += {f}
	return true
}

// The tags array of string arrays. All items go into one buffer and each row
// is a slice of it.
@(private = "file")
read_tags :: proc(c: ^Json_Cursor, dst: ^[][]string, have: ^Fields, scratch: ^Tag_Scratch) -> bool {
	if peek(c) != '[' {
		have^ -= {.Tags}
		_, ok := json_value(c)
		return ok
	}
	c.pos += 1
	items := Grow(string){data = scratch.items[:]}
	ends := Grow(int){data = scratch.ends[:]} // row i is items[ends[i-1]:ends[i]]
	good := true
	json_skip_ws(c)
	if peek(c) == ']' {
		c.pos += 1
	} else {
		loop: for {
			json_skip_ws(c)
			if peek(c) == '[' {
				read_tag(c, &items, &good) or_return
				grow_push(&ends, items.n)
			} else {
				good = false
				_, ok := json_value(c)
				if !ok {
					return false
				}
			}
			json_skip_ws(c)
			switch peek(c) {
			case ',':
				c.pos += 1
			case ']':
				c.pos += 1
				break loop
			case:
				return false
			}
		}
	}
	if !good {
		have^ -= {.Tags}
		return true
	}
	rows := scratch.rows[:]
	if ends.n > len(rows) {
		rows = make([][]string, ends.n)
	}
	start := 0
	for end, i in ends.data[:ends.n] {
		rows[i] = items.data[start:end]
		start = end
	}
	dst^ = rows[:ends.n]
	have^ += {.Tags}
	return true
}

// One tag row; a non-string item clears good but parsing continues.
@(private = "file")
read_tag :: proc(c: ^Json_Cursor, items: ^Grow(string), good: ^bool) -> bool {
	c.pos += 1 // '['
	json_skip_ws(c)
	if peek(c) == ']' {
		c.pos += 1
		return true
	}
	for {
		json_skip_ws(c)
		if peek(c) == '"' {
			s := json_string(c) or_return
			grow_push(items, s)
		} else {
			good^ = false
			_, ok := json_value(c)
			if !ok {
				return false
			}
		}
		json_skip_ws(c)
		switch peek(c) {
		case ',':
			c.pos += 1
		case ']':
			c.pos += 1
			return true
		case:
			return false
		}
	}
}

// --- event id -------------------------------------------------------------

// Streams the NIP-01 serialization [0,<pubkey>,<created_at>,<kind>,<tags>,
// <content>] into SHA-256 through a stack buffer: no builder, no allocation.
@(private = "file")
Id_Hasher :: struct {
	ctx: Sha256_Ctx,
	buf: [256]u8,
	n:   int,
}

@(private = "file")
put :: proc "contextless" (h: ^Id_Hasher, s: string) {
	if h.n + len(s) > len(h.buf) {
		sha256_update(&h.ctx, h.buf[:h.n])
		h.n = 0
		if len(s) > len(h.buf) {
			sha256_update(&h.ctx, transmute([]u8)s)
			return
		}
	}
	copy(h.buf[h.n:], s)
	h.n += len(s)
}

@(private = "file")
put_byte :: #force_inline proc "contextless" (h: ^Id_Hasher, b: u8) {
	if h.n == len(h.buf) {
		sha256_update(&h.ctx, h.buf[:])
		h.n = 0
	}
	#no_bounds_check h.buf[h.n] = b
	h.n += 1
}

@(private = "file")
put_int :: proc "contextless" (h: ^Id_Hasher, v: i64) {
	tmp: [20]u8
	i := len(tmp)
	m := v < 0 ? 0 - u64(v) : u64(v)
	for {
		i -= 1
		tmp[i] = u8('0' + m % 10)
		m /= 10
		if m == 0 {
			break
		}
	}
	if v < 0 {
		put_byte(h, '-')
	}
	put(h, string(tmp[i:]))
}

// A JSON string with exactly json_write_string's (NIP-01) escaping; runs of
// plain bytes are copied in one piece, found 16 bytes at a time.
@(private = "file")
put_json_string :: proc "contextless" (h: ^Id_Hasher, s: string) {
	put_byte(h, '"')
	start := 0
	i := 0
	#no_bounds_check for ; i + 16 <= len(s); i += 16 {
		v := intrinsics.unaligned_load((^#simd[16]u8)(&raw_data(s)[i]))
		special := simd.lanes_lt(v, SPACE16) | simd.lanes_eq(v, QUOTE16) | simd.lanes_eq(v, BACKSLASH16)
		if simd.reduce_or(special) != 0 {
			break
		}
	}
	#no_bounds_check for ; i < len(s); i += 1 {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		put(h, s[start:i])
		switch c {
		case '"':  put(h, "\\\"")
		case '\\': put(h, "\\\\")
		case '\n': put(h, "\\n")
		case '\r': put(h, "\\r")
		case '\t': put(h, "\\t")
		case '\b': put(h, "\\b")
		case '\f': put(h, "\\f")
		case:
			hexd := "0123456789abcdef"
			esc := [6]u8{'\\', 'u', '0', '0', hexd[c >> 4], hexd[c & 0x0f]}
			put(h, string(esc[:]))
		}
		start = i + 1
	}
	put(h, s[start:])
	put_byte(h, '"')
}

@(private = "file") SPACE16 :: #simd[16]u8{0 ..< 16 = 0x20}
@(private = "file") QUOTE16 :: #simd[16]u8{0 ..< 16 = '"'}
@(private = "file") BACKSLASH16 :: #simd[16]u8{0 ..< 16 = '\\'}

// The NIP-01 event id: SHA-256 of the canonical serialization.
@(private = "file")
event_id :: proc "contextless" (ev: Event) -> [32]u8 {
	h: Id_Hasher = ---
	sha256_init(&h.ctx)
	h.n = 0
	put(&h, "[0,")
	put_json_string(&h, ev.pubkey)
	put_byte(&h, ',')
	put_int(&h, ev.created_at)
	put_byte(&h, ',')
	put_int(&h, ev.kind)
	put(&h, ",[")
	for tag, ti in ev.tags {
		if ti > 0 {
			put_byte(&h, ',')
		}
		put_byte(&h, '[')
		for item, ii in tag {
			if ii > 0 {
				put_byte(&h, ',')
			}
			put_json_string(&h, item)
		}
		put_byte(&h, ']')
	}
	put(&h, "],")
	put_json_string(&h, ev.content)
	put_byte(&h, ']')
	sha256_update(&h.ctx, h.buf[:h.n])
	return sha256_final(&h.ctx)
}

// --- verification -----------------------------------------------------------

// Ids of events whose signature this thread has verified, direct-mapped by
// the id's low bits. No locks: each server worker is one thread and keeps a
// connection, so a client's HEAD /upload + PUT /upload with one token verify
// once; a miss costs one 32-byte compare. Keying by the id alone is safe: it
// commits to every signed field, so a hit only re-admits an event its key
// already signed (ditto-blossom's cache does the same).
@(private = "file")
@(thread_local)
verified_ids: [1024][32]u8

@(private = "file")
verified_slot :: #force_inline proc "contextless" (id: [32]u8) -> ^[32]u8 {
	#no_bounds_check return &verified_ids[(u32(id[0]) | u32(id[1]) << 8) & 1023]
}

// Recompute the event id and verify it matches the claimed id, then verify the
// Schnorr signature over that id (skipped if this thread verified it before).
event_verify :: proc(ev: Event) -> bool {
	id, pubkey: [32]u8
	sig: [64]u8
	if !hex_decode_lower(id[:], ev.id) || !hex_decode_lower(pubkey[:], ev.pubkey) || !hex_decode_lower(sig[:], ev.sig) {
		return false
	}
	if event_id(ev) != id {
		return false
	}
	slot := verified_slot(id)
	if slot^ == id && id != ([32]u8{}) {
		return true
	}
	if !schnorr_verify(pubkey[:], id[:], sig[:]) {
		return false
	}
	slot^ = id
	return true
}

@(private = "file")
tag_value :: proc(ev: Event, name: string) -> (string, bool) {
	for tag in ev.tags {
		if len(tag) >= 2 && tag[0] == name {
			return tag[1], true
		}
	}
	return "", false
}

// Build, sign and Base64-URL encode a kind-24242 authorization token. Used by
// the `--make-token` CLI so the server can be exercised end-to-end.
mint_token :: proc(
	seckey_hex, verb, hash: string,
	exp, now: i64,
	allocator := context.allocator,
) -> (string, bool) {
	context.allocator = allocator

	sk: [32]u8
	if !hex_decode(sk[:], seckey_hex) {
		return "", false
	}
	pk, pok := schnorr_pubkey(sk[:])
	if !pok {
		return "", false
	}

	buf: [24]u8
	tags := make([dynamic][]string)
	append(&tags, []string{"t", verb})
	append(&tags, []string{"expiration", strings.clone(strconv.write_int(buf[:], exp, 10))})
	if hash != "" {
		append(&tags, []string{"x", hash})
	}

	ev := Event {
		pubkey     = hex_string(pk[:]),
		created_at = now,
		kind       = 24242,
		content    = "sakura authorization",
		tags       = tags[:],
	}
	id := event_id(ev)
	ev.id = hex_string(id[:])
	sig, sok := schnorr_sign(sk[:], id[:])
	if !sok {
		return "", false
	}
	ev.sig = hex_string(sig[:])

	full := serialize_full_event(ev)
	return base64url_encode(transmute([]u8)full, allocator), true
}

@(private = "file")
serialize_full_event :: proc(ev: Event) -> string {
	b := strings.builder_make()
	buf: [24]u8
	strings.write_string(&b, "{\"id\":")
	json_write_string(&b, ev.id)
	strings.write_string(&b, ",\"pubkey\":")
	json_write_string(&b, ev.pubkey)
	strings.write_string(&b, ",\"created_at\":")
	strings.write_string(&b, strconv.write_int(buf[:], ev.created_at, 10))
	strings.write_string(&b, ",\"kind\":")
	strings.write_string(&b, strconv.write_int(buf[:], ev.kind, 10))
	strings.write_string(&b, ",\"tags\":[")
	for tag, ti in ev.tags {
		if ti > 0 {
			strings.write_byte(&b, ',')
		}
		strings.write_byte(&b, '[')
		for item, ii in tag {
			if ii > 0 {
				strings.write_byte(&b, ',')
			}
			json_write_string(&b, item)
		}
		strings.write_byte(&b, ']')
	}
	strings.write_string(&b, "],\"content\":")
	json_write_string(&b, ev.content)
	strings.write_string(&b, ",\"sig\":")
	json_write_string(&b, ev.sig)
	strings.write_byte(&b, '}')
	return strings.to_string(b)
}

// --- BUD-11 authorization -------------------------------------------------

Auth_Result :: struct {
	ok:     bool,
	pubkey: string,
	reason: string,
}

// Decode the token of a `Nostr <base64>` header into an event (whose tags may
// live in scratch); reason is the refusal when ok is false.
@(private = "file")
auth_event :: proc(
	header: string,
	scratch: ^Tag_Scratch,
	allocator := context.allocator,
) -> (ev: Event, reason: string, ok: bool) {
	if len(header) < 6 || !ascii_ieq(header[:6], "nostr ") {
		return {}, "missing Nostr authorization", false
	}
	token := strings.trim_space(header[6:])

	raw, dok := base64_decode(token, allocator)
	if !dok {
		return {}, "invalid base64 authorization", false
	}
	err: Parse_Error
	ev, err = event_parse(string(raw), scratch)
	switch err {
	case .None:
	case .Json:
		return {}, "invalid authorization event json", false
	case .Malformed:
		return {}, "malformed authorization event", false
	}
	return ev, "", true
}

// Cheap structural pre-check of an authorization header WITHOUT verifying the
// signature (which requires the blob hash). Used by /mirror to reject obviously
// invalid tokens before downloading a remote blob. Checks: scheme, base64,
// JSON, kind==24242, not-future, expiration present and in the future, and the
// `t` verb tag. Returns (reason, ok). The full validate_auth still runs after
// the hash is known.
auth_precheck :: proc(
	header: string,
	verb: string,
	now: i64,
	domain: string,
	allocator := context.allocator,
) -> (reason: string, ok: bool) {
	context.allocator = allocator

	scratch: Tag_Scratch = ---
	ev, why, eok := auth_event(header, &scratch, allocator)
	if !eok {
		return why, false
	}
	if ev.kind != 24242 {
		return "authorization event must be kind 24242", false
	}
	if ev.created_at > now + 300 {
		return "authorization created_at is in the future", false
	}
	exp, has_exp := tag_value(ev, "expiration")
	if !has_exp {
		return "authorization missing expiration tag", false
	}
	exp_ts, exp_ok := strconv.parse_i64(exp)
	if !exp_ok || exp_ts <= now {
		return "authorization token expired", false
	}
	t, has_t := tag_value(ev, "t")
	if !has_t || t != verb {
		return "authorization verb mismatch", false
	}
	if domain != "" && !server_scoped(ev, domain) {
		return "authorization not scoped to this server", false
	}
	return "", true
}

// `server` scoping: if any server tag is present, our domain must appear.
@(private = "file")
server_scoped :: proc(ev: Event, domain: string) -> bool {
	has_server := false
	for tag in ev.tags {
		if len(tag) >= 2 && tag[0] == "server" {
			has_server = true
			if ascii_ieq(tag[1], domain) || ascii_ieq(strip_scheme(tag[1]), domain) {
				return true
			}
		}
	}
	return !has_server
}

// Validate a `Authorization: Nostr <base64url>` header against BUD-11 rules.
//   verb:      required `t` tag value (upload/delete/list/get/media)
//   hash:      blob hash the action targets, or "" if none
//   require_x: whether a matching `x` tag is mandatory
//   domain:    this server's domain for `server` tag scoping ("" disables it)
validate_auth :: proc(
	header: string,
	verb: string,
	hash: string,
	require_x: bool,
	now: i64,
	domain: string,
	allocator := context.allocator,
) -> Auth_Result {
	context.allocator = allocator

	scratch: Tag_Scratch = ---
	ev, reason, ok := auth_event(header, &scratch, allocator)
	if !ok {
		return {reason = reason}
	}
	if ev.kind != 24242 {
		return {reason = "authorization event must be kind 24242"}
	}
	if ev.created_at > now + 300 {
		return {reason = "authorization created_at is in the future"}
	}

	exp, has_exp := tag_value(ev, "expiration")
	if !has_exp {
		return {reason = "authorization missing expiration tag"}
	}
	exp_ts, exp_ok := strconv.parse_i64(exp)
	if !exp_ok || exp_ts <= now {
		return {reason = "authorization token expired"}
	}

	t, has_t := tag_value(ev, "t")
	if !has_t || t != verb {
		return {reason = "authorization verb mismatch"}
	}

	if domain != "" && !server_scoped(ev, domain) {
		return {reason = "authorization not scoped to this server"}
	}

	// `x` scoping.
	if hash != "" {
		has_x := false
		matched := false
		for tag in ev.tags {
			if len(tag) >= 2 && tag[0] == "x" {
				has_x = true
				if tag[1] == hash {
					matched = true
				}
			}
		}
		if require_x && !matched {
			return {reason = "authorization missing matching x tag"}
		}
		if has_x && !matched {
			return {reason = "authorization x tag does not match blob"}
		}
	}

	// Finally, the cryptographic check (most expensive — done last).
	if !event_verify(ev) {
		return {reason = "invalid authorization signature"}
	}

	return {ok = true, pubkey = ev.pubkey}
}

@(private = "file")
ascii_ieq :: proc(a, b: string) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {ca += 32}
		if cb >= 'A' && cb <= 'Z' {cb += 32}
		if ca != cb {
			return false
		}
	}
	return true
}

@(private = "file")
strip_scheme :: proc(s: string) -> string {
	if strings.has_prefix(s, "https://") {
		return s[8:]
	}
	if strings.has_prefix(s, "http://") {
		return s[7:]
	}
	return s
}
