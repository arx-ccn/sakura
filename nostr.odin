package sakura

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

// Extract a typed Event from a parsed JSON object. Returns ok=false on any
// structural problem (wrong types, missing fields).
event_from_json :: proc(j: Json) -> (ev: Event, ok: bool) {
	obj, is_obj := j.(map[string]Json)
	if !is_obj {
		return {}, false
	}

	ev.id = get_string(obj, "id") or_return
	ev.pubkey = get_string(obj, "pubkey") or_return
	ev.sig = get_string(obj, "sig") or_return
	ev.content = get_string(obj, "content") or_return
	ev.created_at = i64(get_number(obj, "created_at") or_return)
	ev.kind = i64(get_number(obj, "kind") or_return)

	tags_json, has_tags := obj["tags"]
	if !has_tags {
		return {}, false
	}
	tags_arr, is_arr := tags_json.([]Json)
	if !is_arr {
		return {}, false
	}
	tags := make([dynamic][]string)
	for t in tags_arr {
		inner, ok2 := t.([]Json)
		if !ok2 {
			return {}, false
		}
		row := make([dynamic]string)
		for item in inner {
			s, ok3 := item.(string)
			if !ok3 {
				return {}, false
			}
			append(&row, s)
		}
		append(&tags, row[:])
	}
	ev.tags = tags[:]
	return ev, true
}

@(private = "file")
get_string :: proc(obj: map[string]Json, key: string) -> (string, bool) {
	v, ok := obj[key]
	if !ok {
		return "", false
	}
	s, is_s := v.(string)
	return s, is_s
}

@(private = "file")
get_number :: proc(obj: map[string]Json, key: string) -> (f64, bool) {
	v, ok := obj[key]
	if !ok {
		return 0, false
	}
	n, is_n := v.(f64)
	return n, is_n
}

// Serialize the event per NIP-01: [0,<pubkey>,<created_at>,<kind>,<tags>,<content>]
@(private = "file")
serialize_for_id :: proc(ev: Event, allocator := context.allocator) -> string {
	b := strings.builder_make(allocator)
	strings.write_string(&b, "[0,")
	json_write_string(&b, ev.pubkey)
	strings.write_byte(&b, ',')
	buf: [32]u8
	strings.write_string(&b, strconv.itoa(buf[:], int(ev.created_at)))
	strings.write_byte(&b, ',')
	strings.write_string(&b, strconv.itoa(buf[:], int(ev.kind)))
	strings.write_byte(&b, ',')
	// tags
	strings.write_byte(&b, '[')
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
	strings.write_byte(&b, ']')
	strings.write_byte(&b, ',')
	json_write_string(&b, ev.content)
	strings.write_byte(&b, ']')
	return strings.to_string(b)
}

// Recompute the event id and verify it matches the claimed id, then verify the
// Schnorr signature over that id.
event_verify :: proc(ev: Event) -> bool {
	if !is_lower_hex(ev.id, 64) || !is_lower_hex(ev.pubkey, 64) || !is_lower_hex(ev.sig, 128) {
		return false
	}

	serial := serialize_for_id(ev)
	computed := sha256(transmute([]u8)serial)

	claimed: [32]u8
	if !hex_decode(claimed[:], ev.id) {
		return false
	}
	if computed != claimed {
		return false
	}

	pubkey: [32]u8
	sig: [64]u8
	if !hex_decode(pubkey[:], ev.pubkey) || !hex_decode(sig[:], ev.sig) {
		return false
	}
	return schnorr_verify(pubkey[:], computed[:], sig[:])
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

	buf1, buf2: [24]u8
	tags := make([dynamic][]string)
	append(&tags, []string{"t", verb})
	append(&tags, []string{"expiration", strings.clone(strconv.itoa(buf1[:], int(exp)))})
	if hash != "" {
		append(&tags, []string{"x", hash})
	}
	_ = buf2

	ev := Event {
		pubkey     = hex_string(pk[:]),
		created_at = now,
		kind       = 24242,
		content    = "sakura authorization",
		tags       = tags[:],
	}
	serial := serialize_for_id(ev)
	id := sha256(transmute([]u8)serial)
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
	strings.write_string(&b, strconv.itoa(buf[:], int(ev.created_at)))
	strings.write_string(&b, ",\"kind\":")
	strings.write_string(&b, strconv.itoa(buf[:], int(ev.kind)))
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

	if len(header) < 6 || !ascii_ieq(header[:6], "nostr ") {
		return "missing Nostr authorization", false
	}
	token := strings.trim_space(header[6:])

	raw, dok := base64_decode(token, allocator)
	if !dok {
		return "invalid base64 authorization", false
	}
	j, jok := json_parse(string(raw), allocator)
	if !jok {
		return "invalid authorization event json", false
	}
	ev, eok := event_from_json(j)
	if !eok {
		return "malformed authorization event", false
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
	if domain != "" {
		has_server := false
		matched := false
		for tag in ev.tags {
			if len(tag) >= 2 && tag[0] == "server" {
				has_server = true
				if ascii_ieq(tag[1], domain) || ascii_ieq(strip_scheme(tag[1]), domain) {
					matched = true
				}
			}
		}
		if has_server && !matched {
			return "authorization not scoped to this server", false
		}
	}
	return "", true
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

	// Scheme must be "Nostr " (case-insensitive).
	if len(header) < 6 || !ascii_ieq(header[:6], "nostr ") {
		return {reason = "missing Nostr authorization"}
	}
	token := strings.trim_space(header[6:])

	raw, ok := base64_decode(token, allocator)
	if !ok {
		return {reason = "invalid base64 authorization"}
	}

	j, jok := json_parse(string(raw), allocator)
	if !jok {
		return {reason = "invalid authorization event json"}
	}
	ev, eok := event_from_json(j)
	if !eok {
		return {reason = "malformed authorization event"}
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

	// `server` scoping: if present, our domain must appear.
	if domain != "" {
		has_server := false
		matched := false
		for tag in ev.tags {
			if len(tag) >= 2 && tag[0] == "server" {
				has_server = true
				if ascii_ieq(tag[1], domain) || ascii_ieq(strip_scheme(tag[1]), domain) {
					matched = true
				}
			}
		}
		if has_server && !matched {
			return {reason = "authorization not scoped to this server"}
		}
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
