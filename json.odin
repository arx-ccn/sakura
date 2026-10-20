package sakura

import "base:intrinsics"
import "core:simd"
import "core:strconv"
import "core:strings"

// Minimal JSON parser, sufficient for Nostr events and the mirror request body.
// `null` is represented by a nil union value. Numbers are f64 (Nostr's
// created_at and kind both fit exactly).
//
// LIFETIME CONTRACT: string values and map keys in the returned Json tree may
// alias the input string `s` passed to `json_parse` (zero-copy fast path for
// strings without escape sequences). The input must therefore outlive the
// parsed tree. Only strings containing backslash escapes are freshly
// allocated. All current callers satisfy this: they parse from per-request
// arena/connection buffers that are not freed until the request completes.

Json :: union {
	bool,
	f64,
	string,
	[]Json,
	map[string]Json,
}

// Read position in a JSON text. json_parse walks it internally; callers that
// know their schema (Nostr events) drive it directly with json_skip_ws,
// json_string, json_int and json_value, skipping the tree and its maps.
Json_Cursor :: struct {
	s:   string,
	pos: int,
}

@(private = "file") QUOTE16 :: #simd[16]u8{0 ..< 16 = '"'}
@(private = "file") BACKSLASH16 :: #simd[16]u8{0 ..< 16 = '\\'}

json_skip_ws :: proc(p: ^Json_Cursor) {
	for p.pos < len(p.s) {
		switch p.s[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos += 1
		case:
			return
		}
	}
}

json_parse :: proc(s: string, allocator := context.allocator) -> (Json, bool) {
	context.allocator = allocator
	p := Json_Cursor{s, 0}
	json_skip_ws(&p)
	v, ok := json_value(&p)
	if !ok {
		return nil, false
	}
	json_skip_ws(&p)
	return v, true
}

json_value :: proc(p: ^Json_Cursor) -> (Json, bool) {
	json_skip_ws(p)
	if p.pos >= len(p.s) {
		return nil, false
	}
	switch p.s[p.pos] {
	case '{':
		return parse_object(p)
	case '[':
		return parse_array(p)
	case '"':
		str, ok := json_string(p)
		return str, ok
	case 't':
		if has_lit(p, "true") {p.pos += 4; return true, true}
		return nil, false
	case 'f':
		if has_lit(p, "false") {p.pos += 5; return false, true}
		return nil, false
	case 'n':
		if has_lit(p, "null") {p.pos += 4; return nil, true}
		return nil, false
	case:
		return parse_number(p)
	}
}

// Match a literal at the current position without constructing a substring.
@(private = "file")
has_lit :: proc(p: ^Json_Cursor, lit: string) -> bool {
	if p.pos + len(lit) > len(p.s) {
		return false
	}
	for i in 0 ..< len(lit) {
		if p.s[p.pos + i] != lit[i] {
			return false
		}
	}
	return true
}

@(private = "file")
parse_number :: proc(p: ^Json_Cursor) -> (Json, bool) {
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if is_number_byte(c) {
			p.pos += 1
		} else {
			break
		}
	}
	if p.pos == start {
		return nil, false
	}
	v, ok := strconv.parse_f64(p.s[start:p.pos])
	if !ok {
		return nil, false
	}
	return v, true
}

// A JSON number truncated to i64, exactly as i64(<json_value's f64>), but
// without strconv for plain integers short enough to be exact in an f64.
json_int :: proc(p: ^Json_Cursor) -> (i64, bool) {
	start := p.pos
	neg := p.pos < len(p.s) && p.s[p.pos] == '-'
	if neg {
		p.pos += 1
	}
	v: i64
	digits := 0
	for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		v = v * 10 + i64(p.s[p.pos] - '0')
		p.pos += 1
		digits += 1
	}
	end_ok := p.pos >= len(p.s) || !is_number_byte(p.s[p.pos])
	if digits > 0 && digits <= 15 && end_ok {
		return neg ? -v : v, true
	}
	p.pos = start
	f, ok := parse_number(p)
	if !ok {
		return 0, false
	}
	return i64(f.(f64)), true
}

@(private = "file")
is_number_byte :: proc(c: u8) -> bool {
	return (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E'
}

json_string :: proc(p: ^Json_Cursor) -> (string, bool) {
	if p.s[p.pos] != '"' {
		return "", false
	}
	p.pos += 1
	start := p.pos

	// Zero-copy fast path: scan to the closing quote. If no backslash escape
	// occurs, the string is a verbatim slice of the input (no allocation).
	// Control characters are tolerated, matching the builder path's behavior.
	// Whole 16-byte chunks free of '"' and '\' are skipped first.
	#no_bounds_check for p.pos + 16 <= len(p.s) {
		v := intrinsics.unaligned_load((^#simd[16]u8)(&raw_data(p.s)[p.pos]))
		hit := simd.lanes_eq(v, QUOTE16) | simd.lanes_eq(v, BACKSLASH16)
		if simd.reduce_or(hit) != 0 {
			break
		}
		p.pos += 16
	}
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == '"' {
			s := p.s[start:p.pos]
			p.pos += 1
			return s, true
		}
		if c == '\\' {
			break
		}
		p.pos += 1
	}
	if p.pos >= len(p.s) {
		return "", false
	}

	// Slow path: an escape sequence is present. Replay from `start` through a
	// builder so the prefix already scanned is included.
	b := strings.builder_make()
	strings.write_string(&b, p.s[start:p.pos])
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		switch c {
		case '"':
			p.pos += 1
			return strings.to_string(b), true
		case '\\':
			p.pos += 1
			if p.pos >= len(p.s) {
				return "", false
			}
			e := p.s[p.pos]
			p.pos += 1
			switch e {
			case '"':  strings.write_byte(&b, '"')
			case '\\': strings.write_byte(&b, '\\')
			case '/':  strings.write_byte(&b, '/')
			case 'n':  strings.write_byte(&b, '\n')
			case 'r':  strings.write_byte(&b, '\r')
			case 't':  strings.write_byte(&b, '\t')
			case 'b':  strings.write_byte(&b, '\b')
			case 'f':  strings.write_byte(&b, '\f')
			case 'u':
				cp, ok := parse_hex4(p)
				if !ok {
					return "", false
				}
				// Handle UTF-16 surrogate pairs.
				if cp >= 0xD800 && cp <= 0xDBFF {
					if p.pos + 1 < len(p.s) && p.s[p.pos] == '\\' && p.s[p.pos + 1] == 'u' {
						p.pos += 2
						lo, ok2 := parse_hex4(p)
						if !ok2 || lo < 0xDC00 || lo > 0xDFFF {
							return "", false
						}
						cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
					}
				}
				write_utf8(&b, cp)
			case:
				return "", false
			}
		case:
			strings.write_byte(&b, c)
			p.pos += 1
		}
	}
	return "", false
}

@(private = "file")
parse_hex4 :: proc(p: ^Json_Cursor) -> (u32, bool) {
	if p.pos + 4 > len(p.s) {
		return 0, false
	}
	v: u32 = 0
	for _ in 0 ..< 4 {
		c := p.s[p.pos]
		d: u32
		switch {
		case c >= '0' && c <= '9': d = u32(c - '0')
		case c >= 'a' && c <= 'f': d = u32(c - 'a' + 10)
		case c >= 'A' && c <= 'F': d = u32(c - 'A' + 10)
		case: return 0, false
		}
		v = (v << 4) | d
		p.pos += 1
	}
	return v, true
}

@(private = "file")
write_utf8 :: proc(b: ^strings.Builder, cp: u32) {
	switch {
	case cp < 0x80:
		strings.write_byte(b, u8(cp))
	case cp < 0x800:
		strings.write_byte(b, u8(0xC0 | (cp >> 6)))
		strings.write_byte(b, u8(0x80 | (cp & 0x3F)))
	case cp < 0x10000:
		strings.write_byte(b, u8(0xE0 | (cp >> 12)))
		strings.write_byte(b, u8(0x80 | ((cp >> 6) & 0x3F)))
		strings.write_byte(b, u8(0x80 | (cp & 0x3F)))
	case:
		strings.write_byte(b, u8(0xF0 | (cp >> 18)))
		strings.write_byte(b, u8(0x80 | ((cp >> 12) & 0x3F)))
		strings.write_byte(b, u8(0x80 | ((cp >> 6) & 0x3F)))
		strings.write_byte(b, u8(0x80 | (cp & 0x3F)))
	}
}

@(private = "file")
parse_array :: proc(p: ^Json_Cursor) -> (Json, bool) {
	p.pos += 1 // '['
	arr := make([dynamic]Json)
	json_skip_ws(p)
	if p.pos < len(p.s) && p.s[p.pos] == ']' {
		p.pos += 1
		return arr[:], true
	}
	for {
		v, ok := json_value(p)
		if !ok {
			return nil, false
		}
		append(&arr, v)
		json_skip_ws(p)
		if p.pos >= len(p.s) {
			return nil, false
		}
		switch p.s[p.pos] {
		case ',': p.pos += 1
		case ']': p.pos += 1; return arr[:], true
		case: return nil, false
		}
	}
}

@(private = "file")
parse_object :: proc(p: ^Json_Cursor) -> (Json, bool) {
	p.pos += 1 // '{'
	obj := make(map[string]Json)
	json_skip_ws(p)
	if p.pos < len(p.s) && p.s[p.pos] == '}' {
		p.pos += 1
		return obj, true
	}
	for {
		json_skip_ws(p)
		if p.pos >= len(p.s) || p.s[p.pos] != '"' {
			return nil, false
		}
		key, ok := json_string(p)
		if !ok {
			return nil, false
		}
		json_skip_ws(p)
		if p.pos >= len(p.s) || p.s[p.pos] != ':' {
			return nil, false
		}
		p.pos += 1
		v, ok2 := json_value(p)
		if !ok2 {
			return nil, false
		}
		obj[key] = v
		json_skip_ws(p)
		if p.pos >= len(p.s) {
			return nil, false
		}
		switch p.s[p.pos] {
		case ',': p.pos += 1
		case '}': p.pos += 1; return obj, true
		case: return nil, false
		}
	}
}

// --- serialization --------------------------------------------------------

// Write a JSON string with the exact escaping NIP-01 mandates for event
// serialization. Only these characters are escaped; everything else, including
// all multi-byte UTF-8, is emitted verbatim.
json_write_string :: proc(b: ^strings.Builder, s: string) {
	strings.write_byte(b, '"')
	for i in 0 ..< len(s) {
		c := s[i]
		switch c {
		case '"':  strings.write_string(b, "\\\"")
		case '\\': strings.write_string(b, "\\\\")
		case '\n': strings.write_string(b, "\\n")
		case '\r': strings.write_string(b, "\\r")
		case '\t': strings.write_string(b, "\\t")
		case '\b': strings.write_string(b, "\\b")
		case '\f': strings.write_string(b, "\\f")
		case:
			if c < 0x20 {
				hexd := "0123456789abcdef"
				strings.write_string(b, "\\u00")
				strings.write_byte(b, hexd[c >> 4])
				strings.write_byte(b, hexd[c & 0x0f])
			} else {
				strings.write_byte(b, c)
			}
		}
	}
	strings.write_byte(b, '"')
}
