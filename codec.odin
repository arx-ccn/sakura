package sakura

// Hex and Base64-URL codecs. No allocations on the decode paths that matter for
// request handling — callers pass in destination buffers.

@(private = "file")
HEX_LOWER := "0123456789abcdef"

hex_encode :: proc(dst: []u8, src: []u8) {
	#no_bounds_check for b, i in src {
		dst[i * 2 + 0] = HEX_LOWER[b >> 4]
		dst[i * 2 + 1] = HEX_LOWER[b & 0x0f]
	}
}

// Encode to a freshly allocated string (used when building JSON responses).
hex_string :: proc(src: []u8, allocator := context.allocator) -> string {
	buf := make([]u8, len(src) * 2, allocator)
	hex_encode(buf, src)
	return string(buf)
}

@(private = "file")
hex_val :: proc "contextless" (c: u8) -> (v: u8, ok: bool) {
	switch c {
	case '0' ..= '9': return c - '0', true
	case 'a' ..= 'f': return c - 'a' + 10, true
	case 'A' ..= 'F': return c - 'A' + 10, true
	}
	return 0, false
}

// Decode hex into dst. Returns false on odd length, wrong size, or bad nibble.
hex_decode :: proc "contextless" (dst: []u8, src: string) -> bool {
	if len(src) != len(dst) * 2 {
		return false
	}
	#no_bounds_check for i in 0 ..< len(dst) {
		hi := hex_val(src[i * 2]) or_return
		lo := hex_val(src[i * 2 + 1]) or_return
		dst[i] = (hi << 4) | lo
	}
	return true
}

// True if s is exactly n lowercase hex characters. Blossom hashes are required
// to be lowercase hex; we validate strictly so the on-disk path is predictable.
is_lower_hex :: proc "contextless" (s: string, n: int) -> bool {
	if len(s) != n {
		return false
	}
	for i in 0 ..< len(s) {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

@(private = "file")
B64URL := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// Encode to Base64-URL without padding (the encoding BUD-11 tokens use).
base64url_encode :: proc(src: []u8, allocator := context.allocator) -> string {
	out := make([dynamic]u8, 0, (len(src) * 4 + 2) / 3, allocator)
	i := 0
	for i + 3 <= len(src) {
		n := (u32(src[i]) << 16) | (u32(src[i + 1]) << 8) | u32(src[i + 2])
		append(&out, B64URL[(n >> 18) & 63], B64URL[(n >> 12) & 63], B64URL[(n >> 6) & 63], B64URL[n & 63])
		i += 3
	}
	rem := len(src) - i
	if rem == 1 {
		n := u32(src[i]) << 16
		append(&out, B64URL[(n >> 18) & 63], B64URL[(n >> 12) & 63])
	} else if rem == 2 {
		n := (u32(src[i]) << 16) | (u32(src[i + 1]) << 8)
		append(&out, B64URL[(n >> 18) & 63], B64URL[(n >> 12) & 63], B64URL[(n >> 6) & 63])
	}
	return string(out[:])
}

@(private = "file")
b64_val :: proc "contextless" (c: u8) -> (v: u8, ok: bool) {
	switch c {
	case 'A' ..= 'Z': return c - 'A', true
	case 'a' ..= 'z': return c - 'a' + 26, true
	case '0' ..= '9': return c - '0' + 52, true
	case '+', '-':    return 62, true // '-' for URL-safe, '+' for standard
	case '/', '_':    return 63, true // '_' for URL-safe, '/' for standard
	}
	return 0, false
}

// Decode Base64 (standard or URL-safe, with or without padding) into a fresh
// buffer. Nostr authorization tokens are required to be Base64-URL without
// padding, but we accept the variants to be liberal in what we accept.
base64_decode :: proc(src: string, allocator := context.allocator) -> (out: []u8, ok: bool) {
	// Strip any trailing '=' padding for the length calculation.
	n := len(src)
	for n > 0 && src[n - 1] == '=' {
		n -= 1
	}
	out_len := n * 6 / 8
	buf := make([dynamic]u8, 0, out_len, allocator)

	acc: u32 = 0
	bits: u32 = 0
	for i in 0 ..< n {
		v := b64_val(src[i]) or_return
		acc = (acc << 6) | u32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			append(&buf, u8(acc >> bits))
		}
	}
	return buf[:], true
}
