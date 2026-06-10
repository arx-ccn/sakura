package sakura

// Dependency-free SHA-256 (FIPS 180-4).
//
// The hot path here is the compression function. Hashing an uploaded blob is
// the single most expensive per-request operation besides the signature check.
//
// Two block implementations live here:
//
//   * sha256_block_simd  — uses the x86 SHA extensions (SHA-NI:
//     sha256rnds2 / sha256msg1 / sha256msg2). ~10x the scalar version.
//   * sha256_block_scalar — a fully unrolled FIPS reference compression
//     function with byte-swap loads. Used everywhere SHA-NI is unavailable.
//
// At first use we probe CPUID (leaf 7, EBX bit 29) once and cache the result;
// every block then dispatches through the cached flag. Everything is
// contextless and allocation-free so the callers (themselves contextless)
// can use it from any thread without a context.

import "base:intrinsics"
import x86 "core:simd/x86"

Sha256_Ctx :: struct {
	state:   [8]u32,
	buf:     [64]u8,
	buf_len: int,
	total:   u64, // total bytes absorbed
}

@(private = "file")
SHA256_K := [64]u32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

@(private = "file")
rotr :: #force_inline proc "contextless" (x: u32, n: u32) -> u32 {
	return (x >> n) | (x << (32 - n))
}

sha256_init :: proc "contextless" (ctx: ^Sha256_Ctx) {
	ctx.state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	ctx.buf_len = 0
	ctx.total = 0
}

// --- CPU feature dispatch ----------------------------------------------------

// 0 = unprobed, 1 = SHA-NI present, 2 = absent. Probed once, then cached.
// A racing double-probe is harmless: CPUID is pure, so every writer stores the
// same value.
@(private = "file")
g_sha_ni_state: u32 = 0

@(private = "file")
detect_sha_ni :: proc "contextless" () -> bool {
	when ODIN_ARCH == .amd64 || ODIN_ARCH == .i386 {
		max_id, _, _, _ := intrinsics.x86_cpuid(0, 0)
		if max_id < 7 {
			return false
		}
		_, ebx7, _, _ := intrinsics.x86_cpuid(7, 0)
		return (ebx7 & (1 << 29)) != 0
	} else {
		return false
	}
}

@(private = "file")
have_sha_ni :: #force_inline proc "contextless" () -> bool {
	s := intrinsics.atomic_load_explicit(&g_sha_ni_state, .Relaxed)
	if s == 0 {
		s = detect_sha_ni() ? 1 : 2
		intrinsics.atomic_store_explicit(&g_sha_ni_state, s, .Relaxed)
	}
	return s == 1
}

@(private = "file")
sha256_block :: #force_inline proc "contextless" (state: ^[8]u32, block: []u8) {
	when ODIN_ARCH == .amd64 || ODIN_ARCH == .i386 {
		if have_sha_ni() {
			sha256_block_simd(state, block)
			return
		}
	}
	sha256_block_scalar(state, block)
}

// --- Scalar (portable fallback) ---------------------------------------------

// Load a big-endian u32 from an unaligned offset via a 4-byte read + byte_swap,
// instead of four shift/or assembly. The compiler folds this into a single
// `movbe`/`bswap` per word.
@(private = "file")
load_be32 :: #force_inline proc "contextless" (b: []u8, #any_int off: int) -> u32 {
	v := intrinsics.unaligned_load((^u32)(&b[off]))
	return intrinsics.byte_swap(v)
}

@(private = "file")
sha256_block_scalar :: proc "contextless" (state: ^[8]u32, block: []u8) {
	w: [64]u32 = ---
	#no_bounds_check {
		w[0]  = load_be32(block, 0);  w[1]  = load_be32(block, 4)
		w[2]  = load_be32(block, 8);  w[3]  = load_be32(block, 12)
		w[4]  = load_be32(block, 16); w[5]  = load_be32(block, 20)
		w[6]  = load_be32(block, 24); w[7]  = load_be32(block, 28)
		w[8]  = load_be32(block, 32); w[9]  = load_be32(block, 36)
		w[10] = load_be32(block, 40); w[11] = load_be32(block, 44)
		w[12] = load_be32(block, 48); w[13] = load_be32(block, 52)
		w[14] = load_be32(block, 56); w[15] = load_be32(block, 60)

		#unroll for i in 16 ..< 64 {
			s0 := rotr(w[i - 15], 7) ~ rotr(w[i - 15], 18) ~ (w[i - 15] >> 3)
			s1 := rotr(w[i - 2], 17) ~ rotr(w[i - 2], 19) ~ (w[i - 2] >> 10)
			w[i] = w[i - 16] + s0 + w[i - 7] + s1
		}

		a := state[0]; b := state[1]; c := state[2]; d := state[3]
		e := state[4]; f := state[5]; g := state[6]; h := state[7]

		// Fully unrolled rounds. Rather than shifting the eight working
		// variables every round (h=g; g=f; ...), the round body is expanded
		// inline and the variable names rotate at the source level, so each
		// stays in a fixed register for the whole block.
		round :: #force_inline proc "contextless" (
			a, b, c: u32, d: ^u32, e, f, g: u32, h: ^u32, k, w: u32,
		) {
			s1 := rotr(e, 6) ~ rotr(e, 11) ~ rotr(e, 25)
			ch := (e & f) ~ (~e & g)
			t1 := h^ + s1 + ch + k + w
			s0 := rotr(a, 2) ~ rotr(a, 13) ~ rotr(a, 22)
			maj := (a & b) ~ (a & c) ~ (b & c)
			d^ += t1
			h^ = t1 + s0 + maj
		}

		#unroll for g8 in 0 ..< 8 {
			i := g8 * 8
			round(a, b, c, &d, e, f, g, &h, SHA256_K[i + 0], w[i + 0])
			round(h, a, b, &c, d, e, f, &g, SHA256_K[i + 1], w[i + 1])
			round(g, h, a, &b, c, d, e, &f, SHA256_K[i + 2], w[i + 2])
			round(f, g, h, &a, b, c, d, &e, SHA256_K[i + 3], w[i + 3])
			round(e, f, g, &h, a, b, c, &d, SHA256_K[i + 4], w[i + 4])
			round(d, e, f, &g, h, a, b, &c, SHA256_K[i + 5], w[i + 5])
			round(c, d, e, &f, g, h, a, &b, SHA256_K[i + 6], w[i + 6])
			round(b, c, d, &e, f, g, h, &a, SHA256_K[i + 7], w[i + 7])
		}

		state[0] += a; state[1] += b; state[2] += c; state[3] += d
		state[4] += e; state[5] += f; state[6] += g; state[7] += h
	}
}

// --- SHA-NI (x86 SHA extensions) --------------------------------------------
//
// Intel's canonical single-block sequence. The eight working words are held in
// two 128-bit registers in the order sha256rnds2 expects:
//
//   STATE0 = { A, B, E, F }   (dword3=A .. dword0=F, big-endian-of-register)
//   STATE1 = { C, D, G, H }
//
// We assemble those once from the incoming state, run all 64 rounds (two per
// sha256rnds2, with sha256msg1/msg2 extending the 16-word window in four
// __m128i lanes), then add the result back into the saved state. K constants
// are pre-added to the message words before each rnds2 pair.

// K as little-endian dword pairs for _mm_set_epi32(e3,e2,e1,e0): e0 is lane 0.
// For a group starting at round i we need lanes {K[i],K[i+1],K[i+2],K[i+3]}
// with K[i] in lane0, so call _mm_set_epi32(K[i+3], K[i+2], K[i+1], K[i+0]).
@(private = "file")
@(enable_target_feature = "sse2")
kvec :: #force_inline proc "contextless" (#any_int i: int) -> x86.__m128i {
	#no_bounds_check {
		return x86._mm_set_epi32(
			i32(SHA256_K[i + 3]), i32(SHA256_K[i + 2]),
			i32(SHA256_K[i + 1]), i32(SHA256_K[i + 0]),
		)
	}
}

// Two compression rounds via sha256rnds2 (low dwords of msg = K+W for the two
// rounds; high dwords for the next two are selected by the 0x0E shuffle).
@(private = "file")
@(enable_target_feature = "sse2,sha")
sha_do2 :: #force_inline proc "contextless" (s0, s1: ^x86.__m128i, msg: x86.__m128i) {
	s1^ = x86._mm_sha256rnds2_epu32(s1^, s0^, msg)
	hi := x86._mm_shuffle_epi32(msg, 0x0E)
	s0^ = x86._mm_sha256rnds2_epu32(s0^, s1^, hi)
}

// One 4-round group with full schedule maintenance: extend lane *b via msg2,
// run two rnds2, and prime lane *d via msg1. Lanes rotate one slot per group.
@(private = "file")
@(enable_target_feature = "sse2,ssse3,sha")
sched :: #force_inline proc "contextless" (
	a, b, c, d: ^x86.__m128i, #any_int kbase: int, s0, s1: ^x86.__m128i,
) {
	msg := x86._mm_add_epi32(a^, kvec(kbase))
	tmp := x86._mm_alignr_epi8(a^, d^, 4)
	b^ = x86._mm_add_epi32(b^, tmp)
	b^ = x86._mm_sha256msg2_epu32(b^, a^)
	sha_do2(s0, s1, msg)
	d^ = x86._mm_sha256msg1_epu32(d^, a^)
}

@(private = "file")
@(enable_target_feature = "sse2,ssse3,sse4.1,sha")
sha256_block_simd :: proc "contextless" (state: ^[8]u32, block: []u8) {
	#no_bounds_check {
		// Byte-swap mask: turns a 16-byte big-endian message chunk into four
		// host-endian dwords.
		mask := x86._mm_set_epi64x(0x0c0d0e0f_08090a0b, 0x04050607_00010203)

		abcd := x86._mm_loadu_si128(transmute(^x86.__m128i)(&state[0])) // A B C D (lane0=A)
		efgh := x86._mm_loadu_si128(transmute(^x86.__m128i)(&state[4])) // E F G H (lane0=E)

		// Build STATE0={A,B,E,F}, STATE1={C,D,G,H} (Intel's working order).
		t := x86._mm_shuffle_epi32(abcd, 0xB1)        // C D A B
		u := x86._mm_shuffle_epi32(efgh, 0x1B)        // H G F E
		state0 := x86._mm_alignr_epi8(t, u, 8)        // A B E F
		state1 := x86._mm_blend_epi16(u, t, 0xF0)     // C D G H

		save0 := state0
		save1 := state1

		// Load + byte-swap the 4 message lanes.
		m0 := x86._mm_shuffle_epi8(x86._mm_loadu_si128(transmute(^x86.__m128i)(&block[0])), mask)
		m1 := x86._mm_shuffle_epi8(x86._mm_loadu_si128(transmute(^x86.__m128i)(&block[16])), mask)
		m2 := x86._mm_shuffle_epi8(x86._mm_loadu_si128(transmute(^x86.__m128i)(&block[32])), mask)
		m3 := x86._mm_shuffle_epi8(x86._mm_loadu_si128(transmute(^x86.__m128i)(&block[48])), mask)

		msg, tmp: x86.__m128i

		// Rounds 0-3
		msg = x86._mm_add_epi32(m0, kvec(0))
		sha_do2(&state0, &state1, msg)
		// Rounds 4-7
		msg = x86._mm_add_epi32(m1, kvec(4))
		sha_do2(&state0, &state1, msg)
		m0 = x86._mm_sha256msg1_epu32(m0, m1)
		// Rounds 8-11
		msg = x86._mm_add_epi32(m2, kvec(8))
		sha_do2(&state0, &state1, msg)
		m1 = x86._mm_sha256msg1_epu32(m1, m2)
		// Rounds 12-15
		msg = x86._mm_add_epi32(m3, kvec(12))
		tmp = x86._mm_alignr_epi8(m3, m2, 4)
		m0 = x86._mm_add_epi32(m0, tmp)
		m0 = x86._mm_sha256msg2_epu32(m0, m3)
		sha_do2(&state0, &state1, msg)
		m2 = x86._mm_sha256msg1_epu32(m2, m3)

		// Rounds 16-51: identical body with the four lanes rotated by one each
		// group (m0->m1->m2->m3->m0).
		sched(&m0, &m1, &m2, &m3, 16, &state0, &state1)
		sched(&m1, &m2, &m3, &m0, 20, &state0, &state1)
		sched(&m2, &m3, &m0, &m1, 24, &state0, &state1)
		sched(&m3, &m0, &m1, &m2, 28, &state0, &state1)
		sched(&m0, &m1, &m2, &m3, 32, &state0, &state1)
		sched(&m1, &m2, &m3, &m0, 36, &state0, &state1)
		sched(&m2, &m3, &m0, &m1, 40, &state0, &state1)
		sched(&m3, &m0, &m1, &m2, 44, &state0, &state1)
		sched(&m0, &m1, &m2, &m3, 48, &state0, &state1)

		// Rounds 52-55: msg2 only (no further msg1 needed).
		msg = x86._mm_add_epi32(m1, kvec(52))
		tmp = x86._mm_alignr_epi8(m1, m0, 4)
		m2 = x86._mm_add_epi32(m2, tmp)
		m2 = x86._mm_sha256msg2_epu32(m2, m1)
		sha_do2(&state0, &state1, msg)
		// Rounds 56-59
		msg = x86._mm_add_epi32(m2, kvec(56))
		tmp = x86._mm_alignr_epi8(m2, m1, 4)
		m3 = x86._mm_add_epi32(m3, tmp)
		m3 = x86._mm_sha256msg2_epu32(m3, m2)
		sha_do2(&state0, &state1, msg)
		// Rounds 60-63
		msg = x86._mm_add_epi32(m3, kvec(60))
		sha_do2(&state0, &state1, msg)

		state0 = x86._mm_add_epi32(state0, save0)
		state1 = x86._mm_add_epi32(state1, save1)

		// Store the two state regs to scratch and reassemble the 8 words.
		// In memory order (lane0 first) state0 = {F,E,B,A}, state1 = {H,G,D,C}.
		s0arr: [4]u32 = ---
		s1arr: [4]u32 = ---
		x86._mm_storeu_si128(transmute(^x86.__m128i)(&s0arr[0]), state0)
		x86._mm_storeu_si128(transmute(^x86.__m128i)(&s1arr[0]), state1)
		state[0] = s0arr[3] // A
		state[1] = s0arr[2] // B
		state[2] = s1arr[3] // C
		state[3] = s1arr[2] // D
		state[4] = s0arr[1] // E
		state[5] = s0arr[0] // F
		state[6] = s1arr[1] // G
		state[7] = s1arr[0] // H
	}
}

sha256_update :: proc "contextless" (ctx: ^Sha256_Ctx, data: []u8) {
	data := data
	ctx.total += u64(len(data))

	// Fill an existing partial buffer first.
	if ctx.buf_len > 0 {
		need := 64 - ctx.buf_len
		n := min(need, len(data))
		copy(ctx.buf[ctx.buf_len:], data[:n])
		ctx.buf_len += n
		data = data[n:]
		if ctx.buf_len == 64 {
			sha256_block(&ctx.state, ctx.buf[:])
			ctx.buf_len = 0
		}
	}

	// Process full blocks directly from the input.
	for len(data) >= 64 {
		sha256_block(&ctx.state, data[:64])
		data = data[64:]
	}

	// Stash the remainder.
	if len(data) > 0 {
		copy(ctx.buf[:], data)
		ctx.buf_len = len(data)
	}
}

sha256_final :: proc "contextless" (ctx: ^Sha256_Ctx) -> [32]u8 {
	bit_len := ctx.total * 8

	// Append 0x80 then pad with zeros, leaving room for the 8-byte length.
	pad: [72]u8 = ---
	#no_bounds_check pad[0] = 0x80
	pad_len := (ctx.buf_len < 56) ? (56 - ctx.buf_len) : (120 - ctx.buf_len)
	#no_bounds_check for i in 1 ..< pad_len {
		pad[i] = 0
	}
	// 8-byte big-endian length.
	#no_bounds_check for i in 0 ..< 8 {
		pad[pad_len + i] = u8(bit_len >> uint(56 - 8 * i))
	}
	sha256_update_no_count(ctx, pad[:pad_len + 8])

	out: [32]u8 = ---
	#no_bounds_check for i in 0 ..< 8 {
		out[i * 4 + 0] = u8(ctx.state[i] >> 24)
		out[i * 4 + 1] = u8(ctx.state[i] >> 16)
		out[i * 4 + 2] = u8(ctx.state[i] >> 8)
		out[i * 4 + 3] = u8(ctx.state[i])
	}
	return out
}

// Padding bytes must not change ctx.total, so finalization uses this variant.
@(private = "file")
sha256_update_no_count :: proc "contextless" (ctx: ^Sha256_Ctx, data: []u8) {
	data := data
	if ctx.buf_len > 0 {
		need := 64 - ctx.buf_len
		n := min(need, len(data))
		copy(ctx.buf[ctx.buf_len:], data[:n])
		ctx.buf_len += n
		data = data[n:]
		if ctx.buf_len == 64 {
			sha256_block(&ctx.state, ctx.buf[:])
			ctx.buf_len = 0
		}
	}
	for len(data) >= 64 {
		sha256_block(&ctx.state, data[:64])
		data = data[64:]
	}
	if len(data) > 0 {
		copy(ctx.buf[:], data)
		ctx.buf_len = len(data)
	}
}

// One-shot helper.
sha256 :: proc "contextless" (data: []u8) -> [32]u8 {
	ctx: Sha256_Ctx = ---
	sha256_init(&ctx)
	sha256_update(&ctx, data)
	return sha256_final(&ctx)
}
