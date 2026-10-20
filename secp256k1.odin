package sakura

import "base:intrinsics"
import "core:fmt"

// Dependency-free secp256k1 + BIP-340 Schnorr signatures.
//
// Everything here is variable-time. That's fine and in fact desirable:
// verification operates exclusively on public data (the Nostr event, its
// pubkey and signature), so there is no secret to leak through timing, and
// dropping the constant-time requirement buys real speed. Signing exists only
// to mint test tokens from the CLI.
//
// The verifier follows libsecp256k1's design:
//   * field elements mod p in five 52-bit limbs with lazy reduction;
//   * R = s*G - e*P in one Strauss-Shamir pass over wNAF digits. e is split
//     with the GLV endomorphism (lambda*(x, y) = (beta*x, y)) into two
//     ~128-bit halves against an 8-entry table of P; s is split into two
//     128-bit halves against tables of odd multiples of G and 2^128*G that
//     are built once, on first use;
//   * the P table lives on an isomorphic curve where its points share one Z,
//     so every addition in the loop is a cheap mixed (Jacobian + affine) one.
//
// p = 2^256 - 2^32 - 977, n = group order, curve y^2 = x^3 + 7.

// --- field elements mod p --------------------------------------------------
//
// Five 52-bit limbs (the top limb 48 bits when normalized). The magnitude m
// of an element bounds each limb by 2m(2^52-1), so sums can be chained before
// a mul/sqr; mul/sqr accept m <= 8 and return m = 1. Magnitudes are tracked
// statically ("// m3" = magnitude 3), exactly as libsecp256k1's field_5x52.

@(private = "file")
Fe :: [5]u64

@(private = "file") M52 :: u64(0xFFFFFFFFFFFFF)
@(private = "file") M48 :: u64(0x0FFFFFFFFFFFF)
@(private = "file") FR :: u64(0x1000003D10) // 2^260 mod p: folds the high half back
@(private = "file") P0 :: u64(0xFFFFEFFFFFC2F) // low limb of p (then 3x M52, then M48)

@(private = "file") FE_ONE :: Fe{1, 0, 0, 0, 0}
@(private = "file") FE_SEVEN :: Fe{7, 0, 0, 0, 0}
@(private = "file") FE_GX :: Fe{0x2815B16F81798, 0xDB2DCE28D959F, 0xE870B07029BFC, 0xBBAC55A06295C, 0x079BE667EF9DC}
@(private = "file") FE_GY :: Fe{0x7D08FFB10D4B8, 0x48A68554199C4, 0xE1108A8FD17B4, 0xC4655DA4FBFC0, 0x0483ADA7726A3}
// beta: cube root of unity mod p, so lambda*(x, y) = (beta*x, y).
@(private = "file") FE_BETA :: Fe{0x96C28719501EE, 0x7512F58995C13, 0xC3434E99CF049, 0x07106E64479EA, 0x07AE96A2B657C}

// r = a*b mod p (libsecp256k1 fe_mul_inner, int128 variant).
@(private = "file")
fe_mul :: #force_inline proc "contextless" (a, b: Fe) -> (r: Fe) {
	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]
	b0, b1, b2, b3, b4 := b[0], b[1], b[2], b[3], b[4]

	d := u128(a0) * u128(b3) + u128(a1) * u128(b2) + u128(a2) * u128(b1) + u128(a3) * u128(b0)
	c := u128(a4) * u128(b4)
	d += u128(FR) * u128(u64(c)); c >>= 64
	t3 := u64(d) & M52; d >>= 52

	d += u128(a0) * u128(b4) + u128(a1) * u128(b3) + u128(a2) * u128(b2) + u128(a3) * u128(b1) + u128(a4) * u128(b0)
	d += u128(FR << 12) * u128(u64(c))
	t4 := u64(d) & M52; d >>= 52
	tx := t4 >> 48; t4 &= M48

	c = u128(a0) * u128(b0)
	d += u128(a1) * u128(b4) + u128(a2) * u128(b3) + u128(a3) * u128(b2) + u128(a4) * u128(b1)
	u0 := u64(d) & M52; d >>= 52
	u0 = (u0 << 4) | tx
	c += u128(u0) * u128(FR >> 4)
	r[0] = u64(c) & M52; c >>= 52

	c += u128(a0) * u128(b1) + u128(a1) * u128(b0)
	d += u128(a2) * u128(b4) + u128(a3) * u128(b3) + u128(a4) * u128(b2)
	c += u128(u64(d) & M52) * u128(FR); d >>= 52
	r[1] = u64(c) & M52; c >>= 52

	c += u128(a0) * u128(b2) + u128(a1) * u128(b1) + u128(a2) * u128(b0)
	d += u128(a3) * u128(b4) + u128(a4) * u128(b3)
	c += u128(FR) * u128(u64(d)); d >>= 64
	r[2] = u64(c) & M52; c >>= 52

	c += u128(FR << 12) * u128(u64(d))
	c += u128(t3)
	r[3] = u64(c) & M52; c >>= 52
	r[4] = u64(c) + t4
	return
}

// r = a^2 mod p: fe_mul with the symmetric cross products folded (15 muls).
@(private = "file")
fe_sqr :: #force_inline proc "contextless" (a: Fe) -> (r: Fe) {
	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]

	d := u128(a0 * 2) * u128(a3) + u128(a1 * 2) * u128(a2)
	c := u128(a4) * u128(a4)
	d += u128(FR) * u128(u64(c)); c >>= 64
	t3 := u64(d) & M52; d >>= 52

	a4 *= 2
	d += u128(a0) * u128(a4) + u128(a1 * 2) * u128(a3) + u128(a2) * u128(a2)
	d += u128(FR << 12) * u128(u64(c))
	t4 := u64(d) & M52; d >>= 52
	tx := t4 >> 48; t4 &= M48

	c = u128(a0) * u128(a0)
	d += u128(a1) * u128(a4) + u128(a2 * 2) * u128(a3)
	u0 := u64(d) & M52; d >>= 52
	u0 = (u0 << 4) | tx
	c += u128(u0) * u128(FR >> 4)
	r[0] = u64(c) & M52; c >>= 52

	a0 *= 2
	c += u128(a0) * u128(a1)
	d += u128(a2) * u128(a4) + u128(a3) * u128(a3)
	c += u128(u64(d) & M52) * u128(FR); d >>= 52
	r[1] = u64(c) & M52; c >>= 52

	c += u128(a0) * u128(a2) + u128(a1) * u128(a1)
	d += u128(a3) * u128(a4)
	c += u128(FR) * u128(u64(d)); d >>= 64
	r[2] = u64(c) & M52; c >>= 52

	c += u128(FR << 12) * u128(u64(d))
	c += u128(t3)
	r[3] = u64(c) & M52; c >>= 52
	r[4] = u64(c) + t4
	return
}

// -a for a of magnitude <= M; the result has magnitude M + 1.
@(private = "file")
fe_neg :: #force_inline proc "contextless" (a: Fe, $M: u64) -> Fe {
	K :: 2 * (M + 1)
	return Fe{P0 * K - a[0], M52 * K - a[1], M52 * K - a[2], M52 * K - a[3], M48 * K - a[4]}
}

// a/2 mod p: add p when odd, then shift. Magnitude m becomes m/2 + 1.
@(private = "file")
fe_half :: #force_inline proc "contextless" (a: Fe) -> Fe {
	t0, t1, t2, t3, t4 := a[0], a[1], a[2], a[3], a[4]
	mask := (0 - (t0 & 1)) >> 12
	t0 += P0 & mask
	t1 += mask
	t2 += mask
	t3 += mask
	t4 += mask >> 4
	return Fe {
		(t0 >> 1) + ((t1 & 1) << 51),
		(t1 >> 1) + ((t2 & 1) << 51),
		(t2 >> 1) + ((t3 & 1) << 51),
		(t3 >> 1) + ((t4 & 1) << 51),
		t4 >> 1,
	}
}

// Carry-propagate to magnitude 1 (value may still be >= p).
@(private = "file")
fe_norm_weak :: #force_inline proc "contextless" (a: Fe) -> Fe {
	t0, t1, t2, t3, t4 := a[0], a[1], a[2], a[3], a[4]
	x := t4 >> 48; t4 &= M48
	t0 += x * 0x1000003D1
	t1 += t0 >> 52; t0 &= M52
	t2 += t1 >> 52; t1 &= M52
	t3 += t2 >> 52; t2 &= M52
	t4 += t3 >> 52; t3 &= M52
	return Fe{t0, t1, t2, t3, t4}
}

// Fully reduce to the unique representative in [0, p).
@(private = "file")
fe_norm :: proc "contextless" (a: Fe) -> Fe {
	t0, t1, t2, t3, t4 := a[0], a[1], a[2], a[3], a[4]
	x := t4 >> 48; t4 &= M48
	t0 += x * 0x1000003D1
	t1 += t0 >> 52; t0 &= M52
	t2 += t1 >> 52; t1 &= M52; m := t1
	t3 += t2 >> 52; t2 &= M52; m &= t2
	t4 += t3 >> 52; t3 &= M52; m &= t3

	// At most one more subtraction of p is needed.
	if (t4 >> 48) != 0 || (t4 == M48 && m == M52 && t0 >= P0) {
		t0 += 0x1000003D1
		t1 += t0 >> 52; t0 &= M52
		t2 += t1 >> 52; t1 &= M52
		t3 += t2 >> 52; t2 &= M52
		t4 += t3 >> 52; t3 &= M52
		t4 &= M48
	}
	return Fe{t0, t1, t2, t3, t4}
}

// a ≡ 0 (mod p), for any magnitude up to 31.
@(private = "file")
fe_is_zero :: proc "contextless" (a: Fe) -> bool {
	t0, t4 := a[0], a[4]
	x := t4 >> 48
	t0 += x * 0x1000003D1

	// z0 tracks a raw value of 0, z1 a raw value of p. Most calls exit here.
	z0 := t0 & M52
	z1 := z0 ~ 0x1000003D0
	if z0 != 0 && z1 != M52 {
		return false
	}

	t1, t2, t3 := a[1], a[2], a[3]
	t4 &= M48
	t1 += t0 >> 52
	t2 += t1 >> 52; t1 &= M52; z0 |= t1; z1 &= t1
	t3 += t2 >> 52; t2 &= M52; z0 |= t2; z1 &= t2
	t4 += t3 >> 52; t3 &= M52; z0 |= t3; z1 &= t3
	z0 |= t4; z1 &= t4 ~ 0xF000000000000
	return z0 == 0 || z1 == M52
}

// a == b for a of magnitude 1 and b of magnitude <= 30.
@(private = "file")
fe_equal :: #force_inline proc "contextless" (a, b: Fe) -> bool {
	return fe_is_zero(fe_neg(a, 1) + b)
}

@(private = "file")
fe_from_u64x4 :: #force_inline proc "contextless" (d: [4]u64) -> Fe {
	return Fe {
		d[0] & M52,
		(d[0] >> 52) | ((d[1] << 12) & M52),
		(d[1] >> 40) | ((d[2] << 24) & M52),
		(d[2] >> 28) | ((d[3] << 36) & M52),
		d[3] >> 16,
	}
}

// Requires a normalized input.
@(private = "file")
fe_to_u64x4 :: #force_inline proc "contextless" (a: Fe) -> [4]u64 {
	return {a[0] | (a[1] << 52), (a[1] >> 12) | (a[2] << 40), (a[2] >> 24) | (a[3] << 28), (a[3] >> 36) | (a[4] << 16)}
}

@(private = "file")
be64 :: #force_inline proc "contextless" (b: []u8, off: int) -> u64 {
	#no_bounds_check return intrinsics.byte_swap(intrinsics.unaligned_load((^u64)(&b[off])))
}

// Parse 32 big-endian bytes into little-endian u64 limbs (len(b) >= 32).
@(private = "file")
u256_from_be :: #force_inline proc "contextless" (b: []u8) -> [4]u64 {
	return {be64(b, 24), be64(b, 16), be64(b, 8), be64(b, 0)}
}

@(private = "file")
u256_to_be :: proc "contextless" (d: [4]u64) -> (out: [32]u8) {
	#no_bounds_check for i in 0 ..< 4 {
		v := intrinsics.byte_swap(d[3 - i])
		intrinsics.unaligned_store((^u64)(&out[i * 8]), v)
	}
	return
}

// Parse a field element; ok is false if the encoding is >= p.
@(private = "file")
fe_from_b32 :: proc "contextless" (b: []u8) -> (Fe, bool) {
	d := u256_from_be(b)
	over := d[3] == max(u64) && d[2] == max(u64) && d[1] == max(u64) && d[0] >= 0xFFFFFFFEFFFFFC2F
	return fe_from_u64x4(d), !over
}

@(private = "file")
fe_sqr_n :: proc "contextless" (a: Fe, n: int) -> Fe {
	if has_bmi2() {
		return fe_sqr_n_bmi2(a, n)
	}
	return sqr_n_body(a, n)
}

@(private = "file")
sqr_n_body :: #force_inline proc "contextless" (a: Fe, n: int) -> Fe {
	r := a
	for _ in 0 ..< n {
		r = fe_sqr(r)
	}
	return r
}

// a^(2^k - 1) for k in {2, 22, 223}: the runs of ones in (p+1)/4, via
// libsecp256k1's addition chain 1,2,3,6,9,11,22,44,88,176,220,223.
@(private = "file")
fe_pow_blocks :: proc "contextless" (a: Fe) -> (x2, x22, x223: Fe) {
	x2 = fe_mul(fe_sqr(a), a)
	x3 := fe_mul(fe_sqr(x2), a)
	x6 := fe_mul(fe_sqr_n(x3, 3), x3)
	x9 := fe_mul(fe_sqr_n(x6, 3), x3)
	x11 := fe_mul(fe_sqr_n(x9, 2), x2)
	x22 = fe_mul(fe_sqr_n(x11, 11), x11)
	x44 := fe_mul(fe_sqr_n(x22, 22), x22)
	x88 := fe_mul(fe_sqr_n(x44, 44), x44)
	x176 := fe_mul(fe_sqr_n(x88, 88), x88)
	x220 := fe_mul(fe_sqr_n(x176, 44), x44)
	x223 = fe_mul(fe_sqr_n(x220, 3), x3)
	return
}

// a^((p+1)/4), a square root since p ≡ 3 (mod 4); ok is false if a has none.
@(private = "file")
fe_sqrt :: proc "contextless" (a: Fe) -> (r: Fe, ok: bool) {
	x2, x22, x223 := fe_pow_blocks(a)
	t := fe_mul(fe_sqr_n(x223, 23), x22)
	t = fe_mul(fe_sqr_n(t, 6), x2)
	r = fe_sqr_n(t, 2)
	return r, fe_equal(fe_sqr(r), a)
}

// --- inversion: safegcd ------------------------------------------------------
//
// Bernstein-Yang divsteps, 62 at a time, on signed 62-bit limbs (a port of
// libsecp256k1's modinv64_var). Several times cheaper than a^(p-2).

@(private = "file")
S62 :: [5]i64

@(private = "file") M62 :: u64(max(u64) >> 2)
@(private = "file") P_LO62 :: i64(-0x1000003D1) // p = P_LO62 + 256*2^248
@(private = "file") P_INV62 :: u64(0x27C7F6E22DDACACF) // p^-1 mod 2^62

// Transition matrix of a batch of divsteps.
@(private = "file")
Trans :: struct {
	u, v, q, r: i64,
}

// 62 divsteps on the low limbs of f, g; returns the new eta (= -delta).
@(private = "file")
divsteps_62 :: proc "contextless" (eta_in: i64, f0, g0: u64, t: ^Trans) -> i64 {
	eta := eta_in
	u, v, q, r: u64 = 1, 0, 0, 1
	f, g := f0, g0
	i := 62
	for {
		// Strip g's trailing zeros at once (each is a halving step); the
		// sentinel stops at the remaining step count.
		zeros := int(intrinsics.count_trailing_zeros(g | (max(u64) << uint(i))))
		g >>= uint(zeros)
		u <<= uint(zeros)
		v <<= uint(zeros)
		eta -= i64(zeros)
		i -= zeros
		if i == 0 {
			break
		}
		w: u64
		if eta < 0 {
			eta = -eta
			f, g = g, 0 - f
			u, q = q, 0 - u
			v, r = r, 0 - v
			// Cancel up to 6 low bits of g with a multiple of f.
			limit := min(int(eta) + 1, i)
			m := (max(u64) >> uint(64 - limit)) & 63
			w = (f * g * (f * f - 2)) & m
		} else {
			// Cancel up to 4 low bits of g.
			limit := min(int(eta) + 1, i)
			m := (max(u64) >> uint(64 - limit)) & 15
			w = f + (((f + 1) & 4) << 1)
			w = ((0 - w) * g) & m
		}
		g += f * w
		q += u * w
		r += v * w
	}
	t^ = Trans{i64(u), i64(v), i64(q), i64(r)}
	return eta
}

// [d, e] = t*[d, e] / 2^62 (mod p), adding multiples of p to make it exact.
@(private = "file")
update_de :: proc "contextless" (d, e: ^S62, t: Trans) {
	d0, d1, d2, d3, d4 := d[0], d[1], d[2], d[3], d[4]
	e0, e1, e2, e3, e4 := e[0], e[1], e[2], e[3], e[4]
	u, v, q, r := t.u, t.v, t.q, t.r
	sd, se := d4 >> 63, e4 >> 63
	md := (u & sd) + (v & se)
	me := (q & sd) + (r & se)
	cd := i128(u) * i128(d0) + i128(v) * i128(e0)
	ce := i128(q) * i128(d0) + i128(r) * i128(e0)
	md -= i64((P_INV62 * u64(cd) + u64(md)) & M62)
	me -= i64((P_INV62 * u64(ce) + u64(me)) & M62)
	cd += i128(P_LO62) * i128(md)
	ce += i128(P_LO62) * i128(me)
	cd >>= 62
	ce >>= 62
	// p's limbs 1..3 are zero; limb 4 (256) adds md/me once more below.
	cd += i128(u) * i128(d1) + i128(v) * i128(e1)
	ce += i128(q) * i128(d1) + i128(r) * i128(e1)
	d[0] = i64(u64(cd) & M62); cd >>= 62
	e[0] = i64(u64(ce) & M62); ce >>= 62
	cd += i128(u) * i128(d2) + i128(v) * i128(e2)
	ce += i128(q) * i128(d2) + i128(r) * i128(e2)
	d[1] = i64(u64(cd) & M62); cd >>= 62
	e[1] = i64(u64(ce) & M62); ce >>= 62
	cd += i128(u) * i128(d3) + i128(v) * i128(e3)
	ce += i128(q) * i128(d3) + i128(r) * i128(e3)
	d[2] = i64(u64(cd) & M62); cd >>= 62
	e[2] = i64(u64(ce) & M62); ce >>= 62
	cd += i128(u) * i128(d4) + i128(v) * i128(e4) + i128(256) * i128(md)
	ce += i128(q) * i128(d4) + i128(r) * i128(e4) + i128(256) * i128(me)
	d[3] = i64(u64(cd) & M62); cd >>= 62
	e[3] = i64(u64(ce) & M62); ce >>= 62
	d[4] = i64(cd)
	e[4] = i64(ce)
}

// [f, g] = t*[f, g] / 2^62 over the first n limbs (exact).
@(private = "file")
update_fg :: proc "contextless" (n: int, f, g: ^S62, t: Trans) {
	u, v, q, r := t.u, t.v, t.q, t.r
	cf := i128(u) * i128(f[0]) + i128(v) * i128(g[0])
	cg := i128(q) * i128(f[0]) + i128(r) * i128(g[0])
	cf >>= 62
	cg >>= 62
	#no_bounds_check {
		for i in 1 ..< n {
			fi, gi := f[i], g[i]
			cf += i128(u) * i128(fi) + i128(v) * i128(gi)
			cg += i128(q) * i128(fi) + i128(r) * i128(gi)
			f[i - 1] = i64(u64(cf) & M62); cf >>= 62
			g[i - 1] = i64(u64(cg) & M62); cg >>= 62
		}
		f[n - 1] = i64(cf)
		g[n - 1] = i64(cg)
	}
}

// Bring d from (-2p, p) into [0, p), negated when sign < 0.
@(private = "file")
normalize_62 :: proc "contextless" (d: S62, sign: i64) -> S62 {
	ML :: i64(M62)
	r0, r1, r2, r3, r4 := d[0], d[1], d[2], d[3], d[4]
	add := r4 >> 63
	r0 += P_LO62 & add
	r4 += 256 & add
	neg := sign >> 63
	r0 = (r0 ~ neg) - neg
	r1 = (r1 ~ neg) - neg
	r2 = (r2 ~ neg) - neg
	r3 = (r3 ~ neg) - neg
	r4 = (r4 ~ neg) - neg
	r1 += r0 >> 62; r0 &= ML
	r2 += r1 >> 62; r1 &= ML
	r3 += r2 >> 62; r2 &= ML
	r4 += r3 >> 62; r3 &= ML
	add = r4 >> 63
	r0 += P_LO62 & add
	r4 += 256 & add
	r1 += r0 >> 62; r0 &= ML
	r2 += r1 >> 62; r1 &= ML
	r3 += r2 >> 62; r2 &= ML
	r4 += r3 >> 62; r3 &= ML
	return S62{r0, r1, r2, r3, r4}
}

// 1/a (mod p), variable time; a must be nonzero mod p.
@(private = "file")
fe_inv :: proc "contextless" (a: Fe) -> Fe {
	x := fe_norm(a)
	g := S62 {
		i64((x[0] | x[1] << 52) & M62),
		i64((x[1] >> 10 | x[2] << 42) & M62),
		i64((x[2] >> 20 | x[3] << 32) & M62),
		i64((x[3] >> 30 | x[4] << 22) & M62),
		i64(x[4] >> 40),
	}
	f := S62{P_LO62, 0, 0, 0, 256}
	d := S62{}
	e := S62{1, 0, 0, 0, 0}
	eta := i64(-1)
	n := 5
	#no_bounds_check for {
		t: Trans
		eta = divsteps_62(eta, u64(f[0]), u64(g[0]), &t)
		update_de(&d, &e, t)
		update_fg(n, &f, &g, t)
		if g[0] == 0 {
			rest: i64
			for j in 1 ..< n {
				rest |= g[j]
			}
			if rest == 0 {
				break
			}
		}
		// Shrink when the top limbs of f and g are both 0 or -1.
		fn, gn := f[n - 1], g[n - 1]
		cond := i64(n - 2) >> 63
		cond |= fn ~ (fn >> 63)
		cond |= gn ~ (gn >> 63)
		if cond == 0 {
			f[n - 2] |= i64(u64(fn) << 62)
			g[n - 2] |= i64(u64(gn) << 62)
			n -= 1
		}
	}
	// f is now ±1 and d is ±1/a.
	r := normalize_62(d, f[n - 1])
	a0, a1, a2, a3, a4 := u64(r[0]), u64(r[1]), u64(r[2]), u64(r[3]), u64(r[4])
	return Fe{a0 & M52, (a0 >> 52 | a1 << 10) & M52, (a1 >> 42 | a2 << 20) & M52, (a2 >> 32 | a3 << 30) & M52, a3 >> 22 | a4 << 40}
}

// --- scalars mod n (4x64 little-endian limbs) ------------------------------

@(private = "file")
Sc :: [4]u64

@(private = "file") SC_N :: Sc{0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF}
@(private = "file") SC_NC :: [3]u64{0x402DA1732FC9BEBF, 0x4551231950B75FC4, 1} // 2^256 - n
@(private = "file") SC_LAMBDA :: Sc{0xDF02967C1B23BD72, 0x122E22EA20816678, 0xA5261C028812645A, 0x5363AD4CC05C30E0}
// GLV decomposition constants (libsecp256k1 scalar_split_lambda).
@(private = "file") SC_G1 :: Sc{0xE893209A45DBB031, 0x3DAA8A1471E8CA7F, 0xE86C90E49284EB15, 0x3086D221A7D46BCD}
@(private = "file") SC_G2 :: Sc{0x1571B4AE8AC47F71, 0x221208AC9DF506C6, 0x6F547FA90ABFE4C4, 0xE4437ED6010E8828}
@(private = "file") SC_MINUS_B1 :: Sc{0x6F547FA90ABFE4C3, 0xE4437ED6010E8828, 0, 0}
@(private = "file") SC_MINUS_B2 :: Sc{0xD765CDA83DB1562C, 0x8A280AC50774346D, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF}

@(private = "file")
sc_geq_n :: proc "contextless" (a: Sc) -> bool {
	n := SC_N
	#no_bounds_check for i := 3; i >= 0; i -= 1 {
		if a[i] != n[i] {
			return a[i] > n[i]
		}
	}
	return true
}

// a - b over 256 bits (wrapping).
@(private = "file")
u256_sub :: proc "contextless" (a, b: Sc) -> (r: Sc) {
	borrow: u64
	#no_bounds_check for i in 0 ..< 4 {
		d, b1 := intrinsics.overflow_sub(a[i], b[i])
		e, b2 := intrinsics.overflow_sub(d, borrow)
		r[i] = e
		borrow = u64(b1 || b2)
	}
	return
}

// Parse 32 big-endian bytes; over is true if the value is >= n.
@(private = "file")
sc_from_b32 :: proc "contextless" (b: []u8) -> (s: Sc, over: bool) {
	s = u256_from_be(b)
	return s, sc_geq_n(s)
}

// Parse 32 big-endian bytes reduced mod n (a single subtraction suffices).
@(private = "file")
sc_reduce_b32 :: proc "contextless" (b: []u8) -> Sc {
	s, over := sc_from_b32(b)
	return over ? u256_sub(s, SC_N) : s
}

@(private = "file")
sc_neg :: proc "contextless" (a: Sc) -> Sc {
	if a == (Sc{}) {
		return a
	}
	return u256_sub(SC_N, a)
}

@(private = "file")
sc_add :: proc "contextless" (a, b: Sc) -> (r: Sc) {
	carry: u128
	#no_bounds_check for i in 0 ..< 4 {
		carry += u128(a[i]) + u128(b[i])
		r[i] = u64(carry)
		carry >>= 64
	}
	if carry != 0 || sc_geq_n(r) {
		r = u256_sub(r, SC_N)
	}
	return
}

// Full 512-bit product.
@(private = "file")
u256_mul :: proc "contextless" (a, b: Sc) -> (l: [8]u64) {
	#no_bounds_check for i in 0 ..< 4 {
		carry: u64
		for j in 0 ..< 4 {
			v := u128(a[i]) * u128(b[j]) + u128(l[i + j]) + u128(carry)
			l[i + j] = u64(v)
			carry = u64(v >> 64)
		}
		l[i + 4] = carry
	}
	return
}

// Reduce a 512-bit value mod n by folding the high half with 2^256 ≡ NC.
@(private = "file")
sc_reduce_512 :: proc "contextless" (l: [8]u64) -> Sc {
	lo := Sc{l[0], l[1], l[2], l[3]}
	hi := Sc{l[4], l[5], l[6], l[7]}
	nc := SC_NC
	#no_bounds_check for hi != (Sc{}) {
		t: [8]u64
		for i in 0 ..< 4 {
			carry: u64
			for j in 0 ..< 3 {
				v := u128(hi[i]) * u128(nc[j]) + u128(t[i + j]) + u128(carry)
				t[i + j] = u64(v)
				carry = u64(v >> 64)
			}
			t[i + 3] = carry
		}
		carry: u128
		for i in 0 ..< 8 {
			carry += u128(t[i]) + u128(i < 4 ? lo[i] : 0)
			t[i] = u64(carry)
			carry >>= 64
		}
		lo = Sc{t[0], t[1], t[2], t[3]}
		hi = Sc{t[4], t[5], t[6], t[7]}
	}
	if sc_geq_n(lo) {
		lo = u256_sub(lo, SC_N)
	}
	return lo
}

@(private = "file")
sc_mul :: proc "contextless" (a, b: Sc) -> Sc {
	return sc_reduce_512(u256_mul(a, b))
}

// round(a*b / 2^384).
@(private = "file")
sc_mul_shift_384 :: proc "contextless" (a, b: Sc) -> Sc {
	l := u256_mul(a, b)
	v := u128(l[6]) + u128(l[5] >> 63)
	r0 := u64(v)
	v = (v >> 64) + u128(l[7])
	return Sc{r0, u64(v), u64(v >> 64), 0}
}

// Split k into (r1, r2) with k ≡ r1 + r2*lambda (mod n) and |r1|, |r2| < 2^128.
@(private = "file")
sc_split_lambda :: proc "contextless" (k: Sc) -> (r1, r2: Sc) {
	c1 := sc_mul(sc_mul_shift_384(k, SC_G1), SC_MINUS_B1)
	c2 := sc_mul(sc_mul_shift_384(k, SC_G2), SC_MINUS_B2)
	r2 = sc_add(c1, c2)
	r1 = sc_add(sc_neg(sc_mul(r2, SC_LAMBDA)), k)
	return
}

// --- points -----------------------------------------------------------------

// Affine point (never infinity where used).
@(private = "file")
Ge :: struct {
	x, y: Fe,
}

// Jacobian point: affine (X/Z^2, Y/Z^3). x/y magnitudes stay <= 4, z's is 1.
@(private = "file")
Gej :: struct {
	x, y, z: Fe,
	inf:     bool,
}

// r = 2r, 3M + 4S (libsecp256k1 gej_double). No y = 0 case: secp256k1 has
// no points of order two.
@(private = "file")
gej_double :: proc "contextless" (r: ^Gej) {
	dbl_body(r)
}

@(private = "file")
dbl_body :: #force_inline proc "contextless" (r: ^Gej) {
	if r.inf {
		return
	}
	x, y := r.x, r.y
	r.z = fe_mul(r.z, y)
	s := fe_sqr(y)
	l := fe_half(fe_sqr(x) * 3) // (3/2)x^2, m2
	t := fe_mul(fe_neg(s, 1), x) // -x*y^2
	rx := fe_sqr(l) + t + t // m3
	s = fe_sqr(s)
	r.y = fe_neg(fe_mul(rx + t, l) + s, 2) // m3
	r.x = rx
}

// r += b for affine b, 8M + 3S. rzr (if given) receives new z / old z, which
// builds the shared-Z table.
@(private = "file")
gej_add_ge :: proc "contextless" (r: ^Gej, b: ^Ge, rzr: ^Fe = nil) {
	add_ge_body(r, b, rzr)
}

@(private = "file")
add_ge_body :: #force_inline proc "contextless" (r: ^Gej, b: ^Ge, rzr: ^Fe) {
	if r.inf {
		r^ = Gej{x = b.x, y = b.y, z = FE_ONE}
		return
	}
	z12 := fe_sqr(r.z)
	u1 := r.x
	u2 := fe_mul(b.x, z12)
	s1 := r.y
	s2 := fe_mul(fe_mul(b.y, z12), r.z)
	h := fe_neg(u1, 4) + u2 // m6
	i := fe_neg(s2, 1) + s1 // m6
	if fe_is_zero(h) {
		gej_add_same_x(r, i, rzr)
		return
	}
	if rzr != nil {
		rzr^ = h
	}
	gej_add_finish(r, u1, s1, h, i, r.z)
}

// r += b where b's true Z is 1/bzinv: by the curve's isomorphism this is an
// affine addition with r.z scaled by bzinv for the x/y math only.
@(private = "file")
gej_add_zinv :: proc "contextless" (r: ^Gej, b: ^Ge, bzinv: Fe) {
	add_zinv_body(r, b, bzinv)
}

@(private = "file")
add_zinv_body :: #force_inline proc "contextless" (r: ^Gej, b: ^Ge, bzinv: Fe) {
	if r.inf {
		zi2 := fe_sqr(bzinv)
		r^ = Gej{x = fe_mul(b.x, zi2), y = fe_mul(b.y, fe_mul(zi2, bzinv)), z = FE_ONE}
		return
	}
	az := fe_mul(r.z, bzinv)
	z12 := fe_sqr(az)
	u1 := r.x
	u2 := fe_mul(b.x, z12)
	s1 := r.y
	s2 := fe_mul(fe_mul(b.y, z12), az)
	h := fe_neg(u1, 4) + u2
	i := fe_neg(s2, 1) + s1
	if fe_is_zero(h) {
		gej_add_same_x(r, i, nil)
		return
	}
	gej_add_finish(r, u1, s1, h, i, r.z)
}

// Equal x: the sum is a doubling (same y) or infinity (opposite y).
@(private = "file")
gej_add_same_x :: proc "contextless" (r: ^Gej, i: Fe, rzr: ^Fe) {
	if fe_is_zero(i) {
		if rzr != nil {
			rzr^ = fe_norm_weak(r.y)
		}
		gej_double(r)
		return
	}
	if rzr != nil {
		rzr^ = {}
	}
	r.inf = true
}

// Shared tail of the mixed additions (h = u2 - u1, i = s1 - s2).
@(private = "file")
gej_add_finish :: #force_inline proc "contextless" (r: ^Gej, u1, s1, h, i, z: Fe) {
	r.z = fe_mul(z, h)
	h2 := fe_neg(fe_sqr(h), 1) // -h^2, m2
	h3 := fe_mul(h2, h)
	t := fe_mul(u1, h2)
	rx := fe_sqr(i) + h3 + t + t // m4
	r.y = fe_mul(t + rx, i) + fe_mul(h3, s1) // m2
	r.x = rx
}

// --- BMI2 copies of the hot paths -------------------------------------------
//
// With BMI2 the compiler multiplies through mulx, free of mul's fixed rax/rdx
// registers, which trims ~5% off the field arithmetic. The bodies above are
// force-inlined into these feature-enabled copies; ecmult and fe_sqr_n pick
// a copy from a CPUID probe cached on first use.

// 0 = unprobed, 1 = present, 2 = absent. A racing double-probe is harmless.
@(private = "file")
g_bmi2_state: u32

@(private = "file")
has_bmi2 :: #force_inline proc "contextless" () -> bool {
	s := intrinsics.atomic_load_explicit(&g_bmi2_state, .Relaxed)
	if s == 0 {
		s = detect_bmi2() ? 1 : 2
		intrinsics.atomic_store_explicit(&g_bmi2_state, s, .Relaxed)
	}
	return s == 1
}

@(private = "file")
detect_bmi2 :: proc "contextless" () -> bool {
	when ODIN_ARCH == .amd64 {
		max_id, _, _, _ := intrinsics.x86_cpuid(0, 0)
		if max_id < 7 {
			return false
		}
		_, ebx7, _, _ := intrinsics.x86_cpuid(7, 0)
		return ebx7 & (1 << 8) != 0
	} else {
		return false
	}
}

@(private = "file")
@(enable_target_feature = "bmi2")
fe_sqr_n_bmi2 :: proc "contextless" (a: Fe, n: int) -> Fe {
	return sqr_n_body(a, n)
}

@(private = "file")
@(enable_target_feature = "bmi2")
gej_double_bmi2 :: proc "contextless" (r: ^Gej) {
	dbl_body(r)
}

@(private = "file")
@(enable_target_feature = "bmi2")
gej_add_ge_bmi2 :: proc "contextless" (r: ^Gej, b: ^Ge) {
	add_ge_body(r, b, nil)
}

@(private = "file")
@(enable_target_feature = "bmi2")
gej_add_zinv_bmi2 :: proc "contextless" (r: ^Gej, b: ^Ge, bzinv: Fe) {
	add_zinv_body(r, b, bzinv)
}

// Affine coordinates, both normalized. r must not be infinity.
@(private = "file")
gej_to_ge :: proc "contextless" (r: Gej) -> Ge {
	zi := fe_inv(r.z)
	zi2 := fe_sqr(zi)
	return Ge{fe_norm(fe_mul(r.x, zi2)), fe_norm(fe_mul(r.y, fe_mul(zi2, zi)))}
}

// The even-y point with the given x; ok is false if x is not on the curve.
@(private = "file")
lift_x :: proc "contextless" (x: Fe) -> (p: Ge, ok: bool) {
	y := fe_sqrt(fe_mul(fe_sqr(x), x) + FE_SEVEN) or_return
	y = fe_norm(y)
	if y[0] & 1 == 1 {
		y = fe_norm(fe_neg(y, 1))
	}
	return Ge{x, y}, true
}

// --- wNAF and precomputed tables --------------------------------------------

@(private = "file") WINDOW_A :: 5 // P table: 1P, 3P, ..., 15P
@(private = "file") TBL_A :: 1 << (WINDOW_A - 2)
@(private = "file") WINDOW_G :: 15 // G tables: 8192 odd multiples each
@(private = "file") TBL_G :: 1 << (WINDOW_G - 2)
@(private = "file") WNAF_LEN :: 129 // digits of a <= 128-bit half scalar

// Width-w NAF of a, a ≡ ±(value < 2^128) mod n: digits are 0 or odd in
// (-2^(w-1), 2^(w-1)). Returns the number of digits (libsecp256k1 ecmult_wnaf).
@(private = "file")
wnaf :: proc "contextless" (out: ^[WNAF_LEN]i32, a: Sc, $W: int) -> int {
	out^ = {}
	s := a
	sign: i32 = 1
	if s[3] >> 63 == 1 {
		s = sc_neg(s)
		sign = -1
	}
	last := -1
	carry: u64
	bit := 0
	#no_bounds_check for bit < WNAF_LEN {
		if (s[bit >> 6] >> uint(bit & 63)) & 1 == carry {
			bit += 1
			continue
		}
		now := min(W, WNAF_LEN - bit)
		word := sc_bits(s, bit, now) + carry
		carry = (word >> uint(W - 1)) & 1
		out[bit] = sign * (i32(word) - i32(carry << uint(W)))
		last = bit
		bit += now
	}
	return last + 1
}

// count (< 64) bits of s starting at off.
@(private = "file")
sc_bits :: #force_inline proc "contextless" (s: Sc, off, count: int) -> u64 {
	lo := off >> 6
	sh := uint(off & 63)
	v: u64
	#no_bounds_check {
		v = s[lo] >> sh
		if int(sh) + count > 64 && lo < 3 {
			v |= s[lo + 1] << (64 - sh)
		}
	}
	return v & ((u64(1) << uint(count)) - 1)
}

// Normalized affine point in 4x64 form: one cache line per table entry.
@(private = "file")
Ge_Storage :: struct #align (64) {
	x, y: [4]u64,
}

@(private = "file") pre_g: [TBL_G]Ge_Storage // G, 3G, 5G, ...
@(private = "file") pre_g_128: [TBL_G]Ge_Storage // the same for 2^128*G
@(private = "file") g_tables_state: u32 // 0 = unbuilt, 1 = building, 2 = ready

// Table entry for a nonzero wNAF digit n.
@(private = "file")
storage_get :: #force_inline proc "contextless" (t: ^[TBL_G]Ge_Storage, n: i32) -> Ge {
	idx := n > 0 ? (n - 1) >> 1 : (-n - 1) >> 1
	#no_bounds_check s := &t[idx]
	g := Ge{fe_from_u64x4(s.x), fe_from_u64x4(s.y)}
	if n < 0 {
		g.y = fe_neg(g.y, 1)
	}
	return g
}

@(private = "file")
table_get :: #force_inline proc "contextless" (pre: ^[TBL_A]Ge, n: i32) -> Ge {
	if n > 0 {
		#no_bounds_check return pre[(n - 1) >> 1]
	}
	#no_bounds_check g := pre[(-n - 1) >> 1]
	g.y = fe_neg(g.y, 1)
	return g
}

// The G tables are ~1 MiB, so they are built on first use rather than at
// startup. One caller builds; racing callers spin until they are published.
@(private = "file")
ensure_tables :: #force_inline proc "contextless" () {
	if intrinsics.atomic_load_explicit(&g_tables_state, .Acquire) != 2 {
		build_tables()
	}
}

@(private = "file")
build_tables :: proc "contextless" () {
	_, won := intrinsics.atomic_compare_exchange_strong_explicit(&g_tables_state, 0, 1, .Acquire, .Acquire)
	if !won {
		for intrinsics.atomic_load_explicit(&g_tables_state, .Acquire) != 2 {
			intrinsics.cpu_relax()
		}
		return
	}
	g := Ge{FE_GX, FE_GY}
	fill_odd_multiples(pre_g[:], g)
	h := Gej{x = g.x, y = g.y, z = FE_ONE}
	for _ in 0 ..< 128 {
		gej_double(&h)
	}
	fill_odd_multiples(pre_g_128[:], gej_to_ge(h))
	intrinsics.atomic_store_explicit(&g_tables_state, 2, .Release)
}

// out[i] = (2i+1)*base, normalized affine. Points are generated in Jacobian
// form in chunks and converted with one inversion per chunk.
@(private = "file")
fill_odd_multiples :: proc "contextless" (out: []Ge_Storage, base: Ge) {
	CHUNK :: 64
	d := Gej{x = base.x, y = base.y, z = FE_ONE}
	gej_double(&d)
	two := gej_to_ge(d)
	cur := Gej{x = base.x, y = base.y, z = FE_ONE}
	jac: [CHUNK]Gej = ---
	acc: [CHUNK]Fe = ---
	#no_bounds_check for start := 0; start < len(out); start += CHUNK {
		cnt := min(CHUNK, len(out) - start)
		for j in 0 ..< cnt {
			jac[j] = cur
			gej_add_ge(&cur, &two)
		}
		acc[0] = jac[0].z
		for j in 1 ..< cnt {
			acc[j] = fe_mul(acc[j - 1], jac[j].z)
		}
		inv := fe_inv(acc[cnt - 1])
		for j := cnt - 1; j >= 0; j -= 1 {
			zi := j > 0 ? fe_mul(inv, acc[j - 1]) : inv
			inv = fe_mul(inv, jac[j].z)
			zi2 := fe_sqr(zi)
			x := fe_norm(fe_mul(jac[j].x, zi2))
			y := fe_norm(fe_mul(jac[j].y, fe_mul(zi2, zi)))
			out[start + j] = Ge_Storage{fe_to_u64x4(x), fe_to_u64x4(y)}
		}
	}
}

// Everything ecmult needs about P: odd multiples 1P..15P on the isomorphic
// curve where they all share one Z (entry (x, y) stands for the Jacobian
// point (x, y, z)), plus beta*x of each for the lambda half.
@(private = "file")
A_Table :: struct {
	pre:   [TBL_A]Ge,
	lam_x: [TBL_A]Fe,
	z:     Fe,
}

// libsecp256k1 odd_multiples_table + ge_table_set_globalz.
@(private = "file")
build_a_table :: proc "contextless" (t: ^A_Table, a: ^Ge) {
	// d = 2P is affine on the curve scaled by C = d.z, where P becomes
	// (x*C^2, y*C^3); every step is then a mixed addition of d.
	pre := &t.pre
	d := Gej{x = a.x, y = a.y, z = FE_ONE}
	gej_double(&d)
	dg := Ge{d.x, d.y}
	c2 := fe_sqr(d.z)
	pre[0] = Ge{fe_mul(a.x, c2), fe_mul(a.y, fe_mul(c2, d.z))}
	ai := Gej{x = pre[0].x, y = pre[0].y, z = FE_ONE}
	zr: [TBL_A]Fe = ---
	#no_bounds_check for i in 1 ..< TBL_A {
		gej_add_ge(&ai, &dg, &zr[i])
		pre[i] = Ge{ai.x, fe_norm_weak(ai.y)}
	}
	// Rescale every entry to the last entry's Z using the z ratios.
	zs := zr[TBL_A - 1]
	#no_bounds_check for i := TBL_A - 2; i >= 0; i -= 1 {
		if i != TBL_A - 2 {
			zs = fe_mul(zs, zr[i + 1])
		}
		zs2 := fe_sqr(zs)
		pre[i] = Ge{fe_mul(pre[i].x, zs2), fe_mul(pre[i].y, fe_mul(zs2, zs))}
	}
	#no_bounds_check for i in 0 ..< TBL_A {
		t.lam_x[i] = fe_mul(pre[i].x, FE_BETA)
	}
	t.z = fe_mul(ai.z, d.z)
}

// Per-thread cache of pubkey precomputation (lift_x's square root and the A
// table: ~15% of a verify), since a server sees the same keys over and over.
// Direct-mapped on the key's last byte; it holds only public data.
@(private = "file")
Pub_Slot :: struct {
	key: [32]u8,
	ok:  bool,
	tbl: A_Table,
}

@(private = "file")
@(thread_local)
pub_slots: [16]Pub_Slot

// The A table of a 32-byte x-only pubkey, cached or built into the cache;
// nil if the key is not the x coordinate of a curve point.
@(private = "file")
pubkey_table :: proc "contextless" (pubkey: []u8) -> ^A_Table {
	key := (^[32]u8)(raw_data(pubkey))^
	#no_bounds_check slot := &pub_slots[key[31] & 15]
	if slot.ok && slot.key == key {
		return &slot.tbl
	}
	px, in_field := fe_from_b32(pubkey)
	if !in_field {
		return nil
	}
	p, on_curve := lift_x(px)
	if !on_curve {
		return nil
	}
	build_a_table(&slot.tbl, &p)
	slot.key = key
	slot.ok = true
	return &slot.tbl
}

// r = na*A + ng*G (t, A's table, may be nil) in one Strauss-Shamir pass: na
// split by GLV against the A table, ng split into 128-bit halves against the
// G tables.
@(private = "file")
ecmult :: proc "contextless" (t: ^A_Table, na, ng: Sc) -> Gej {
	if has_bmi2() {
		return ecmult_with(t, na, ng, true)
	}
	return ecmult_with(t, na, ng, false)
}

@(private = "file")
ecmult_with :: proc "contextless" (t: ^A_Table, na, ng: Sc, $BMI2: bool) -> Gej {
	dbl :: #force_inline proc "contextless" (r: ^Gej) {
		when BMI2 {gej_double_bmi2(r)} else {gej_double(r)}
	}
	add :: #force_inline proc "contextless" (r: ^Gej, b: ^Ge) {
		when BMI2 {gej_add_ge_bmi2(r, b)} else {gej_add_ge(r, b)}
	}
	add_zinv :: #force_inline proc "contextless" (r: ^Gej, b: ^Ge, z: Fe) {
		when BMI2 {gej_add_zinv_bmi2(r, b, z)} else {gej_add_zinv(r, b, z)}
	}

	w1: [WNAF_LEN]i32 = ---
	wl: [WNAF_LEN]i32 = ---
	wg1: [WNAF_LEN]i32 = ---
	wg2: [WNAF_LEN]i32 = ---
	b1, bl := 0, 0
	z := FE_ONE
	if t != nil && na != (Sc{}) {
		n1, nl := sc_split_lambda(na)
		b1 = wnaf(&w1, n1, WINDOW_A)
		bl = wnaf(&wl, nl, WINDOW_A)
		z = t.z
	}
	bg1 := wnaf(&wg1, Sc{ng[0], ng[1], 0, 0}, WINDOW_G)
	bg2 := wnaf(&wg2, Sc{ng[2], ng[3], 0, 0}, WINDOW_G)

	r := Gej{inf = true}
	#no_bounds_check for i := max(b1, bl, bg1, bg2) - 1; i >= 0; i -= 1 {
		dbl(&r)
		if i < b1 && w1[i] != 0 {
			g := table_get(&t.pre, w1[i])
			add(&r, &g)
		}
		if i < bl && wl[i] != 0 {
			g := table_get(&t.pre, wl[i])
			g.x = t.lam_x[(abs(wl[i]) - 1) >> 1]
			add(&r, &g)
		}
		if i < bg1 && wg1[i] != 0 {
			g := storage_get(&pre_g, wg1[i])
			add_zinv(&r, &g, z)
		}
		if i < bg2 && wg2[i] != 0 {
			g := storage_get(&pre_g_128, wg2[i])
			add_zinv(&r, &g, z)
		}
	}
	if !r.inf {
		r.z = fe_mul(r.z, z)
	}
	return r
}

// k*G as a normalized affine point; ok is false for k ≡ 0.
@(private = "file")
gen_mul :: proc "contextless" (k: Sc) -> (Ge, bool) {
	ensure_tables()
	r := ecmult(nil, {}, k)
	if r.inf {
		return {}, false
	}
	return gej_to_ge(r), true
}

// --- BIP-340 ----------------------------------------------------------------

// SHA-256 state after absorbing SHA256(tag) || SHA256(tag): exactly one
// block, so each tagged hash starts from this midstate.
@(private = "file") mid_challenge: [8]u32
@(private = "file") mid_aux: [8]u32
@(private = "file") mid_nonce: [8]u32

@(init)
init_secp_tags :: proc "contextless" () {
	mid_challenge = tag_midstate("BIP0340/challenge")
	mid_aux = tag_midstate("BIP0340/aux")
	mid_nonce = tag_midstate("BIP0340/nonce")
}

@(private = "file")
tag_midstate :: proc "contextless" (tag: string) -> [8]u32 {
	th := sha256(transmute([]u8)tag)
	ctx: Sha256_Ctx
	sha256_init(&ctx)
	sha256_update(&ctx, th[:])
	sha256_update(&ctx, th[:])
	return ctx.state
}

@(private = "file")
tagged_hash :: proc "contextless" (mid: [8]u32, parts: ..[]u8) -> [32]u8 {
	ctx := Sha256_Ctx {
		state = mid,
		total = 64,
	}
	for p in parts {
		sha256_update(&ctx, p)
	}
	return sha256_final(&ctx)
}

// Verify a 64-byte BIP-340 Schnorr signature.
//   pubkey: 32-byte x-only public key
//   msg:    any length (here, a 32-byte Nostr event id)
//   sig:    64 bytes (r || s)
schnorr_verify :: proc "contextless" (pubkey, msg, sig: []u8) -> bool {
	if len(pubkey) != 32 || len(sig) != 64 {
		return false
	}
	r, r_ok := fe_from_b32(sig[0:32])
	s, s_over := sc_from_b32(sig[32:64])
	if !r_ok || s_over {
		return false
	}
	// P = lift_x(pubkey); fails if x >= p or x is not on the curve.
	tbl := pubkey_table(pubkey)
	if tbl == nil {
		return false
	}

	// e = H(r || P || m) mod n; R = s*G - e*P.
	ch := tagged_hash(mid_challenge, sig[0:32], pubkey, msg)
	e := sc_reduce_b32(ch[:])
	ensure_tables()
	rj := ecmult(tbl, sc_neg(e), s)
	if rj.inf {
		return false
	}
	// R.x == r is checked projectively (r*Z^2 == X), so a mismatch costs no
	// inversion; only the y parity needs the affine Y/Z^3.
	z2 := fe_sqr(rj.z)
	if !fe_equal(fe_mul(r, z2), rj.x) {
		return false
	}
	zi := fe_inv(rj.z)
	y := fe_norm(fe_mul(rj.y, fe_mul(fe_sqr(zi), zi)))
	return y[0] & 1 == 0
}

// --- signing (used to mint test authorization tokens) ---------------------

// Return the 32-byte x-only public key for a secret key.
schnorr_pubkey :: proc "contextless" (seckey: []u8) -> (out: [32]u8, ok: bool) {
	if len(seckey) != 32 {
		return {}, false
	}
	d, over := sc_from_b32(seckey)
	if over || d == (Sc{}) {
		return {}, false
	}
	p := gen_mul(d) or_return
	return u256_to_be(fe_to_u64x4(p.x)), true
}

// Produce a 64-byte BIP-340 signature (aux randomness fixed to zero — fine for
// minting test tokens; not for production key material).
schnorr_sign :: proc "contextless" (seckey, msg: []u8) -> (out: [64]u8, ok: bool) {
	if len(seckey) != 32 {
		return {}, false
	}
	d, over := sc_from_b32(seckey)
	if over || d == (Sc{}) {
		return {}, false
	}
	p := gen_mul(d) or_return
	if p.y[0] & 1 == 1 {
		d = sc_neg(d)
	}

	aux: [32]u8
	aux_h := tagged_hash(mid_aux, aux[:])
	d_be := u256_to_be(d)
	t: [32]u8 = ---
	for i in 0 ..< 32 {
		t[i] = d_be[i] ~ aux_h[i]
	}
	px_be := u256_to_be(fe_to_u64x4(p.x))

	nonce := tagged_hash(mid_nonce, t[:], px_be[:], msg)
	k := sc_reduce_b32(nonce[:])
	if k == (Sc{}) {
		return {}, false
	}
	rp := gen_mul(k) or_return
	if rp.y[0] & 1 == 1 {
		k = sc_neg(k)
	}
	rx_be := u256_to_be(fe_to_u64x4(rp.x))

	ch := tagged_hash(mid_challenge, rx_be[:], px_be[:], msg)
	e := sc_reduce_b32(ch[:])
	s_be := u256_to_be(sc_add(k, sc_mul(e, d)))
	#no_bounds_check {
		copy(out[0:32], rx_be[:])
		copy(out[32:64], s_be[:])
	}
	return out, true
}

// --- internal unit tests (field / scalar / point arithmetic) --------------
//
// These reach into the file-private primitives that the public API never
// exposes, validating them directly rather than only through verify/sign.

@(private = "file")
fe_from_hex :: proc(s: string) -> Fe {
	b: [32]u8
	hex_decode(b[:], s)
	f, _ := fe_from_b32(b[:])
	return f
}

@(private = "file")
sc_from_hex :: proc(s: string) -> Sc {
	b: [32]u8
	hex_decode(b[:], s)
	return u256_from_be(b[:])
}

// x and y of k*G, normalized.
@(private = "file")
mul_g :: proc(k: Sc) -> Ge {
	p, _ := gen_mul(k)
	return p
}

secp_unit_tests :: proc() -> (pass: int, fail: int) {
	check :: proc(name: string, ok: bool, pass, fail: ^int) {
		if ok {
			pass^ += 1
		} else {
			fail^ += 1
		}
		fmt.printfln("  [%s] %s", ok ? "PASS" : "FAIL", name)
	}

	// Field: a * a^-1 == 1 for several a.
	for a in ([]Fe{{2, 0, 0, 0, 0}, {7, 0, 0, 0, 0}, FE_GX, FE_GY}) {
		check("fe_inv round-trip", fe_equal(fe_mul(a, fe_inv(a)), FE_ONE), &pass, &fail)
	}

	// Field: (sqrt(a^2))^2 == a^2 (modular square root, p ≡ 3 mod 4).
	{
		sq := fe_sqr(FE_SEVEN)
		r, ok := fe_sqrt(sq)
		check("fe_sqrt^2 == square", ok && fe_equal(fe_sqr(r), sq), &pass, &fail)
	}

	// Field: lazy-magnitude negation, halving, full normalization.
	{
		a := FE_GX
		check("fe_neg: a + (-a) == 0", fe_is_zero(a + fe_neg(a, 1)), &pass, &fail)
		h := fe_half(a)
		check("fe_half: h + h == a", fe_equal(a, h + h), &pass, &fail)
		p_plus_gx := a + Fe{P0, M52, M52, M52, M48}
		check("fe_norm(a + p) == a", fe_norm(p_plus_gx) == a, &pass, &fail)
	}

	// Scalar: (n-1)^2 == 1 (mod n), and the GLV split recombines.
	{
		nm1 := u256_sub(SC_N, Sc{1, 0, 0, 0})
		check("sc_mul (n-1)^2 == 1", sc_mul(nm1, nm1) == Sc{1, 0, 0, 0}, &pass, &fail)
		k := sc_from_hex("a5261c028812645a122e22ea20816678df02967c1b23bd725363ad4cc05c30e0")
		r1, r2 := sc_split_lambda(k)
		small := proc(s: Sc) -> bool {
			t := s[3] >> 63 == 1 ? sc_neg(s) : s
			return t[2] == 0 && t[3] == 0
		}
		ok := sc_add(r1, sc_mul(r2, SC_LAMBDA)) == k && small(r1) && small(r2)
		check("GLV split: k == r1 + r2*lambda, halves < 2^128", ok, &pass, &fail)
	}

	G := Ge{FE_GX, FE_GY}

	// Point: known x-coordinates of small multiples of G.
	// k=3 is corroborated by BIP-340 vector 0 (seckey=3); k=2 is the standard
	// published doubling of the generator.
	want2 := fe_from_hex("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	want3 := fe_from_hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
	check("2*G x-coordinate", mul_g(Sc{2, 0, 0, 0}).x == want2, &pass, &fail)
	check("3*G x-coordinate", mul_g(Sc{3, 0, 0, 0}).x == want3, &pass, &fail)

	// Point: (n-1)*G == -G, so x matches Gx and y is odd.
	{
		p := mul_g(u256_sub(SC_N, Sc{1, 0, 0, 0}))
		check("(n-1)*G == -G", p.x == FE_GX && p.y[0] & 1 == 1, &pass, &fail)
	}

	// Point: 2G + G == 3G through the Jacobian double and mixed add.
	{
		p := Gej{x = G.x, y = G.y, z = FE_ONE}
		gej_double(&p)
		gej_add_ge(&p, &G)
		check("2G + G == 3G", gej_to_ge(p).x == want3, &pass, &fail)
	}

	// Endomorphism: lambda*G == (beta*Gx, Gy).
	{
		p := mul_g(SC_LAMBDA)
		check("lambda*G == (beta*Gx, Gy)", p.x == fe_norm(fe_mul(FE_GX, FE_BETA)) && p.y == FE_GY, &pass, &fail)
	}

	// Strauss-Shamir: a*(7G) + b*G == (7a + b)*G.
	{
		a := sc_from_hex("6f547fa90abfe4c3e4437ed6010e88283086d221a7d46bcde86c90e49284eb15")
		b := sc_from_hex("d765cda83db1562c8a280ac50774346d5363ad4cc05c30e0a5261c028812645a")
		seven := mul_g(Sc{7, 0, 0, 0})
		tbl: A_Table
		build_a_table(&tbl, &seven)
		ensure_tables()
		got := gej_to_ge(ecmult(&tbl, a, b))
		want := mul_g(sc_add(sc_mul(a, Sc{7, 0, 0, 0}), b))
		check("a*(7G) + b*G == (7a+b)*G", got == want, &pass, &fail)
	}

	// lift_x(Gx) recovers Gy (with even y — Gy is even).
	{
		pt, ok := lift_x(FE_GX)
		check("lift_x(Gx) == (Gx,Gy)", ok && pt.x == FE_GX && pt.y == FE_GY, &pass, &fail)
	}

	return pass, fail
}
