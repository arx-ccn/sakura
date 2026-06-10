package sakura

import "core:fmt"

// Dependency-free secp256k1 + BIP-340 Schnorr verification.
//
// Field elements and scalars are 256-bit, stored as four little-endian u64
// limbs. This is variable-time arithmetic — that's fine and in fact desirable
// here: signature verification operates exclusively on public data (the Nostr
// event, its pubkey and signature), so there is no secret to leak through
// timing, and dropping the constant-time requirement buys real speed.
//
// p = 2^256 - 2^32 - 977   (field prime)
// n = curve order
// Curve: y^2 = x^3 + 7

Fe :: [4]u64

@(private = "file") P := Fe{0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
@(private = "file") N := Fe{0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF}
@(private = "file") P_MINUS_2 := Fe{0xFFFFFFFEFFFFFC2D, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
// (p+1)/4, the exponent for the modular square root since p ≡ 3 (mod 4).
@(private = "file") P_PLUS_1_DIV_4 := Fe{0xFFFFFFFFBFFFFF0C, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF}

// secp256k1 generator point, affine.
@(private = "file") GX := Fe{0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC}
@(private = "file") GY := Fe{0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465}

ZERO :: Fe{0, 0, 0, 0}
ONE :: Fe{1, 0, 0, 0}

// --- limb helpers ---------------------------------------------------------

@(private = "file")
add4 :: proc "contextless" (a, b: Fe) -> (Fe, u64) {
	r: Fe = ---
	carry: u128 = 0
	#no_bounds_check for i in 0 ..< 4 {
		v := u128(a[i]) + u128(b[i]) + carry
		r[i] = u64(v)
		carry = v >> 64
	}
	return r, u64(carry)
}

@(private = "file")
sub4 :: proc "contextless" (a, b: Fe) -> (Fe, u64) {
	r: Fe = ---
	borrow: u128 = 0
	#no_bounds_check for i in 0 ..< 4 {
		bi := u128(b[i]) + borrow
		ai := u128(a[i])
		if ai >= bi {
			r[i] = u64(ai - bi)
			borrow = 0
		} else {
			r[i] = u64(ai + (u128(1) << 64) - bi)
			borrow = 1
		}
	}
	return r, u64(borrow)
}

@(private = "file")
geq4 :: proc "contextless" (a, b: Fe) -> bool {
	#no_bounds_check for i := 3; i >= 0; i -= 1 {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// --- field arithmetic mod p ----------------------------------------------

@(private = "file")
fe_reduce :: proc "contextless" (t: [8]u64) -> Fe {
	C :: 0x1000003D1 // 2^256 ≡ C (mod p)
	r: Fe = ---
	carry: u128 = 0
	#no_bounds_check for i in 0 ..< 4 {
		v := u128(t[i]) + u128(u64(C)) * u128(t[i + 4]) + carry
		r[i] = u64(v)
		carry = v >> 64
	}
	for carry != 0 {
		c2 := u128(u64(C)) * carry
		carry = 0
		v0 := u128(r[0]) + c2
		r[0] = u64(v0)
		cc := v0 >> 64
		i := 1
		for cc != 0 {
			if i < 4 {
				#no_bounds_check v := u128(r[i]) + cc
				#no_bounds_check r[i] = u64(v)
				cc = v >> 64
				i += 1
			} else {
				carry = cc
				cc = 0
			}
		}
	}
	if geq4(r, P) {
		r, _ = sub4(r, P)
	}
	return r
}

@(private = "file")
fe_mul :: proc "contextless" (a, b: Fe) -> Fe {
	prod: [8]u64 // zero-initialized
	#no_bounds_check for i in 0 ..< 4 {
		carry: u64 = 0
		for j in 0 ..< 4 {
			v := u128(a[i]) * u128(b[j]) + u128(prod[i + j]) + u128(carry)
			prod[i + j] = u64(v)
			carry = u64(v >> 64)
		}
		prod[i + 4] = carry
	}
	return fe_reduce(prod)
}

// Dedicated squaring: schoolbook with the symmetric off-diagonal products
// computed once and doubled, so 10 limb multiplications instead of the 16 a
// generic fe_mul(a, a) would perform. point_double is squaring-heavy, so this
// is a meaningful win on the hot path.
@(private = "file")
fe_sqr :: proc "contextless" (a: Fe) -> Fe {
	prod: [8]u64 // zero-initialized

	// Accumulate the off-diagonal cross terms a[i]*a[j] (i < j) once, doubling
	// each as it is added. Carries propagate up through the product limbs.
	#no_bounds_check {
		add_at :: proc "contextless" (prod: ^[8]u64, idx: int, add: u128) {
			i := idx
			c := add
			for c != 0 && i < 8 {
				v := u128(prod[i]) + c
				prod[i] = u64(v)
				c = v >> 64
				i += 1
			}
		}

		// j > i pairs, each contributing 2*a[i]*a[j].
		for i in 0 ..< 4 {
			for j in i + 1 ..< 4 {
				m := u128(a[i]) * u128(a[j])
				// 2*m may exceed 128 bits; split the doubling carefully.
				lo := m << 1
				hi := m >> 127 // top bit shifted out by the doubling
				add_at(&prod, i + j, lo)
				if hi != 0 {
					add_at(&prod, i + j + 2, hi)
				}
			}
		}
		// Diagonal squares a[i]*a[i].
		for i in 0 ..< 4 {
			add_at(&prod, 2 * i, u128(a[i]) * u128(a[i]))
		}
	}
	return fe_reduce(prod)
}

@(private = "file")
fe_add :: proc "contextless" (a, b: Fe) -> Fe {
	r, c := add4(a, b)
	t: [8]u64
	t[0] = r[0]; t[1] = r[1]; t[2] = r[2]; t[3] = r[3]; t[4] = c
	return fe_reduce(t)
}

@(private = "file")
fe_sub :: proc "contextless" (a, b: Fe) -> Fe {
	r, borrow := sub4(a, b)
	if borrow != 0 {
		r, _ = add4(r, P)
	}
	return r
}

@(private = "file")
fe_neg :: proc "contextless" (a: Fe) -> Fe {
	if a == ZERO {
		return ZERO
	}
	r, _ := sub4(P, a)
	return r
}

@(private = "file")
fe_pow :: proc "contextless" (a: Fe, e: Fe) -> Fe {
	result := ONE
	base := a
	#no_bounds_check for i in 0 ..< 256 {
		if (e[i / 64] >> uint(i % 64)) & 1 == 1 {
			result = fe_mul(result, base)
		}
		base = fe_sqr(base)
	}
	return result
}

@(private = "file")
fe_inv :: proc "contextless" (a: Fe) -> Fe {
	return fe_pow(a, P_MINUS_2)
}

@(private = "file")
fe_is_odd :: proc "contextless" (a: Fe) -> bool {
	return (a[0] & 1) == 1
}

@(private = "file")
fe_from_be :: proc "contextless" (b: []u8) -> Fe {
	f: Fe = ---
	#no_bounds_check for i in 0 ..< 4 {
		base := (3 - i) * 8
		f[i] =
			(u64(b[base]) << 56) | (u64(b[base + 1]) << 48) | (u64(b[base + 2]) << 40) |
			(u64(b[base + 3]) << 32) | (u64(b[base + 4]) << 24) | (u64(b[base + 5]) << 16) |
			(u64(b[base + 6]) << 8) | u64(b[base + 7])
	}
	return f
}

// --- points (Jacobian coordinates) ---------------------------------------
//
// Affine (x, y) maps to (X, Y, Z) with x = X/Z^2, y = Y/Z^3. The point at
// infinity is represented by Z = 0.

Point :: struct {
	x, y, z: Fe,
}

@(private = "file")
point_is_inf :: proc "contextless" (p: Point) -> bool {
	return p.z == ZERO
}

@(private = "file")
point_double :: proc "contextless" (p: Point) -> Point {
	if p.z == ZERO || p.y == ZERO {
		return Point{ZERO, ZERO, ZERO}
	}
	// dbl-2009-l (a = 0)
	a := fe_sqr(p.x)
	b := fe_sqr(p.y)
	c := fe_sqr(b)
	t := fe_add(p.x, b)
	d := fe_sub(fe_sub(fe_sqr(t), a), c)
	d = fe_add(d, d)
	e := fe_add(fe_add(a, a), a)
	f := fe_sqr(e)
	x3 := fe_sub(f, fe_add(d, d))
	y3 := fe_sub(fe_mul(e, fe_sub(d, x3)), fe_add(fe_add(fe_add(c, c), fe_add(c, c)), fe_add(fe_add(c, c), fe_add(c, c))))
	z3 := fe_add(fe_mul(p.y, p.z), fe_mul(p.y, p.z))
	return Point{x3, y3, z3}
}

@(private = "file")
point_add :: proc "contextless" (p, q: Point) -> Point {
	if p.z == ZERO {
		return q
	}
	if q.z == ZERO {
		return p
	}
	// add-2007-bl
	z1z1 := fe_sqr(p.z)
	z2z2 := fe_sqr(q.z)
	u1 := fe_mul(p.x, z2z2)
	u2 := fe_mul(q.x, z1z1)
	s1 := fe_mul(fe_mul(p.y, q.z), z2z2)
	s2 := fe_mul(fe_mul(q.y, p.z), z1z1)
	if u1 == u2 {
		if s1 != s2 {
			return Point{ZERO, ZERO, ZERO} // P + (-P) = infinity
		}
		return point_double(p)
	}
	h := fe_sub(u2, u1)
	i := fe_sqr(fe_add(h, h))
	j := fe_mul(h, i)
	r := fe_add(fe_sub(s2, s1), fe_sub(s2, s1))
	v := fe_mul(u1, i)
	x3 := fe_sub(fe_sub(fe_sqr(r), j), fe_add(v, v))
	y3 := fe_sub(fe_mul(r, fe_sub(v, x3)), fe_add(fe_mul(s1, j), fe_mul(s1, j)))
	z3 := fe_mul(fe_sub(fe_sub(fe_sqr(fe_add(p.z, q.z)), z1z1), z2z2), h)
	return Point{x3, y3, z3}
}

// Mixed addition: add an affine point q (implicitly z = 1) to a Jacobian point
// p. Because q.z == 1, the z2z2/s1-style multiplications by powers of q.z drop
// out, saving ~4-5 field multiplications versus the general point_add. Used for
// folding precomputed (affine) table entries into an accumulator.
@(private = "file")
point_add_mixed :: proc "contextless" (p: Point, qx, qy: Fe) -> Point {
	if p.z == ZERO {
		return Point{qx, qy, ONE}
	}
	// madd-2007-bl (q.z = 1)
	z1z1 := fe_sqr(p.z)
	u2 := fe_mul(qx, z1z1)
	s2 := fe_mul(fe_mul(qy, p.z), z1z1)
	if p.x == u2 {
		if p.y != s2 {
			return Point{ZERO, ZERO, ZERO} // P + (-P) = infinity
		}
		return point_double(p)
	}
	h := fe_sub(u2, p.x)
	hh := fe_sqr(h)
	i := fe_add(hh, hh)
	i = fe_add(i, i)
	j := fe_mul(h, i)
	r := fe_sub(s2, p.y)
	r = fe_add(r, r)
	v := fe_mul(p.x, i)
	x3 := fe_sub(fe_sub(fe_sqr(r), j), fe_add(v, v))
	y3 := fe_sub(fe_mul(r, fe_sub(v, x3)), fe_add(fe_mul(p.y, j), fe_mul(p.y, j)))
	z3 := fe_mul(fe_add(p.z, h), fe_add(p.z, h))
	z3 = fe_sub(fe_sub(z3, z1z1), hh)
	return Point{x3, y3, z3}
}

// Variable-time scalar multiplication k·P via double-and-add (k < 2^256).
@(private = "file")
scalar_mul :: proc "contextless" (p: Point, k: Fe) -> Point {
	r := Point{ZERO, ZERO, ZERO}
	#no_bounds_check for i := 255; i >= 0; i -= 1 {
		r = point_double(r)
		if (k[i / 64] >> uint(i % 64)) & 1 == 1 {
			r = point_add(r, p)
		}
	}
	return r
}

@(private = "file")
to_affine :: proc "contextless" (p: Point) -> (x: Fe, y: Fe, ok: bool) {
	if p.z == ZERO {
		return ZERO, ZERO, false
	}
	zinv := fe_inv(p.z)
	zinv2 := fe_sqr(zinv)
	zinv3 := fe_mul(zinv2, zinv)
	return fe_mul(p.x, zinv2), fe_mul(p.y, zinv3), true
}

// lift_x: recover the even-y curve point with the given x coordinate.
@(private = "file")
lift_x :: proc "contextless" (x: Fe) -> (Point, bool) {
	// c = x^3 + 7
	c := fe_add(fe_mul(fe_sqr(x), x), Fe{7, 0, 0, 0})
	y := fe_pow(c, P_PLUS_1_DIV_4)
	if fe_sqr(y) != c {
		return {}, false // x is not on the curve
	}
	if fe_is_odd(y) {
		y = fe_neg(y)
	}
	return Point{x, y, ONE}, true
}

// --- windowed / precomputed scalar multiplication -------------------------
//
// All of this is variable-time by design: the inputs are public (a signature
// and pubkey), so branching on scalar bits leaks nothing of value.

// Affine point used in precomputed tables (z is implicitly 1).
@(private = "file")
Affine :: struct {
	x, y: Fe,
}

WNAF_W :: 5 // window width for the variable base (pubkey)
WNAF_TBL :: 1 << (WNAF_W - 2) // number of stored odd multiples: 1,3,5,...,2^(w-1)-1

// width-w NAF of a 256-bit scalar. Returns the digit sequence (LSB first) and
// its length. Digits are odd integers in (-2^(w-1), 2^(w-1)) or zero. The
// number of nonzero digits is ~ 256/(w+1).
@(private = "file")
wnaf :: proc "contextless" (k: Fe, w: uint) -> (digits: [257]i32, n: int) {
	// Operate on a mutable copy of k as a little-endian bigint (extra limb to
	// absorb the borrow/carry from the signed-digit subtraction).
	d: [5]u64
	d[0] = k[0]; d[1] = k[1]; d[2] = k[2]; d[3] = k[3]; d[4] = 0

	is_zero :: proc "contextless" (d: ^[5]u64) -> bool {
		return d[0] == 0 && d[1] == 0 && d[2] == 0 && d[3] == 0 && d[4] == 0
	}

	width := 1 << w // 2^w
	half := i64(1 << (w - 1)) // 2^(w-1)
	i := 0
	#no_bounds_check for !is_zero(&d) {
		if d[0] & 1 == 1 {
			// signed remainder mod 2^w, in (-2^(w-1), 2^(w-1)]
			rem := i64(d[0] & u64(width - 1))
			if rem >= half {
				rem -= i64(width)
			}
			digits[i] = i32(rem)
			// d -= rem  (rem may be negative)
			if rem > 0 {
				borrow := u64(rem)
				j := 0
				for borrow != 0 {
					v := d[j]
					d[j] = v - borrow
					borrow = d[j] > v ? 1 : 0
					j += 1
				}
			} else if rem < 0 {
				carry := u64(-rem)
				j := 0
				for carry != 0 {
					v := d[j] + carry
					carry = v < d[j] ? 1 : 0
					d[j] = v
					j += 1
				}
			}
		} else {
			digits[i] = 0
		}
		// d >>= 1
		d[0] = (d[0] >> 1) | (d[1] << 63)
		d[1] = (d[1] >> 1) | (d[2] << 63)
		d[2] = (d[2] >> 1) | (d[3] << 63)
		d[3] = (d[3] >> 1) | (d[4] << 63)
		d[4] = d[4] >> 1
		i += 1
	}
	return digits, i
}

// --- fixed-base table for the generator G ---------------------------------
//
// G is constant, so we precompute its odd multiples once at startup and reuse
// them for every s·G (verify), d·G (pubkey) and k·G (sign). Stored affine so
// the hot loop can use point_add_mixed.

FIXED_W :: 6 // window width for the fixed base
FIXED_TBL :: 1 << (FIXED_W - 2) // odd multiples 1,3,...,2^(w-1)-1

@(private = "file") g_odd: [FIXED_TBL]Affine // 1·G, 3·G, 5·G, ...
@(private = "file") tag_challenge: [32]u8 // cached SHA256("BIP0340/challenge")
@(private = "file") tag_aux: [32]u8 // cached SHA256("BIP0340/aux")
@(private = "file") tag_nonce: [32]u8 // cached SHA256("BIP0340/nonce")
@(private = "file") tables_ready: bool

// Convert a slice of Jacobian points to affine using a single field inversion
// (Montgomery's batch trick).
@(private = "file")
batch_to_affine :: proc "contextless" (pts: []Point, out: []Affine) {
	n := len(pts)
	if n == 0 {
		return
	}
	prefix := make_local(n)
	acc := ONE
	#no_bounds_check for i in 0 ..< n {
		acc = fe_mul(acc, pts[i].z)
		prefix[i] = acc
	}
	inv := fe_inv(acc)
	#no_bounds_check for i := n - 1; i >= 0; i -= 1 {
		zinv: Fe = ---
		if i == 0 {
			zinv = inv
		} else {
			zinv = fe_mul(inv, prefix[i - 1])
		}
		inv = fe_mul(inv, pts[i].z)
		zinv2 := fe_sqr(zinv)
		zinv3 := fe_mul(zinv2, zinv)
		out[i] = Affine{fe_mul(pts[i].x, zinv2), fe_mul(pts[i].y, zinv3)}
	}
}

// Tiny fixed-capacity scratch buffer so batch_to_affine needs no allocator in a
// contextless setting. FIXED_TBL is the largest n we ever pass.
@(private = "file") batch_scratch: [FIXED_TBL]Fe
@(private = "file")
make_local :: proc "contextless" (n: int) -> []Fe {
	return batch_scratch[:n]
}

@(init)
init_secp_tables :: proc "contextless" () {
	// Cache the BIP-340 tag hashes (each a constant SHA256 of an ASCII tag).
	tag_challenge = sha256(transmute([]u8)string("BIP0340/challenge"))
	tag_aux = sha256(transmute([]u8)string("BIP0340/aux"))
	tag_nonce = sha256(transmute([]u8)string("BIP0340/nonce"))

	// Build odd multiples of G: 1G, 3G, 5G, ... in Jacobian, then batch-convert.
	G := Point{GX, GY, ONE}
	g2 := point_double(G)
	jac: [FIXED_TBL]Point
	jac[0] = G
	for i in 1 ..< FIXED_TBL {
		jac[i] = point_add(jac[i - 1], g2)
	}
	aff: [FIXED_TBL]Affine
	batch_to_affine(jac[:], aff[:])
	for i in 0 ..< FIXED_TBL {
		g_odd[i] = aff[i]
	}
	tables_ready = true
}

// s·G using the precomputed fixed-base odd-multiple table and width-FIXED_W
// wNAF. Falls back to plain scalar_mul if (defensively) the table is unbuilt.
@(private = "file")
fixed_base_mul :: proc "contextless" (k: Fe) -> Point {
	if !tables_ready {
		return scalar_mul(Point{GX, GY, ONE}, k)
	}
	digits, n := wnaf(k, FIXED_W)
	r := Point{ZERO, ZERO, ZERO}
	#no_bounds_check for i := n - 1; i >= 0; i -= 1 {
		r = point_double(r)
		dgt := digits[i]
		if dgt > 0 {
			e := g_odd[(dgt - 1) / 2]
			r = point_add_mixed(r, e.x, e.y)
		} else if dgt < 0 {
			e := g_odd[(-dgt - 1) / 2]
			r = point_add_mixed(r, e.x, fe_neg(e.y))
		}
	}
	return r
}

// Combined R = s·G + l·P (Strauss/Shamir interleaving): a single double-and-add
// loop shares the doublings between both scalar multiplications. s·G uses the
// fixed-base table; l·P uses a per-call wNAF table of odd multiples of P.
@(private = "file")
double_scalar_mul :: proc "contextless" (s: Fe, p: Point, l: Fe) -> Point {
	// Build odd multiples of P: 1P, 3P, 5P, ..., as affine via one batch inv.
	p2 := point_double(p)
	pj: [WNAF_TBL]Point
	pj[0] = p
	#no_bounds_check for i in 1 ..< WNAF_TBL {
		pj[i] = point_add(pj[i - 1], p2)
	}
	p_odd: [WNAF_TBL]Affine
	batch_to_affine(pj[:], p_odd[:])

	sd, sn := wnaf(s, FIXED_W)
	ld, ln := wnaf(l, WNAF_W)
	m := sn > ln ? sn : ln

	r := Point{ZERO, ZERO, ZERO}
	#no_bounds_check for i := m - 1; i >= 0; i -= 1 {
		r = point_double(r)
		if i < sn {
			dgt := sd[i]
			if dgt > 0 {
				e := g_odd[(dgt - 1) / 2]
				r = point_add_mixed(r, e.x, e.y)
			} else if dgt < 0 {
				e := g_odd[(-dgt - 1) / 2]
				r = point_add_mixed(r, e.x, fe_neg(e.y))
			}
		}
		if i < ln {
			dgt := ld[i]
			if dgt > 0 {
				e := p_odd[(dgt - 1) / 2]
				r = point_add_mixed(r, e.x, e.y)
			} else if dgt < 0 {
				e := p_odd[(-dgt - 1) / 2]
				r = point_add_mixed(r, e.x, fe_neg(e.y))
			}
		}
	}
	return r
}

// --- BIP-340 verification -------------------------------------------------

@(private = "file")
sc_reduce_be :: proc "contextless" (b: []u8) -> Fe {
	v := fe_from_be(b)
	if geq4(v, N) {
		v, _ = sub4(v, N) // input < 2n, so a single subtraction suffices
	}
	return v
}

// Tagged hash per BIP-340: SHA256(SHA256(tag) || SHA256(tag) || data).
// tag = "BIP0340/challenge", data = r || pubkey || msg (each 32 bytes).
@(private = "file")
challenge_hash :: proc "contextless" (r_bytes, pubkey, msg: []u8) -> [32]u8 {
	// tag is the cached SHA256("BIP0340/challenge"), precomputed at startup.
	tag := tag_challenge
	ctx: Sha256_Ctx = ---
	sha256_init(&ctx)
	sha256_update(&ctx, tag[:])
	sha256_update(&ctx, tag[:])
	sha256_update(&ctx, r_bytes)
	sha256_update(&ctx, pubkey)
	sha256_update(&ctx, msg)
	return sha256_final(&ctx)
}

// Verify a 64-byte BIP-340 Schnorr signature.
//   pubkey: 32-byte x-only public key
//   msg:    32 bytes (here, a Nostr event id)
//   sig:    64 bytes (r || s)
schnorr_verify :: proc "contextless" (pubkey, msg, sig: []u8) -> bool {
	// BIP-340 permits any message length; Nostr always passes a 32-byte id.
	if len(pubkey) != 32 || len(sig) != 64 {
		return false
	}

	// Public key point P = lift_x(int(pubkey)); fails if x >= p or not on curve.
	px := fe_from_be(pubkey)
	if geq4(px, P) {
		return false
	}
	pub_point, ok := lift_x(px)
	if !ok {
		return false
	}

	// r = sig[0:32] must be a valid field element (< p).
	r := fe_from_be(sig[0:32])
	if geq4(r, P) {
		return false
	}
	// s = sig[32:64] must be a valid scalar (< n).
	s := fe_from_be(sig[32:64])
	if geq4(s, N) {
		return false
	}

	// e = int(hash(r || P || m)) mod n
	ch := challenge_hash(sig[0:32], pubkey, msg)
	e := sc_reduce_be(ch[:])

	// R = s·G - e·P = s·G + (n - e)·P, computed in one interleaved
	// (Shamir/Strauss) pass that shares the doublings between both terms.
	neg_e, _ := sub4(N, e)
	rr := double_scalar_mul(s, pub_point, neg_e)

	rx, ry, valid := to_affine(rr)
	if !valid {
		return false // R is the point at infinity
	}
	if fe_is_odd(ry) {
		return false // R.y must be even
	}
	return rx == r // R.x must equal r
}

// --- signing (used to mint test authorization tokens) ---------------------

@(private = "file")
fe_to_be :: proc "contextless" (f: Fe) -> [32]u8 {
	out: [32]u8 = ---
	#no_bounds_check for i in 0 ..< 4 {
		base := (3 - i) * 8
		v := f[i]
		out[base + 0] = u8(v >> 56)
		out[base + 1] = u8(v >> 48)
		out[base + 2] = u8(v >> 40)
		out[base + 3] = u8(v >> 32)
		out[base + 4] = u8(v >> 24)
		out[base + 5] = u8(v >> 16)
		out[base + 6] = u8(v >> 8)
		out[base + 7] = u8(v)
	}
	return out
}

@(private = "file")
tagged_hash :: proc "contextless" (tag: string, parts: ..[]u8) -> [32]u8 {
	// Use the cached tag hash for the three BIP-340 tags; otherwise hash inline.
	th: [32]u8 = ---
	switch tag {
	case "BIP0340/challenge":
		th = tag_challenge
	case "BIP0340/aux":
		th = tag_aux
	case "BIP0340/nonce":
		th = tag_nonce
	case:
		th = sha256(transmute([]u8)tag)
	}
	ctx: Sha256_Ctx = ---
	sha256_init(&ctx)
	sha256_update(&ctx, th[:])
	sha256_update(&ctx, th[:])
	for p in parts {
		sha256_update(&ctx, p)
	}
	return sha256_final(&ctx)
}

// Schoolbook 8-limb product reduced mod n by binary long division. Only used
// off the request path (token minting), so the simple bit-by-bit reduction is
// perfectly adequate.
@(private = "file")
sc_mulmod :: proc "contextless" (a, b: Fe) -> Fe {
	prod: [8]u64
	#no_bounds_check for i in 0 ..< 4 {
		carry: u64 = 0
		for j in 0 ..< 4 {
			v := u128(a[i]) * u128(b[j]) + u128(prod[i + j]) + u128(carry)
			prod[i + j] = u64(v)
			carry = u64(v >> 64)
		}
		prod[i + 4] = carry
	}
	r := ZERO
	#no_bounds_check for i := 511; i >= 0; i -= 1 {
		carry := r[3] >> 63
		r[3] = (r[3] << 1) | (r[2] >> 63)
		r[2] = (r[2] << 1) | (r[1] >> 63)
		r[1] = (r[1] << 1) | (r[0] >> 63)
		bit := (prod[i / 64] >> uint(i % 64)) & 1
		r[0] = (r[0] << 1) | bit
		if carry == 1 || geq4(r, N) {
			r, _ = sub4(r, N)
		}
	}
	return r
}

@(private = "file")
sc_addmod :: proc "contextless" (a, b: Fe) -> Fe {
	r, c := add4(a, b)
	if c == 1 || geq4(r, N) {
		r, _ = sub4(r, N)
	}
	return r
}

// Return the 32-byte x-only public key for a secret key.
schnorr_pubkey :: proc "contextless" (seckey: []u8) -> (out: [32]u8, ok: bool) {
	d := fe_from_be(seckey)
	if d == ZERO || geq4(d, N) {
		return {}, false
	}
	p := fixed_base_mul(d)
	px, _, valid := to_affine(p)
	if !valid {
		return {}, false
	}
	return fe_to_be(px), true
}

// Produce a 64-byte BIP-340 signature (aux randomness fixed to zero — fine for
// minting test tokens; not for production key material).
schnorr_sign :: proc "contextless" (seckey, msg: []u8) -> (out: [64]u8, ok: bool) {
	d0 := fe_from_be(seckey)
	if d0 == ZERO || geq4(d0, N) {
		return {}, false
	}
	p := fixed_base_mul(d0)
	px, py, _ := to_affine(p)
	d := d0
	if fe_is_odd(py) {
		d, _ = sub4(N, d0)
	}

	aux: [32]u8
	aux_h := tagged_hash("BIP0340/aux", aux[:])
	d_be := fe_to_be(d)
	t: [32]u8 = ---
	for i in 0 ..< 32 {
		t[i] = d_be[i] ~ aux_h[i]
	}
	px_be := fe_to_be(px)

	nonce := tagged_hash("BIP0340/nonce", t[:], px_be[:], msg)
	k0 := sc_reduce_be(nonce[:])
	if k0 == ZERO {
		return {}, false
	}
	rp := fixed_base_mul(k0)
	rx, ry, _ := to_affine(rp)
	k := k0
	if fe_is_odd(ry) {
		k, _ = sub4(N, k0)
	}
	rx_be := fe_to_be(rx)

	ch := tagged_hash("BIP0340/challenge", rx_be[:], px_be[:], msg)
	e := sc_reduce_be(ch[:])
	s := sc_addmod(k, sc_mulmod(e, d))
	s_be := fe_to_be(s)

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
	return fe_from_be(b[:])
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
	for a in ([]Fe{{2, 0, 0, 0}, {7, 0, 0, 0}, GX, GY}) {
		check("fe_inv round-trip", fe_mul(a, fe_inv(a)) == ONE, &pass, &fail)
	}

	// Field: (sqrt(a^2))^2 == a^2 (modular square root, p ≡ 3 mod 4).
	{
		sq := fe_sqr(Fe{7, 0, 0, 0})
		r := fe_pow(sq, P_PLUS_1_DIV_4)
		check("fe_sqrt^2 == square", fe_sqr(r) == sq, &pass, &fail)
	}

	// Field: a - a == 0, a + 0 == a, neg.
	{
		a := GX
		check("fe_sub self == 0", fe_sub(a, a) == ZERO, &pass, &fail)
		check("fe_add zero", fe_add(a, ZERO) == a, &pass, &fail)
		check("fe_neg", fe_add(a, fe_neg(a)) == ZERO, &pass, &fail)
	}

	G := Point{GX, GY, ONE}

	// Point: known x-coordinates of small multiples of G.
	// k=3 is corroborated by BIP-340 vector 0 (seckey=3); k=2 is the standard
	// published doubling of the generator.
	{
		x2, _, _ := to_affine(scalar_mul(G, Fe{2, 0, 0, 0}))
		want2 := fe_from_hex("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
		check("2*G x-coordinate", x2 == want2, &pass, &fail)

		x3, _, _ := to_affine(scalar_mul(G, Fe{3, 0, 0, 0}))
		want3 := fe_from_hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
		check("3*G x-coordinate", x3 == want3, &pass, &fail)
	}

	// Point: (n-1)*G == -G, so x matches Gx and y is odd.
	{
		nm1, _ := sub4(N, ONE)
		x, y, _ := to_affine(scalar_mul(G, nm1))
		check("(n-1)*G == -G", x == GX && fe_is_odd(y), &pass, &fail)
	}

	// Point: associativity-ish — 2*G + G == 3*G.
	{
		p2 := scalar_mul(G, Fe{2, 0, 0, 0})
		x, _, _ := to_affine(point_add(p2, G))
		want3 := fe_from_hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
		check("2G + G == 3G", x == want3, &pass, &fail)
	}

	// lift_x(Gx) recovers Gy (with even y — Gy is even).
	{
		pt, ok := lift_x(GX)
		check("lift_x(Gx) == (Gx,Gy)", ok && pt.x == GX && pt.y == GY, &pass, &fail)
	}

	return pass, fail
}
