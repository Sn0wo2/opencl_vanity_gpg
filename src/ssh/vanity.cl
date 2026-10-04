// vanity.cl — from-scratch ed25519 vanity key search.
//
// Per work item:
//   seed = base_seed with (start_offset + global_id) added (LE) into bytes 24..31
//   a    = clamp(SHA-512(seed)[0..32])
//   P    = a * B  over edwards25519
//   pub  = compressed encoding of P
//   line = "ssh-ed25519 " || base64(ssh blob(pub))   (36 constant + 48 computed chars)
//   if line matches the mask filter, record the candidate offset.
//
// Field arithmetic is donna-style: 5 unsigned 64-bit limbs, radix 2^51.
// Point arithmetic uses the complete twisted-Edwards addition formula in
// extended coordinates (a = -1); doubling is addition with itself.

typedef ulong fe[5];

typedef struct {
    fe X, Y, Z, T;
} ge;

// ---------------------------------------------------------------- SHA-512

static ulong rotr64(ulong x, int n) { return (x >> n) | (x << (64 - n)); }

__constant ulong SHA512_K[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
};

// SHA-512 of a 32-byte message (single padded block); writes the first
// 32 digest bytes.
static void sha512_first32(const __private uchar msg[32], __private uchar out[32]) {
    ulong w[80];
    for (int i = 0; i < 4; i++) {
        ulong v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | (ulong)msg[i * 8 + j];
        w[i] = v;
    }
    w[4] = 0x8000000000000000UL;
    for (int i = 5; i < 15; i++) w[i] = 0;
    w[15] = 256UL; // message length: 32 bytes = 256 bits
    for (int t = 16; t < 80; t++) {
        ulong s0 = rotr64(w[t - 15], 1) ^ rotr64(w[t - 15], 8) ^ (w[t - 15] >> 7);
        ulong s1 = rotr64(w[t - 2], 19) ^ rotr64(w[t - 2], 61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    ulong a = 0x6a09e667f3bcc908UL, b = 0xbb67ae8584caa73bUL;
    ulong c = 0x3c6ef372fe94f82bUL, d = 0xa54ff53a5f1d36f1UL;
    ulong e = 0x510e527fade682d1UL, f = 0x9b05688c2b3e6c1fUL;
    ulong g = 0x1f83d9abfb41bd6bUL, h = 0x5be0cd19137e2179UL;

    for (int t = 0; t < 80; t++) {
        ulong S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        ulong ch = (e & f) ^ (~e & g);
        ulong t1 = h + S1 + ch + SHA512_K[t] + w[t];
        ulong S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    a += 0x6a09e667f3bcc908UL; b += 0xbb67ae8584caa73bUL;
    c += 0x3c6ef372fe94f82bUL; d += 0xa54ff53a5f1d36f1UL;
    ulong hv[4] = {a, b, c, d};
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) out[i * 8 + j] = (uchar)(hv[i] >> (56 - 8 * j));
    }
}

// ------------------------------------------------- field arithmetic mod 2^255-19

// 128-bit product/accumulation helpers for the 5x51-bit limbs.
typedef struct { ulong lo, hi; } u128;

static u128 u128_mul(ulong a, ulong b) {
    u128 r;
    r.lo = a * b;
    r.hi = mul_hi(a, b);
    return r;
}

static u128 u128_add(u128 x, u128 y) {
    u128 r;
    r.lo = x.lo + y.lo;
    r.hi = x.hi + y.hi + (r.lo < x.lo ? 1 : 0);
    return r;
}

static void u128_add64(__private u128 *x, ulong b) {
    ulong old = x->lo;
    x->lo += b;
    if (x->lo < old) x->hi++;
}

// Split x into (low 51 bits in x->lo, returned carry).
static ulong u128_take51(__private u128 *x) {
    ulong carry = (x->lo >> 51) | (x->hi << 13);
    x->lo &= 0x7ffffffffffffUL;
    x->hi = 0;
    return carry;
}

static void fe_0(__private fe h) {
    for (int i = 0; i < 5; i++) h[i] = 0;
}

static void fe_1(__private fe h) {
    h[0] = 1;
    for (int i = 1; i < 5; i++) h[i] = 0;
}

static void fe_copy(__private fe h, const __private fe f) {
    for (int i = 0; i < 5; i++) h[i] = f[i];
}

static void fe_add(__private fe h, const __private fe f, const __private fe g) {
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

// h = f - g, kept non-negative with a 2p pad (donna-style).
static void fe_sub(__private fe h, const __private fe f, const __private fe g) {
    h[0] = f[0] + 0xfffffffffffdaUL - g[0];
    h[1] = f[1] + 0xffffffffffffeUL - g[1];
    h[2] = f[2] + 0xffffffffffffeUL - g[2];
    h[3] = f[3] + 0xffffffffffffeUL - g[3];
    h[4] = f[4] + 0xffffffffffffeUL - g[4];
}

// h = f * g, donna-style 5 limbs of 51 bits with 128-bit products.
static void fe_mul(__private fe h, const __private fe f, const __private fe g) {
    ulong f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    ulong g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    ulong f1_19 = 19 * f1, f2_19 = 19 * f2, f3_19 = 19 * f3, f4_19 = 19 * f4;

    u128 h0 = u128_mul(f0, g0);
    h0 = u128_add(h0, u128_mul(f1_19, g4));
    h0 = u128_add(h0, u128_mul(f2_19, g3));
    h0 = u128_add(h0, u128_mul(f3_19, g2));
    h0 = u128_add(h0, u128_mul(f4_19, g1));
    u128 h1 = u128_mul(f0, g1);
    h1 = u128_add(h1, u128_mul(f1, g0));
    h1 = u128_add(h1, u128_mul(f2_19, g4));
    h1 = u128_add(h1, u128_mul(f3_19, g3));
    h1 = u128_add(h1, u128_mul(f4_19, g2));
    u128 h2 = u128_mul(f0, g2);
    h2 = u128_add(h2, u128_mul(f1, g1));
    h2 = u128_add(h2, u128_mul(f2, g0));
    h2 = u128_add(h2, u128_mul(f3_19, g4));
    h2 = u128_add(h2, u128_mul(f4_19, g3));
    u128 h3 = u128_mul(f0, g3);
    h3 = u128_add(h3, u128_mul(f1, g2));
    h3 = u128_add(h3, u128_mul(f2, g1));
    h3 = u128_add(h3, u128_mul(f3, g0));
    h3 = u128_add(h3, u128_mul(f4_19, g4));
    u128 h4 = u128_mul(f0, g4);
    h4 = u128_add(h4, u128_mul(f1, g3));
    h4 = u128_add(h4, u128_mul(f2, g2));
    h4 = u128_add(h4, u128_mul(f3, g1));
    h4 = u128_add(h4, u128_mul(f4, g0));

    ulong c = u128_take51(&h0); u128_add64(&h1, c);
    c = u128_take51(&h1); u128_add64(&h2, c);
    c = u128_take51(&h2); u128_add64(&h3, c);
    c = u128_take51(&h3); u128_add64(&h4, c);
    c = u128_take51(&h4);
    h0 = u128_add(h0, u128_mul(c, 19));
    c = u128_take51(&h0);
    h1.lo += c;

    h[0] = h0.lo; h[1] = h1.lo; h[2] = h2.lo; h[3] = h3.lo; h[4] = h4.lo;
}

static void fe_sq(__private fe h, const __private fe f) { fe_mul(h, f, f); }

// h = z^(p-2) = 1/z, ref10 addition chain: 255 squarings, 11 multiplies.
static void fe_invert(__private fe out, const __private fe z) {
    fe t0, t1, t2, t3;
    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (int i = 1; i < 5; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 1; i < 20; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (int i = 1; i < 5; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

// Full reduction then little-endian packing (donna fe51_tobytes).
static void fe_tobytes(__private uchar s[32], const __private fe h_in) {
    ulong h0 = h_in[0], h1 = h_in[1], h2 = h_in[2], h3 = h_in[3], h4 = h_in[4];
    ulong q, c;
    const ulong m = 0x7ffffffffffffUL;

    q = (19 * h4 + (1UL << 50)) >> 51;
    q = (h0 + q) >> 51;
    q = (h1 + q) >> 51;
    q = (h2 + q) >> 51;
    q = (h3 + q) >> 51;
    q = (h4 + q) >> 51;
    h0 += 19 * q;

    c = h0 >> 51; h1 += c; h0 &= m;
    c = h1 >> 51; h2 += c; h1 &= m;
    c = h2 >> 51; h3 += c; h2 &= m;
    c = h3 >> 51; h4 += c; h3 &= m;
    c = h4 >> 51; h4 &= m;

    s[0] = (uchar)(h0);
    s[1] = (uchar)(h0 >> 8);
    s[2] = (uchar)(h0 >> 16);
    s[3] = (uchar)(h0 >> 24);
    s[4] = (uchar)(h0 >> 32);
    s[5] = (uchar)(h0 >> 40);
    s[6] = (uchar)((h0 >> 48) | (h1 << 3));
    s[7] = (uchar)(h1 >> 5);
    s[8] = (uchar)(h1 >> 13);
    s[9] = (uchar)(h1 >> 21);
    s[10] = (uchar)(h1 >> 29);
    s[11] = (uchar)(h1 >> 37);
    s[12] = (uchar)((h1 >> 45) | (h2 << 6));
    s[13] = (uchar)(h2 >> 2);
    s[14] = (uchar)(h2 >> 10);
    s[15] = (uchar)(h2 >> 18);
    s[16] = (uchar)(h2 >> 26);
    s[17] = (uchar)(h2 >> 34);
    s[18] = (uchar)(h2 >> 42);
    s[19] = (uchar)((h2 >> 50) | (h3 << 1));
    s[20] = (uchar)(h3 >> 7);
    s[21] = (uchar)(h3 >> 15);
    s[22] = (uchar)(h3 >> 23);
    s[23] = (uchar)(h3 >> 31);
    s[24] = (uchar)(h3 >> 39);
    s[25] = (uchar)((h3 >> 47) | (h4 << 4));
    s[26] = (uchar)(h4 >> 4);
    s[27] = (uchar)(h4 >> 12);
    s[28] = (uchar)(h4 >> 20);
    s[29] = (uchar)(h4 >> 28);
    s[30] = (uchar)(h4 >> 36);
    s[31] = (uchar)(h4 >> 44);
}


// ------------------------------------------------------- edwards25519 points

// Curve constant d = -121665/121666, basepoint B and T = Bx*By,
// as 5x51-bit limb constants.
__constant fe FE_D = {0x34dca135978a3UL, 0x1a8283b156ebdUL, 0x5e7a26001c029UL,
                      0x739c663a03cbbUL, 0x52036cee2b6ffUL};
__constant fe FE_BX = {0x62d608f25d51aUL, 0x412a4b4f6592aUL, 0x75b7171a4b31dUL,
                       0x1ff60527118feUL, 0x216936d3cd6e5UL};
__constant fe FE_BY = {0x6666666666658UL, 0x4ccccccccccccUL, 0x1999999999999UL,
                       0x3333333333333UL, 0x6666666666666UL};
__constant fe FE_BT = {0x68ab3a5b7dda3UL, 0x00eea2a5eadbbUL, 0x2af8df483c27eUL,
                       0x332b375274732UL, 0x67875f0fd78b7UL};

// Complete addition formula (a = -1), safe for aliasing r == p == q.
static void ge_add(__private ge *r, const __private ge *p, const __private ge *q) {
    fe A, B, C, D, E, F, G, H, t1, t2, d;
    for (int i = 0; i < 5; i++) d[i] = FE_D[i];
    fe_mul(A, p->X, q->X);
    fe_mul(B, p->Y, q->Y);
    fe_mul(t1, p->T, q->T);
    fe_mul(C, t1, d);
    fe_mul(D, p->Z, q->Z);
    fe_add(t1, p->X, p->Y);
    fe_add(t2, q->X, q->Y);
    fe_mul(E, t1, t2);
    fe_sub(E, E, A);
    fe_sub(E, E, B);
    fe_sub(F, D, C);
    fe_add(G, D, C);
    fe_add(H, B, A);
    fe_mul(r->X, E, F);
    fe_mul(r->Y, G, H);
    fe_mul(r->T, E, H);
    fe_mul(r->Z, F, G);
}

// r = a * B, double-and-add over the 256 bits of the clamped scalar.
static void ge_scalarmult_base(__private ge *r, const __private uchar a[32]) {
    ge P, Q;
    for (int i = 0; i < 5; i++) {
        P.X[i] = FE_BX[i];
        P.Y[i] = FE_BY[i];
        P.T[i] = FE_BT[i];
    }
    fe_1(P.Z);
    fe_0(Q.X);
    fe_1(Q.Y);
    fe_1(Q.Z);
    fe_0(Q.T);
    for (int i = 0; i < 256; i++) {
        if ((a[i >> 3] >> (i & 7)) & 1) {
            ge_add(&Q, &Q, &P);
        }
        ge_add(&P, &P, &P);
    }
    *r = Q;
}

// Mixed addition with a precomputed table point q = (y+x, y-x, 2dxy),
// negating the point when `neg` is set: -(x,y) = (-x,y) swaps (y+x, y-x)
// and negates 2dxy.
static void ge_add_mixed_signed(__private ge *r, const __private ge *p,
                                __global const ulong *q, int neg) {
    fe ypx, ymx, t2d, t;
    for (int i = 0; i < 5; i++) {
        ypx[i] = q[i];
        ymx[i] = q[5 + i];
        t2d[i] = q[10 + i];
    }
    if (neg) {
        fe_copy(t, ypx);
        fe_copy(ypx, ymx);
        fe_copy(ymx, t);
        fe_0(t);
        fe_sub(t2d, t, t2d);
    }
    fe A, B, C, D2, E, F, G, H, t1, t2;
    fe_add(t1, p->Y, p->X);
    fe_sub(t2, p->Y, p->X);
    fe_mul(A, t1, ypx);
    fe_mul(B, t2, ymx);
    fe_mul(C, p->T, t2d);
    fe_add(D2, p->Z, p->Z);
    fe_sub(E, A, B);
    fe_sub(F, D2, C);
    fe_add(G, D2, C);
    fe_add(H, A, B);
    fe_mul(r->X, E, F);
    fe_mul(r->Y, G, H);
    fe_mul(r->T, E, H);
    fe_mul(r->Z, F, G);
}

// r = a * B via the fixed-window table: the 32-byte scalar is recoded into
// 19 signed 14-bit digits (each in [-8192, 8191]), so 19 lookups + mixed
// additions. Table slot (w, |d|) holds |d| * 2^(12w) * B; slot 0 is identity.
static void ge_scalarmult_base_table(__private ge *r, const __private uchar a[32],
                                     __global const ulong *table) {
    ge acc;
    fe_0(acc.X);
    fe_1(acc.Y);
    fe_1(acc.Z);
    fe_0(acc.T);
    int carry = 0;
    for (int w = 0; w < 16; w++) {
        int bit0 = 16 * w;
        int v = carry;
        for (int i = 0; i < 16; i++) {
            int byte = (bit0 + i) >> 3;
            int bit = byte < 32 ? (a[byte] >> ((bit0 + i) & 7)) & 1 : 0;
            v += bit << i;
        }
        if (v >= 32768) {
            v -= 65536;
            carry = 1;
        } else {
            carry = 0;
        }
        int av = v < 0 ? -v : v;
        ge_add_mixed_signed(&acc, &acc, table + (w * 32769 + av) * 15, v < 0);
    }
    // 16 windows cover exactly 256 bits, so a final carry is possible;
    // the last table slot holds 2^256 * B.
    if (carry) {
        ge_add_mixed_signed(&acc, &acc, table + (16 * 32769) * 15, 0);
    }
    *r = acc;
}

// Compressed encoding: y little-endian, top bit = parity of x.
static void ge_tobytes(__private uchar s[32], const __private ge *p) {
    fe zinv, x, y;
    fe_invert(zinv, p->Z);
    fe_mul(x, p->X, zinv);
    fe_mul(y, p->Y, zinv);
    fe_tobytes(s, y);
    uchar xs[32];
    fe_tobytes(xs, x);
    s[31] |= (xs[0] & 1) << 7;
}

// ------------------------------------------------------------- line & match

// Index of each constant line character in the base64 alphabet; 64 marks
// characters outside the alphabet (matched by no mask).
__constant uchar LINE_CONST[36] = {
    44, 44, 33, 64, 30, 29, 54, 57, 57, 53, 61, 64, // "ssh-ed25519 "
    0, 0, 0, 0, 2, 55, 13, 51, 26, 2, 53, 37,       // "AAAAC3NzaC1l"
    25, 3, 8, 53, 13, 19, 4, 57, 0, 0, 0, 0,         // "ZDI1NTE5AAAA"
};

// mode: 0 = sliding window, 1 = anchored at line end, 2 = anchored at start.
static int line_matches(const __private uchar line[80], __constant const ulong *masks,
                        int plen, int mode) {
    if (plen == 0) return 1;
    int lo = 0;
    int hi = 80 - plen;
    if (mode == 1) {
        lo = hi;
    } else if (mode == 2) {
        hi = 0;
    }
    for (int start = lo; start <= hi; start++) {
        int ok = 1;
        for (int j = 0; j < plen; j++) {
            uchar c = line[start + j];
            if (c >= 64 || !((masks[j] >> c) & 1)) {
                ok = 0;
                break;
            }
        }
        if (ok) return 1;
    }
    return 0;
}

// Build the authorized_keys line (as base64 alphabet indices) for a pubkey.
static void build_line(__private uchar line[80], const __private uchar pub[32]) {
    for (int i = 0; i < 36; i++) line[i] = LINE_CONST[i];
    // Variable blob part: 0x20 || pub (33 bytes -> 44 sextets).
    uchar var[33];
    var[0] = 0x20;
    for (int i = 0; i < 32; i++) var[1 + i] = pub[i];
    for (int k = 0; k < 11; k++) {
        uchar b0 = var[3 * k], b1 = var[3 * k + 1], b2 = var[3 * k + 2];
        line[36 + 4 * k + 0] = b0 >> 2;
        line[36 + 4 * k + 1] = ((b0 & 3) << 4) | (b1 >> 4);
        line[36 + 4 * k + 2] = ((b1 & 15) << 2) | (b2 >> 6);
        line[36 + 4 * k + 3] = b2 & 63;
    }
}

// seed = base_seed with gid added (LE) into bytes 24..31.
static void make_seed(__private uchar seed[32], __global const uchar *base_seed, ulong gid) {
    ulong tail = 0;
    for (int i = 0; i < 24; i++) seed[i] = base_seed[i];
    for (int i = 0; i < 8; i++) tail |= ((ulong)base_seed[24 + i]) << (8 * i);
    tail += gid;
    for (int i = 0; i < 8; i++) {
        seed[24 + i] = (uchar)(tail & 0xff);
        tail >>= 8;
    }
}

// Point (extended coords, not yet encoded) for one candidate seed.
static void point_from_seed(__private ge *R, __global const uchar *base_seed,
                            ulong gid, __global const ulong *table) {
    uchar seed[32];
    uchar a[32];
    make_seed(seed, base_seed, gid);
    sha512_first32(seed, a);
    a[0] &= 248;
    a[31] &= 63;
    a[31] |= 64;
    ge_scalarmult_base_table(R, a, table);
}

// Compressed encoding of (X, Y) given z^{-1}.
static void encode_with_zinv(__private uchar s[32], const __private fe X,
                             const __private fe Y, const __private fe zinv) {
    fe x, y;
    fe_mul(x, X, zinv);
    fe_mul(y, Y, zinv);
    fe_tobytes(s, y);
    uchar xs[32];
    fe_tobytes(xs, x);
    s[31] |= (xs[0] & 1) << 7;
}

// Keys derived per work item; one field inversion is shared across them
// (Montgomery's batch inversion trick).
#define KEYS_PER_ITEM 32

#define RESULTS_CAP 4096

__kernel void vanity(
    __global const uchar *base_seed,
    ulong start_offset,
    __constant const ulong *masks,
    int plen,
    int mode,
    __global ulong *results,
    __global uint *count,
    __global const ulong *table)
{
    ulong gid0 = start_offset + (ulong)get_global_id(0) * KEYS_PER_ITEM;
    fe X[KEYS_PER_ITEM], Y[KEYS_PER_ITEM], Z[KEYS_PER_ITEM], C[KEYS_PER_ITEM];
    ge R;
    for (int k = 0; k < KEYS_PER_ITEM; k++) {
        point_from_seed(&R, base_seed, gid0 + k, table);
        fe_copy(X[k], R.X);
        fe_copy(Y[k], R.Y);
        fe_copy(Z[k], R.Z);
    }
    fe_copy(C[0], Z[0]);
    for (int k = 1; k < KEYS_PER_ITEM; k++) fe_mul(C[k], C[k - 1], Z[k]);

    fe u, zi;
    fe_invert(u, C[KEYS_PER_ITEM - 1]);
    for (int k = KEYS_PER_ITEM - 1; k >= 0; k--) {
        if (k == 0) {
            fe_copy(zi, u);
        } else {
            fe_mul(zi, u, C[k - 1]);
            fe_mul(u, u, Z[k]);
        }
        uchar pub[32];
        uchar line[80];
        encode_with_zinv(pub, X[k], Y[k], zi);
        build_line(line, pub);
        if (line_matches(line, masks, plen, mode)) {
            uint idx = atomic_inc(count);
            if (idx < RESULTS_CAP) results[idx] = gid0 + k;
        }
    }
}

// Debug/test kernel: write the 32-byte pubkeys of KEYS_PER_ITEM consecutive
// candidates per work item (same batching as `vanity`).
__kernel void debug_pubkeys(
    __global const uchar *base_seed,
    ulong start_offset,
    __global uchar *out,
    __global const ulong *table)
{
    ulong gid0 = start_offset + (ulong)get_global_id(0) * KEYS_PER_ITEM;
    fe X[KEYS_PER_ITEM], Y[KEYS_PER_ITEM], Z[KEYS_PER_ITEM], C[KEYS_PER_ITEM];
    ge R;
    for (int k = 0; k < KEYS_PER_ITEM; k++) {
        point_from_seed(&R, base_seed, gid0 + k, table);
        fe_copy(X[k], R.X);
        fe_copy(Y[k], R.Y);
        fe_copy(Z[k], R.Z);
    }
    fe_copy(C[0], Z[0]);
    for (int k = 1; k < KEYS_PER_ITEM; k++) fe_mul(C[k], C[k - 1], Z[k]);

    fe u, zi;
    fe_invert(u, C[KEYS_PER_ITEM - 1]);
    size_t out_id = get_global_id(0) * KEYS_PER_ITEM;
    for (int k = KEYS_PER_ITEM - 1; k >= 0; k--) {
        if (k == 0) {
            fe_copy(zi, u);
        } else {
            fe_mul(zi, u, C[k - 1]);
            fe_mul(u, u, Z[k]);
        }
        uchar pub[32];
        encode_with_zinv(pub, X[k], Y[k], zi);
        for (int i = 0; i < 32; i++) out[(out_id + k) * 32 + i] = pub[i];
    }
}

// Debug/test kernel: write the 32-byte clamped scalar of each candidate.
__kernel void debug_scalar(
    __global const uchar *base_seed,
    ulong start_offset,
    __global uchar *out)
{
    ulong gid = start_offset + (ulong)get_global_id(0);
    uchar seed[32];
    uchar a[32];
    make_seed(seed, base_seed, gid);
    sha512_first32(seed, a);
    a[0] &= 248;
    a[31] &= 63;
    a[31] |= 64;
    size_t id = get_global_id(0);
    for (int i = 0; i < 32; i++) out[id * 32 + i] = a[i];
}

// Debug/test kernel: compressed encoding of scalar * B for each 32-byte
// scalar in `scalars`.
__kernel void debug_mul_base(
    __global const uchar *scalars,
    __global uchar *out,
    __global const ulong *table)
{
    size_t id = get_global_id(0);
    uchar a[32];
    for (int i = 0; i < 32; i++) a[i] = scalars[id * 32 + i];
    ge R;
    ge_scalarmult_base_table(&R, a, table);
    uchar pub[32];
    ge_tobytes(pub, &R);
    for (int i = 0; i < 32; i++) out[id * 32 + i] = pub[i];
}

// One-time initialization: table[w][d] = d * 2^(8w) * B in the ref10
// precomputed format (y+x, y-x, 2dxy), 10 limbs each.
__kernel void gen_table(__global ulong *table) {
    size_t id = get_global_id(0); // 16*32769+1 items: w = id / 32769, d = id % 32769
    uchar a[32];
    for (int i = 0; i < 32; i++) a[i] = 0;
    ge R;
    int doubles;
    if (id == 16 * 32769) {
        // extra slot: 2^256 * B (the scalar doesn't fit 32 bytes)
        a[30] = 1;
        ge_scalarmult_base(&R, a); // 2^240 * B
        doubles = 16;
    } else {
        int w = (int)(id / 32769);
        int d = (int)(id % 32769);
        a[0] = (uchar)(d & 0xff);
        a[1] = (uchar)((d >> 8) & 0xff);
        ge_scalarmult_base(&R, a); // d * B
        doubles = 16 * w;
    }
    for (int j = 0; j < doubles; j++) ge_add(&R, &R, &R);
    fe zinv, x, y, t, dd;
    fe_invert(zinv, R.Z);
    fe_mul(x, R.X, zinv);
    fe_mul(y, R.Y, zinv);
    for (int i = 0; i < 5; i++) dd[i] = FE_D[i];
    __global ulong *slot = table + id * 15;
    fe_add(t, y, x);
    for (int i = 0; i < 5; i++) slot[i] = t[i];
    fe_sub(t, y, x);
    for (int i = 0; i < 5; i++) slot[5 + i] = t[i];
    fe_mul(t, x, y);
    fe_mul(t, t, dd);
    fe_add(t, t, t);
    for (int i = 0; i < 5; i++) slot[10 + i] = t[i];
}

