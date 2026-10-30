// Host prepends #defines for INIT0..INIT3 (initializer hash lanes) and
// CREATE2_0..CREATE2_16 (padded CREATE2 preimage with the salt bytes zeroed).
// Keeping the whole Keccak state in ulong lanes with constant indices lets the
// compiler hold it in registers, fold the constant lanes and drop dead outputs.

#ifndef CANDIDATE_CAP
#define CANDIDATE_CAP 1024u
#endif
#define FOUND_WORDS 5

#define rol(x, s) (((x) << (s)) | ((x) >> (64u - (s))))
#define rol1(x) rol(x, 1u)
#define theta_(m, n, o) t = b[m] ^ rol1(b[n]); a[o + 0] ^= t; a[o + 5] ^= t; a[o + 10] ^= t; a[o + 15] ^= t; a[o + 20] ^= t;
#define theta() b[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]; b[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]; b[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]; b[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]; b[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]; theta_(4, 1, 0); theta_(0, 2, 1); theta_(1, 3, 2); theta_(2, 4, 3); theta_(3, 0, 4);
#define rhoPi_(m, n) t = b[0]; b[0] = a[m]; a[m] = rol(t, n);
#define rhoPi() t = a[1]; b[0] = a[10]; a[10] = rol1(t); rhoPi_(7, 3); rhoPi_(11, 6); rhoPi_(17, 10); rhoPi_(18, 15); rhoPi_(3, 21); rhoPi_(5, 28); rhoPi_(16, 36); rhoPi_(8, 45); rhoPi_(21, 55); rhoPi_(24, 2); rhoPi_(4, 14); rhoPi_(15, 27); rhoPi_(23, 41); rhoPi_(19, 56); rhoPi_(13, 8); rhoPi_(12, 25); rhoPi_(2, 43); rhoPi_(20, 62); rhoPi_(14, 18); rhoPi_(22, 39); rhoPi_(9, 61); rhoPi_(6, 20); rhoPi_(1, 44);
#define chi_(n) b[0] = a[n + 0]; b[1] = a[n + 1]; b[2] = a[n + 2]; b[3] = a[n + 3]; b[4] = a[n + 4]; a[n + 0] = b[0] ^ ((~b[1]) & b[2]); a[n + 1] = b[1] ^ ((~b[2]) & b[3]); a[n + 2] = b[2] ^ ((~b[3]) & b[4]); a[n + 3] = b[3] ^ ((~b[4]) & b[0]); a[n + 4] = b[4] ^ ((~b[0]) & b[1]);
#define chi() chi_(0); chi_(5); chi_(10); chi_(15); chi_(20);
#define iteration(x) theta(); rhoPi(); chi(); a[0] ^= x;

static inline void keccakf(ulong *a) {
  ulong b[5];
  ulong t;
  iteration(0x0000000000000001UL); iteration(0x0000000000008082UL);
  iteration(0x800000000000808aUL); iteration(0x8000000080008000UL);
  iteration(0x000000000000808bUL); iteration(0x0000000080000001UL);
  iteration(0x8000000080008081UL); iteration(0x8000000000008009UL);
  iteration(0x000000000000008aUL); iteration(0x0000000000000088UL);
  iteration(0x0000000080008009UL); iteration(0x000000008000000aUL);
  iteration(0x000000008000808bUL); iteration(0x800000000000008bUL);
  iteration(0x8000000000008089UL); iteration(0x8000000000008003UL);
  iteration(0x8000000000008002UL); iteration(0x8000000000000080UL);
  iteration(0x000000000000800aUL); iteration(0x800000008000000aUL);
  iteration(0x8000000080008081UL); iteration(0x8000000000008080UL);
  iteration(0x0000000080000001UL); iteration(0x8000000080008008UL);
}

static inline ulong bswap64(ulong x) {
  x = ((x & 0x00ff00ff00ff00ffUL) << 8) | ((x >> 8) & 0x00ff00ff00ff00ffUL);
  x = ((x & 0x0000ffff0000ffffUL) << 16) | ((x >> 16) & 0x0000ffff0000ffffUL);
  return (x << 32) | (x >> 32);
}

static inline ulong ctz64(ulong x) {
  return 63 - clz(x & (0 - x));
}

// salt = keccak256(initializer_hash ++ uint256(nonce)), as four little-endian lanes.
static inline void salt_lanes(ulong nonce, ulong *s) {
  ulong a[25] = {
    INIT0, INIT1, INIT2, INIT3, 0, 0, 0, bswap64(nonce), 1, 0, 0, 0, 0,
    0, 0, 0, 0x8000000000000000UL, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  keccakf(a);
  s[0] = a[0]; s[1] = a[1]; s[2] = a[2]; s[3] = a[3];
}

// Address bytes are hash bytes 12..31 = high half of a1, then a2, a3.
// p0 holds address bytes 0..3 in its top 32 bits; p1, p2 hold bytes 4..19.
static inline uint address_score(ulong a1, ulong a2, ulong a3) {
  ulong p0 = bswap64(a1) << 32, p1 = bswap64(a2), p2 = bswap64(a3);
  ulong rep = (p0 >> 60) * 0x1111111111111111UL;
  ulong x;
  uint prefix;
  if ((x = (p0 ^ rep) & 0xffffffff00000000UL) != 0) prefix = clz(x) >> 2;
  else if ((x = p1 ^ rep) != 0) prefix = 8 + (clz(x) >> 2);
  else if ((x = p2 ^ rep) != 0) prefix = 24 + (clz(x) >> 2);
  else prefix = 40;
  rep = (p2 & 15) * 0x1111111111111111UL;
  uint suffix;
  if ((x = p2 ^ rep) != 0) suffix = ctz64(x) >> 2;
  else if ((x = p1 ^ rep) != 0) suffix = 16 + (ctz64(x) >> 2);
  else if ((x = (p0 ^ rep) >> 32) != 0) suffix = 32 + (ctz64(x) >> 2);
  else suffix = 40;
  return max(prefix, suffix);
}

__kernel void hash_nonce(ulong nonce, __global ulong *output) {
  ulong s[4];
  salt_lanes(nonce + get_global_id(0), s);
  output += get_global_id(0) * 4;
  output[0] = s[0]; output[1] = s[1]; output[2] = s[2]; output[3] = s[3];
}

// Every nonce scoring at least min_score is appended to found as
// {nonce, a1, a2, a3, score}; count may exceed CANDIDATE_CAP.
__kernel void mine(ulong base, uint min_score, __global uint *count, __global ulong *found) {
  ulong n = base + get_global_id(0);
  ulong s[4];
  salt_lanes(n, s);
  // 0xff ++ factory ++ salt ++ code_hash: salt starts at byte 21 = lane 2, byte 5.
  ulong a[25] = {
    CREATE2_0, CREATE2_1, CREATE2_2 | (s[0] << 40),
    CREATE2_3 | (s[0] >> 24) | (s[1] << 40), CREATE2_4 | (s[1] >> 24) | (s[2] << 40),
    CREATE2_5 | (s[2] >> 24) | (s[3] << 40), CREATE2_6 | (s[3] >> 24),
    CREATE2_7, CREATE2_8, CREATE2_9, CREATE2_10, CREATE2_11, CREATE2_12,
    CREATE2_13, CREATE2_14, CREATE2_15, CREATE2_16, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  keccakf(a);
  uint score = address_score(a[1], a[2], a[3]);
  if (score >= min_score) {
    uint i = atomic_inc(count);
    if (i < CANDIDATE_CAP) {
      found += i * FOUND_WORDS;
      found[0] = n; found[1] = a[1]; found[2] = a[2]; found[3] = a[3]; found[4] = score;
    }
  }
}
