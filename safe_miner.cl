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
  iteration(0x0000000000000001); iteration(0x0000000000008082);
  iteration(0x800000000000808a); iteration(0x8000000080008000);
  iteration(0x000000000000808b); iteration(0x0000000080000001);
  iteration(0x8000000080008081); iteration(0x8000000000008009);
  iteration(0x000000000000008a); iteration(0x0000000000000088);
  iteration(0x0000000080008009); iteration(0x000000008000000a);
  iteration(0x000000008000808b); iteration(0x800000000000008b);
  iteration(0x8000000000008089); iteration(0x8000000000008003);
  iteration(0x8000000000008002); iteration(0x8000000000000080);
  iteration(0x000000000000800a); iteration(0x800000008000000a);
  iteration(0x8000000080008081); iteration(0x8000000000008080);
  iteration(0x0000000080000001); iteration(0x8000000080008008);
}

static uchar nibble(uchar *d, uint i) {
  uchar b = d[i >> 1];
  return (i & 1) ? b & 15 : b >> 4;
}

static uint score(uchar *d) {
  uint p = 1, s = 1;
  while (p < 40 && nibble(d, p) == nibble(d, 0)) p++;
  while (s < 40 && nibble(d, 39 - s) == nibble(d, 39)) s++;
  return max(p, s);
}

__kernel void hash_nonce(__constant uchar *init_hash, ulong nonce, __global uchar *output) {
  nonce += get_global_id(0);
  union { ulong lanes[25]; uchar bytes[136]; } state;
  ulong *a = state.lanes;
  uchar *m = state.bytes;
  for (uint i = 0; i < 25; ++i) a[i] = 0;
  a[7] = ((nonce & 0xffUL) << 56) | ((nonce & 0xff00UL) << 40) |
    ((nonce & 0xff0000UL) << 24) | ((nonce & 0xff000000UL) << 8) |
    ((nonce >> 8) & 0xff000000UL) | ((nonce >> 24) & 0xff0000UL) |
    ((nonce >> 40) & 0xff00UL) | ((nonce >> 56) & 0xffUL);
  for (uint i = 0; i < 32; ++i) m[i] = init_hash[i];
  m[64] = 1;
  m[135] = 0x80;
  output += get_global_id(0) * 32;
  keccakf(a);
  for (uint i = 0; i < 32; ++i) output[i] = m[i];
}

__kernel void mine(__constant uchar *init_hash, __constant uchar *factory,
                   __constant uchar *code_hash, ulong base,
                   __global uint *best_score, __global ulong *best_nonce,
                   __global uchar *best_address, __global uint *best_lock,
                   __global uchar *best_salt) {
  union { ulong lanes[25]; uchar bytes[136]; } state;
  ulong *a = state.lanes;
  uchar *m = state.bytes;
  for (uint i = 0; i < 25; ++i) a[i] = 0;
  ulong n = base + get_global_id(0);
  a[7] = ((n & 0xffUL) << 56) | ((n & 0xff00UL) << 40) |
    ((n & 0xff0000UL) << 24) | ((n & 0xff000000UL) << 8) |
    ((n >> 8) & 0xff000000UL) | ((n >> 24) & 0xff0000UL) |
    ((n >> 40) & 0xff00UL) | ((n >> 56) & 0xffUL);
  for (uint i = 0; i < 32; ++i) m[i] = init_hash[i];
  m[64] = 1;
  m[135] = 0x80;
  keccakf(a);
  uchar salt[32];
  for (uint i = 0; i < 32; ++i) salt[i] = m[i];
  for (uint i = 0; i < 25; ++i) a[i] = 0;
  m[0] = 0xff;
  for (uint i = 0; i < 20; ++i) m[1 + i] = factory[i];
  for (uint i = 0; i < 32; ++i) m[21 + i] = salt[i];
  for (uint i = 0; i < 32; ++i) m[53 + i] = code_hash[i];
  m[85] = 1;
  m[135] = 0x80;
  keccakf(a);
  uint s = score(m + 12);
  if (s >= 5 && s > *best_score) {
    while (atomic_xchg(best_lock, 1u));
    mem_fence(CLK_GLOBAL_MEM_FENCE);
    if (s > *best_score) {
      *best_nonce = n;
      for (uint i = 0; i < 32; ++i) best_salt[i] = salt[i];
      for (uint i = 0; i < 20; ++i) best_address[i] = m[12 + i];
      mem_fence(CLK_GLOBAL_MEM_FENCE);
      *best_score = s;
    }
    mem_fence(CLK_GLOBAL_MEM_FENCE);
    atomic_xchg(best_lock, 0u);
  }
}
