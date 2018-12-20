// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Portions Copyright (c) 2018 The Monero developers

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 19)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

#define VARIANT1_1(p) \
  do if (variant == 1) \
  { \
    const uint8_t tmp = ((const uint8_t*)(p))[11]; \
    static const uint32_t table = 0x75310; \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
  } while(0)

#define VARIANT1_2(p) \
  do if (variant == 1) \
  { \
    xor64(p, tweak1_2); \
  } while(0)

#define VARIANT1_CHECK() \
  do if (length < 43) \
  { \
    fprintf(stderr, "Cryptonight variant 1 need at least 43 bytes of data"); \
    abort(); \
  } while(0)

#define NONCE_POINTER (((const uint8_t*)data)+35)

#define VARIANT1_PORTABLE_INIT() \
  uint8_t tweak1_2[8]; \
  do if (variant == 1) \
  { \
    VARIANT1_CHECK(); \
    memcpy(&tweak1_2, &state.hs.b[192], sizeof(tweak1_2)); \
    xor64(tweak1_2, NONCE_POINTER); \
  } while(0)

#define VARIANT1_INIT64() \
  if (variant == 1) \
  { \
    VARIANT1_CHECK(); \
  } \
  const uint64_t tweak1_2 = (variant == 1) ? (state.hs.w[24] ^ (*((const uint64_t*)NONCE_POINTER))) : 0

#pragma pack(push, 1)
union cn_slow_hash_state
{
  union hash_state hs;
  struct
  {
    uint8_t k[64];
    uint8_t init[INIT_SIZE_BYTE];
  };
};
#pragma pack(pop)

THREADV uint8_t *hp_state = NULL;
THREADV int hp_allocated = 0;

#if defined(_MSC_VER)
#define cpuid(info,x)    __cpuidex(info,x,0)
#else
void cpuid(int CPUInfo[4], int InfoType)
{
  ASM __volatile__
  (
  "cpuid":
    "=a" (CPUInfo[0]),
    "=b" (CPUInfo[1]),
    "=c" (CPUInfo[2]),
    "=d" (CPUInfo[3]) :
        "a" (InfoType), "c" (0)
    );
}

STATIC INLINE void xor_blocks(uint8_t *a, const uint8_t *b)
{
  U64(a)[0] ^= U64(b)[0];
  U64(a)[1] ^= U64(b)[1];
}

STATIC INLINE void xor64(uint64_t *a, const uint64_t b)
{
  *a ^= b;
}

STATIC INLINE int force_software_aes(void)
{
  static int use = -1;

  if (use != -1)
    return use;

  const char *env = getenv("TURTLECOIN_USE_SOFTWARE_AES");
  if (!env) {
    use = 0;
  }
  else if (!strcmp(env, "0") || !strcmp(env, "no")) {
    use = 0;
  }
  else {
    use = 1;
  }
  return use;
}

STATIC INLINE int check_aes_hw(void)
{
  int cpuid_results[4];
  static int supported = -1;

  if(supported >= 0)
    return supported;

  cpuid(cpuid_results,1);
  return supported = cpuid_results[2] & (1 << 25);
}

STATIC INLINE void aes_256_assist1(__m128i* t1, __m128i * t2)
{
  __m128i t4;
  *t2 = _mm_shuffle_epi32(*t2, 0xff);
  t4 = _mm_slli_si128(*t1, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  t4 = _mm_slli_si128(t4, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  t4 = _mm_slli_si128(t4, 0x04);
  *t1 = _mm_xor_si128(*t1, t4);
  *t1 = _mm_xor_si128(*t1, *t2);
}

STATIC INLINE void aes_256_assist2(__m128i* t1, __m128i * t3)
{
  __m128i t2, t4;
  t4 = _mm_aeskeygenassist_si128(*t1, 0x00);
  t2 = _mm_shuffle_epi32(t4, 0xaa);
  t4 = _mm_slli_si128(*t3, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  t4 = _mm_slli_si128(t4, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  t4 = _mm_slli_si128(t4, 0x04);
  *t3 = _mm_xor_si128(*t3, t4);
  *t3 = _mm_xor_si128(*t3, t2);
}

STATIC INLINE void aes_expand_key(const uint8_t *key, uint8_t *expandedKey)
{
  __m128i *ek = R128(expandedKey);
  __m128i t1, t2, t3;

  t1 = _mm_loadu_si128(R128(key));
  t3 = _mm_loadu_si128(R128(key + 16));

  ek[0] = t1;
  ek[1] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x01);
  aes_256_assist1(&t1, &t2);
  ek[2] = t1;
  aes_256_assist2(&t1, &t3);
  ek[3] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x02);
  aes_256_assist1(&t1, &t2);
  ek[4] = t1;
  aes_256_assist2(&t1, &t3);
  ek[5] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x04);
  aes_256_assist1(&t1, &t2);
  ek[6] = t1;
  aes_256_assist2(&t1, &t3);
  ek[7] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x08);
  aes_256_assist1(&t1, &t2);
  ek[8] = t1;
  aes_256_assist2(&t1, &t3);
  ek[9] = t3;

  t2 = _mm_aeskeygenassist_si128(t3, 0x10);
  aes_256_assist1(&t1, &t2);
  ek[10] = t1;
}

void cn_slow_hash(const void *data, size_t length, char *hash, int light, int variant, int prehashed, uint32_t PAGE_SIZE, uint32_t scratchpad, uint32_t iterations)
{
  uint32_t TOTALBLOCKS = (PAGE_SIZE / AES_BLOCK_SIZE);
  uint32_t init_rounds = (scratchpad / INIT_SIZE_BYTE);
  uint32_t aes_rounds = (iterations / 2);
  if (variant == 3) aes_rounds = aes_rounds / 2;
  size_t lightFlag = (light ? 2: 1);

  RDATA_ALIGN16 uint8_t expandedKey[240];  /* These buffers are aligned to use later with SSE functions */

  uint8_t text[INIT_SIZE_BYTE];
  RDATA_ALIGN16 uint64_t a[2];
  RDATA_ALIGN16 uint64_t b[4];
  RDATA_ALIGN16 uint64_t c[2];
  RDATA_ALIGN16 uint64_t c1[2];
  union cn_slow_hash_state state;
  __m128i _a, _b, _b1, _c;
  uint64_t hi, lo;

  size_t i, j;
  uint64_t *p = NULL;
  oaes_ctx *aes_ctx = NULL;
  int useAes = !force_software_aes() && check_aes_hw();

  static void (*const extra_hashes[4])(const void *, size_t, char *) =
  {
      hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
  };

  slow_hash_allocate_state(PAGE_SIZE);

  /* CryptoNight Step 1:  Use Keccak1600 to initialize the 'state' (and 'text') buffers from the data. */
  if (prehashed) {
      memcpy(&state.hs, data, length);
  } else {
      hash_process(&state.hs, data, length);
  }
  memcpy(text, state.init, INIT_SIZE_BYTE);

  VARIANT1_INIT64();
  VARIANT2_INIT64();

  /* CryptoNight Step 2:  Iteratively encrypt the results from Keccak to fill
   * the 2MB large random access buffer.
   */

  if(useAes)
  {
      aes_expand_key(state.hs.b, expandedKey);
      for(i = 0; i < init_rounds; i++)
      {
          aes_pseudo_round(text, text, expandedKey, INIT_SIZE_BLK);
          memcpy(&hp_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
      }
  }
  else
  {
      aes_ctx = (oaes_ctx *) oaes_alloc();
      oaes_key_import_data(aes_ctx, state.hs.b, AES_KEY_SIZE);
      for(i = 0; i < init_rounds; i++)
      {
          for(j = 0; j < INIT_SIZE_BLK; j++)
              aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);

          memcpy(&hp_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
      }
  }

  U64(a)[0] = U64(&state.k[0])[0] ^ U64(&state.k[32])[0];
  U64(a)[1] = U64(&state.k[0])[1] ^ U64(&state.k[32])[1];
  U64(b)[0] = U64(&state.k[16])[0] ^ U64(&state.k[48])[0];
  U64(b)[1] = U64(&state.k[16])[1] ^ U64(&state.k[48])[1];

  /* CryptoNight Step 3:  Bounce randomly 1,048,576 times (1<<20) through the mixing buffer,
   * using 524,288 iterations of the following mixing function.  Each execution
   * performs two reads and writes from the mixing buffer.
   */

  _b = _mm_load_si128(R128(b));
  _b1 = _mm_load_si128(R128(b) + 1);
  // Two independent versions, one with AES, one without, to ensure that
  // the useAes test is only performed once, not every iteration.
  if(useAes)
  {
    if (variant == 0){ 
        for(i = 0; i < aes_rounds/2; i++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes();
        }
    }else{    
      for(i = 0; i < aes_rounds*2; i++)
      {      
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            _mm_store_si128(R128(c), _c);
            a[0] ^= c[0]; a[1] ^= c[1];
      }
    }
  }else{
    if (variant == 0){
      for(i = 0; i < aes_rounds/2; i++)
      {
          pre_aes();
          aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
          post_aes();
      }
    }else{
      for(i = 0; i < aes_rounds*2; i++)
      {
          pre_aes();
          aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
          _mm_store_si128(R128(c), _c);
          a[0] ^= c[0]; a[1] ^= c[1];
       }
    }
  }

  /* CryptoNight Step 4:  Sequentially pass through the mixing buffer and use 10 rounds
   * of AES encryption to mix the random data back into the 'text' buffer.  'text'
   * was originally created with the output of Keccak1600. */

  memcpy(text, state.init, INIT_SIZE_BYTE);
  if(useAes)
  {
      aes_expand_key(&state.hs.b[32], expandedKey);
      for(i = 0; i < init_rounds; i++)
      {
          // add the xor to the pseudo round
          aes_pseudo_round_xor(text, text, expandedKey, &hp_state[i * INIT_SIZE_BYTE], INIT_SIZE_BLK);
      }
  }
  else
  {
      oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
      for(i = 0; i < init_rounds; i++)
      {
          for(j = 0; j < INIT_SIZE_BLK; j++)
          {
              xor_blocks(&text[j * AES_BLOCK_SIZE], &hp_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
              aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
          }
      }
      oaes_free((OAES_CTX **) &aes_ctx);
  }

  /* CryptoNight Step 5:  Apply Keccak to the state again, and then
   * use the resulting data to select which of four finalizer
   * hash functions to apply to the data (Blake, Groestl, JH, or Skein).
   * Use this hash to squeeze the state array down
   * to the final 256 bit hash output.
   */

  memcpy(state.init, text, INIT_SIZE_BYTE);
  hash_permutation(&state.hs);
  extra_hashes[state.hs.b[0] & 3](&state, 200, hash);
  slow_hash_free_state(PAGE_SIZE);
}

#elif !defined NO_AES && (defined(__arm__) || defined(__aarch64__))
void slow_hash_allocate_state(void)
{
  // Do nothing, this is just to maintain compatibility with the upgraded slow-hash.c
  return;
}

void slow_hash_free_state(void)
{
  // As above
  return;
}
