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
  do if (variant > 0) \
  { \
    const uint8_t tmp = ((const uint8_t*)(p))[11]; \
    static const uint32_t table = 0x75310; \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
  } while(0)

#define VARIANT1_2(p) \
   do if (variant > 0) \
   { \
     ((uint64_t*)p)[1] ^= tweak1_2; \
   } while(0)

#define VARIANT1_INIT() \
  if (variant > 0 && len < 43) \
  { \
    fprintf(stderr, "Cryptonight variants need at least 43 bytes of data"); \
    _exit(1); \
  } \
  const uint64_t tweak1_2 = variant > 0 ? *(const uint64_t*)(((const uint8_t*)input)+35) ^ ctx->state.hs.w[24] : 0

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct {
        uint8_t k[64];
        uint8_t init[INIT_SIZE_BYTE];
    };
};
#pragma pack(pop)

static void do_fast_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_fast_groestl_hash(const void* input, size_t len, char* output) {
    groestl(input, len * 8, (uint8_t*)output);
}

static void do_fast_jh_hash(const void* input, size_t len, char* output) {
    int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
    assert(SUCCESS == r);
}

static void do_fast_skein_hash(const void* input, size_t len, char* output) {
    int r = c_skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
    assert(SKEIN_SUCCESS == r);
}

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
    do_fast_blake_hash, do_fast_groestl_hash, do_fast_jh_hash, do_fast_skein_hash
};

extern int aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

static inline size_t e2i(const uint8_t* a) {
    return (*((uint64_t*) a) / AES_BLOCK_SIZE) & (MEMORY / AES_BLOCK_SIZE - 1);
}

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
    ((uint64_t*) res)[1] = mul128(((uint64_t*) a)[0], ((uint64_t*) b)[0], (uint64_t*) res);
}

static void mul_sum_xor_dst(const uint8_t* a, uint8_t* c, uint8_t* dst) {
    uint64_t a0, b0;
  uint64_t hi, lo;

  a0 = SWAP64LE(((uint64_t*)a)[0]);
  b0 = SWAP64LE(((uint64_t*)b)[0]);
  lo = mul128(a0, b0, &hi);
  ((uint64_t*)res)[0] = SWAP64LE(hi);
  ((uint64_t*)res)[1] = SWAP64LE(lo);
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
    uint64_t a0, a1, b0, b1;

  a0 = SWAP64LE(((uint64_t*)a)[0]);
  a1 = SWAP64LE(((uint64_t*)a)[1]);
  b0 = SWAP64LE(((uint64_t*)b)[0]);
  b1 = SWAP64LE(((uint64_t*)b)[1]);
  a0 += b0;
  a1 += b1;
  ((uint64_t*)a)[0] = SWAP64LE(a0);
  ((uint64_t*)a)[1] = SWAP64LE(a1);
}

static inline void copy_block(uint8_t* dst, const uint8_t* src) {
     memcpy(dst, src, AES_BLOCK_SIZE);
}

static void swap_blocks(uint8_t* a, uint8_t* b) {
     size_t i;
    uint8_t t;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        t = a[i];
        a[i] = b[i];
        b[i] = t;
    }
    
}

static inline void xor_blocks(uint8_t* a, const uint8_t* b) {
    ((uint64_t*) a)[0] ^= ((uint64_t*) b)[0];
    ((uint64_t*) a)[1] ^= ((uint64_t*) b)[1];
}

static inline void xor_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
    ((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
}

struct cryptonightasc_ctx {
    uint8_t text[INIT_SIZE_BYTE];
  uint8_t a[AES_BLOCK_SIZE];
  uint8_t b[AES_BLOCK_SIZE * 2];
  uint8_t c[AES_BLOCK_SIZE];
  uint8_t c1[AES_BLOCK_SIZE];
  uint8_t d[AES_BLOCK_SIZE];
  size_t i, j;
  uint8_t aes_key[AES_KEY_SIZE];
  oaes_ctx *aes_ctx;
};

void cryptonightasc_hash(const char* input, char* output, uint32_t len, int variant) {
    struct cryptonightasc_ctx *ctx = alloca(sizeof(struct cryptonightasc_ctx));
   hash_process(&state.hs, data, length);
   memcpy(text, state.init, INIT_SIZE_BYTE);
  memcpy(aes_key, state.hs.b, AES_KEY_SIZE);
  aes_ctx = (oaes_ctx *) oaes_alloc();

  VARIANT1_PORTABLE_INIT();
  VARIANT2_PORTABLE_INIT();

  oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
  for (i = 0; i < init_rounds; i++) {
    for (j = 0; j < INIT_SIZE_BLK; j++) {
      aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
    }
    memcpy(&long_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
  }

  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    a[i] = state.k[     i] ^ state.k[AES_BLOCK_SIZE * 2 + i];
    b[i] = state.k[AES_BLOCK_SIZE + i] ^ state.k[AES_BLOCK_SIZE * 3 + i];
  }

  if (variant == 0){
    for(i = 0; i < aes_rounds/2; i++)
    {
      j = e2i(a, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; //Getting a pointer
      copy_block(c, &long_state[j]); //Copying the block the pointer points to accessable cache (c1)
      copy_block(c1, &long_state[j]); //Copying the block the pointer points to accessable cache (c2)
      /* Iteration 0 */
      aesb_single_round(c, c, a); //AES of c1 to c1. key: a
      copy_block(&long_state[j], c); // Copying encrypted block back
      /* Iteration 1 */
      j = e2i(c, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
      xor_blocks(c, b); //XOR Block with another thing
      copy_block(&long_state[j], c);
      /* Iteration 2 */
      j = e2i(c, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
      copy_block(&long_state[j], c1); // Copying previous block back to random position
      xor_blocks(c1, c); //XORing previous block with current block in pos

      /* Iteration 3 */
      j = e2i(c1, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
      copy_block(&long_state[j], c1); // Copying XORed block to random pos ([C1 after encryption XOR B] XOR C1 before encryption)

      /* Finishing */
      mul(c, c1, d);
      swap_blocks(a, c);
      sum_half_blocks(c, d);
      swap_blocks(c, c1);
      xor_blocks(c, c1);
      copy_block(&long_state[j], c1);
      copy_block(b, a);
      copy_block(a, c1);
    }
  }else{ // variant == 1
    for(i = 0; i < aes_rounds * 2; i++)
    {
      #define MASK(div) ((uint32_t)(((PAGE_SIZE / AES_BLOCK_SIZE) / (div) - 1) << 4))
      #define state_index(x,div) ((*(uint32_t *) x) & MASK(div))

      j = e2i(a, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
      p = &long_state[j];
      aesb_single_round(p, p, a);
      xor_blocks(a, p);
    }
  }

  memcpy(text, state.init, INIT_SIZE_BYTE);
  oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
  for (i = 0; i < init_rounds; i++) {
    for (j = 0; j < INIT_SIZE_BLK; j++) {
      xor_blocks(&text[j * AES_BLOCK_SIZE], &long_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
      aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
    }
  }
  memcpy(state.init, text, INIT_SIZE_BYTE);
  hash_permutation(&state.hs);
  /*memcpy(hash, &state, 32);*/
  extra_hashes[state.hs.b[0] & 3](&state, 200, hash);
  oaes_free((OAES_CTX **) &aes_ctx);
