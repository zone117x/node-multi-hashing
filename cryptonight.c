// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)


extern int aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct {
        uint8_t k[64];
        uint8_t init[INIT_SIZE_BYTE];
    };
};
#pragma pack(pop)

static void do_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
    groestl(input, len * 8, (uint8_t*)output);
}

static void do_jh_hash(const void* input, size_t len, char* output) {
    int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
    assert(SUCCESS == r);
}

static void do_skein_hash(const void* input, size_t len, char* output) {
    int r = c_skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
    assert(SKEIN_SUCCESS == r);
}

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
    do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash
};

static size_t e2i(const uint8_t* a, size_t count) {
    return (*((uint64_t*) a) / AES_BLOCK_SIZE) & (count - 1);
}

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
    uint64_t a0, b0;
    uint64_t hi, lo;

    a0 = SWAP64LE(((uint64_t*) a)[0]);
    b0 = SWAP64LE(((uint64_t*) b)[0]);
    lo = mul128(a0, b0, &hi);
    ((uint64_t*) res)[0] = SWAP64LE(hi);
    ((uint64_t*) res)[1] = SWAP64LE(lo);
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
    uint64_t a0, a1, b0, b1;

    a0 = SWAP64LE(((uint64_t*) a)[0]);
    a1 = SWAP64LE(((uint64_t*) a)[1]);
    b0 = SWAP64LE(((uint64_t*) b)[0]);
    b1 = SWAP64LE(((uint64_t*) b)[1]);
    a0 += b0;
    a1 += b1;
    ((uint64_t*) a)[0] = SWAP64LE(a0);
    ((uint64_t*) a)[1] = SWAP64LE(a1);
    
}

#define U64(x) ((uint64_t *) (x))

static void copy_block(uint8_t* dst, const uint8_t* src) {
    memcpy(dst, src, AES_BLOCK_SIZE);
}


static void swap_blocks(uint8_t *a, uint8_t *b){
uint64_t t[2];
U64(t)[0] = U64(a)[0];
U64(t)[1] = U64(a)[1];
U64(a)[0] = U64(b)[0];
U64(a)[1] = U64(b)[1];
U64(b)[0] = U64(t)[0];
U64(b)[1] = U64(t)[1];
}

static void xor_blocks(uint8_t* a, const uint8_t* b) {
    size_t i;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        a[i] ^= b[i];
    }
}

void cryptonight_hash(const char* input, char* output, uint32_t len) {
    uint8_t long_state[MEMORY];
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE];
    uint8_t a[AES_BLOCK_SIZE];
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t c[AES_BLOCK_SIZE];
    uint8_t d[AES_BLOCK_SIZE];
    size_t i, j;
    uint8_t aes_key[AES_KEY_SIZE];
    oaes_ctx *aes_ctx;

    hash_process(&state.hs, (const uint8_t*) input, len);
    memcpy(text, state.init, INIT_SIZE_BYTE);
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);
    aes_ctx = (oaes_ctx *) oaes_alloc();

    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
		  aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
        }
        memcpy(&long_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
    }

    for (i = 0; i < 16; i++) {
        a[i] = state.k[i] ^ state.k[32 + i];
        b[i] = state.k[16 + i] ^ state.k[48 + i];
    }

    for (i = 0; i < ITER / 2; i++) {
        /* Dependency chain: address -> read value ------+
         * written value <-+ hard function (AES or MUL) <+
         * next address  <-+
         */
        /* Iteration 1 */
        j = e2i(a, MEMORY / AES_BLOCK_SIZE);
        copy_block(c, &long_state[j * AES_BLOCK_SIZE]);
        aesb_single_round(c, c, a);
        xor_blocks(b, c);
        swap_blocks(b, c);
        copy_block(&long_state[j * AES_BLOCK_SIZE], c);
        assert(j == e2i(a, MEMORY / AES_BLOCK_SIZE));
        swap_blocks(a, b);
        /* Iteration 2 */
        j = e2i(a, MEMORY / AES_BLOCK_SIZE);
        copy_block(c, &long_state[j * AES_BLOCK_SIZE]);
        mul(a, c, d);
        sum_half_blocks(b, d);
        swap_blocks(b, c);
        xor_blocks(b, c);
        copy_block(&long_state[j * AES_BLOCK_SIZE], c);
        swap_blocks(a, b);
    }

    memcpy(text, state.init, INIT_SIZE_BYTE);
    oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            xor_blocks(&text[j * AES_BLOCK_SIZE],
                    &long_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
	                aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
        }
    }
    memcpy(state.init, text, INIT_SIZE_BYTE);
    hash_permutation(&state.hs);
    /*memcpy(hash, &state, 32);*/
    extra_hashes[state.hs.b[0] & 3](&state, 200, output);
    oaes_free((OAES_CTX **) &aes_ctx);
}

void cryptonight_fast_hash(const char* input, char* output, uint32_t len) {
    union hash_state state;
    hash_process(&state, input, len);
    memcpy(output, &state, HASH_SIZE);
}
