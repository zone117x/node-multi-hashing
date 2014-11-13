#include "x5.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

void x5_hash(const char* input, char* output)
{
    sph_blake512_context     ctx_blake;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;

    unsigned char hash[64];

    // BLAKE
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, 80);
    sph_blake512_close(&ctx_blake, (void*) hash);
    // GROESTL
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, (const void*) hash, 64);
    sph_groestl512_close(&ctx_groestl, (void*) hash);
    // JH
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, (const void*) hash, 64);
    sph_jh512_close(&ctx_jh, (void*) hash);
    // KECCAK
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, (const void*) hash, 64);
    sph_keccak512_close(&ctx_keccak, (void*) hash);
    // SKEIN
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, (const void*) hash, 64);
    sph_skein512_close(&ctx_skein, (void*) hash);

    memcpy(state, hash, 32);
}
