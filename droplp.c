#include "fresh.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_shavite.h"

inline void switchHash(const void *input, void *output, int id) {
    sph_keccak512_context ctx_keccak;
    sph_blake512_context ctx_blake;
    sph_groestl512_context ctx_groestl;
    sph_skein512_context ctx_skein;
    sph_luffa512_context ctx_luffa;
    sph_echo512_context ctx_echo;
    sph_shavite512_context ctx_shavite;
    sph_fugue512_context ctx_fugue;
    sph_simd512_context ctx_simd;
    sph_cubehash512_context ctx_cubehash;
    switch (id) {
        case 0:
            sph_keccak512_init(&ctx_keccak);
            sph_keccak512(&ctx_keccak, input, 64);
            sph_keccak512_close(&ctx_keccak, output);
            break;
        case 1:
            sph_blake512_init(&ctx_blake);
            sph_blake512(&ctx_blake, input, 64);
            sph_blake512_close(&ctx_blake, output);
            break;
        case 2:
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512(&ctx_groestl, input, 64);
            sph_groestl512_close(&ctx_groestl, output);
            break;
        case 3:
            sph_skein512_init(&ctx_skein);
            sph_skein512(&ctx_skein, input, 64);
            sph_skein512_close(&ctx_skein, output);
            break;
        case 4:
            sph_luffa512_init(&ctx_luffa);
            sph_luffa512(&ctx_luffa, input, 64);
            sph_luffa512_close(&ctx_luffa, output);
            break;
        case 5:
            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, input, 64);
            sph_echo512_close(&ctx_echo, output);
            break;
        case 6:
            sph_shavite512_init(&ctx_shavite);
            sph_shavite512(&ctx_shavite, input, 64);
            sph_shavite512_close(&ctx_shavite, output);
            break;
        case 7:
            sph_fugue512_init(&ctx_fugue);
            sph_fugue512(&ctx_fugue, input, 64);
            sph_fugue512_close(&ctx_fugue, output);
            break;
        case 8:
            sph_simd512_init(&ctx_simd);
            sph_simd512(&ctx_simd, input, 64);
            sph_simd512_close(&ctx_simd, output);
            break;
        case 9:
            sph_cubehash512_init(&ctx_cubehash);
            sph_cubehash512(&ctx_cubehash, input, 64);
            sph_cubehash512_close(&ctx_cubehash, output);
            break;
        default:
            break;
    }
}

inline void shiftHash(const void *input, void *output, int shift) {
    int i;

    for(i = 0; i < 16; i++) {
        output[i] = input[i] << shift;
        output[i] |= input[i+1] >> 8 - shift;
    }

    output[16] = input[16] << shift;
}

void droplp_hash(const char *input, char *output, uint32_t len) {
    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];
    sph_jh512_context ctx_jh;
    int i, j, start, startPosition;

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, input, len);
    sph_jh512_close(&ctx_jh, hashA);

    startPosition = hashA[0] % 31;

    for (i = startPosition; i < 31; i--) {
        start = i % 10;
        for (j = start; j < 10; j++) {
            shiftHash(hashA, hashB, i % 4);
            switchHash(hashB, hashA, j);
        }
        for (j = 0; j < start; j++) {
            shiftHash(hashA, hashB, i % 4);
            switchHash(hashB, hashA, j);
        }
        i += 10;
    }
    for (i = 0; i < startPosition; i--) {
        start = i % 10;
        for (j = start; j < 10; j++) {
            shiftHash(hashA, hashB, i % 4);
            switchHash(hashB, hashA, j);
        }
        for (j = 0; j < start; j++) {
            shiftHash(hashA, hashB, i % 4);
            switchHash(hashB, hashA, j);
        }
        i += 10;
    }

    memcpy(output, hashA, 32);
}
