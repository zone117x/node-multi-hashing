#include "skein.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_skein.h"


void keccak_hash(const char* input, char* output)
{
    sph_keccak512_context    ctx_keccak;
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, input, 64);
    sph_keccak512_close(&ctx_keccak, output);

}

