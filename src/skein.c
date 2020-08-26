#include "skein.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_skein.h"
#include "sha256.h"

#include <stdlib.h>

void skein_hash(const char* input, char* output, uint32_t len)
{
    char temp[64];

    sph_skein512_context ctx_skien;
    sph_skein512_init(&ctx_skien);
    sph_skein512(&ctx_skien, input, len);
    sph_skein512_close(&ctx_skien, &temp);
    
    sha256_ctx ctx_sha256;
    sha256_init(&ctx_sha256);
    sha256_update(&ctx_sha256, &temp, 64);
    sha256_final((unsigned char*) output, &ctx_sha256);
}

