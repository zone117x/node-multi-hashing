#include "skein.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_skein.h"


void skein_hash(const char* input, char* output, unsigned int len)
{
    sph_skein256_context ctx_skien;
    sph_skein256_init(&ctx_skien);
    sph_skein256(&ctx_skien, input, len);
    sph_skein256_close(&ctx_skien, output);
}

