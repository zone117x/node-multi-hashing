#include "skein.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_skein.h"


void skein_hash(const char* input, char* output)
{
    sph_skein512_context    ctx_skien;
    sph_skein512_init(&ctx_skien);
    sph_skeink512 (&ctx_skien, input, 64);
    sph_skein512_close(&ctx_skien, output);

}

