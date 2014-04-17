#include "groestl.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_groestl.h"


void groestl_hash(const char* input, char* output, unsigned int len)
{
    sph_groestl256_context ctx_groestl;
    sph_groestl256_init(&ctx_groestl);
    sph_groestl256(&ctx_groestl, input, len);
    sph_groestl256_close(&ctx_groestl, output);
}

