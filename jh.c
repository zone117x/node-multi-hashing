#include "jh.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "uint256.h"
#include "sha3/sph_jh.h"


void jh_hash(const char* input, char* output, uint32_t len) {

    sph_jh256_context ctx_jh;
    static unsigned char pblank[1];
    uint256 hash;

    sph_jh256_init(&ctx_jh);
    sph_jh256 (&ctx_jh, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_jh256_close(&ctx_jh, static_cast<void*>(&hash));

    return hash;

}

