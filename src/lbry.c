#include "lbry.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_sha2.h"
#include "sha3/sph_ripemd.h"

void lbry_hash(const char* input, char* output, uint32_t len)
{
	uint32_t hashA[16] = { 0 }, hashB[8], hashC[8];
	
	//lbry hash is designed to hash exactly 112 bytes (block header size)
	//so only calculate a hash if 112 bytes are available
	if(len >= 112) {
		sph_sha256_context ctx_sha256;
		sph_sha512_context ctx_sha512;
		sph_ripemd160_context ctx_ripemd;

		sph_sha256_init(&ctx_sha256);
		sph_sha512_init(&ctx_sha512);
		sph_ripemd160_init(&ctx_ripemd);

		sph_sha256(&ctx_sha256, input, len);
		sph_sha256_close(&ctx_sha256, hashA);

		sph_sha256(&ctx_sha256, hashA, 32);
		sph_sha256_close(&ctx_sha256, hashA);

		sph_sha512(&ctx_sha512, hashA, 32);
		sph_sha512_close(&ctx_sha512, hashA);

		sph_ripemd160(&ctx_ripemd, hashA, 32);
		sph_ripemd160_close(&ctx_ripemd, hashB);

		sph_ripemd160(&ctx_ripemd, &hashA[8], 32);
		sph_ripemd160_close(&ctx_ripemd, hashC);

		sph_sha256(&ctx_sha256, hashB, 20);
		sph_sha256(&ctx_sha256, hashC, 20);
		sph_sha256_close(&ctx_sha256, hashA);

		sph_sha256(&ctx_sha256, hashA, 32);
		sph_sha256_close(&ctx_sha256, hashA);
	}

	memcpy(output, hashA, 32);
}
