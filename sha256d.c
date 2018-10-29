#include "sha256d.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_sha2.h"

void sha256d_hash(const char* input, char* output, uint32_t len)
{
	uint32_t hashA[32], hashB[32];

	sph_sha256_context ctx_sha2;

	sph_sha256_init(&ctx_sha2);

	sph_sha256(&ctx_sha2, input, len);
	sph_sha256_close(&ctx_sha2, hashA);

	sph_sha256(&ctx_sha2, hashA, 32);
	sph_sha256_close(&ctx_sha2, hashB);

	memcpy(output, hashB, 32);
}
