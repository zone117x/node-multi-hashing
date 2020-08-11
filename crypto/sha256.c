/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "sha256.h"

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static void
be32enc_vect(unsigned char *dst, const uint32_t *src, size_t len)
{
	size_t i;

	for (i = 0; i < len / 4; i++)
		be32enc(dst + i * 4, src[i]);
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
static void
be32dec_vect(uint32_t *dst, const unsigned char *src, size_t len)
{
	size_t i;

	for (i = 0; i < len / 4; i++)
		dst[i] = be32dec(src + i * 4);
}

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)	((x & (y ^ z)) ^ z)
#define Maj(x, y, z)	((x & (y | z)) | (y & z))
#define SHR(x, n)	SPH_T32((x) >> n)
#define ROTR		SPH_ROTR32
#define S0(x)		(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)		(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k)			\
	t0 = h + S1(e) + Ch(e, f, g) + k;		\
	t1 = S0(a) + Maj(a, b, c);			\
	d += t0;					\
	h  = t0 + t1;

/* Adjusted round function for rotating state */
#define RNDr(S, W, i, k)			\
	RND(S[(64 - (i)) % 8], S[(65 - (i)) % 8],	\
	    S[(66 - (i)) % 8], S[(67 - (i)) % 8],	\
	    S[(68 - (i)) % 8], S[(69 - (i)) % 8],	\
	    S[(70 - (i)) % 8], S[(71 - (i)) % 8],	\
	    W[i] + k)

#ifndef UNROLL
static const uint32_t K[64] = {
	SPH_C32(0x428a2f98), SPH_C32(0x71374491), SPH_C32(0xb5c0fbcf), SPH_C32(0xe9b5dba5),
	SPH_C32(0x3956c25b), SPH_C32(0x59f111f1), SPH_C32(0x923f82a4), SPH_C32(0xab1c5ed5),
	SPH_C32(0xd807aa98), SPH_C32(0x12835b01), SPH_C32(0x243185be), SPH_C32(0x550c7dc3),
	SPH_C32(0x72be5d74), SPH_C32(0x80deb1fe), SPH_C32(0x9bdc06a7), SPH_C32(0xc19bf174),
	SPH_C32(0xe49b69c1), SPH_C32(0xefbe4786), SPH_C32(0x0fc19dc6), SPH_C32(0x240ca1cc),
	SPH_C32(0x2de92c6f), SPH_C32(0x4a7484aa), SPH_C32(0x5cb0a9dc), SPH_C32(0x76f988da),
	SPH_C32(0x983e5152), SPH_C32(0xa831c66d), SPH_C32(0xb00327c8), SPH_C32(0xbf597fc7),
	SPH_C32(0xc6e00bf3), SPH_C32(0xd5a79147), SPH_C32(0x06ca6351), SPH_C32(0x14292967),
	SPH_C32(0x27b70a85), SPH_C32(0x2e1b2138), SPH_C32(0x4d2c6dfc), SPH_C32(0x53380d13),
	SPH_C32(0x650a7354), SPH_C32(0x766a0abb), SPH_C32(0x81c2c92e), SPH_C32(0x92722c85),
	SPH_C32(0xa2bfe8a1), SPH_C32(0xa81a664b), SPH_C32(0xc24b8b70), SPH_C32(0xc76c51a3),
	SPH_C32(0xd192e819), SPH_C32(0xd6990624), SPH_C32(0xf40e3585), SPH_C32(0x106aa070),
	SPH_C32(0x19a4c116), SPH_C32(0x1e376c08), SPH_C32(0x2748774c), SPH_C32(0x34b0bcb5),
	SPH_C32(0x391c0cb3), SPH_C32(0x4ed8aa4a), SPH_C32(0x5b9cca4f), SPH_C32(0x682e6ff3),
	SPH_C32(0x748f82ee), SPH_C32(0x78a5636f), SPH_C32(0x84c87814), SPH_C32(0x8cc70208),
	SPH_C32(0x90befffa), SPH_C32(0xa4506ceb), SPH_C32(0xbef9a3f7), SPH_C32(0xc67178f2),
};
#endif

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void
sha256_transform(uint32_t * state, const unsigned char block[64])
{
	uint32_t W[64];
	uint32_t S[8];
	uint32_t t0, t1;
	int i;

	/* 1. Prepare message schedule W. */
	be32dec_vect(W, block, 64);
	for (i = 16; i < 64; i++)
		W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];

	/* 2. Initialize working variables. */
	memcpy(S, state, 32);

	/* 3. Mix. */
#ifdef UNROLL
	RNDr(S, W, 0, SPH_C32(0x428a2f98));
	RNDr(S, W, 1, SPH_C32(0x71374491));
	RNDr(S, W, 2, SPH_C32(0xb5c0fbcf));
	RNDr(S, W, 3, SPH_C32(0xe9b5dba5));
	RNDr(S, W, 4, SPH_C32(0x3956c25b));
	RNDr(S, W, 5, SPH_C32(0x59f111f1));
	RNDr(S, W, 6, SPH_C32(0x923f82a4));
	RNDr(S, W, 7, SPH_C32(0xab1c5ed5));
	RNDr(S, W, 8, SPH_C32(0xd807aa98));
	RNDr(S, W, 9, SPH_C32(0x12835b01));
	RNDr(S, W, 10, SPH_C32(0x243185be));
	RNDr(S, W, 11, SPH_C32(0x550c7dc3));
	RNDr(S, W, 12, SPH_C32(0x72be5d74));
	RNDr(S, W, 13, SPH_C32(0x80deb1fe));
	RNDr(S, W, 14, SPH_C32(0x9bdc06a7));
	RNDr(S, W, 15, SPH_C32(0xc19bf174));
	RNDr(S, W, 16, SPH_C32(0xe49b69c1));
	RNDr(S, W, 17, SPH_C32(0xefbe4786));
	RNDr(S, W, 18, SPH_C32(0x0fc19dc6));
	RNDr(S, W, 19, SPH_C32(0x240ca1cc));
	RNDr(S, W, 20, SPH_C32(0x2de92c6f));
	RNDr(S, W, 21, SPH_C32(0x4a7484aa));
	RNDr(S, W, 22, SPH_C32(0x5cb0a9dc));
	RNDr(S, W, 23, SPH_C32(0x76f988da));
	RNDr(S, W, 24, SPH_C32(0x983e5152));
	RNDr(S, W, 25, SPH_C32(0xa831c66d));
	RNDr(S, W, 26, SPH_C32(0xb00327c8));
	RNDr(S, W, 27, SPH_C32(0xbf597fc7));
	RNDr(S, W, 28, SPH_C32(0xc6e00bf3));
	RNDr(S, W, 29, SPH_C32(0xd5a79147));
	RNDr(S, W, 30, SPH_C32(0x06ca6351));
	RNDr(S, W, 31, SPH_C32(0x14292967));
	RNDr(S, W, 32, SPH_C32(0x27b70a85));
	RNDr(S, W, 33, SPH_C32(0x2e1b2138));
	RNDr(S, W, 34, SPH_C32(0x4d2c6dfc));
	RNDr(S, W, 35, SPH_C32(0x53380d13));
	RNDr(S, W, 36, SPH_C32(0x650a7354));
	RNDr(S, W, 37, SPH_C32(0x766a0abb));
	RNDr(S, W, 38, SPH_C32(0x81c2c92e));
	RNDr(S, W, 39, SPH_C32(0x92722c85));
	RNDr(S, W, 40, SPH_C32(0xa2bfe8a1));
	RNDr(S, W, 41, SPH_C32(0xa81a664b));
	RNDr(S, W, 42, SPH_C32(0xc24b8b70));
	RNDr(S, W, 43, SPH_C32(0xc76c51a3));
	RNDr(S, W, 44, SPH_C32(0xd192e819));
	RNDr(S, W, 45, SPH_C32(0xd6990624));
	RNDr(S, W, 46, SPH_C32(0xf40e3585));
	RNDr(S, W, 47, SPH_C32(0x106aa070));
	RNDr(S, W, 48, SPH_C32(0x19a4c116));
	RNDr(S, W, 49, SPH_C32(0x1e376c08));
	RNDr(S, W, 50, SPH_C32(0x2748774c));
	RNDr(S, W, 51, SPH_C32(0x34b0bcb5));
	RNDr(S, W, 52, SPH_C32(0x391c0cb3));
	RNDr(S, W, 53, SPH_C32(0x4ed8aa4a));
	RNDr(S, W, 54, SPH_C32(0x5b9cca4f));
	RNDr(S, W, 55, SPH_C32(0x682e6ff3));
	RNDr(S, W, 56, SPH_C32(0x748f82ee));
	RNDr(S, W, 57, SPH_C32(0x78a5636f));
	RNDr(S, W, 58, SPH_C32(0x84c87814));
	RNDr(S, W, 59, SPH_C32(0x8cc70208));
	RNDr(S, W, 60, SPH_C32(0x90befffa));
	RNDr(S, W, 61, SPH_C32(0xa4506ceb));
	RNDr(S, W, 62, SPH_C32(0xbef9a3f7));
	RNDr(S, W, 63, SPH_C32(0xc67178f2));
#else
	for (i = 0; i < 64; i+=8) {
		RNDr(S, W, i, K[i]);
		RNDr(S, W, i+1, K[i+1]);
		RNDr(S, W, i+2, K[i+2]);
		RNDr(S, W, i+3, K[i+3]);
		RNDr(S, W, i+4, K[i+4]);
		RNDr(S, W, i+5, K[i+5]);
		RNDr(S, W, i+6, K[i+6]);
		RNDr(S, W, i+7, K[i+7]);
	}
#endif

	/* 4. Mix local working variables into global state */
	for (i = 0; i < 8; i++)
		state[i] += S[i];

	/* Clean the stack. */
	memset(W, 0, 256);
	memset(S, 0, 32);
	t0 = t1 = 0;
}

/* SHA-256 initialization.  Begins a SHA-256 operation. */
void
sha256_init(sha256_ctx * ctx)
{

	/* Zero bits processed so far */
	ctx->count[0] = ctx->count[1] = 0;

	/* Magic initialization constants */
	ctx->state[0] = SPH_C32(0x6A09E667);
	ctx->state[1] = SPH_C32(0xBB67AE85);
	ctx->state[2] = SPH_C32(0x3C6EF372);
	ctx->state[3] = SPH_C32(0xA54FF53A);
	ctx->state[4] = SPH_C32(0x510E527F);
	ctx->state[5] = SPH_C32(0x9B05688C);
	ctx->state[6] = SPH_C32(0x1F83D9AB);
	ctx->state[7] = SPH_C32(0x5BE0CD19);
}

/* Add bytes into the hash */
void
sha256_update(sha256_ctx * ctx, const void *in, size_t len)
{
	uint32_t bitlen[2];
	const unsigned char *src = in;

	/* Number of bytes left in the buffer from previous updates */
	uint32_t r = (ctx->count[1] >> 3) & 0x3f;

	/* Convert the length into a number of bits */
	bitlen[1] = ((uint32_t)len) << 3;
	bitlen[0] = (uint32_t)(len >> 29);

	/* Update number of bits */
	if ((ctx->count[1] += bitlen[1]) < bitlen[1])
		ctx->count[0]++;
	ctx->count[0] += bitlen[0];

	/* Handle the case where we don't need to perform any transforms */
	if (len < 64 - r) {
		memcpy(&ctx->buf[r], src, len);
		return;
	}

	/* Finish the current block */
	memcpy(&ctx->buf[r], src, 64 - r);
	sha256_transform(ctx->state, ctx->buf);
	src += 64 - r;
	len -= 64 - r;

	/* Perform complete blocks */
	while (len >= 64) {
		sha256_transform(ctx->state, src);
		src += 64;
		len -= 64;
	}

	/* Copy left over data into buffer */
	memcpy(ctx->buf, src, len);
}

/* Add padding and terminating bit-count. */
static void
sha256_pad(sha256_ctx * ctx)
{
	const unsigned char PAD[64] = {
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	/*
	 * Convert length to a vector of bytes -- we do this now rather
	 * than later because the length will change after we pad.
	 */
	unsigned char len[8];
	be32enc_vect(len, ctx->count, 8);

	/* Add 1--64 bytes so that the resulting length is 56 mod 64 */
	uint32_t r = (ctx->count[1] >> 3) & 0x3f;
	uint32_t plen = (r < 56) ? (56 - r) : (120 - r);
	sha256_update(ctx, PAD, (size_t)plen);

	/* Add the terminating bit-count */
	sha256_update(ctx, len, 8);
}

/*
 * SHA-256 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
void
sha256_final(unsigned char digest[32], sha256_ctx * ctx)
{

	/* Add padding */
	sha256_pad(ctx);

	/* Write the hash */
	be32enc_vect(digest, ctx->state, 32);

	/* Clear the context state */
	memset((void *)ctx, 0, sizeof(*ctx));
}

/* Initialize an HMAC-SHA256 operation with the given key. */
void
hmac_sha256_init(hmac_sha256_ctx * ctx, const void * _K, size_t Klen)
{
	unsigned char pad[64];
	unsigned char khash[32];
	const unsigned char * K = _K;
	size_t i;

	/* If Klen > 64, the key is really SHA256(K). */
	if (Klen > 64) {
		sha256_init(&ctx->ictx);
		sha256_update(&ctx->ictx, K, Klen);
		sha256_final(khash, &ctx->ictx);
		K = khash;
		Klen = 32;
	}

	/* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
	sha256_init(&ctx->ictx);
	memset(pad, 0x36, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	sha256_update(&ctx->ictx, pad, 64);

	/* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
	sha256_init(&ctx->octx);
	memset(pad, 0x5c, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	sha256_update(&ctx->octx, pad, 64);

	/* Clean the stack. */
	memset(khash, 0, 32);
}

/* Add bytes to the HMAC-SHA256 operation. */
void
hmac_sha256_update(hmac_sha256_ctx * ctx, const void *in, size_t len)
{

	/* Feed data to the inner SHA256 operation. */
	sha256_update(&ctx->ictx, in, len);
}

/* Finish an HMAC-SHA256 operation. */
void
hmac_sha256_final(unsigned char digest[32], hmac_sha256_ctx * ctx)
{
	unsigned char ihash[32];

	/* Finish the inner SHA256 operation. */
	sha256_final(ihash, &ctx->ictx);

	/* Feed the inner hash to the outer SHA256 operation. */
	sha256_update(&ctx->octx, ihash, 32);

	/* Finish the outer SHA256 operation. */
	sha256_final(digest, &ctx->octx);

	/* Clean the stack. */
	memset(ihash, 0, 32);
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
PBKDF2_SHA256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
	hmac_sha256_ctx PShctx, hctx;
	size_t i;
	uint8_t ivec[4];
	uint8_t U[32];
	uint8_t T[32];
	uint64_t j;
	int k;
	size_t clen;

	/* Compute HMAC state after processing P and S. */
	hmac_sha256_init(&PShctx, passwd, passwdlen);
	hmac_sha256_update(&PShctx, salt, saltlen);

	/* Iterate through the blocks. */
	for (i = 0; i * 32 < dkLen; i++) {
		/* Generate INT(i + 1). */
		be32enc(ivec, (uint32_t)(i + 1));

		/* Compute U_1 = PRF(P, S || INT(i)). */
		memcpy(&hctx, &PShctx, sizeof(hmac_sha256_ctx));
		hmac_sha256_update(&hctx, ivec, 4);
		hmac_sha256_final(U, &hctx);

		/* T_i = U_1 ... */
		memcpy(T, U, 32);

		for (j = 2; j <= c; j++) {
			/* Compute U_j. */
			hmac_sha256_init(&hctx, passwd, passwdlen);
			hmac_sha256_update(&hctx, U, 32);
			hmac_sha256_final(U, &hctx);

			/* ... xor U_j ... */
			for (k = 0; k < 32; k++)
				T[k] ^= U[k];
		}

		/* Copy as many bytes as necessary into buf. */
		clen = dkLen - i * 32;
		if (clen > 32)
			clen = 32;
		memcpy(&buf[i * 32], T, clen);
	}

	/* Clean PShctx, since we never called _Final on it. */
	memset(&PShctx, 0, sizeof(hmac_sha256_ctx));
}
