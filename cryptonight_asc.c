/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  */
#pragma once

#include "cryptonight.h"
#include <memory.h>
#include <stdio.h>

#ifdef __GNUC__
#include <x86intrin.h>
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
	unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
	*hi = r >> 64;
	return (uint64_t)r;
}
#define _mm256_set_m128i(v0, v1)  _mm256_insertf128_si256(_mm256_castsi128_si256(v1), (v0), 1)
#else
#include <intrin.h>
#endif // __GNUC__
#define U64(x) ((uint64_t *) (x))
#define R128(x) ((__m128i *) (x))
#define state_index(x) (((*((uint64_t *)x) >> 4) & (TOTALBLOCKS /(2) - 1)) << 4)
#if !defined(_LP64) && !defined(_WIN64)
#error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

extern "C"
{
	void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
	void keccakf(uint64_t st[25], int rounds);
	extern void(*const extra_hashes[4])(const void *, size_t, char *);

	__m128i soft_aesenc(__m128i in, __m128i key);
	__m128i soft_aeskeygenassist(__m128i key, uint8_t rcon);
}

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
	__m128i tmp4;
	tmp4 = _mm_slli_si128(tmp1, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	return tmp1;
}

template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
	__m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
	xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
	*xout0 = sl_xor(*xout0);
	*xout0 = _mm_xor_si128(*xout0, xout1);
	xout1 = _mm_aeskeygenassist_si128(*xout0, 0x00);
	xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
	*xout2 = sl_xor(*xout2);
	*xout2 = _mm_xor_si128(*xout2, xout1);
}

static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2, uint8_t rcon)
{
	__m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
	xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
	*xout0 = sl_xor(*xout0);
	*xout0 = _mm_xor_si128(*xout0, xout1);
	xout1 = soft_aeskeygenassist(*xout0, 0x00);
	xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
	*xout2 = sl_xor(*xout2);
	*xout2 = _mm_xor_si128(*xout2, xout1);
}

template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
	__m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
	__m128i xout0, xout2;

	xout0 = _mm_load_si128(memory);
	xout2 = _mm_load_si128(memory+1);
	*k0 = xout0;
	*k1 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x01);
	else
		aes_genkey_sub<0x01>(&xout0, &xout2);
	*k2 = xout0;
	*k3 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x02);
	else
		aes_genkey_sub<0x02>(&xout0, &xout2);
	*k4 = xout0;
	*k5 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x04);
	else
		aes_genkey_sub<0x04>(&xout0, &xout2);
	*k6 = xout0;
	*k7 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x08);
	else
		aes_genkey_sub<0x08>(&xout0, &xout2);
	*k8 = xout0;
	*k9 = xout2;
}

static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = _mm_aesenc_si128(*x0, key);
	*x1 = _mm_aesenc_si128(*x1, key);
	*x2 = _mm_aesenc_si128(*x2, key);
	*x3 = _mm_aesenc_si128(*x3, key);
	*x4 = _mm_aesenc_si128(*x4, key);
	*x5 = _mm_aesenc_si128(*x5, key);
	*x6 = _mm_aesenc_si128(*x6, key);
	*x7 = _mm_aesenc_si128(*x7, key);
}

static inline void soft_aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = soft_aesenc(*x0, key);
	*x1 = soft_aesenc(*x1, key);
	*x2 = soft_aesenc(*x2, key);
	*x3 = soft_aesenc(*x3, key);
	*x4 = soft_aesenc(*x4, key);
	*x5 = soft_aesenc(*x5, key);
	*x6 = soft_aesenc(*x6, key);
	*x7 = soft_aesenc(*x7, key);
}

template<size_t MEM, bool SOFT_AES, bool PREFETCH>
void cn_explode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

	xin0 = _mm_load_si128(input + 4);
	xin1 = _mm_load_si128(input + 5);
	xin2 = _mm_load_si128(input + 6);
	xin3 = _mm_load_si128(input + 7);
	xin4 = _mm_load_si128(input + 8);
	xin5 = _mm_load_si128(input + 9);
	xin6 = _mm_load_si128(input + 10);
	xin7 = _mm_load_si128(input + 11);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		if(SOFT_AES)
		{
			soft_aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}
		else
		{
			aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}

		_mm_store_si128(output + i + 0, xin0);
		_mm_store_si128(output + i + 1, xin1);
		_mm_store_si128(output + i + 2, xin2);
		_mm_store_si128(output + i + 3, xin3);

		if(PREFETCH)
			_mm_prefetch((const char*)output + i + 0, _MM_HINT_T2);

		_mm_store_si128(output + i + 4, xin4);
		_mm_store_si128(output + i + 5, xin5);
		_mm_store_si128(output + i + 6, xin6);
		_mm_store_si128(output + i + 7, xin7);

		if(PREFETCH)
			_mm_prefetch((const char*)output + i + 4, _MM_HINT_T2);
	}
}

template<size_t MEM, bool SOFT_AES, bool PREFETCH>
void cn_implode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

	xout0 = _mm_load_si128(output + 4);
	xout1 = _mm_load_si128(output + 5);
	xout2 = _mm_load_si128(output + 6);
	xout3 = _mm_load_si128(output + 7);
	xout4 = _mm_load_si128(output + 8);
	xout5 = _mm_load_si128(output + 9);
	xout6 = _mm_load_si128(output + 10);
	xout7 = _mm_load_si128(output + 11);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		if(PREFETCH)
			_mm_prefetch((const char*)input + i + 0, _MM_HINT_NTA);

		xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
		xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
		xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
		xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);

		if(PREFETCH)
			_mm_prefetch((const char*)input + i + 4, _MM_HINT_NTA);

		xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
		xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
		xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
		xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

		if(SOFT_AES)
		{
			soft_aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
		else
		{
			aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
	}

	_mm_store_si128(output + 4, xout0);
	_mm_store_si128(output + 5, xout1);
	_mm_store_si128(output + 6, xout2);
	_mm_store_si128(output + 7, xout3);
	_mm_store_si128(output + 8, xout4);
	_mm_store_si128(output + 9, xout5);
	_mm_store_si128(output + 10, xout6);
	_mm_store_si128(output + 11, xout7);
}

template<size_t ITERATIONS, size_t MEM, bool SOFT_AES, bool PREFETCH>
void cryptonight_hash(const void* input, size_t len, void* output, cryptonight_ctx* ctx0)
{
keccak((const uint8_t *)input, len, ctx0->hash_state, 200); 
/* Optim - 99% time boundary */ 
cn_explode_scratchpad<2097152, SOFT_AES, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state); 
__m128i ax1; 
uint64_t idx1; 
uint8_t* l1 = ctx0->long_state; 

uint64_t[2] c, c1; 
uint64_t* h1 = (uint64_t*)ctx0->hash_state; 
idx1 = h1[0] ^ h1[4]; 
ax1 = _mm_set_epi64x(h1[1] ^ h1[5], idx1); 
uint64_t c1l, c1h; 
uint64_t al1 = _mm_cvtsi128_si64(ax1); 
uint64_t ah1 = ((uint64_t*)&ax1)[1]; 
__m128i *ptr1;
for(size_t i = 0; i < 0x1000; i++)  //Change to 0x100000 after Softfork (20th December)
{
	__m128i c1x, c1xx; 
	ptr1 = (__m128i *)&l1[idx1 & 0x1FFFF0]; 
	c1x = _mm_load_si128(ptr1); 
	if(SOFT_AES) c1x = soft_aesenc(c1x, ax1); else c1x = _mm_aesenc_si128(c1x, ax1); 
	_mm_store_si128(R128(c), c1x);  
	_mm_store_si128(R128(c1), _mm_load_si128(ptr1); 
	ptr1 = state_index(c); 
	c[0] ^= al1; c[1] ^= ah1; 
	_mm_store_si128((__m128i *)ptr1, _mm_load_si128(c)); 
	ptr1 = state_index(c);
	_mm_store_si128((__m128i *)ptr1, _mm_load_si128(c1)); 
	c1[0] ^= c[0]; c1[1] ^= c[1];
	ptr1 = state_index(c1);
	_mm_store_si128((__m128i *)ptr1, _mm_load_si128(c1)); 
	c1l = ((uint64_t*)ptr1)[0]; 
	c1h = ((uint64_t*)ptr1)[1]; 
	((uint64_t*)ptr1)[0] = al1; 
	((uint64_t*)ptr1)[1] = ah1; 
	al1 ^= c1l; 
	ah1 ^= c1h; 
	ax1 = _mm_set_epi64x(ah1, al1); 
	idx1 = al1;
}
/* Optim - 90% time boundary */ 
cn_implode_scratchpad<2097152, SOFT_AES, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state); 
/* Optim - 99% time boundary */ 
keccakf((uint64_t*)ctx0->hash_state, 24); 
extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
}

// This lovely creation will do 2 cn hashes at a time. We have plenty of space on silicon
// to fit temporary vars for two contexts. Function will read len*2 from input and write 64 bytes to output
// We are still limited by L3 cache, so doubling will only work with CPUs where we have more than 2MB to core (Xeons)
template<size_t ITERATIONS, size_t MEM, bool SOFT_AES, bool PREFETCH>
void cryptonight_double_hash(const void* input, size_t len, void* output, cryptonight_ctx* __restrict ctx0, cryptonight_ctx* __restrict ctx1)
{ // NOT WORKING!
	keccak((const uint8_t *)input, len, ctx0->hash_state, 200); 
	keccak((const uint8_t *)input + len, len, ctx1->hash_state, 200); 
	/* Optim - 99% time boundary */ 
	cn_explode_scratchpad<2097152, SOFT_AES, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state); 
	cn_explode_scratchpad<2097152, SOFT_AES, PREFETCH>((__m128i*)ctx1->hash_state, (__m128i*)ctx1->long_state); 
	__m128i ax0, ax1; 
	uint64_t idx0, idx1; 
	uint8_t* l0 = ctx0->long_state; 
	uint8_t* l1 = ctx1->long_state; 
	uint64_t* h0 = (uint64_t*)ctx0->hash_state; 
	uint64_t* h1 = (uint64_t*)ctx1->hash_state; 
	idx0 = h0[0] ^ h0[4]; 
	idx1 = h1[0] ^ h1[4]; 
	ax0 = _mm_set_epi64x(h0[1] ^ h0[5], idx0); 
	ax1 = _mm_set_epi64x(h1[1] ^ h1[5], idx1); 
	__m128i *ptr0, *ptr1;
	for(size_t i = 0; i < 0x1000; i++)
	{
		__m128i c0x, c0xx, c1x, c1xx; 
		ptr0 = (__m128i *)&l0[idx0 & 0x1FFFF0]; 
		ptr1 = (__m128i *)&l1[idx1 & 0x1FFFF0]; 
		c0x = _mm_load_si128(ptr0); 
		c1x = _mm_load_si128(ptr1); 
		c0xx = _mm_load_si128(ptr0); 
		c1xx = _mm_load_si128(ptr1); 
		if(SOFT_AES){
			c0x = soft_aesenc(c0x, ax0);
			c1x = soft_aesenc(c1x, ax1); 
		}else{ 
			c0x = _mm_aesenc_si128(c0x, ax0);
			c1x = _mm_aesenc_si128(c1x, ax1);
		}
		_mm_store_si128((__m128i *)ptr0, c0x); 
		_mm_store_si128((__m128i *)ptr1, c1x); 
		idx0 = _mm_cvtsi128_si64(c0x); 
		idx1 = _mm_cvtsi128_si64(c1x); 
		ptr0 = (__m128i *)&l0[idx0 & 0x1FFFF0]; 
		ptr1 = (__m128i *)&l1[idx1 & 0x1FFFF0]; 
		if(PREFETCH) {
			_mm_prefetch((const char*)ptr0, _MM_HINT_T0);
			_mm_prefetch((const char*)ptr1, _MM_HINT_T0);
		} 
		_mm_store_si128((__m128i *)ptr0, c0xx); 
		_mm_store_si128((__m128i *)ptr1, c1xx); 
		c0xx = _mm_xor_si128(c0xx,c0x);
		c1xx = _mm_xor_si128(c1xx,c1x);
		idx0 = _mm_cvtsi128_si64(c0xx); 
		idx1 = _mm_cvtsi128_si64(c1xx); 
		ptr0 = (__m128i *)&l0[idx0 & 0x1FFFF0]; 
		ptr1 = (__m128i *)&l1[idx1 & 0x1FFFF0]; 
		_mm_store_si128((__m128i *)ptr0, c0xx); 
		_mm_store_si128((__m128i *)ptr1, c1xx); 
		uint64_t c0l, c0h; 
		uint64_t c1l, c1h; 
		uint64_t al0 = _mm_cvtsi128_si64(ax0); 
		uint64_t al1 = _mm_cvtsi128_si64(ax1); 
		uint64_t ah0 = ((uint64_t*)&ax0)[1]; 
		uint64_t ah1 = ((uint64_t*)&ax1)[1]; 
		c0l = ((uint64_t*)ptr0)[0]; 
		c1l = ((uint64_t*)ptr1)[0]; 
		c0h = ((uint64_t*)ptr0)[1]; 
		c1h = ((uint64_t*)ptr1)[1]; 
		((uint64_t*)ptr0)[0] = al0; 
		((uint64_t*)ptr1)[0] = al1; 
		if(PREFETCH) {
			_mm_prefetch((const char*)ptr0, _MM_HINT_T0);
			_mm_prefetch((const char*)ptr1, _MM_HINT_T0);
		}
		((uint64_t*)ptr0)[1] = ah0; 
		((uint64_t*)ptr1)[1] = ah1; 
		al0 ^= c0l; 
		al1 ^= c1l; 
		ah0 ^= c0h; 
		ah1 ^= c1h; 
		ax0 = _mm_set_epi64x(ah0, al0); 
		ax1 = _mm_set_epi64x(ah1, al1); 
		idx0 = al0;
		idx1 = al1;
	}
	/* Optim - 90% time boundary */ 
	cn_implode_scratchpad<2097152, SOFT_AES, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state); 
	cn_implode_scratchpad<2097152, SOFT_AES, PREFETCH>((__m128i*)ctx1->long_state, (__m128i*)ctx1->hash_state); 
	/* Optim - 99% time boundary */ 
	keccakf((uint64_t*)ctx0->hash_state, 24); 
	extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
	keccakf((uint64_t*)ctx1->hash_state, 24); 
	extra_hashes[ctx1->hash_state[0] & 3](ctx1->hash_state, 200, (char*)output + 32);
}
