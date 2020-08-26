#include "sha1.h"

#include <string.h>
#include "sha3/sph_sha1.h"

#if defined(__GNUC__)
#define ALIGN32(x) x __attribute__((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN32(x) __declspec(align(32)) x
#else
#define ALIGN32(x) x
#endif

static inline void encodeb64(const unsigned char* pch, char* buff)
{
  const char *pbase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int mode = 0, left = 0;
  const int len = 20;
  const unsigned char *pchEnd = pch + len;
  while (pch < pchEnd) {
    int enc = *(pch++);
    if (mode == 0) {
      *buff++ = pbase64[enc >> 2];
      left = (enc & 3) << 4;
      mode = 1;
    }
    else if (mode == 1) {
      *buff++ = pbase64[left | (enc >> 4)];
      left = (enc & 15) << 2;
      mode = 2;
    }
    else {
      *buff++ = pbase64[left | (enc >> 6)];
      *buff++ = pbase64[enc & 63];
      mode = 0;
    }
  }
  *buff = pbase64[left];
  *(buff + 1) = 0;
}

void sha1_hash(const char* input, char* output, uint32_t len)
{
  ALIGN32(char str[38]); // 26 + 11 + 1
  ALIGN32(uint32_t prehash[5]);
  ALIGN32(uint32_t hash[5]) = { 0 };
  int i = 0;
  sph_sha1_context ctx;
  sph_sha1_init(&ctx);
  sph_sha1(&ctx, (void *)input, len);
  sph_sha1_close(&ctx, (void *)prehash);
  encodeb64((const unsigned char *)prehash, str);
  memcpy(&str[26], str, 11);
  str[37] = 0;
  for (i = 0; i < 26; i++) {
    sph_sha1_init(&ctx);
    sph_sha1(&ctx, (void *)&str[i], 12);
    sph_sha1_close(&ctx, (void *)prehash);
    hash[0] ^= prehash[0];
    hash[1] ^= prehash[1];
    hash[2] ^= prehash[2];
    hash[3] ^= prehash[3];
    hash[4] ^= prehash[4];
  }
  memset(output, 0, 32 - 20);
  memcpy(&output[32 - 20], hash, 20);
}
