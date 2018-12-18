#ifndef CRYPTONIGHTASC_H
#define CRYPTONIGHTASC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void cryptonightasc_hash(const char* input, char* output, uint32_t len, int variant);
void cryptonightasc_asc_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
