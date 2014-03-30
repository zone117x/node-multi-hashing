#ifndef SCRYPTN_H
#define SCRYPTN_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

void scrypt_N_1_1_256(const char* input, char* output, uint32_t N);
void scrypt_N_1_1_256_sp(const char* input, char* output, char* scratchpad, uint32_t N);
//const int scrypt_scratchpad_size = 131583;

#ifdef __cplusplus
}
#endif

#endif