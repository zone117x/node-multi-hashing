#ifndef KECCAK_H
#define KECCAK_H

#ifdef __cplusplus
extern "C" {
#endif

void keccak_hash(const char* input, char* output, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif
