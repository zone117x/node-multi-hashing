#ifndef BLAKE_H
#define BLAKE_H

#ifdef __cplusplus
extern "C" {
#endif

void blake_hash(const char* input, char* output, unsigned int len);

#ifdef __cplusplus
}
#endif

#endif
