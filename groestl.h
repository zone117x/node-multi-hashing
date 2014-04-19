#ifndef GROESTL_H
#define GROESTL_H

#ifdef __cplusplus
extern "C" {
#endif

void groestl_hash(const char* input, char* output, unsigned int len);
void groestl_myriad_hash(const char* input, char* output, unsigned int len);

#ifdef __cplusplus
}
#endif

#endif
