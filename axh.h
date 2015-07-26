#ifndef AXH_H
#define AXH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void axh_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
