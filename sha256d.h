#ifndef SHA256D_H
#define SHA256D_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
    void sha256d_hash(const char* input, char* output, uint32_t len);
#ifdef __cplusplus
}
#endif

#endif
