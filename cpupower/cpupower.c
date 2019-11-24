#include "cpupower.h"

void cpupower_hash(const char *input, char *output) {
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = "CPUpower: The number of CPU working or available for proof-of-work mining",
        .perslen = 73
    };
    yespower_tls( (yespower_binary_t*)input, 80, &params, (yespower_binary_t*)output );
}
