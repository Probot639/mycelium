#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    volatile int x = 0;
    for (size_t i = 0; i < size && i < 24; i++) {
        if (data[i] == 'a') x += 1; else if (data[i] == 'b') x += 2;
        else if (data[i] == 'c') x += 4; else if (data[i] == 'd') x += 8;
        else if (data[i] == 0x7f) x += 16;
    }
    return 0;
}
