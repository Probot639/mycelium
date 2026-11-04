// A libFuzzer target for the multi-fuzzer validation. It creates coverage to
// explore (so libFuzzer keeps adding new corpus entries) but never crashes, so
// the node can be observed sharing corpus for a sustained run.
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    volatile int x = 0;
    for (size_t i = 0; i < size && i < 16; i++) {
        if (data[i] == 0x41) x += 1;
        else if (data[i] == 0x42) x += 2;
        else if (data[i] == 0x43) x += 4;
        else if (data[i] == 0x7f) x += 8;
    }
    return 0;
}
