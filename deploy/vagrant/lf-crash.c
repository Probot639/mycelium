// A libFuzzer target that crashes on any input beginning with "BUG". Many
// distinct inputs trigger the same abort() at the same place, so they are the
// same bug: used to show crash-vs-bug dedup (total_crashes > unique_bugs).
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 3 && data[0] == 'B' && data[1] == 'U' && data[2] == 'G') {
        abort();
    }
    return 0;
}
