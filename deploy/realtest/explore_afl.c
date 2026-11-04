#include <stdint.h>
#include <unistd.h>
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        volatile int x = 0;
        for (int i = 0; i < len && i < 24; i++) {
            if (buf[i] == 'a') x += 1; else if (buf[i] == 'b') x += 2;
            else if (buf[i] == 'c') x += 4; else if (buf[i] == 'd') x += 8;
            else if (buf[i] == 0x7f) x += 16;
        }
    }
    return 0;
}
