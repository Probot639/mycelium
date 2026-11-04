#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len >= 4 && buf[0]=='B' && buf[1]=='U' && buf[2]=='G' && buf[3]=='!') abort();
    }
    return 0;
}
