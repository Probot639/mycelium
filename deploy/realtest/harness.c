// Real-tailnet test target. Any input beginning with "BUG!" triggers a
// heap-buffer-overflow at one fixed place, so many distinct inputs are the same
// bug: used to show crash-trace dedup (total_crashes > unique_bugs) on real
// heterogeneous machines. Built two ways:
//   fuzzing:  AFL_USE_ASAN=1 afl-clang-fast -o harness harness.c
//   triage:   clang -DSTANDALONE -fsanitize=address -O1 -o harness_asan harness.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void trigger(const unsigned char *buf, int len) {
    if (len >= 4 && buf[0] == 'B' && buf[1] == 'U' && buf[2] == 'G' && buf[3] == '!') {
        volatile char *p = (char *)malloc(8);
        p[100] = 1; // heap-buffer-overflow, ASAN reports a stable stack
        free((void *)p);
    }
}

#ifdef STANDALONE
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    unsigned char buf[8192];
    int n = (int)fread(buf, 1, sizeof buf, f);
    fclose(f);
    trigger(buf, n);
    return 0;
}
#else
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        trigger(buf, len);
    }
    return 0;
}
#endif
