// A small format parser with a few planted bugs for testing mycelium.
// Parses a made-up "MYC" binary format:
//   magic: "MYC\x00" (4 bytes)
//   version: u8
//   num_entries: u16 LE
//   entries: [entry; num_entries]
//     entry_type: u8
//     entry_len: u16 LE
//     payload: [u8; entry_len]

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ENTRIES 256
#define MAX_PAYLOAD 4096

struct entry {
    uint8_t type;
    uint16_t len;
    uint8_t *payload;
};

struct document {
    uint8_t version;
    uint16_t num_entries;
    struct entry entries[MAX_ENTRIES];
};

// Bug 1: heap-buffer-overflow when entry_len > remaining data
// Bug 2: stack-buffer-overflow in handle_type_3 (copies without bound check)
// Bug 3: use-after-free in handle_type_5 (frees then reads)

static void handle_type_1(struct entry *e) {
    // "string" entry: just print it
    if (e->len > 0) {
        char buf[128];
        size_t n = e->len < 127 ? e->len : 127;
        memcpy(buf, e->payload, n);
        buf[n] = '\0';
    }
}

static void handle_type_3(struct entry *e) {
    // Bug 2: stack buffer overflow -- copies payload into fixed buffer
    // without checking length against buffer size
    char local[64];
    memcpy(local, e->payload, e->len);
    local[e->len] = '\0';
    volatile int x = local[0];
    (void)x;
}

static void handle_type_5(struct entry *e) {
    // Bug 3: use-after-free
    uint8_t *tmp = malloc(e->len);
    if (!tmp) return;
    memcpy(tmp, e->payload, e->len);
    free(tmp);
    // read after free when len >= 32
    if (e->len >= 32) {
        volatile uint8_t x = tmp[16];
        (void)x;
    }
}

int parse_document(const uint8_t *data, size_t size) {
    if (size < 7) return -1;

    // check magic
    if (memcmp(data, "MYC", 3) != 0 || data[3] != 0) return -1;

    struct document doc;
    doc.version = data[4];
    doc.num_entries = data[5] | (data[6] << 8);

    if (doc.num_entries > MAX_ENTRIES) return -1;

    size_t offset = 7;
    for (uint16_t i = 0; i < doc.num_entries; i++) {
        if (offset + 3 > size) return -1;

        doc.entries[i].type = data[offset];
        doc.entries[i].len = data[offset + 1] | (data[offset + 2] << 8);
        offset += 3;

        // Bug 1: only checks offset, not offset + len
        if (offset > size) return -1;

        doc.entries[i].payload = (uint8_t *)(data + offset);
        offset += doc.entries[i].len;

        switch (doc.entries[i].type) {
        case 1: handle_type_1(&doc.entries[i]); break;
        case 3: handle_type_3(&doc.entries[i]); break;
        case 5: handle_type_5(&doc.entries[i]); break;
        default: break;
        }
    }

    return 0;
}

// AFL++ persistent mode: fast re-execution without fork overhead.
// __AFL_COMPILER is defined by afl-clang-fast/afl-clang-lto.
#ifdef __AFL_COMPILER
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        parse_document(buf, len);
    }
    return 0;
}

#else

// libFuzzer entry point (also present in standalone builds, just uncalled)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_document(data, size);
    return 0;
}

// standalone: read from file (for triage / crash replay).
// Excluded when libFuzzer provides its own main().
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(len);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, len, f);
    fclose(f);
    parse_document(buf, len);
    free(buf);
    return 0;
}
#endif

#endif
