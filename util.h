#ifndef UTIL_H_
#define UTIL_H_

#include "elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

struct elf;

#define pr_error(...) fprintf(stderr, __VA_ARGS__)

#ifdef BUILD_TYPE_RELEASE
static void __attribute__((format(printf, 1, 2))) __attribute__((unused))
dummy_pr_debug__(const char *fmt, ...) { (void) fmt; }
#define pr_debug(...) dummy_pr_debug__(__VA_ARGS__)
#else
#define pr_debug printf
#endif /* BUILDTYPE */

/* Container for an array of bytes */
struct blob {
    uint64_t size;
    uint8_t *data;
};

int read_file(const char *path, struct blob *out);

int write_file(const char *path, const struct blob *data);

static inline int popcnt(uint64_t x) {
    int ret = 0;
    for (int i = 0; i < 64; i++) {
        if (x & (UINT64_C(1) << i))
            ret++;
    }
    return ret;
}

static inline uint64_t align_pow2(uint64_t x, uint64_t n) {
    if (popcnt(n) != 1) {
        pr_error("%s: Not a power of two\n", __func__);
        fflush(stderr);
        abort();
    }

    if (x > UINT64_MAX - (n - 1)) {
        pr_error("%s: Integer overflow\n", __func__);
        fflush(stderr);
        abort();
    }

    return (x + (n - 1)) & ~(n - 1);
}

static inline bool ranges_overlap(uint64_t start1, uint64_t size1,
                                  uint64_t start2, uint64_t size2)
{
    if (start1 > UINT64_MAX - size1 ||
        start2 > UINT64_MAX - size2)
    {
        pr_error("%s: Invalid ranges (integer overflow)\n", __func__);
        return false;
    }

    const uint64_t end1 = start1 + size1;
    const uint64_t end2 = start2 + size2;

    return start1 < end2 && start2 < end1;
}

const Elf64_Phdr * get_load_segment_containing_range(
        const Elf64_Phdr *phdrs, Elf64_Xword nphdrs,
        Elf64_Xword start, Elf64_Xword size
);

const char * section_name_strptr(const struct elf *elf, Elf64_Addr sh_name);

void find_load_segment_limits(const struct elf *elf,
                              uint64_t *out_vaddr, uint64_t *out_align);

#endif /* UTIL_H_ */
