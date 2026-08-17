#ifndef UTIL_H_
#define UTIL_H_

/**
 * @file Various utilities.
 */

#include "elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

struct elf;

#define pr_error(...) fprintf(stderr, __VA_ARGS__)

#ifdef BUILD_TYPE_RELEASE
static void __attribute__((format(printf, 1, 2))) __attribute__((unused))
dummy_pr_debug__(const char *fmt, ...) { (void) fmt; }
#define pr_debug(...) dummy_pr_debug__(__VA_ARGS__)
#else
#define pr_debug printf
#endif /* BUILDTYPE */

/** @struct Generic container for an array of bytes */
struct blob {
    /** The size of `data` */
    uint64_t size;

    /** The (usually malloc'd) buffer containing the bytes */
    uint8_t *data;
};

/**
 * Reads a file into a newly allocated buffer.
 *
 * @param[in] path The path of the file to read.
 *  Must not be NULL.
 *
 * @param[out] out An empty blob structure
 *  to which the file contents will be copied.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int read_file(const char *path, struct blob *out);

/**
 * Writes a data buffer into a file.
 *
 * @param[in] path The path of the file to write to.
 *  The file is created if it doesn't exist and truncated otherwise.
 *  Must not be NULL.
 *
 * @param[in] data A blob structure containing the data to write.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int write_file(const char *path, const struct blob *data);

/** Check whether a number is a power of two */
static inline bool is_pow2(uint64_t x) {
    return x != 0 && (x & (x - 1)) == 0;
}

/**
 * Aligns (rounds up) a value to a power of 2.
 *
 * @param[in] x The value to align.
 *
 * @param[in] n The target value to align to.
 *  Must be a power of two.
 *
 * @return The aligned value.
 */
static inline uint64_t align_pow2(uint64_t x, uint64_t n) {
    if (!is_pow2(n)) {
        pr_error("%s: Target value (%" PRIu64 ") is not a power of two\n",
                 __func__, n);
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

/**
 * Checks whether two ranges intersect at any point.
 * This function doesn't work for zero-sized ranges.
 */
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

/**
 * Wrapper for `realloc` which frees `ptr` on failure.
 *
 * Calls `realloc(ptr, new_n * size)` in a safe way; by checking for
 * integer overflow (`new_n * size`), like the GNU-specific `reallocarray`.
 * If the check or `realloc` itself fail, `ptr` is freed if not previously NULL.
 *
 * @param[in] ptr_p Pointer to the pointer to be realloc'd.
 *  If `ptr_p == NULL || *ptr_p == NULL`,
 *  the behavior is the same as with standard `realloc` -
 *  the call is equivalent to `malloc(new_n * size)`.
 *  Note: After this call, the original `*ptr_p` is set to NULL
 *  and the returned value should be used instead.
 *
 * @param[in] new_n Like `calloc`'s `n` parameter;
 *  the desired new number of array entries.
 *
 * @param[in] size Like `calloc`'s `size parameter; size of the type.
 *
 * @return The new realloc'd pointer on success, NULL on failure.
 */
void * safe_realloc(void **ptr_p, size_t new_n, size_t size);

/**
 * Attempts to find a PT_LOAD segment
 * that contains a given virtual address range.
 *
 * @param[in] phdrs The parsed in-memory array of program headers to search.
 *  Must not be NULL if `nphdrs > 0`.
 *
 * @param[in] nphdrs The number of entries in the `phdrs` array.
 *
 * @param[in] start The start of the range to check.
 *
 * @param[in] size The size (length) of the range to check.
 *
 * @return If a segment containing the full range is found,
 *  the corresponding program header (a reference into `phdrs`).
 *  If nothing valid is found, `NULL` is returned.
 */
const Elf64_Phdr * get_load_segment_containing_range(
        const Elf64_Phdr *phdrs, Elf64_Xword nphdrs,
        Elf64_Xword start, Elf64_Xword size
);

/**
 * Finds the section name by the `sh_name` field of a section header.
 *
 * @param[in] elf A valid ELF context sucessfully populated by `read_elf`.
 *  Must not be NULL.
 *
 * @param[in] sh_name The `sh_name` field of the section header
 *  whose name string is to be found.
 *
 * @return A pointer into the ELF's `.shstrtab` section
 *  where all the section names are, or an error message
 *  if something goes wrong. This function never returns NULL.
 */
const char * section_name_strptr(const struct elf *elf, Elf64_Addr sh_name);

/**
 * @brief
 * Finds the largest virtual address and alignment of all PT_LOAD segments.
 *
 * This is used to allocate a new segment at the end of the address space.
 *
 * Note: It's assumed that the provided `elf->phdrs` are
 * already validated to fit within the address space.
 *
 * This function finds the last byte of an already existing LOAD segment,
 * which is why it can have no failure case and return `void`.
 * It's up to the caller to align the returned value and check
 * that there's enough room left in the address space to fit the new data.
 *
 * @param[in] elf The ELF context containing a parsed and validated
 *  in-memory array of program headers. Must not be NULL.
 *
 * @param[out] out_vaddr Output pointer for the found virtual address
 *  of the end of the last PT_LOAD segment. Must not be NULL.
 *
 * @param[out] out_align Output pointer for the found maximum aligment value.
 *  Must not be NULL. The minimal returned "fallback" value is 4096.
 *  Due to the spec's requirements, the returned value is always a power of two.
 */
void find_load_segment_limits(const struct elf *elf,
                              uint64_t *out_vaddr, uint64_t *out_align);

#endif /* UTIL_H_ */
