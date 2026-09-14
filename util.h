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
struct elf_phdrs;
struct elf_dyn_entries;
typedef Elf64_Xword elf_idx_t;

#define pr_error(...) fprintf(stderr, __VA_ARGS__)

#ifdef BUILD_TYPE_RELEASE
static void __attribute__((format(printf, 1, 2))) __attribute__((unused))
dummy_pr_debug__(const char *fmt, ...) { (void) fmt; }
#define pr_debug(...) dummy_pr_debug__(__VA_ARGS__)
#else
#define pr_debug printf
#endif /* BUILDTYPE */

#define u_min(a, b) ((a) < (b) ? (a) : (b))
#define u_max(a, b) ((a) > (b) ? (a) : (b))

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

/**
 * Increments `*off_p` by `size`, storing the previous value in `out`.
 *
 * @param[in,out] off_p A pointer to the current offset to increment.
 *  Must not be NULL.
 *
 * @param[in] size The size to reserve.
 *
 * @param[out] out Output pointer for the start of the reserved range.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero in case of integer overflow.
 */
static inline int reserve_range(Elf64_Off *off_p,
                                Elf64_Xword size, Elf64_Off *out)
{
    if (size > UINT64_MAX - *off_p) {
        pr_error("Can't reserve new range (integer overflow)\n");
        return 1;
    }

    *out = *off_p;
    *off_p += size;
    pr_debug("%s: out: %" PRIu64 "\n", __func__, *out);
    return 0;
}

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
 *  Must not be NULL.
 *
 * @param[in] start The start address of the range to check.
 *
 * @param[in] size The size (length) of the range to check.
 *
 * @return If a segment containing the full range is found,
 *  the corresponding program header's index (a reference into `phdrs`).
 *  If nothing valid is found, `ELF_IDX_NULL` is returned.
 */
elf_idx_t
find_containing_mem_ptload(const struct elf_phdrs *phdrs,
                           Elf64_Addr start, Elf64_Xword size);

/**
 * Attempts to find a PT_LOAD segment that contains a given file range.
 *
 * @param[in] phdrs The parsed in-memory array of program headers to search.
 *  Must not be NULL.
 *
 * @param[in] off The start offset of the file range to check.
 *
 * @param[in] size The size (length) of the range to check.
 *
 * @return If a segment containing the full range is found,
 *  the corresponding program header's index (a reference into `phdrs`).
 *  If nothing valid is found, `ELF_IDX_NULL` is returned.
 */
elf_idx_t
find_containing_file_ptload(const struct elf_phdrs *phdrs,
                            Elf64_Off off, Elf64_Xword size);

/**
 * Finds the start of the next segment, used to calculate how much
 * slack space there's left for modifications.
 *
 * @param[in] phdrs The parsed in-memory array of program headers to search.
 *  Must not be NULL.
 *
 * @param[in] pos The starting position (file offset).
 *
 * @return The start of the next segment from `pos`,
 *  or `0` if no such segment exists.
 */
Elf64_Off find_next_segment_start(const struct elf_phdrs *phdrs, Elf64_Off pos);

/**
 * @brief
 * Finds a collection of _DYNAMIC entries by their respective tags,
 * ensuring that each requested tag appears exactly once
 * (i.e. no missing or duplicate entries).
 *
 * Example usage:
 * ```
 *  elf_idx_t idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };
 *  if (find_unique_dyn_entries(entries, 2,
 *          (Elf64_Sxword[2]) { DT_STRTAB, DT_STRSZ }, idxs))
 *  {
 *      pr_error("Missing or duplicate DT_STRTAB and/or DT_STRSZ entries\n");
 *      [...]
 *  }
 *  const elf_idx_t dt_strtab_idx = idxs[0];
 *  const elf_idx_t dt_strsz_idx = idxs[1];
 *  [...]
 * ```
 *
 * @param[in] entries The dynamic entries array to search. Must not be NULL.
 *
 * @param[in] count Number of DT_* tags to look for.
 *
 * @param[in] tags Array of `count` DT_* tags to be found.
 *
 * @param[out] out Array of `count` indices. On success, `out[i]`
 *  contains the index of the entrycorresponding to `tags[i]`.
 *
 * @return 0 on success,
 *  non-zero if any of the DT_* entries are missing or have duplicates.
 */
int find_unique_dyn_entries(
        const struct elf_dyn_entries *entries, size_t count,
        const Elf64_Sxword tags[static count], elf_idx_t out[static count]
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
