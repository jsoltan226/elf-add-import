#include "elf-dyn-parsing.h"
#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/**
 * Finds and validates the PT_DYNAMIC program header.
 * Part of `parse_dyn`.
 *
 * @param[in] phdrs The array of program headers to search. Must not be NULL.
 *
 * @param[in] entsize Size of an ElfXX_Dyn entry (depends on the ELF's class).
 *
 * @param[out] out Output pointer for the PT_DYNAMIC phdr's index.
 *  On success will always contain the index of the found PT_DYNAMIC phdr.
 *  Must not be NULL.
 *
 * @param[out] out_dynnum Output pointer for the number of dynamic entries.
 *  Must not be NULL.
 *
 * @return 0 on success,
 *  non-zero on failure (invalid or missing PT_DYNAMIC program header).
 */
static int find_validate_pt_dynamic(const struct elf_phdrs *phdrs,
                                    Elf64_Half entsize,
                                    elf_idx_t *out, Elf64_Xword *out_dynnum);

/**
 * Looks for a SHT_DYNAMIC section header and if found,
 * validates it against the PT_DYNAMIC program header.
 * Part of `parse_dyn`.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] pt_dynamic_idx The index of the previously checked PT_DYNAMIC
 *  program header, against which the found SHT_DYNAMIC shdr is to be validated.
 *  Must not be `ELF_IDX_NULL`.
 *
 * @param[in] entsize Size of an ElfXX_Dyn entry (depends on the ELF's class).
 *
 * @param[out] out Output pointer for the found `SHT_DYNAMIC` shdr's index.
 *  On success will contain either the index of the validated SHT_DYNAMIC shdr,
 *  or `ELF_IDX_NULL` if no `SHT_DYNAMIC` section header exists.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_sht_dynamic_if_exists(
        const struct elf_shdrs *shdrs, const struct elf_phdrs *phdrs,
        elf_idx_t pt_dynamic_idx, Elf64_Xword entsize,

        elf_idx_t *out
);

/**
 * Parses and validates the array of dynamic entries
 * pointed to by a PT_DYNAMIC program header.
 * Part of `parse_dyn`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] count Number of dynamic entries.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] pt_dynamic_idx The previously validated PT_DYNAMIC phdr's index.
 *  Must not be ELF_IDX_NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int parse_dyn_table(
        const struct blob *data, int clazz, int encoding, Elf64_Xword count,
        const struct elf_phdrs *phdrs, elf_idx_t pt_dynamic_idx,

        struct elf_dyn_entries *out
);

/**
 * Finds the `DT_STRTAB` and `DT_STRSZ` dynamic entries and using them,
 * locates and validates the dynamic string table `.dynstr`.
 * Part of `parse_dyn`.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] entries The array of parsed dynamic entries. Must not be NULL.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[out] out Output pointer which on success, will contain all metadata
 *  relevant to `.dynstr`. See the definition of `struct elf_dyn_strtab`.
 *  Must not be NULL.
 *
 * @return 0 on success,
 *  non-zero on failure (missing or invalid dynamic string table).
 */
static int parse_dynstr(
        const struct blob *data, const struct elf_dyn_entries *entries,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,

        struct elf_dyn_strtab *out
);

/**
 * Finds and validates a .dynstr section header corresponding
 * to the values of `DT_STRTAB` and `DT_STRSZ`.
 * Part of `parse_dynstr`.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] addr Virtual address of the dynamic string table
 *  (the value of DT_STRTAB).
 *
 * @param[in] off Offset within the ELF file of the dynamic string table.
 *
 * @param[in] size Size of the dynamic string table (the value of DT_STRSZ).
 *
 * @param[out] out Output pointer for the found valid .dynstr section header's
 *  index. On success it will either contain a reference into `shdrs`
 *  or `ELF_IDX_NULL` (if there's no .dynstr section). Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int find_validate_strtab_shdr(const struct elf_shdrs *shdrs,
                                     Elf64_Addr addr, Elf64_Off off,
                                     Elf64_Xword size, elf_idx_t *out);

/**
 * Finds and parses the DT_HASH structure - the legacy dynamic symbol lookup
 * hash table. For the modern DT_GNU_HASH, see `parse_dt_gnu_hash`.
 * Part of `parse_dynsym`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[out] out Output pointer (see the definition of `struct elf_dt_hash`).
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int parse_dt_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_hash *out
);

/**
 * Finds the DT_HASH dynamic entry and using that,
 * locates and validates the bounds of the DT_HASH table structure.
 * Part of `parse_dt_hash`.
 *
 * Initializes the `struct elf_dt_hash`.
 * The following fields are populated with validated values:
 *  - vaddr, off, total_size, dyn_entry,
 *  - hdr.nbucket, hdr.nchain,
 * The following fields are initialized to empty values:
 *  - buckets (array), chain (array) - NULL,
 *  - shdr (shdr table index) - ELF_IDX_NULL.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int find_dt_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_dyn_entries *entries,
        struct elf_dt_hash *out
);

/**
 * Based on the data from `find_dt_hash`, reads and validates the contents
 * of the DT_HASH `buckets` and `chain` arrays.
 * Part of `parse_dt_hash`.
 *
 * All temporary resources are freed in case of failure.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[in] hdr The DT_HASH header containing the number of entries
 *  in `buckets` and `chain`. Must not be NULL.
 *
 * @param[in] end The byte right after the end of the whole structure,
 *  i. e. the offset + size. Used to validate the value of `*off_p`
 *  after reading.
 *
 * @param[out] out_buckets Output pointer for the buckets array.
 *  On success, will contain `hdr->nbucket` entries. Must not be NULL.
 *
 * @param[out] out_chain Output pointer for the chain array.
 *  On success, will contain `hdr->nchain` entries. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_dt_hash_contents(
        const struct blob *data, int clazz, int encoding, uint64_t *off_p,
        const struct elf_dt_hash_hdr *hdr, Elf64_Off end,
        Elf32_Word **out_buckets, Elf32_Word **out_chain
);

/**
 * Tries to find a `SHT_HASH` section header and validates it if present.
 * Part of `parse_dt_hash`.
 *
 * Also validates that the SHT_DYNSYM table size matches the value
 * derived from the DT_HASH data.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] dt_hash The DT_HASH data previously populated by
 *  `find_dt_hash` and `read_dt_hash_contents`.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[in] clazz Class of the ELF file.
 *
 * @param[out] out Output pointer for the found SHT_HASH section header's index
 *  (a reference into `shdrs`), or `ELF_IDX_NULL` if nothing is found.
 *  Must not be NULL.
 *
 * @return 0 on success (either nothing or a valid shdr is found),
 *  non-zero on failure (an invalid shdr is found).
 */
static int validate_sht_hash_if_exists(const struct elf_shdrs *shdrs,
                                       const struct elf_dt_hash *dt_hash,
                                       elf_idx_t sht_dynsym_idx, int clazz,
                                       elf_idx_t *out);

/**
 * Parses the DT_GNU_HASH structure - the modern dynamic symbol lookup
 * hash table. For the legacy DT_HASH, see `parse_dt_hash`.
 * Part of `parse_dynsym`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int parse_dt_gnu_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_gnu_hash *out
);

/**
 * Reads the DT_GNU_HASH structure's header,
 * also validating that the `nbuckets` and `bloom_size` fields
 * are representable as `size_t` (they are later used in allocations).
 * Part of `find_dt_gnu_hash`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 */
static int read_dt_gnu_hash_hdr(
        const struct blob *data, int clazz, int encoding, uint64_t *off_p,
        struct elf_dt_gnu_hash_hdr *out
);

/**
 * Finds the `DT_GNU_HASH` dynamic entry and based on it,
 * locates and parses the GNU hash structure header, validating
 * that it fits within its PT_LOAD segment's file range and address space.
 * Part of `parse_dt_gnu_hash`.
 *
 * The following fields of `struct elf_dt_hash` are parsed:
 *  - vaddr, off
 *  - dyn_entry,
 *  - hdr,
 *  - bloomentsize
 * The rest are initialized to default values:
 *  - bloom (array), buckets (array), chain (array) - NULL,
 *  - nchain, total_size - 0,
 *  - shdr (shdr table index) - ELF_IDX_NULL
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @param[out] out_pt_load_idx Output pointer for the index of the PT_LOAD
 *  segment that contains the GNU hash header (a reference into `phdrs`).
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int find_dt_gnu_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_dyn_entries *entries,
        struct elf_dt_gnu_hash *out, elf_idx_t *out_pt_load_idx
);

/**
 * Based on the information from the GNU hash structure
 * header (`find_dt_gnu_hash`), parses the bloom filter and buckets array.
 * Part of `parse_dt_gnu_hash`.
 *
 * The following fields in `struct elf_dt_gnu_hash` are read:
 *  - off, vaddr,
 *  - hdr,
 *  - bloomentsize
 * The following fields are populated:
 *  - buckets (array),
 *  - bloom (array)
 *
 * The rest of the fields are unused.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in,out] ctx The DT_GNU_HASH structure context.
 *  See the details of this function's description for info
 *  on which fields are used and written to. Must not be NULL.
 *
 * @param[in] pt_load_idx The index of the PT_LOAD segment that contains
 *  the GNU hash structure. Must be the one obtained from `find_dt_gnu_hash`.
 *
 * @param[out] out_max_bucket Output pointer for the highest value
 *  in the `buckets` array. This is used in later steps; computed here
 *  for convenience since we're parsing the buckets array anyways.
 *  Must not be NULL.
 *
 * @param[out] out_chain_off Output pointer for the offset of the `chain`
 *  array. This is also used in later steps and similarly; computed here
 *  for convenience. This value will points past the read `bloom` and `buckets`
 *  arrays. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_bloom_and_buckets(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, struct elf_dt_gnu_hash *ctx,
        elf_idx_t pt_load_idx, Elf32_Word *out_max_bucket,
        Elf64_Off *out_chain_off
);

/**
 * Based on the information from the GNU hash header and buckets array,
 * locates and traverses the chain array to find its length.
 * Part of `parse_dt_gnu_hash`.
 *
 * The traversal is bounds-checked against the PT_LOAD segment
 * that contains the rest of the GNU hash structure.
 * Due to the... questionable way the spec is written (not specifying
 * the length of this array in the header), the value obtained from this
 * function can only really be finally trusted after trying to look up
 * every symbol that the hash table indexes.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] containing_phdr_idx The index of the PT_LOAD segment that contains
 *  the GNU hash structure. Must be the one obtained from `find_dt_gnu_hash`.
 *
 * @param[in] ctx The GNU hash structure data, populated by
 *  `find_dt_gnu_hash` and `read_bloom_and_buckets`. Must not be NULL.
 *
 * @param[in] max_bucket The highest value in the `buckets` array.
 *  Must be the value obtained from `read_bloom_and_buckets`.
 *
 * @param[in] chain_off Offset of the chain array.
 *  Must be the value obtained from `read_bloom_and_buckets`.
 *
 * @param[out] out Output pointer for the found number of chain array entries.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero if the chain array doesn't terminate properly
 *  before reaching the segment bounds.
 */
static int find_gnu_hash_nchain(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t containing_phdr_idx,
        const struct elf_dt_gnu_hash *ctx, Elf32_Word max_bucket,
        Elf64_Off chain_off, Elf32_Word *out
);

/**
 * Reads the GNU hash `chain` array.
 * Part of `parse_dt_gnu_hash`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] chain_off Offset of the chain array (at which to start reading).
 *  Must be the value obtained from `read_bloom_and_buckets`.
 *
 * @param[in] nchain The number of entries to read.
 *  Must be the value obtained from `find_gnu_hash_nchain`.
 *
 * @param[out] out Output pointer for the read chain array of `nchain` entries.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_gnu_hash_chain(
        const struct blob *data, int clazz, int encoding,
        Elf64_Off chain_off, Elf32_Word nchain, Elf32_Word **out
);

/**
 * Tries to find a `SHT_GNU_HASH` section header and validates it if present.
 * Part of `parse_dt_gnu_hash`.
 *
 * Also validates that the SHT_DYNSYM table size matches the value
 * derived from the DT_GNU_HASH data.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] ctx The DT_GNU_HASH data previously populated by
 *  `find_dt_hash`, `read_bloom_and_buckets` and `read_gnu_hash_chain`.
 *  Must not be NULL.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[in] clazz Class of the ELF file.
 *
 * @param[out] out_sht_gnu_hash_idx Output pointer for the found SHT_GNU_HASH
 *  section header's index (a reference into `shdrs`),
 *  or `ELF_IDX_NULL` if nothing is found. Must not be NULL.
 *
 * @return 0 on success (either nothing or a valid shdr is found),
 *  non-zero on failure (an invalid shdr is found).
 */
static int validate_sht_gnu_hash_if_exists(const struct elf_dt_gnu_hash *ctx,
                                           const struct elf_shdrs *shdrs,
                                           elf_idx_t sht_dynsym_idx, int clazz,
                                           elf_idx_t *out_sht_gnu_hash_idx);

int parse_dyn(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,

        struct elf_dynamic *out, Elf64_Half *out_dynentsize
)
{
    if (data == NULL || phdrs == NULL || shdrs == NULL) {
        pr_error("%s: Invalid parameters!\n", __func__);
        return -1;
    }

    struct elf_dynamic dyn = { 0 };
    int ret = 1;

    const Elf64_Half entsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);

    /* Find and validate the PT_DYNAMIC program header */
    Elf64_Xword dynnum = 0;
    if (find_validate_pt_dynamic(phdrs, entsize, &dyn.phdr, &dynnum)) {
        pr_error("Missing or invalid PT_DYNAMIC program header\n");
        goto err;
    }

    /* If present, validate the section header against the program header */
    if (validate_sht_dynamic_if_exists(shdrs, phdrs, dyn.phdr, entsize,
                                       &dyn.shdr))
    {
        pr_error("Invalid SHT_DYNAMIC .dynamic section header\n");
        goto err;
    }

    /* Parse the ElfXX_Dyn entries */
    if (parse_dyn_table(data, clazz, encoding, dynnum, phdrs, dyn.phdr,
                        &dyn.entries))
    {
        pr_error("Failed to parse the dynamic entry array\n");
        goto err;
    }
    pr_debug("Number of dynamic entries: %" PRIu64 "\n", dynnum);

    if (parse_dynstr(data, &dyn.entries, phdrs, shdrs, &dyn.strtab)) {
        pr_error("Invalid or missing .dynstr dynamic string table\n");
        goto err;
    }
    if (dyn.shdr != ELF_IDX_NULL) {
        /* .dynamic's `sh_link` must point to .dynstr */
        if (shdrs->arr[dyn.shdr].sh_link != dyn.strtab.shdr) {
            pr_error("SHT_DYNAMIC's sh_link doesn't point to .dynstr\n");
            goto err;
        }
    }

    ret = 0;

err:
    if (ret || out == NULL) {
        if (dyn.entries.arr != NULL)
            free(dyn.entries.arr);
    } else if (!ret && out != NULL) {
        *out = dyn;
    }
    memset(&dyn, 0, sizeof(struct elf_dynamic));

    if (!ret && out_dynentsize != NULL)
        *out_dynentsize = entsize;

    return ret;
}

static int find_validate_pt_dynamic(const struct elf_phdrs *phdrs,
                                    Elf64_Half entsize,
                                    elf_idx_t *out, Elf64_Xword *out_dynnum)
{
    elf_idx_t pt_dynamic_idx = ELF_IDX_NULL;
    {
        for (Elf64_Xword i = 0; i < phdrs->num; i++) {
            if (phdrs->arr[i].p_type == PT_DYNAMIC) {
                pt_dynamic_idx = i;
                break;
            }
        }
        if (pt_dynamic_idx == ELF_IDX_NULL) {
            pr_error("No PT_DYNAMIC header; "
                     "the ELF is probably not dynamically linked\n");
            return 1;
        }
    }
    const Elf64_Phdr *const pt_dynamic = &phdrs->arr[pt_dynamic_idx];

    /* Segment bounds already checked in `read_validate_phdrs` */

    if (pt_dynamic->p_filesz % entsize != 0) {
        pr_error("PT_DYNAMIC segment size (%" PRIu64 ") "
                 "is not a multiple of sizeof(ElfXX_Dyn) (%" PRIu16 ")\n",
                 pt_dynamic->p_filesz, entsize);
        return 1;
    } else if (pt_dynamic->p_filesz != pt_dynamic->p_memsz) {
        pr_error("WARNING: PT_DYNAMIC filesz != memsz\n");
        /* return 1; */
    }

    const Elf64_Xword dynnum = pt_dynamic->p_filesz / entsize;
    if (dynnum > SIZE_MAX) {
        pr_error("Number of dynamic entries overflows size_t\n");
        return 1;
    }

    *out = pt_dynamic_idx;
    *out_dynnum = dynnum;
    return 0;
}

static int validate_sht_dynamic_if_exists(
        const struct elf_shdrs *shdrs, const struct elf_phdrs *phdrs,
        elf_idx_t pt_dynamic_idx, Elf64_Xword entsize,

        elf_idx_t *out
)
{
    elf_idx_t sht_dynamic_idx = ELF_IDX_NULL;
    for (Elf64_Xword i = 0; i < shdrs->num; i++) {
        if (shdrs->arr[i].sh_type == SHT_DYNAMIC) {
            if (sht_dynamic_idx != ELF_IDX_NULL) {
                pr_error("Multiple SHT_DYNAMIC section headers\n");
                return 1;
            }
            sht_dynamic_idx = i;
        }
    }
    if (sht_dynamic_idx == ELF_IDX_NULL) {
        pr_debug("No SHT_DYNAMIC .dynamic section header\n");
        *out = ELF_IDX_NULL;
        return 0;
    }
    const Elf64_Shdr *const sht_dynamic = &shdrs->arr[sht_dynamic_idx];

    const Elf64_Phdr *const pt_dynamic = &phdrs->arr[pt_dynamic_idx];

#define sht_pt_val_cmp(sht_field, shtpri, pt_field, ptpri)              \
do {                                                                    \
    static_assert(sizeof(sht_dynamic->sh_##sht_field) ==                \
                    sizeof(pt_dynamic->p_##pt_field),                   \
                  "Comparing fields of different sizes");               \
                                                                        \
    if (sht_dynamic->sh_##sht_field != pt_dynamic->p_##pt_field) {      \
        pr_error("SHT_DYNAMIC " #sht_field " (0x%" shtpri ") "          \
            "does not match PT_DYNAMIC " #pt_field "(0x%" ptpri ")\n",  \
            sht_dynamic->sh_##sht_field, pt_dynamic->p_##pt_field);     \
        return 1;                                                       \
    }                                                                   \
} while (0)

    sht_pt_val_cmp(offset, PRIx64,      offset, PRIx64);
    sht_pt_val_cmp(size, PRIx64,        filesz, PRIx64);
    sht_pt_val_cmp(addr, PRIx64,        vaddr, PRIx64);
    /* sht_pt_val_cmp(addralign, PRIu64,   align, PRIu64); */

#undef sht_pt_val_cmp

    if (sht_dynamic->sh_entsize != entsize) {
        pr_error("Unexpected value of SHT_DYNAMIC sh_entsize\n");
        return 1;
    }

    if (sht_dynamic->sh_info != 0)
        pr_error("WARNING: SHT_DYNAMIC sh_info is not zero\n");

    *out = sht_dynamic_idx;
    return 0;
}

static int parse_dyn_table(
        const struct blob *data, int clazz, int encoding, Elf64_Xword dynnum,
        const struct elf_phdrs *phdrs, elf_idx_t pt_dynamic_idx,

        struct elf_dyn_entries *out
)
{
    Elf64_Dyn *arr = NULL;
    *out = (struct elf_dyn_entries) { 0 };

    if (pt_dynamic_idx == ELF_IDX_NULL) {
        pr_error("Invalid PT_DYNAMIC program header index\n");
        goto err;
    }
    const Elf64_Phdr *const pt_dynamic = &phdrs->arr[pt_dynamic_idx];

    if (dynnum == 0) {
        pr_error("Number of dynamic entries is 0!\n");
        goto err;
    }
    arr = calloc(dynnum, sizeof(Elf64_Dyn));
    if (arr == NULL) {
        pr_error("Failed to allocate the dynamic entries array\n");
        goto err;
    }

    Elf64_Xword off = pt_dynamic->p_offset;

    bool terminated = false;
    for (Elf64_Xword i = 0; i < dynnum; i++) {
        Elf64_Dyn tmp;
        if (read_dyn(data, &off, clazz, encoding, &tmp)) {
            pr_error("Failed to parse dynamic entry "
                     "no %" PRIu64 " at offset 0x%" PRIx64 "\n", i, off);
            goto err;
        }

        if (terminated) {
            /* Any entries after the first `DT_NULL` should be ignored */

            /* memset(&arr[i], 0, sizeof(Elf64_Dyn));
             *  ^ `calloc` already zeroes the array */
            continue;
        } else if (tmp.d_tag == DT_NULL && !terminated) {
            terminated = true;
        }

        arr[i] = tmp;
    }
    if (!terminated) {
        pr_error("Dynamic entry array not terminated\n");
        goto err;
    }

    if (off != pt_dynamic->p_offset + pt_dynamic->p_filesz) {
        pr_error("Invalid offset (0x%" PRIx64 ") after parsing "
                "dynamic table (expected 0x%" PRIx64 ")\n",
                off, pt_dynamic->p_offset + pt_dynamic->p_filesz);
        goto err;
    }

    out->arr = arr; arr = NULL;
    out->num = dynnum;
    /* `dynnum` is calculated as `pt_dynamic->p_filesz / entsize` anyway */
    out->size = pt_dynamic->p_filesz;
    out->dirty = false;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int parse_dynstr(
        const struct blob *data, const struct elf_dyn_entries *entries,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,

        struct elf_dyn_strtab *out
)
{
    memset(out, 0, sizeof(struct elf_dyn_strtab));

    /* Locate the dynamic string table */
    Elf64_Addr strtab_addr = 0;
    Elf64_Xword strtab_size = 0;
    {
        elf_idx_t idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };
        if (find_unique_dyn_entries(entries, 2,
                    (const Elf64_Sxword[]) { DT_STRTAB, DT_STRSZ },
                    idxs))
        {
            pr_error("Invalid or missing DT_STRTAB and/or DT_STRSZ entries\n");
            return 1;
        }
        strtab_addr = entries->arr[idxs[0]].d_un.d_ptr;
        strtab_size = entries->arr[idxs[1]].d_un.d_val;
        if (strtab_size == 0) {
            pr_error("Zero-size dynamic string table\n");
            return 1;
        }
    }

    /* Ensure that the string table is within a PT_LOAD segment */
    elf_idx_t strtab_ptload_idx =
        find_containing_mem_ptload(phdrs, strtab_addr, strtab_size);
    if (strtab_ptload_idx == ELF_IDX_NULL) {
        pr_error("Dynamic string table not within any PT_LOAD segment\n");
        return 1;
    }
    const Elf64_Phdr *strtab_ptload = &phdrs->arr[strtab_ptload_idx];

    /* Deduce the strtab's file offset from the PT_LOAD segment header */
    const Elf64_Off off_in_load_seg = strtab_addr - strtab_ptload->p_vaddr;
    const Elf64_Off strtab_off = strtab_ptload->p_offset + off_in_load_seg;
    if (find_containing_file_ptload(phdrs, strtab_off, strtab_size)
            != strtab_ptload_idx)
    {
        pr_error("Dynamic string table file offset/size invalid\n");
        return 1;
    }

    /* String tables must begin and end with NUL bytes */
    if (data->data[strtab_off] != '\0' ||
        data->data[strtab_off + strtab_size - 1] != '\0')
    {
        pr_error("Dynamic string table doesn't begin and end with NUL bytes\n");
        return 1;
    }

    /* Validate the corresponding .dynstr section header, if present */
    elf_idx_t strtab_shdr_idx = ELF_IDX_NULL;
    if (find_validate_strtab_shdr(shdrs,
                                  strtab_addr, strtab_off, strtab_size,
                                  &strtab_shdr_idx))
    {
        pr_error("Invalid .dynstr section header\n");
        return 1;
    }

    out->vaddr = strtab_addr;
    out->off = strtab_off;
    out->size = strtab_size;
    out->shdr = strtab_shdr_idx;
    return 0;
}

static int find_validate_strtab_shdr(const struct elf_shdrs *shdrs,
                                     Elf64_Addr addr, Elf64_Off off,
                                     Elf64_Xword size, elf_idx_t *out)
{
    *out = ELF_IDX_NULL;
    elf_idx_t idx = ELF_IDX_NULL;

    for (Elf64_Xword i = 0; i < shdrs->num; i++) {
        const Elf64_Shdr *const curr = &shdrs->arr[i];

        const bool vaddr_overlap =
            ranges_overlap(curr->sh_addr, curr->sh_size, addr, size);

        const bool file_overlap = curr->sh_type != SHT_NOBITS &&
            ranges_overlap(curr->sh_offset, curr->sh_size, off, size);

        if (vaddr_overlap || file_overlap) {
            if (idx != ELF_IDX_NULL) {
                pr_error("Multiple sections overlap "
                         "the dynamic string table\n");
                return 1;
            }
            idx = i;
        }
    }

    if (idx == ELF_IDX_NULL) {
        /* no .dynstr section was found */
        return 0;
    }
    const Elf64_Shdr *const shdr = &shdrs->arr[idx];

    int ret = 0;
    if (shdr->sh_type != SHT_STRTAB) {
        pr_error("Invalid .dynstr section type\n");
        ret = 1;
    }
    if (shdr->sh_offset != off) {
        pr_error("Invalid .dynstr section file offset\n");
        ret = 1;
    }
    if (shdr->sh_addr != addr) {
        pr_error("Invalid .dynstr section virtual address\n");
        ret = 1;
    }
    if (shdr->sh_size != size) {
        pr_error("Invalid .dynstr section size\n");
        ret = 1;
    }

    if (!ret)
        *out = idx;

    return ret;
}

static int find_ptload_and_off_from_vaddr(Elf64_Addr vaddr, Elf64_Xword size,
                                          const struct elf_phdrs *phdrs,
                                          Elf64_Off *out_off,
                                          elf_idx_t *out_pt_load_idx)
{
    *out_off = 0;
    *out_pt_load_idx = ELF_IDX_NULL;

    const elf_idx_t ptload_idx = find_containing_mem_ptload(phdrs, vaddr, size);
    if (ptload_idx == ELF_IDX_NULL) {
        pr_error("Given range not inside any PT_LOAD segment\n");
        return 1;
    }
    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];

    const Elf64_Off off_in_load_seg = vaddr - ptload->p_vaddr;
    if (off_in_load_seg > UINT64_MAX - ptload->p_offset) {
        pr_error("Offset in load segment too large (integer overflow)\n");
        return 1;
    }
    const Elf64_Off off = ptload->p_offset + off_in_load_seg;

    if (find_containing_file_ptload(phdrs, off, size) != ptload_idx) {
        pr_error("Given range not file-backed by its PT_LOAD segment\n");
        return 1;
    }

    *out_off = off;
    *out_pt_load_idx = ptload_idx;
    return 0;
}

static int parse_dt_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_hash *out
)
{
    *out = (struct elf_dt_hash) { 0 };
    if (find_dt_hash(data, clazz, encoding, phdrs, entries, out))
        goto err; /* error already printed */

    uint64_t off = out->off;
    /* `find_dt_hash` already checks that
     * `dt_hash.off + dt_hash.total_size` doesn't overflow */
    const uint64_t end = off + out->total_size;
    if (read_dt_hash_contents(data, clazz, encoding, &off, &out->hdr, end,
                              &out->buckets, &out->chain))
    {
        pr_error("Failed to read the DT_HASH table contents\n");
        goto err;
    }

    if (validate_sht_hash_if_exists(shdrs, out, sht_dynsym_idx, clazz,
                                    &out->shdr))
    {
        pr_error("Invalid SHT_HASH section\n");
        goto err;
    }

    pr_debug("DT_HASH nbucket: %" PRIu32 ", nchain: %" PRIu32 "\n",
             out->hdr.nbucket, out->hdr.nchain);

    return 0;

err:
    if (out->buckets != NULL)
        free(out->buckets);
    if (out->chain != NULL)
        free(out->chain);

    memset(out, 0, sizeof(struct elf_dt_hash));
    return 1;
}

static int find_dt_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_dyn_entries *entries,
        struct elf_dt_hash *out
)
{
    *out = (struct elf_dt_hash) { 0 };
    out->dyn_entry = ELF_IDX_NULL;
    out->shdr = ELF_IDX_NULL;

    /* Find the vaddr, file offset and containing PT_LOAD */
    elf_idx_t dt_hash_idx = ELF_IDX_NULL;
    if (find_unique_dyn_entries(entries, 1,
                (Elf64_Sxword[]) { DT_HASH }, &dt_hash_idx))
    {
        pr_debug("Missing or duplicate DT_HASH entry\n");
        return 1;
    }
    const Elf64_Addr dt_hash_vaddr = entries->arr[dt_hash_idx].d_un.d_ptr;

    Elf64_Off dt_hash_off = 0;
    elf_idx_t pt_load_idx = ELF_IDX_NULL;
    /* we will later validate that this segment contains the entire structure
     * and not just the header, but we must first read the header to determine
     * the total size of the table. */
    if (find_ptload_and_off_from_vaddr(dt_hash_vaddr, DT_HASH_HDR_SIZE, phdrs,
                                       &dt_hash_off, &pt_load_idx))
    {
        pr_error("No PT_LOAD segment properly contains the DT_HASH header\n");
        return 1;
    }

    /* Read the header */
    struct elf_dt_hash_hdr hdr = { 0 }; /* same across both classes */
    uint64_t off = dt_hash_off;
    if (read_Word(data, &off, clazz, encoding, &hdr.nbucket) ||
        read_Word(data, &off, clazz, encoding, &hdr.nchain) ||
        (off < dt_hash_off || off != dt_hash_off + DT_HASH_HDR_SIZE) ||
        (size_t)hdr.nbucket != hdr.nbucket || (size_t)hdr.nchain != hdr.nchain)
    {
        pr_error("Failed to read the DT_HASH table header\n");
        return 1;
    }
    /* during lookup, a modulo operation like this is performed:
     *  `index = bucket[hash(name) % nbucket]`
     * so it must not be zero.
     *
     * also, `nchain` is the number of entries in the associated dynsym table,
     * which contains at least one reserved STN_UNDEF entry.
     */
    if (hdr.nbucket == 0 || hdr.nchain == 0) {
        pr_error("DT_HASH table nbucket and nchain must be greater than 0\n");
        return 1;
    }

    /* none of this can ever overflow a uint64_t */
    const uint64_t buckets_total_size = hdr.nbucket * sizeof(Elf32_Word);
    const uint64_t chain_total_size = hdr.nchain * sizeof(Elf32_Word);
    const Elf64_Xword dt_hash_total_size =
            DT_HASH_HDR_SIZE + buckets_total_size + chain_total_size;

    /* Now validate that the entire table is in the PT_LOAD,
     * not just the header */
    {
        Elf64_Off tmp_off = 0;
        elf_idx_t tmp_idx = ELF_IDX_NULL;
        if (find_ptload_and_off_from_vaddr(dt_hash_vaddr, dt_hash_total_size,
                                           phdrs, &tmp_off, &tmp_idx) ||
                tmp_off != dt_hash_off ||
                tmp_idx != pt_load_idx)
        {
            pr_error("The found PT_LOAD segment doesn't properly contain "
                    "the entire DT_HASH structure\n");
            return 1;
        }
    }

    out->hdr = hdr;
    out->vaddr = dt_hash_vaddr;
    out->off = dt_hash_off;
    out->dyn_entry = dt_hash_idx;
    out->total_size = dt_hash_total_size;
    return 0;
}

static int read_dt_hash_contents(
        const struct blob *data, int clazz, int encoding, uint64_t *off_p,
        const struct elf_dt_hash_hdr *hdr, Elf64_Off end,
        Elf32_Word **out_buckets, Elf32_Word **out_chain
)
{
    /* the above `find_dt_hash` already validates that both
     * `hdr->nbucket` and `hdr->nchain` are representable as size_t */
    int ret = 1;
    Elf32_Word *buckets = NULL, *chain = NULL;
    if ((buckets = calloc((size_t)hdr->nbucket, sizeof(Elf32_Word)))
            == NULL)
    {
        pr_error("Failed to allocate the DT_HASH bucket array\n");
        goto err;
    }
    if ((chain = calloc((size_t)hdr->nchain, sizeof(Elf32_Word))) == NULL) {
        pr_error("Failed to allocate the DT_HASH chain array\n");
        goto err;
    }

    /* `hdr` has already been read by `find_dt_hash` */
    *off_p += DT_HASH_HDR_SIZE;

    for (Elf32_Word i = 0; i < hdr->nbucket; i++) {
        if (read_Word(data, off_p, clazz, encoding, &buckets[i])) {
            pr_error("Failed to read DT_HASH bucket no %" PRIu32 "\n", i);
            goto err;
        }
        if (buckets[i] >= hdr->nchain) {
            pr_error("Invalid DT_HASH bucket no %" PRIu32 "\n", i);
            goto err;
        }
    }

    for (Elf32_Word i = 0; i < hdr->nchain; i++) {
        if (read_Word(data, off_p, clazz, encoding, &chain[i])) {
            pr_error("Failed to read DT_HASH chain no %" PRIu32 "\n", i);
            goto err;
        }
        if (chain[i] >= hdr->nchain) {
            pr_error("Invalid DT_HASH chain no %" PRIu32 "\n", i);
            goto err;
        }
    }

    if (*off_p != end) {
        pr_error("Invalid offset after reading the DT_HASH table "
                 "(expected 0x%" PRIx64 ", got 0x%" PRIx64 ")\n",
                 *off_p, end);
        goto err;
    }

    ret = 0;

err:
    if (!ret) {
        *out_buckets = buckets; buckets = NULL;
        *out_chain = chain; chain = NULL;
    } else {
        if (buckets != NULL) {
            free(buckets);
            buckets = NULL;
        }
        if (chain != NULL) {
            free(chain);
            chain = NULL;
        }
    }

    return ret;
}

static int validate_sht_hash_if_exists(const struct elf_shdrs *shdrs,
                                       const struct elf_dt_hash *dt_hash,
                                       elf_idx_t sht_dynsym_idx, int clazz,
                                       elf_idx_t *out)
{
    *out = ELF_IDX_NULL;
    elf_idx_t sht_hash_idx = ELF_IDX_NULL;
    /* `read_validate_shdrs` guarantees that
     * there aren't multiple `SHT_HASH` sections */
    for (Elf64_Xword i = 0; i < shdrs->num; i++) {
        if (shdrs->arr[i].sh_type == SHT_HASH) {
            sht_hash_idx = i;
            break;
        }
    }
    if (sht_hash_idx == ELF_IDX_NULL && sht_dynsym_idx == ELF_IDX_NULL) {
        pr_debug("%s: No SHT_DYNSYM or SHT_HASH section headers\n",
                __func__);
        return 0;
    } else if (sht_hash_idx == ELF_IDX_NULL || sht_dynsym_idx == ELF_IDX_NULL) {
        pr_error("One of SHT_DYNSYM and SHT_HASH sections is present "
                 "while the other one is missing\n");
        return 1;
    }

    int ret = 0;
    const Elf64_Shdr *const sht_hash = &shdrs->arr[sht_hash_idx];
    const Elf64_Shdr *const sht_dynsym = &shdrs->arr[sht_dynsym_idx];

    if (sht_hash->sh_addr != dt_hash->vaddr) {
        pr_error("Invalid SHT_HASH vaddr\n");
        ret = 1;
    }
    if (sht_hash->sh_offset != dt_hash->off) {
        pr_error("Invalid SHT_HASH offset\n");
        ret = 1;
    }
    if (sht_hash->sh_size != dt_hash->total_size) {
        pr_error("Invalid SHT_HASH size\n");
        ret = 1;
    }

    const size_t symentsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Sym) : sizeof(Elf64_Sym);
    const Elf64_Xword total_symtab_size =
        (Elf64_Xword)dt_hash->hdr.nchain * symentsize;
    if (total_symtab_size != sht_dynsym->sh_size) {
        pr_error("%s: Calculated dynamic symbol table size (0x%" PRIx64 ") "
                 "doesn't match the dynsym section header (0x%" PRIx64 ")\n",
                 __func__, total_symtab_size, sht_dynsym->sh_size);
        ret = 1;
    }

    if (sht_dynsym_idx != ELF_IDX_NULL) {
        if (sht_hash->sh_link != sht_dynsym_idx) {
            pr_error("SHT_HASH sh_link doesn't point to SHT_DYNSYM\n");
            ret = 1;
        }
    } else {
        pr_error("SHT_HASH exists without any SHT_DYNSYM\n");
        ret = 1;
    }

    if (sht_hash->sh_info != 0)
        pr_error("WARNING: SHT_HASH sh_info non-zero\n");
    if (sht_hash->sh_entsize != sizeof(Elf32_Word))
        pr_error("WARNING: SHT_HASH sh_entsize != sizeof(Elf32_Word)\n");

    if (!ret)
        *out = sht_hash_idx;
    return ret;
}

static int parse_dt_gnu_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_gnu_hash *out
)
{
    *out = (struct elf_dt_gnu_hash) { 0 };

    elf_idx_t ptload = ELF_IDX_NULL;
    if (find_dt_gnu_hash(data, clazz, encoding, phdrs, entries, out, &ptload)) {
        /* error already printed */
        goto err;
    }

    Elf32_Word max_bucket = 0;
    Elf64_Off chain_off = 0;
    if (read_bloom_and_buckets(data, clazz, encoding, phdrs,
                               out, ptload, &max_bucket, &chain_off))
    {
        pr_error("Failed to read the DT_GNU_HASH bloom filter and buckets\n");
        goto err;
    }

    if (find_gnu_hash_nchain(data, clazz, encoding, phdrs,
                             ptload, out, max_bucket, chain_off, &out->nchain))
    {
        pr_error("Couldn't find the number of entries in the GNU hash chain\n");
        goto err;
    }

    if (read_gnu_hash_chain(data, clazz, encoding, chain_off, out->nchain,
                            &out->chain))
    {
        pr_error("Failed to read the GNU hash chain\n");
        goto err;
    }

    /* max value: (16 + 8 + 4 + 4) * 2^32; doesn't overflow a uint64 */
    out->total_size = (Elf64_Xword)DT_GNU_HASH_HDR_SIZE +
                        (out->bloomentsize * out->hdr.bloom_size) +
                        (sizeof(Elf32_Word) * out->hdr.nbuckets) +
                        (sizeof(Elf32_Word) * out->nchain);
    {
        Elf64_Off tmp_off = 0;
        elf_idx_t tmp_ptload = ELF_IDX_NULL;
        if (find_ptload_and_off_from_vaddr(out->vaddr, out->total_size, phdrs,
                    &tmp_off, &tmp_ptload) ||
                tmp_off != out->off || tmp_ptload != ptload)
        {
            pr_error("DT_GNU_HASH contents not contained in the found "
                     "PT_LOAD segment\n");
            goto err;
        }
    }

    if (validate_sht_gnu_hash_if_exists(out, shdrs, sht_dynsym_idx, clazz,
                                        &out->shdr))
    {
        pr_error("GNU hash section data mismatch\n");
        goto err;
    }

    pr_debug("DT_GNU_HASH nbucket: %" PRIu32 ", nchain: %" PRIu32 ", "
             "symoffset: %" PRIu32 "\n",
             out->hdr.nbuckets, out->nchain, out->hdr.symoffset);

    return 0;

err:
    if (out->chain != NULL) {
        free(out->chain);
        out->chain = NULL;
    }
    if (out->buckets != NULL) {
        free(out->buckets);
        out->buckets = NULL;
    }
    if (out->bloom != NULL) {
        free(out->bloom);
        out->bloom = NULL;
    }
    return 1;
}

static int read_dt_gnu_hash_hdr(
        const struct blob *data, int clazz, int encoding, uint64_t *off_p,
        struct elf_dt_gnu_hash_hdr *out
)
{
    const uint64_t start_off = *off_p;
    if (start_off > UINT64_MAX - DT_GNU_HASH_HDR_SIZE)
        return -1;
    const uint64_t end = start_off + DT_GNU_HASH_HDR_SIZE;

    /* same across both classes */
    if (read_Word(data, off_p, clazz, encoding, &out->nbuckets) ||
        read_Word(data, off_p, clazz, encoding, &out->symoffset) ||
        read_Word(data, off_p, clazz, encoding, &out->bloom_size) ||
        read_Word(data, off_p, clazz, encoding, &out->bloom_shift))
    {
        return 1;
    }
    if (*off_p != end)
        return 1;

    if (((size_t)out->nbuckets != out->nbuckets) ||
        ((size_t)out->bloom_size != out->bloom_size))
    {
        return 1;
    }

    return 0;
}

static int find_dt_gnu_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_dyn_entries *entries,
        struct elf_dt_gnu_hash *out, elf_idx_t *out_pt_load_idx
)
{
    *out = (struct elf_dt_gnu_hash) { 0 };
    out->shdr = ELF_IDX_NULL;
    out->dyn_entry = ELF_IDX_NULL;
    *out_pt_load_idx = ELF_IDX_NULL;

    /* Find the DT_GNU_HASH vaddr, file offset and containing PT_LOAD */
    elf_idx_t dt_gnu_hash_idx = ELF_IDX_NULL;
    if (find_unique_dyn_entries(entries, 1,
                (const Elf64_Sxword[]) { DT_GNU_HASH }, &dt_gnu_hash_idx))
    {
        pr_debug("Missing or duplicate DT_GNU_HASH entry\n");
        return 1;
    }
    const Elf64_Addr vaddr = entries->arr[dt_gnu_hash_idx].d_un.d_ptr;

    Elf64_Off dt_gnu_hash_off = 0;
    elf_idx_t pt_load_idx = ELF_IDX_NULL;
    /* as with DT_HASH, we must first read the header to determine the size
     * of the whole DT_GNU_HASH, which is validated later  */
    if (find_ptload_and_off_from_vaddr(vaddr, DT_GNU_HASH_HDR_SIZE, phdrs,
                                       &dt_gnu_hash_off, &pt_load_idx))
    {
        pr_error("No PT_LOAD segment properly contains "
                "the DT_GNU_HASH header\n");
        return 1;
    }

    /* Read the header */
    uint64_t off = dt_gnu_hash_off;
    struct elf_dt_gnu_hash_hdr hdr = { 0 };
    if (read_dt_gnu_hash_hdr(data, clazz, encoding, &off, &hdr)) {
        pr_error("Failed to read the DT_GNU_HASH header\n");
        return 1;
    }

    if (hdr.bloom_size == 0) {
        pr_error("Bloom filter size cannot be zero\n");
        return 1;
    }

    out->hdr = hdr;
    out->off = dt_gnu_hash_off;
    out->vaddr = vaddr;
    out->dyn_entry = dt_gnu_hash_idx;
    out->bloomentsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Word) : sizeof(Elf64_Xword);
    *out_pt_load_idx = pt_load_idx;

    return 0;
}

static int read_bloom_and_buckets(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, struct elf_dt_gnu_hash *ctx,
        elf_idx_t pt_load_idx, Elf32_Word *out_max_bucket,
        Elf64_Off *out_chain_off
)
{
    Elf64_Xword *bloom = NULL;
    Elf32_Word *buckets = NULL;

    /* Overflow safety established by `read_dt_gnu_hash_hdr` */
    const uint64_t bloom_off = ctx->off + DT_GNU_HASH_HDR_SIZE;
    const uint64_t bloom_total_size = ctx->hdr.bloom_size * ctx->bloomentsize;
    if (bloom_off > UINT64_MAX - bloom_total_size) {
        pr_error("Bloom filter size too large (integer overflow)\n");
        goto err;
    }

    const uint64_t buckets_off = bloom_off + bloom_total_size;
    const uint64_t buckets_total_size = ctx->hdr.nbuckets * sizeof(Elf32_Word);
    if (buckets_off > UINT64_MAX - buckets_total_size) {
        pr_error("Buckets size too large (integer overflow)\n");
        goto err;
    }
    const uint64_t chain_off = buckets_off + buckets_total_size;

    /* Check that the bloom filter and buckets array are contained
     * in the same PT_LOAD segment as the header */
    {
        uint64_t tmp_off = 0;
        elf_idx_t tmp_pt_load_idx = ELF_IDX_NULL;
        /* 16 + 2^32 + 2^32 doesn't overflow a uint64_t */
        const uint64_t size =
            DT_GNU_HASH_HDR_SIZE + bloom_total_size + buckets_total_size;
        if (find_ptload_and_off_from_vaddr(ctx->vaddr, size, phdrs,
                                           &tmp_off, &tmp_pt_load_idx) ||
                tmp_off != ctx->off ||
                tmp_pt_load_idx != pt_load_idx)
        {
            pr_error("DT_GNU_HASH header, bloom filter and buckets "
                     "not file-backed by the found PT_LOAD segment\n");
            goto err;
        }
    }

    /* Read the bloom filter */
    /* bloom_size is guaranteed to be non-zero by `find_dt_gnu_hash` */
    bloom = calloc(ctx->hdr.bloom_size, sizeof(Elf64_Xword));
    if (bloom == NULL) {
        pr_error("Failed to allocate the bloom filter array\n");
        goto err;
    }
    uint64_t off = bloom_off;
    for (Elf32_Word i = 0; i < ctx->hdr.bloom_size; i++) {
        /* glibc uses `ElfXX_Addr` for this too, lol */
        if (read_Addr(data, &off, clazz, encoding, &bloom[i])) {
            pr_error("Failed to read bloom filter entry no %" PRIu32 "\n", i);
            goto err;
        }
    }
    if (off != buckets_off) {
        pr_error("Incorrect number of bytes read for the bloom filter\n");
        goto err;
    }

    /* Read the buckets; this time `nbuckets` can theoretically be 0 */
    Elf32_Word max_bucket = 0;
    if (ctx->hdr.nbuckets > 0) {
        buckets = calloc(ctx->hdr.nbuckets, sizeof(Elf32_Word));
        if (buckets == NULL) {
            pr_error("Failed to allocate the buckets array\n");
            goto err;
        }
        uint64_t off = buckets_off;
        for (Elf32_Word i = 0; i < ctx->hdr.nbuckets; i++) {
            if (read_Word(data, &off, clazz, encoding, &buckets[i])) {
                pr_error("Failed to read bucket no %" PRIu32 "\n", i);
                goto err;
            }
            if (buckets[i] < ctx->hdr.symoffset && buckets[i] != 0) {
                pr_error("DT_GNU_HASH bucket %" PRIu32 " (%" PRIu32 ") "
                         "refers to symbol below symoffset\n", i, buckets[i]);
                goto err;
            }

            if (buckets[i] > max_bucket)
                max_bucket = buckets[i];
        }
        if (off != buckets_off + buckets_total_size) {
            pr_error("Incorrect number of bytes read for the buckets array\n");
            goto err;
        }
    }

    ctx->buckets = buckets; buckets = NULL;
    ctx->bloom = bloom; bloom = NULL;
    *out_max_bucket = max_bucket;
    *out_chain_off = chain_off;
    return 0;

err:
    if (buckets != NULL) {
        free(buckets);
        buckets = NULL;
    }
    if (bloom != NULL) {
        free(bloom);
        bloom = NULL;
    }
    return 1;
}

static int find_gnu_hash_nchain(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t containing_phdr_idx,
        const struct elf_dt_gnu_hash *ctx, Elf32_Word max_bucket,
        Elf64_Off chain_off, Elf32_Word *out
)
{
    if (max_bucket == 0) {
        pr_debug("%s: No hashed symbols\n", __func__);
        *out = 0;
        return 0;
    } else if (max_bucket < ctx->hdr.symoffset) {
        pr_error("Invalid max bucket value\n");
        return 1;
    }
    const Elf32_Word start_idx = max_bucket - ctx->hdr.symoffset;

    /* never overflows */
    const Elf64_Xword min_chain_size =
        ((Elf64_Xword)start_idx + 1) * sizeof(Elf32_Word);

    const Elf64_Phdr *const containing_phdr = &phdrs->arr[containing_phdr_idx];
    /* it's assumed that every entry in `phdrs` has already been validated */
    const Elf64_Off seg_end =
        containing_phdr->p_offset + containing_phdr->p_filesz;

    if (seg_end < sizeof(Elf32_Word) ||
        seg_end < chain_off ||
        min_chain_size > seg_end - chain_off)
    {
        pr_error("GNU hash chain doesn't fit in its PT_LOAD segment\n");
        return 1;
    }

    uint64_t idx = (uint64_t)start_idx;
    uint64_t off = chain_off + ((uint64_t)start_idx * sizeof(Elf32_Word));
    while (true) {
        if (off > seg_end - sizeof(Elf32_Word)) {
            pr_error("GNU hash chain doesn't fit in its PT_LOAD segment "
                     "(no terminator found)\n");
            return 1;
        }

        Elf32_Word c = 0;
        if (read_Word(data, &off, clazz, encoding, &c)) {
            pr_error("Failed to read chain entry no %" PRIu64 "\n", idx);
            return 1;
        }
        if (c & UINT32_C(1))
            break;

        if (idx == (uint64_t)UINT32_MAX) {
            pr_error("Chain entry index too large (integer overflow)\n");
            return 1;
        }
        idx++;
    }

    if (idx >= (uint64_t)UINT32_MAX) {
        pr_error("Chain entry index too large (integer overflow)\n");
        return 1;
    }
    *out = (Elf32_Word)(idx + 1);
    return 0;
}

static int read_gnu_hash_chain(
        const struct blob *data, int clazz, int encoding,
        Elf64_Off chain_off, Elf32_Word nchain, Elf32_Word **out
)
{
    Elf32_Word *chain = NULL;

    if (nchain == 0) {
        pr_debug("%s: No chain entries\n", __func__);
        *out = NULL;
        return 0;
    }

    chain = calloc(nchain, sizeof(Elf32_Word));
    if (chain == NULL) {
        pr_error("Failed to allocate the hash chain array\n");
        goto err;
    }

    uint64_t off = chain_off;
    for (Elf32_Word i = 0; i < nchain; i++) {
        if (read_Word(data, &off, clazz, encoding, &chain[i])) {
            pr_error("Failed to read hash chain entry no %" PRIu32 "\n", i);
            goto err;
        }
    }

    *out = chain;
    return 0;

err:
    if (chain != NULL) {
        free(chain);
        chain = NULL;
    }
    *out = NULL;
    return 1;
}

static int validate_sht_gnu_hash_if_exists(const struct elf_dt_gnu_hash *ctx,
                                           const struct elf_shdrs *shdrs,
                                           elf_idx_t sht_dynsym_idx, int clazz,
                                           elf_idx_t *out_sht_gnu_hash_idx)
{
    *out_sht_gnu_hash_idx = ELF_IDX_NULL;
    elf_idx_t sht_gnu_hash_idx = ELF_IDX_NULL;
    /* `read_validate_shdrs` guarantees that
     * there aren't multiple `SHT_GNU_HASH` sections */
    for (Elf64_Xword i = 0; i < shdrs->num; i++) {
        if (shdrs->arr[i].sh_type == SHT_GNU_HASH) {
            sht_gnu_hash_idx = i;
            break;
        }
    }
    if (sht_gnu_hash_idx == ELF_IDX_NULL && sht_dynsym_idx == ELF_IDX_NULL) {
        pr_debug("%s: No SHT_DYNSYM or SHT_GNU_HASH section headers\n",
                __func__);
        return 0;
    } else if (sht_gnu_hash_idx == ELF_IDX_NULL ||
               sht_dynsym_idx == ELF_IDX_NULL)
    {
        pr_error("One of SHT_DYNSYM and SHT_GNU_HASH sections is present "
                 "while the other one is missing\n");
        return 1;
    }
    const Elf64_Shdr *const sht_dynsym = &shdrs->arr[sht_dynsym_idx];
    const Elf64_Shdr *const sht_gnu_hash = &shdrs->arr[sht_gnu_hash_idx];

    int ret = 0;

    if (sht_gnu_hash->sh_addr != ctx->vaddr) {
        pr_error("Invalid SHT_GNU_HASH vaddr\n");
        ret = 1;
    }
    if (sht_gnu_hash->sh_offset != ctx->off) {
        pr_error("Invalid SHT_GNU_HASH offset\n");
        ret = 1;
    }
    if (ctx->total_size != sht_gnu_hash->sh_size) {
        pr_error("GNU hash calculated size (0x%" PRIx64 ") doesn't match "
                 "the section header (0x%" PRIx64 ")\n",
                 ctx->total_size, sht_gnu_hash->sh_size);
        ret = 1;
    }

    const size_t symentsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Sym) : sizeof(Elf64_Sym);
    const Elf64_Xword total_symtab_size =
        ((Elf64_Xword)ctx->hdr.symoffset + ctx->nchain) * symentsize;
    if (total_symtab_size != sht_dynsym->sh_size) {
        pr_error("Calculated dynamic symbol table size (0x%" PRIx64 ") "
                 "doesn't match the dynsym section header (0x%" PRIx64 ")\n",
                 total_symtab_size, sht_dynsym->sh_size);
        ret = 1;
    }

    if (sht_gnu_hash->sh_link != sht_dynsym_idx) {
        pr_error("SHT_GNU_HASH sh_link doesn't point to the dynsym section\n");
        ret = 1;
    }

    if (!ret)
        *out_sht_gnu_hash_idx = sht_gnu_hash_idx;
    return ret;
}

int parse_dynsym(const struct blob *data, int clazz, int encoding,
                 const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
                 const struct elf_dyn_entries *entries)
{
    elf_idx_t idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };
    if (find_unique_dyn_entries(entries, 2,
                                (const Elf64_Sxword[]) { DT_SYMTAB, DT_SYMENT },
                                idxs))
    {
        pr_error("Invalid or missing DT_SYMTAB and/or DT_SYMENT entries\n");
        return 1;
    }
    const Elf64_Dyn *const dt_symtab = &entries->arr[idxs[0]];
    const Elf64_Dyn *const dt_syment = &entries->arr[idxs[1]];
    (void) dt_symtab;

    if (!((clazz == ELFCLASS32 && dt_syment->d_un.d_val == sizeof(Elf32_Sym)) ||
          (clazz == ELFCLASS64 && dt_syment->d_un.d_val == sizeof(Elf64_Sym))))
    {
        pr_error("Invalid value of DT_SYMENT for class %s: %" PRIu64 "\n",
                 clazz == ELFCLASS32 ? "ELFCLASS32" : "ELFCLASS64",
                 dt_syment->d_un.d_val);
        return 1;
    }

    /* The following is inspired by:
     *  https://lldb.llvm.org/cpp_reference/ObjectFileELF_8cpp_source.html
     * (line ~4315) */

    elf_idx_t sht_dynsym_idx = ELF_IDX_NULL;
    for (Elf64_Xword i = 0; i < shdrs->num; i++) {
        if (shdrs->arr[i].sh_type == SHT_DYNSYM) {
            sht_dynsym_idx = i;
            break;
        }
    }

    Elf64_Xword nsyms_dt_hash = 0;
    struct elf_dt_hash dt_hash = { 0 };
    if (parse_dt_hash(data, clazz, encoding, phdrs, shdrs,
                      entries, sht_dynsym_idx, &dt_hash))
    {
        pr_error("Failed to parse DT_HASH\n");
        return 1;
    }
    nsyms_dt_hash = dt_hash.hdr.nchain;
    free(dt_hash.chain);
    free(dt_hash.buckets);
    dt_hash = (struct elf_dt_hash) { 0 };

    Elf64_Xword nsyms_dt_gnu_hash = 0;
    struct elf_dt_gnu_hash dt_gnu_hash = { 0 };
    if (parse_dt_gnu_hash(data, clazz, encoding, phdrs, shdrs,
                          entries, sht_dynsym_idx, &dt_gnu_hash))
    {
        pr_error("Failed to parse DT_GNU_HASH\n");
        return 1;
    }
    nsyms_dt_gnu_hash =
        (Elf64_Xword)dt_gnu_hash.hdr.symoffset + dt_gnu_hash.nchain;
    free(dt_gnu_hash.chain);
    free(dt_gnu_hash.buckets);
    free(dt_gnu_hash.bloom);
    dt_gnu_hash = (struct elf_dt_gnu_hash) { 0 };

    printf("nsyms: DT_HASH: %" PRIu64 ", DT_GNU_HASH: %" PRIu64 "\n",
            nsyms_dt_hash, nsyms_dt_gnu_hash);

    return 0;
}
