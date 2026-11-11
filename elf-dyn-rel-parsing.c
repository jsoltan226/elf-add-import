#include "elf-dyn-rel-parsing.h"
#include "elf-types.h"
#include "elf.h"
#include "ctx.h"
#include "util.h"
#include "elf-dyn-parsing.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/**
 * Reads a table of ElfXX_Rel or ElfXX_Rela entries.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] num The number of relocation entries to read;
 *  the value of `DT_REL(A)SZ / DT_REL(A)ENT`. Must be greater than 0.
 *  Note: `num * struct_size` must not overflow `size_t`.
 *
 * @param[out] out_arr Output pointer for the newly allocated array
 *  of `num` parsed ElfXX_Rel or ElfXX_Rela entries. Must not be NULL.
 *  Will contain a value only on success; `NULL` otherwise.
 *
 * @param[in,out] max_symidx_p Pointer to a variable storing the highest-seen
 *  dynamic symbol index referenced by a relocation entry. Must not be NULL.
 *
 * @param[in] struct_size `sizeof(Elf64_Rel)` or `sizeof(Elf64_Rela)`;
 *  the size of each entry in `*out_arr`.
 *
 * @param[in] r_info_offset The offset of the `r_info` field in the respective
 *  `Elf64_Rel(a)` struct.
 *
 * @param[in] read_proc The `read_rel(a)` function from `elf-types.h`
 *  corresponding to the given struct.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_relX_table(
        const ElfFileData *data, Elf64_Off tbl_off, size_t num, void **out_arr,
        Elf64_Word *max_symidx_p, size_t struct_size, size_t r_info_offset,
        int (*read_proc)(const ElfFileData *data, Elf64_Off *off_p, void *out)
);

/**
 * Looks for any `SHT_REL(A)` section headers overlapping
 * the corresponding `DT_REL(A)` table range and validates them.
 *
 * @param[in] shdrs The parased section headers array. Must not be NULL.
 *
 * @param[in] tbl_vaddr The virtual address of the corresponding REL(A) table;
 *  the value of `DT_REL(A)`.
 *
 * @param[in] tbl_off File offset of the corresponding REL(A) table.
 *
 * @param[in] tbl_size Size of the corresponding REL(A) table;
 *  the value of `DT_REL(A)SZ`.
 *
 * @param[in] sht_dynsym_idx Index (into `shdrs`) of the `SHT_DYNSYM`
 *  section header, or `ELF_IDX_NULL` if it doesn't exist.
 *
 * @param[in] entsize The size of each entry in the corresponding REL(A) table;
 *  the value of `DT_REL(A)ENT`.
 *
 * @param[out] out_arr Output pointer for the newly allocated array
 *  of `*out_num` section header indices (into `shdrs`),
 *  or `NULL` if no `SHT_RELA` section headers overlapping the REL(A) table
 *  are found or some other error occurs. Must not be NULL.
 *
 * @param[out] out_num Output pointer for the number of found `SHT_RELA`
 *  section headers which overlap the respective REL(A) table;
 *  the size of `*out_arr`. Must not be NULL.
 *
 * @param[in] sh_type The type of the section header, corresponding to
 *  the relevant type of relocation entries; `SHT_REL` or `SHT_RELA`.
 *
 * @return 0 on success,
 *  positive (>0) value if no shdrs that meet the requirements are found,
 *  negative (<0) if an invalid shdr is found or some other error occurs.
 */
static int find_validate_sht_relX_shdrs(
    const struct elf_shdrs *shdrs, Elf64_Addr tbl_vaddr, Elf64_Off tbl_off,
    Elf64_Xword tbl_size, elf_idx_t sht_dynsym_idx, Elf64_Half entsize,
    elf_idx_t **out_arr, size_t *out_num, Elf64_Word sh_type
);

/**
 * Validates a single `SHT_REL(A)` section header overlapping
 * the corresponding REL(A) table.
 *
 * Checks that:
 *  - The section is fully contained in the REL(A) table's file & memory range,
 *  - The section doesn't overlap any other `SHT_REL(A)` sections associated
 *      with the REL(A) table,
 *  - The `sh_link` value references the `SHT_DYNSYM` section,
 *  - The `sh_size` and `sh_entsize` values match those of the dynamic entries,
 *  - The `sh_info` value is either 0 or a valid index into `shdrs`.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] shdr_idx Index (into `shdrs`) of the `SHT_REL(A)` section header
 *  to be validated.
 *
 * @param[in] tbl_addr The virtual address of the corresponding REL(A) table;
 *  the value of `DT_REL(A)`.
 *
 * @param[in] tbl_off File offset of the corresponding REL(A) table.
 *
 * @param[in] tbl_size Size of the corresponding REL(A) table;
 *  the value of `DT_REL(A)SZ`.
 *
 * @param[in] found_shdrs The array of `curr_num_found_shdrs`
 *  indices of other `SHT_REL(A)` section headers which have been found
 *  to overlap the corresponding REL(A) table.
 *
 * @param[in] entsize The size of each entry in the corresponding REL(A) table;
 *  the value of `DT_REL(A)ENT`.
 *
 * @param[in] sht_dynsym_idx Index (into `shdrs`) of the `SHT_DYNSYM`
 *  section header, or `ELF_IDX_NULL` if it doesn't exist.
 *
 * @return 0 on success, non-zero if the shdr is invalid.
 */
static int validate_sht_relX_shdr(
        const struct elf_shdrs *shdrs, elf_idx_t shdr_idx,
        Elf64_Addr tbl_addr, Elf64_Off tbl_off, Elf64_Xword tbl_size,
        const elf_idx_t *found_shdrs, size_t curr_num_found_shdrs,
        Elf64_Half entsize, elf_idx_t sht_dynsym_idx
);

/**
 * Finds and, if present, parses the DT_REL relocation-without-addends table.
 *
 * Uses the `find_rel` function and the generic wrappers to:
 *  - Check for and parse the DT_REL entries and other metadata; (`find_rel`)
 *  - Read the DT_REL table (`read_relX_table`);
 *  - Find and validate and section headers which overlap the DT_REL table
 *      (`find_validate_sht_relX_shdrs`)
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in,out] max_symidx_p Pointer to a variable storing the highest-seen
 *  dynamic symbol index referenced by a relocation entry. Must not be NULL.
 *
 * @param[out] out Output pointer, populated with actual values on success
 *  and initialized to `empty_reloc_rel_st` otherwise. Must not be NULL.
 *
 * @return 0 if the DT_REL table was found and parsed successfully,
 *  positive (>0) value if no DT_REL table exists,
 *  negative (<0) if the DT_REL table is invalid or some other error occured.
 */
static int parse_dt_rel(
        const ElfFileData *data,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, Elf64_Word *max_symidx_p,
        struct elf_reloc_rel *out
);

/**
 * A function that locates and parses the DT_REL table metadata,
 * initializing the relevant fields in the `elf_reloc_rel` struct.
 *
 * The following fields are populated with the parsed values:
 *      vaddr, off, size, entsize;
 *      num,
 *      dt_rel_idx, dt_relsz_idx, dt_relent_idx;
 *      dt_relcount_idx, relcount; (if DT_RELCOUNT exists)
 * The following fields are initialized to NULL/empty values:
 *      arr;
 *      n_shdrs, shdrs;
 *      dt_relcount_idx, relcount; (if DT_RELCOUNT does not exist)
 *      present; (meant to be set in the top-level `parse_dt_rel`
 *                only after full successful parsing)
 *
 * See the definition of `struct elf_reloc_rel` for the details
 * regarding the values with which the above fields are initialized.
 *
 * In case of failure or if no DT_REL metadata is found,
 * `out` is initialized to `empty_reloc_rel_st`.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 if valid DT_REL metadata was found,
 *         positive (>0) value if the DT_REL table is absent,
 *         negative (<0) value if the found DT_REL metadata is invalid.
 */
static int find_rel(const struct elf_dyn_entries *entries, int clazz,
                    const struct elf_phdrs *phdrs, struct elf_reloc_rel *out);


/** A `void *` wrapper for the `read_rel` function from `elf-types.h`. */
static inline int
read_rel_wrapper(const ElfFileData *data, Elf64_Off *off_p, void *out)
{
    return read_rel(data, off_p, (Elf64_Rel *)out);
}

/** A REL wrapper for the `read_relX_table` function. */
static inline int
read_rel_table(const ElfFileData *data, Elf64_Off tbl_off, size_t num,
               Elf64_Rel **out_arr, Elf64_Word *max_symidx_p)
{
    *out_arr = NULL;
    void *tmp_arr = NULL;

    const int ret =
        read_relX_table(data, tbl_off, num, &tmp_arr, max_symidx_p,
                        sizeof(Elf64_Rel), offsetof(Elf64_Rel, r_info),
                        read_rel_wrapper);
    if (ret == 0) {
        *out_arr = tmp_arr;
        tmp_arr = NULL;
    }
    return ret;
}

/**
 * Finds and, if present, parses the DT_RELA relocation-with-addends table.
 *
 * Uses the `find_rela` function and the generic wrappers to:
 *  - Check for and parse the DT_RELA entries and other metadata; (`find_rela`)
 *  - Read the DT_RELA table (`read_relX_table`);
 *  - Find and validate and section headers which overlap the DT_RELA table
 *      (`find_validate_sht_relX_shdrs`)
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in,out] max_symidx_p Pointer to a variable storing the highest-seen
 *  dynamic symbol index referenced by a relocation entry. Must not be NULL.
 *
 * @param[out] out Output pointer, populated with actual values on success
 *  and initialized to `empty_reloc_rela_st` otherwise. Must not be NULL.
 *
 * @return 0 if the DT_RELA table was found and parsed successfully,
 *  positive (>0) value if no DT_RELA table exists,
 *  negative (<0) if the DT_RELA table is invalid or some other error occured.
 */
static int parse_dt_rela(
        const ElfFileData *data,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, Elf64_Word *max_symidx_p,
        struct elf_reloc_rela *out
);

/**
 * A function that locates and parses the DT_RELA table metadata,
 * initializing the relevant fields in the `elf_reloc_rela` struct.
 *
 * The following fields are populated with the parsed values:
 *      vaddr, off, size, entsize;
 *      num,
 *      dt_rela_idx, dt_relasz_idx, dt_relaent_idx;
 *      dt_relacount_idx, relacount; (if DT_RELACOUNT exists)
 * The following fields are initialized to NULL/empty values:
 *      arr;
 *      n_shdrs, shdrs;
 *      dt_relacount_idx, relacount; (if DT_RELACOUNT does not exist)
 *      present; (meant to be set in the top-level `parse_dt_rela`
 *                only after full successful parsing)
 *
 * See the definition of `struct elf_reloc_rela` for the details
 * regarding the values with which the above fields are initialized.
 *
 * In case of failure or if no DT_RELA metadata is found,
 * `out` is initialized to `empty_reloc_rela_st`.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 if valid DT_RELA metadata was found,
 *         positive (>0) value if the DT_RELA table is absent,
 *         negative (<0) value if the found DT_RELA metadata is invalid.
 */
static int find_rela(const struct elf_dyn_entries *entries, int clazz,
                     const struct elf_phdrs *phdrs, struct elf_reloc_rela *out);

/** A `void *` wrapper for the `read_rela` function from `elf-types.h`. */
static inline int
read_rela_wrapper(const ElfFileData *data, Elf64_Off *off_p, void *out)
{
    return read_rela(data, off_p, (Elf64_Rela *)out);
}

/** A RELA wrapper for the `read_relX_table` function. */
static inline int
read_rela_table(const ElfFileData *data, Elf64_Off tbl_off, size_t num,
                Elf64_Rela **out_arr, Elf64_Word *max_symidx_p)
{
    *out_arr = NULL;
    void *tmp_arr = NULL;

    const int ret =
        read_relX_table(data, tbl_off, num, &tmp_arr, max_symidx_p,
                        sizeof(Elf64_Rela), offsetof(Elf64_Rela, r_info),
                        read_rela_wrapper);
    if (ret == 0) {
        *out_arr = tmp_arr;
        tmp_arr = NULL;
    }
    return ret;
}

int parse_reloc(const ElfFileData *data,
                const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
                const struct elf_dyn_entries *entries,
                struct elf_reloc *out, Elf64_Word *out_max_symidx)
{
    struct elf_reloc rel = empty_reloc_st;
    Elf64_Word max_symidx = 0;
    *out = empty_reloc_st;
    *out_max_symidx = 0;

    if (parse_dt_rela(data, phdrs, shdrs, entries, &max_symidx, &rel.rela)
            < 0)
    {
        pr_error("Invalid relocation (with addends) table\n");
        goto err;
    }

    if (parse_dt_rel(data, phdrs, shdrs, entries, &max_symidx, &rel.rel)
            < 0)
    {
        pr_error("Invalid relocation (without addends) table\n");
        goto err;
    }

    *out = rel;
    *out_max_symidx = max_symidx;
    return 0;

err:
    destroy_rel(&rel);
    return -1;
}

void destroy_rel(struct elf_reloc *rel)
{
    if (rel == NULL)
        return;

    if (rel->rela.arr != NULL)
        free(rel->rela.arr);
    if (rel->rela.shdrs != NULL)
        free(rel->rela.shdrs);

    if (rel->rel.arr != NULL)
        free(rel->rel.arr);
    if (rel->rel.shdrs != NULL)
        free(rel->rel.shdrs);

    *rel = empty_reloc_st;
}

static int read_relX_table(
        const ElfFileData *data, Elf64_Off tbl_off, size_t num, void **out_arr,
        Elf64_Word *max_symidx_p, size_t struct_size, size_t r_info_offset,
        int (*read_proc)(const ElfFileData *data, Elf64_Off *off_p, void *out)
)
{
    void *arr = NULL;
    Elf64_Off off = 0;

    *out_arr = NULL;

    assert(num > 0);
    assert(num < SIZE_MAX / struct_size);

    arr = calloc(num, struct_size);
    if (arr == NULL) {
        pr_error("Failed to allocate the REL(A) table array\n");
        goto err;
    }

    off = tbl_off;
    for (size_t i = 0; i < num; i++) {
        void *const ptr = (unsigned char *)arr + (struct_size * i);
        if (read_proc(data, &off, ptr)) {
            pr_error("Failed to read REL(A) entry no %zu\n", i);
            goto err;
        }

        /* `r_offset` is a virtual address in ET_DYN ELFs,
         * don't validate here */

        /* This will be used and validated later, in `elf-dyn-sym-parsing` */
        Elf64_Xword r_info;
        memcpy(&r_info, (unsigned char *)ptr + r_info_offset,
                sizeof(Elf64_Xword));
        const Elf64_Word r_sym = (Elf64_Word)ELF64_R_SYM(r_info);
                                /* ^ Always fits in 32 bits */
        if (r_sym > *max_symidx_p)
            *max_symidx_p = (Elf64_Word)r_sym;

        /* `R_TYPE` of `r_info` is machine-specific; don't check it */

        /* (For ElfXX_Rela) `r_addend` can't really be validated here either */
    }

    *out_arr = arr; arr = NULL;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int find_validate_sht_relX_shdrs(
    const struct elf_shdrs *shdrs, Elf64_Addr tbl_vaddr, Elf64_Off tbl_off,
    Elf64_Xword tbl_size, elf_idx_t sht_dynsym_idx, Elf64_Half entsize,
    elf_idx_t **out_arr, size_t *out_num, Elf64_Word sh_type
)
{
    size_t num = 0;
    elf_idx_t *arr = NULL;

    *out_arr = NULL;
    *out_num = 0;

    assert(tbl_size > 0);

    for (Elf64_Xword i = 0; i < shdrs->num; i++) {
        const Elf64_Shdr *const shdr = &shdrs->arr[i];

        if (shdr->sh_type != sh_type || shdr->sh_size == 0)
            continue;

        if (ranges_overlap(shdr->sh_offset, shdr->sh_size, tbl_off, tbl_size) ||
            ranges_overlap(shdr->sh_addr, shdr->sh_size, tbl_vaddr, tbl_size))
        {
            if (num == SIZE_MAX) {
                pr_error("Too many section headers (integer overflow)\n");
                return -1;
            }
            num++;
        }
    }
    if (num == 0) {
        pr_debug("No SHT_RELA sections overlapping the DT_REL(A) table\n");
        return 1;
    }

    arr = calloc(num, sizeof(elf_idx_t));
    if (arr == NULL) {
        pr_error("Failed to allocate the SHT_REL(A) section headers array\n");
        return -1;
    }
    {
        size_t j = 0;
        for (Elf64_Xword i = 0; i < shdrs->num; i++) {
            const Elf64_Shdr *const shdr = &shdrs->arr[i];

            if (shdr->sh_type != sh_type || shdr->sh_size == 0 ||
                (!ranges_overlap(shdr->sh_offset, shdr->sh_size,
                                tbl_off, tbl_size) &&
                 !ranges_overlap(shdr->sh_addr, shdr->sh_size,
                                tbl_vaddr, tbl_size)))
            {
                continue;
            }

            assert(j < num);
            if (validate_sht_relX_shdr(shdrs, i, tbl_vaddr, tbl_off, tbl_size,
                                       arr, j, entsize, sht_dynsym_idx))
            {
                pr_error("Invalid SHT_REL(A) section header\n");
                free(arr); arr = NULL;
                return -1;
            }
            arr[j++] = i;
        }
        assert(j == num);
    }

    *out_arr = arr; arr = NULL;
    *out_num = num;
    return 0;
}

static int validate_sht_relX_shdr(
        const struct elf_shdrs *shdrs, elf_idx_t shdr_idx,
        Elf64_Addr tbl_addr, Elf64_Off tbl_off, Elf64_Xword tbl_size,
        const elf_idx_t *found_shdrs, size_t curr_num_found_shdrs,
        Elf64_Half entsize, elf_idx_t sht_dynsym_idx
)
{
    const Elf64_Shdr *const shdr = &shdrs->arr[shdr_idx];
    int ret = 0;

    /* Check that the SHT_RELA section is fully contained
     * in the DT_RELA table */

    /* The DT_RELA table has already been validated to be fully contained
     * in some PT_LOAD segment, so these additions are safe */
    const Elf64_Addr tbl_end_addr = tbl_addr + tbl_size;
    const Elf64_Off tbl_end_off = tbl_off + tbl_size;

    /* Likewise, all section headers are validated (in `elf-parsing.c`)
     * to not overflow the file or address space bounds */
    const Elf64_Addr section_end_addr = shdr->sh_addr + shdr->sh_size;
    const Elf64_Off section_end_off = shdr->sh_offset + shdr->sh_size;

    if ((shdr->sh_addr < tbl_addr || section_end_addr > tbl_end_addr) ||
        (shdr->sh_offset < tbl_off || section_end_off > tbl_end_off))
    {
        pr_error("SHT_REL(A) section (%" PRIu64 ") not fully contained "
                 "within the DT_REL(A) table bounds\n", shdr_idx);
        ret = 1;
    }

    for (size_t i = 0; i < curr_num_found_shdrs; i++) {
        const elf_idx_t curr_idx = found_shdrs[i];
        const Elf64_Shdr *const curr = &shdrs->arr[curr_idx];

        if (ranges_overlap(curr->sh_offset, curr->sh_size,
                           shdr->sh_offset, shdr->sh_size) ||
            ranges_overlap(curr->sh_addr, curr->sh_size,
                           shdr->sh_addr, shdr->sh_size))
        {
            pr_error("SHT_REL(A) section (%" PRIu64 ") "
                     "overlaps another SHT_REL(A) section (%" PRIu64 ")\n",
                     shdr_idx, curr_idx);
            ret = 1;
        }
    }

    if (shdr->sh_entsize != entsize) {
        pr_error("Invalid SHT_REL(A) entsize\n");
        ret = 1;
    }
    if (shdr->sh_size % entsize != 0) {
        pr_error("SHT_REL(A) sh_size is not divisible "
                 "by the value of DT_REL(A)ENT\n");
        ret = 1;
    }

    if (sht_dynsym_idx == ELF_IDX_NULL) {
        pr_error("SHT_REL(A) exists without a SHT_DYNSYM\n");
        ret = 1;
    } else if (shdr->sh_link != sht_dynsym_idx) {
        pr_error("SHT_REL(A) sh_link doesn't reference the SHT_DYNSYM shdr\n");
        ret = 1;
    }

    /* The SHT_RELA `sh_info` field should point to
     * "the section to which the relocations apply",
     * or `0` in some cases on some platforms. */
    if (shdr->sh_info >= shdrs->num) {
        pr_error("Invalid SHT_REL(A) sh_info section reference\n");
        ret = 1;
    }

    return ret;
}

static int parse_dt_rel(
        const ElfFileData *data,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, Elf64_Word *max_symidx_p,
        struct elf_reloc_rel *out
)
{
    *out = empty_reloc_rel_st;
    struct elf_reloc_rel rel = empty_reloc_rel_st;
    elf_idx_t sht_dynsym_idx = ELF_IDX_NULL;

    const int r = find_rel(entries, data->clazz, phdrs, &rel);
    /* Safe to just `return` because neither `rel.arr` nor `rel.shdrs`
     * have been allocated yet */
    if (r < 0) {
        pr_error("Invalid REL table information\n");
        return -1;
    } else if (r > 0) {
        /* No REL table present at all */
        return 1;
    }

    if (read_rel_table(data, rel.off, rel.num, &rel.arr, max_symidx_p)) {
        pr_error("Failed to read the REL table\n");
        goto err;
    }

    sht_dynsym_idx = find_unique_shdr_by_type(shdrs, shdr_unique_SHT_DYNSYM);
    if (find_validate_sht_relX_shdrs(shdrs, rel.vaddr, rel.off, rel.size,
                                     sht_dynsym_idx, rel.entsize,
                                     &rel.shdrs, &rel.n_shdrs, SHT_REL))
    {
        pr_error("Invalid SHT_REL section header(s)\n");
        goto err;
    }

    rel.present = true;
    *out = rel; rel = empty_reloc_rel_st;
    return 0;

err:
    if (rel.arr != NULL) {
        free(rel.arr);
        rel.arr = NULL;
    }
    if (rel.shdrs != NULL) {
        free(rel.shdrs);
        rel.shdrs = NULL;
    }
    return -1;
}

static int find_rel(const struct elf_dyn_entries *entries, int clazz,
                    const struct elf_phdrs *phdrs, struct elf_reloc_rel *out)
{
    *out = empty_reloc_rel_st;

    enum { DT_REL_IDX = 0, DT_RELSZ_IDX = 1, DT_RELENT_IDX = 2 };
    elf_idx_t rel_idxs[3] = { ELF_IDX_NULL, ELF_IDX_NULL, ELF_IDX_NULL };
    int r = find_unique_dyn_entries(entries, 3,
                (Elf64_Sxword[]) { DT_REL, DT_RELSZ, DT_RELENT }, rel_idxs);
    if (r < 0) {
        pr_error("Invalid combination of the DT_REL* entries\n");
        return -1;
    } else if (r > 0) {
        pr_debug("No dynamic REL table\n");
        return 1;
    }

    const Elf64_Addr vaddr = entries->arr[rel_idxs[DT_REL_IDX]].d_un.d_ptr;
    const Elf64_Xword size = entries->arr[rel_idxs[DT_RELSZ_IDX]].d_un.d_val;
    const Elf64_Xword entsize =
        entries->arr[rel_idxs[DT_RELENT_IDX]].d_un.d_val;

    if (!(clazz == ELFCLASS32 && entsize == sizeof(Elf32_Rel)) &&
        !(clazz == ELFCLASS64 && entsize == sizeof(Elf64_Rel)))
    {
        pr_error("Invalid ElfXX_Rel entsize\n");
        return -1;
    }

    if (size % entsize != 0) {
        pr_error("REL table size (%" PRIu64 ") is not divisible by "
                 "a REL entry size (%" PRIu64 ")\n", size, entsize);
        return -1;
    } else if (size == 0) {
        pr_error("Zero-size REL table\n");
        return -1;
    }
    const Elf64_Xword n_ents = size / entsize;
    if (n_ents > SIZE_MAX) {
        pr_error("Count of REL entries overflows size_t\n");
        return -1;
    }

    Elf64_Off off = 0;
    if (find_ptload_and_off_from_vaddr(vaddr, size, phdrs, &off, NULL)) {
        pr_error("REL table not contained in any single PT_LOAD segment\n");
        return -1;
    }

    Elf64_Xword relcount = 0;
    elf_idx_t dt_relcount_idx = ELF_IDX_NULL;
    r = find_unique_dyn_entry(entries, DT_RELCOUNT, &dt_relcount_idx);
    if (r < 0) {
        pr_error("Duplicate DT_RELCOUNT tag\n");
        return -1;
    } else if (r == 0) {
        relcount = entries->arr[dt_relcount_idx].d_un.d_val;
        if (relcount > n_ents) {
            pr_error("DT_RELCOUNT value too large\n");
            return -1;
        }
    }

    /* `present` flag set later, only after successful parsing */

    out->vaddr = vaddr;
    out->off = off;
    out->size = size;
    out->entsize = (Elf64_Half)entsize;

    out->arr = NULL;
    out->num = (size_t)n_ents;

    out->dt_rel_idx = rel_idxs[DT_REL_IDX];
    out->dt_relsz_idx = rel_idxs[DT_RELSZ_IDX];
    out->dt_relent_idx = rel_idxs[DT_RELENT_IDX];

    if (r == 0) {
        out->dt_relcount_idx = dt_relcount_idx;
        out->relcount = relcount;
    }

    out->n_shdrs = 0;
    out->shdrs = NULL;

    return 0;
}

static int parse_dt_rela(
        const ElfFileData *data,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, Elf64_Word *max_symidx_p,
        struct elf_reloc_rela *out
)
{
    *out = empty_reloc_rela_st;
    struct elf_reloc_rela rela = empty_reloc_rela_st;
    elf_idx_t sht_dynsym_idx = ELF_IDX_NULL;

    const int r = find_rela(entries, data->clazz, phdrs, &rela);
    /* Safe to just `return` because neither `rela.arr` nor `rela.shdrs`
     * have been allocated yet */
    if (r < 0) {
        pr_error("Invalid RELA table information\n");
        return -1;
    } else if (r > 0) {
        /* No RELA table present at all */
        return 1;
    }

    if (read_rela_table(data, rela.off, rela.num, &rela.arr, max_symidx_p)) {
        pr_error("Failed to read the RELA table\n");
        goto err;
    }

    sht_dynsym_idx = find_unique_shdr_by_type(shdrs, shdr_unique_SHT_DYNSYM);
    if (find_validate_sht_relX_shdrs(shdrs, rela.vaddr, rela.off, rela.size,
                                     sht_dynsym_idx, rela.entsize,
                                     &rela.shdrs, &rela.n_shdrs, SHT_RELA))
    {
        pr_error("Invalid SHT_RELA section header(s)\n");
        goto err;
    }

    rela.present = true;
    *out = rela; rela = empty_reloc_rela_st;
    return 0;

err:
    if (rela.arr != NULL) {
        free(rela.arr);
        rela.arr = NULL;
    }
    if (rela.shdrs != NULL) {
        free(rela.shdrs);
        rela.shdrs = NULL;
    }
    return -1;
}

static int find_rela(const struct elf_dyn_entries *entries, int clazz,
                     const struct elf_phdrs *phdrs, struct elf_reloc_rela *out)
{
    *out = empty_reloc_rela_st;

    enum { DT_RELA_IDX = 0, DT_RELASZ_IDX = 1, DT_RELAENT_IDX = 2 };
    elf_idx_t rela_idxs[3] = { ELF_IDX_NULL, ELF_IDX_NULL, ELF_IDX_NULL };
    int r = find_unique_dyn_entries(entries, 3,
                (Elf64_Sxword[]) { DT_RELA, DT_RELASZ, DT_RELAENT }, rela_idxs);
    if (r < 0) {
        pr_error("Invalid combination of the DT_RELA* entries\n");
        return -1;
    } else if (r > 0) {
        pr_debug("No dynamic RELA table\n");
        return 1;
    }

    const Elf64_Addr vaddr = entries->arr[rela_idxs[DT_RELA_IDX]].d_un.d_ptr;
    const Elf64_Xword size = entries->arr[rela_idxs[DT_RELASZ_IDX]].d_un.d_val;
    const Elf64_Xword entsize =
        entries->arr[rela_idxs[DT_RELAENT_IDX]].d_un.d_val;

    if (!(clazz == ELFCLASS32 && entsize == sizeof(Elf32_Rela)) &&
        !(clazz == ELFCLASS64 && entsize == sizeof(Elf64_Rela)))
    {
        pr_error("Invalid ElfXX_Rela entsize\n");
        return -1;
    }

    if (size % entsize != 0) {
        pr_error("RELA table size (%" PRIu64 ") is not divisible by "
                 "a RELA entry size (%" PRIu64 ")\n", size, entsize);
        return -1;
    } else if (size == 0) {
        pr_error("Zero-size RELA table\n");
        return -1;
    }
    const Elf64_Xword n_ents = size / entsize;
    if (n_ents > SIZE_MAX || size > SIZE_MAX) {
        pr_error("RELA entry count too large (integer overflow)\n");
        return -1;
    }

    Elf64_Off off = 0;
    if (find_ptload_and_off_from_vaddr(vaddr, size, phdrs, &off, NULL)) {
        pr_error("RELA table not contained in any single PT_LOAD segment\n");
        return -1;
    }

    Elf64_Xword relacount = 0;
    elf_idx_t dt_relacount_idx = ELF_IDX_NULL;
    r = find_unique_dyn_entry(entries, DT_RELACOUNT, &dt_relacount_idx);
    if (r < 0) {
        pr_error("Duplicate DT_RELACOUNT tag\n");
        return -1;
    } else if (r == 0) {
        relacount = entries->arr[dt_relacount_idx].d_un.d_val;
        if (relacount > n_ents) {
            pr_error("DT_RELACOUNT value too large\n");
            return -1;
        }
    }

    /* `present` flag set later, only after successful parsing */

    out->vaddr = vaddr;
    out->off = off;
    out->size = size;
    out->entsize = (Elf64_Half)entsize;

    out->arr = NULL;
    out->num = (size_t)n_ents;

    out->dt_rela_idx = rela_idxs[DT_RELA_IDX];
    out->dt_relasz_idx = rela_idxs[DT_RELASZ_IDX];
    out->dt_relaent_idx = rela_idxs[DT_RELAENT_IDX];

    if (r == 0) {
        out->dt_relacount_idx = dt_relacount_idx;
        out->relacount = relacount;
    }

    out->n_shdrs = 0;
    out->shdrs = NULL;

    return 0;
}
