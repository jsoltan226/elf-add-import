#include "elf-dyn-parsing.h"
#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include "elf-dyn-sym-parsing.h"
#include <assert.h>
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

int parse_dyn(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,

        struct elf_dynamic *out,
        Elf64_Half *out_dynentsize, Elf64_Half *out_dynsymentsize
)
{
    if (data == NULL || phdrs == NULL || shdrs == NULL) {
        pr_error("%s: Invalid parameters!\n", __func__);
        return -1;
    }

    struct elf_dynamic dyn = { 0 };
    dyn.phdr = ELF_IDX_NULL;
    dyn.shdr = ELF_IDX_NULL;
    dyn.strtab.shdr = ELF_IDX_NULL;
    dyn.hash.dyn_entry = ELF_IDX_NULL; dyn.hash.shdr = ELF_IDX_NULL;
    dyn.gnu_hash.dyn_entry = ELF_IDX_NULL; dyn.gnu_hash.shdr = ELF_IDX_NULL;
    dyn.symtab_shndx.dyn_entry = dyn.symtab_shndx.shdr = ELF_IDX_NULL;
    dyn.symtab.dt_symtab = dyn.symtab.dt_syment = ELF_IDX_NULL;
    dyn.symtab.shdr = ELF_IDX_NULL;
    if (out != NULL) *out = dyn;
    if (out_dynentsize != NULL) *out_dynentsize = 0;
    if (out_dynsymentsize != NULL) *out_dynsymentsize = 0;
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

    /* Parse the dynamic symbol table (.dynsym),
     * along with the named symbol lookup table(s) `DT(GNU_)HASH` */
    if (parse_dynsym(data, clazz, encoding,
                     phdrs, shdrs, &dyn.entries, &dyn.strtab,
                     &dyn.hash, &dyn.gnu_hash, &dyn.symtab_shndx, &dyn.symtab))
    {
        pr_error("Failed to parse the dynamic symbol table and related data\n");
        goto err;
    }

    ret = 0;

err:
    if (ret || out == NULL) {
        if (dyn.entries.arr != NULL)
            free(dyn.entries.arr);

        if (dyn.hash.buckets != NULL)
            free(dyn.hash.buckets);
        if (dyn.hash.chain != NULL)
            free(dyn.hash.chain);

        if (dyn.gnu_hash.bloom != NULL)
            free(dyn.gnu_hash.bloom);
        if (dyn.gnu_hash.buckets != NULL)
            free(dyn.gnu_hash.buckets);
        if (dyn.gnu_hash.chain != NULL)
            free(dyn.gnu_hash.chain);

        if (dyn.symtab_shndx.arr != NULL)
            free(dyn.symtab_shndx.arr);

        if (dyn.symtab.syms != NULL)
            free(dyn.symtab.syms);
    } else if (!ret && out != NULL) {
        *out = dyn;
    }

    if (!ret && out_dynentsize != NULL)
        *out_dynentsize = entsize;
    if (!ret && out_dynsymentsize != NULL)
        *out_dynsymentsize = dyn.symtab.entsize;

    memset(&dyn, 0, sizeof(struct elf_dynamic));

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

    Elf64_Off mapped_off = 0;

    if (find_ptload_and_off_from_vaddr(
                pt_dynamic->p_vaddr, pt_dynamic->p_filesz, phdrs,
                &mapped_off, NULL
        ) || mapped_off != pt_dynamic->p_offset)
    {
        pr_error("PT_DYNAMIC does not match its PT_LOAD file mapping\n");
        return 1;
    }

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
    elf_idx_t sht_dynamic_idx =
        find_unique_shdr_by_type(shdrs, shdr_unique_SHT_DYNAMIC);
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
    *out = (struct elf_dyn_entries) { 0 };

    if (pt_dynamic_idx == ELF_IDX_NULL) {
        pr_error("Invalid PT_DYNAMIC program header index\n");
        return 1;
    }
    const Elf64_Phdr *const pt_dynamic = &phdrs->arr[pt_dynamic_idx];

    if (dynnum == 0) {
        pr_error("Number of dynamic entries is 0!\n");
        return 1;
    }
    /* `dynnum <= SIZE_MAX` checked by `find_validate_pt_dynamic` */
    Elf64_Dyn *arr = calloc((size_t)dynnum, sizeof(Elf64_Dyn));
    if (arr == NULL) {
        pr_error("Failed to allocate the dynamic entries array\n");
        return 1;
    }
    {
        Elf64_Off off = pt_dynamic->p_offset;
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

    /* Deduce the strtab's file offset from the PT_LOAD segment header */
    Elf64_Off strtab_off = 0;
    {
        elf_idx_t tmp_ptload_idx = ELF_IDX_NULL;
        if (find_ptload_and_off_from_vaddr(strtab_addr, strtab_size,
                                           phdrs, &strtab_off, &tmp_ptload_idx)
            || tmp_ptload_idx != strtab_ptload_idx)
        {
            pr_error("Dynamic string table not file-backed "
                     "by its PT_LOAD segment\n");
            return 1;
        }
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

        const bool vaddr_overlap = curr->sh_flags & SHF_ALLOC &&
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

static int validate_sht_gnu_verdef_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword min_size, Elf64_Xword num,
        elf_idx_t *out
)
{
    *out = ELF_IDX_NULL;

    const elf_idx_t shdr_idx =
        find_unique_shdr_by_type(shdrs, shdr_unique_SHT_GNU_verdef);
    if (shdr_idx == ELF_IDX_NULL) {
        pr_debug("No SHT_GNU_verdef section\n");
        return 0;
    }
    const Elf64_Shdr *const shdr = &shdrs->arr[shdr_idx];

    if (dynstr_idx == ELF_IDX_NULL) {
        pr_error("SHT_GNU_verdef exists without a dynstr section\n");
        return 1;
    }

    int ret = 0;

    if (shdr->sh_addr != vaddr) {
        pr_error("Invalid SHT_GNU_verdef virtual address\n");
        ret = 1;
    }

    if (shdr->sh_offset != off) {
        pr_error("Invalid SHT_GNU_verdef offset\n");
        ret = 1;
    }

    if (shdr->sh_size < min_size) {
        pr_error("Invalid SHT_GNU_verdef size\n");
        ret = 1;
    }

    if (shdr->sh_info != num) {
        pr_error("Invalid value of SHT_GNU_verdef sh_info\n");
        ret = 1;
    }

    if (shdr->sh_link != dynstr_idx) {
        pr_error("SHT_GNU_verdef sh_link doesn't point "
                 "to the dynstr section\n");
        ret = 1;
    }

    if (shdr->sh_entsize != sizeof(Elf64_Verdef)) {
        pr_error("Invalid SHT_GNU_verdef entsize\n");
        ret = 1;
    }

    *out = shdr_idx;
    return ret;
}

static_assert(sizeof(Elf64_Verdef) == sizeof(Elf32_Verdef),
              "sizeof(ElfXX_Verdef) must be the same for both classes");
#define VERDEF_ENTSIZE (sizeof(Elf64_Verdef))

static_assert(sizeof(Elf64_Verdaux) == sizeof(Elf32_Verdaux),
              "sizeof(ElfXX_Verdaux) must be the same for both classes");
#define VERDAUX_ENTSIZE (sizeof(Elf64_Verdaux))

static __attribute__((unused)) int read_verdef_entries(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        Elf64_Off start_off, size_t num,
        Elf64_Verdef **out, Elf64_Verdaux ***out_aux_lists,
        Elf64_Xword *out_size
)
{
    *out = NULL;
    *out_aux_lists = NULL;
    *out_size = 0;
    Elf64_Verdef *defs = NULL;
    Elf64_Verdaux **aux_lists = NULL;
    Elf64_Off max_end = 0;
    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];
    const Elf64_Off ptload_end = ptload->p_offset + ptload->p_filesz;

    defs = calloc(num, VERDEF_ENTSIZE);
    if (defs == NULL) {
        pr_error("Failed to allocate the verdef entries array\n");
        goto err;
    }
    aux_lists = calloc(num, sizeof(Elf64_Verdaux *));
    if (aux_lists == NULL) {
        pr_error("Failed to allocate the verdef auxiliary entry lists array\n");
        goto err;
    }

    {
        Elf64_Xword i = 0;
        Elf64_Off off = start_off;
        while (i < num) {
            if (off > ptload_end || ptload_end - off < VERDEF_ENTSIZE) {
                pr_error("verdef entry no %" PRIu64 " would overflow "
                         "the PT_LOAD segment\n", i);
                goto err;
            }
            if (read_verdef(data, &off, clazz, encoding, &defs[i])) {
                pr_error("Failed to read verdef entry no %" PRIu64 "\n", i);
                goto err;
            }
            if (off > max_end)
                max_end = off;

            aux_lists[i] = NULL;

            const Elf64_Verdef *const curr = &defs[i];
            if (curr->vd_version != VER_DEF_CURRENT) {
                pr_error("Verdef entry no %" PRIu64 ": invalid version\n", i);
                goto err;
            }

            if (curr->vd_ndx) {
            }
        }
    }

err:
    if (defs != NULL) {
        free(defs);
        defs = NULL;
    }
    if (aux_lists != NULL) {
        free(aux_lists);
        aux_lists = NULL;
    }

    return 1;
}

static int parse_verdef(const struct elf_phdrs *phdrs,
                        const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
                        const struct elf_dyn_entries *entries,
                        elf_idx_t dt_verdef_idx, elf_idx_t dt_verdefnum_idx,
                        const struct blob *data, int clazz, int encoding)
{
    const Elf64_Addr vaddr = entries->arr[dt_verdef_idx].d_un.d_ptr;
    const Elf64_Xword num = entries->arr[dt_verdefnum_idx].d_un.d_val;

    Elf64_Xword min_tbl_size = 0;
    elf_idx_t ptload = ELF_IDX_NULL;
    Elf64_Off tbl_off = 0;
    Elf64_Verdef *arr = NULL;
    elf_idx_t sht_gnu_verdef_idx = ELF_IDX_NULL;

    if (num > UINT64_MAX / VERDEF_ENTSIZE || num > SIZE_MAX) {
        pr_error("Number of verdef entries too large (integer overflow)\n");
        goto err;
    }
    min_tbl_size = num * VERDEF_ENTSIZE;

    if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                       &tbl_off, &ptload))
    {
        pr_error("Verdef table not contained in any PT_LOAD segment\n");
        goto err;
    }

    arr = calloc((size_t)num, sizeof(Elf64_Verdef));
    if (arr == NULL) {
        pr_error("Failed to allocate the verdef structs array\n");
        goto err;
    }
    {
        uint64_t off = tbl_off;
        for (Elf64_Xword i = 0; i < num; i++) {
            if (read_verdef(data, &off, clazz, encoding, &arr[i])) {
                pr_error("Failed to read version definition entry "
                         "no %" PRIu64 "\n", i);
                goto err;
            }

            if (arr[i].vd_version != VER_DEF_CURRENT) {
                pr_error("Invalid struct version of "
                         "verdef entry no %" PRIu64 "\n", i);
                goto err;
            }

        }
    }

    if (validate_sht_gnu_verdef_if_exists(shdrs, dynstr_idx, vaddr, tbl_off,
                                          min_tbl_size, num,
                                          &sht_gnu_verdef_idx))
    {
        pr_error("Invalid SHT_GNU_verdef section\n");
        goto err;
    }

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }

    return 1;
}

static __attribute__((unused))
int parse_ver(const struct elf_phdrs *phdrs,
              const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
              const struct elf_dyn_entries *entries,
              const struct blob *data, int clazz, int encoding)
{
    int r = 0;
    elf_idx_t dt_versym_idx = ELF_IDX_NULL;
    enum { DT_VERDEF_IDX = 0, DT_VERDEFNUM_IDX = 1 };
    elf_idx_t verdef_idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };
    enum { DT_VERNEED_IDX = 0, DT_VERNEEDNUM_IDX = 1 };
    elf_idx_t verneed_idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };

    bool __attribute__((unused)) versym_present = false,
         verdef_present = false,
         verneed_present = false;

    r = find_unique_dyn_entry(entries, DT_VERSYM, &dt_versym_idx);
    if (r < 0) {
        pr_error("Duplicate DT_VERSYM entry\n");
        goto err;
    }
    versym_present = r == 0;

    r = find_unique_dyn_entries(entries, 2,
            (Elf64_Sxword[]) { DT_VERDEF, DT_VERDEFNUM }, verdef_idxs);
    if (r < 0) {
        pr_error("Duplicate and/or missing DT_VERDEF and/or DT_VERDEFNUM "
                 "entries");
        goto err;
    }
    verdef_present = r == 0;

    r = find_unique_dyn_entries(entries, 2,
            (Elf64_Sxword[]) { DT_VERNEED, DT_VERNEEDNUM }, verneed_idxs);
    if (r < 0) {
        pr_error("Duplicate and/or missing DT_VERNEED and/or DT_VERNEEDNUM "
                 "entries");
        goto err;
    }
    verneed_present = r == 0;

    if (verdef_present) {
        if (parse_verdef(phdrs, shdrs, dynstr_idx, entries,
                    verdef_idxs[DT_VERDEF_IDX], verdef_idxs[DT_VERDEFNUM_IDX],
                    data, clazz, encoding))
        {
            pr_error("Failed to parse symbol version definition information\n");
            goto err;
        }
    }

err:
    return 1;
}
