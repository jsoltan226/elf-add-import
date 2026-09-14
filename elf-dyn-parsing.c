#include "elf-dyn-parsing.h"
#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static int find_unique_dyn_entries(
        const struct elf_dyn_entries *entries, size_t count,
        const Elf64_Sxword tags[static count], elf_idx_t out[static count]
);

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
 * @param[in] shdrs The section header array. Must not be NULL.
 *
 * @param[in] phdrs The program header array. Must not be NULL.
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

        struct elf_dynamic *out, Elf64_Half *out_dynentsize
)
{
    if (data == NULL || phdrs == NULL || shdrs == NULL) {
        pr_error("%s: Invalid parameters!\n", __func__);
        return -1;
    }

    if (out != NULL)
        memset(out, 0, sizeof(struct elf_dynamic));
    if (out_dynentsize != NULL)
        *out_dynentsize = 0;

    const Elf64_Half entsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);
    *out_dynentsize = entsize;

    /* Find and validate the PT_DYNAMIC program header */
    Elf64_Xword dynnum = 0;
    if (find_validate_pt_dynamic(phdrs, entsize, &out->phdr, &dynnum)) {
        pr_error("Missing or invalid PT_DYNAMIC program header\n");
        goto err;
    }

    /* If present, validate the section header against the program header */
    if (validate_sht_dynamic_if_exists(shdrs, phdrs, out->phdr, entsize,
                                       &out->shdr))
    {
        pr_error("Invalid SHT_DYNAMIC .dynamic section header\n");
        goto err;
    }

    /* Parse the ElfXX_Dyn entries */
    if (parse_dyn_table(data, clazz, encoding, dynnum, phdrs, out->phdr,
                        &out->entries))
    {
        pr_error("Failed to parse the dynamic entry array\n");
        goto err;
    }
    pr_debug("Number of dynamic entries: %" PRIu64 "\n", dynnum);

    if (parse_dynstr(data, &out->entries, phdrs, shdrs, &out->strtab)) {
        pr_error("Invalid or missing .dynstr dynamic string table\n");
        goto err;
    }
    if (out->shdr != ELF_IDX_NULL) {
        /* .dynamic's `sh_link` must point to .dynstr */
        if (shdrs->arr[out->shdr].sh_link != out->strtab.shdr) {
            pr_error("SHT_DYNAMIC's sh_link doesn't point to .dynstr\n");
            goto err;
        }
    }

    return 0;

err:
    if (out->entries.arr != NULL)
        free(out->entries.arr);
    memset(out, 0, sizeof(struct elf_dynamic));
    *out_dynentsize = 0;
    return 1;
}

static int find_unique_dyn_entries(
        const struct elf_dyn_entries *entries, size_t count,
        const Elf64_Sxword tags[static count], elf_idx_t out[static count]
)
{
    int ret = 0;

    for (size_t i = 0; i < count; i++)
        out[i] = ELF_IDX_NULL;

    for (Elf64_Xword i = 0; i < entries->num; i++) {
        const Elf64_Sxword t = entries->arr[i].d_tag;
        for (size_t j = 0; j < count; j++) {
            if (t == tags[j]) {
                if (out[j] != ELF_IDX_NULL) {
                    pr_error("Duplicate dynamic entry %" PRIi64 " (%s)\n",
                             t, dynamic_tag_to_string(t));
                    ret = 1;
                }
                out[j] = i;
                break;
            }
        }
    }

    for (size_t i = 0; i < count; i++) {
        if (out[i] == ELF_IDX_NULL) {
            pr_error("Missing dynamic entry %" PRIi64 " (%s)\n",
                     tags[i], dynamic_tag_to_string(tags[i]));
            ret = 1;
        }
    }

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

#if 0
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


    /*
    pr_debug("Value of DT_SYMENT for class %s: %" PRIu64 "\n",
             clazz == ELFCLASS32 ? "ELFCLASS32" : "ELFCLASS64",
             dt_syment->d_un.d_val);
             */

    return 0;
}
#endif /* 0 */
