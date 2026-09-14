#include "elf-parsing.h"
#include "elf.h"
#include "ctx.h"
#include "util.h"
#include "elf-types.h"
#include "elf-dyn-parsing.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/**
 * Parses and validates the ELF ident bytes.
 * Part of `read_elf`; called before `read_validate_ehdr`
 * to determine the ELF's class and data encoding.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 if the ELF ident bytes have sensible and supported values,
 *  non-zero on failure.
 */
static int read_validate_ident(const struct blob *data, struct elf_ident *out);

/**
 * Parses the ELF header to obtain the number of entries and the size
 * of the program header table, validating everything needed along the way.
 * Part of `read_validate_phdrs`.
 *
 * @param[in] ehdr The (valid) ELF header. Must not be NULL.
 *
 * @param[in] first_shdr The initial entry in the section header table.
 *  Cannot be NULL if `ehdr->e_phnum == PN_XNUM`, otherwise ignored.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[out] out_phnum Output pointer for the real number of program headers.
 *  Must not be NULL.
 *
 * @param[out] out_phsize Output pointer for
 *  the size of the program header table. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int parse_phdr_tbl_data_from_ehdr(
        const Elf64_Ehdr *ehdr,
        const Elf64_Shdr *first_shdr, const struct blob *data,
        Elf64_Xword *out_phnum, uint64_t *out_phsize
);

/**
 * Validates the generic (non-phdr-type-specific) information
 * in a program header. Part of `read_validate_phdrs`.
 *
 * @param[in] ehdr The (valid) ELF header. Must not be NULL.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] i The program header's table index.
 *
 * @param[in] off The program header's offset within `data`.
 *
 * @param[in] phdr The program header to validate. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_phdr_generic(
        const Elf64_Ehdr *ehdr, const struct blob *data,
        Elf64_Xword i, uint64_t off,
        const Elf64_Phdr *phdr
);

/**
 * Validates the PT_LOAD-specific information in a PT_LOAD program header.
 * Part of `read_validate_phdrs`.
 *
 * Note: The header's generic information should have been previously checked
 * by `validate_phdr_generic`.
 *
 * What's checked:
 *  - That the PT_LOAD segments appear in ascending order,
 *      sorted by their `p_vaddr` fields,
 *  - That `p_memsz` is not smaller than `p_filesz`,
 *  - That `p_align` is either 0, 1 or a power of two,
 *  - That `p_vaddr` and `p_offset` are congruent modulo `p_align` (if non-zero)
 *      i.e. they are aligned to `p_align`
 *
 * @param[in] phdr The program header to validate.
 *
 * @param[in,out] prev_vaddr_p Non-NULL pointer to a variable storing
 *  the previous PT_LOAD's `p_vaddr` value, used for the ascending order check.
 *  After returning, the value is set to the provided `phdr`'s `p_vaddr`.
 *
 * @param[out] found_p Non-NULL pointer to a boolean `found_pt_load` variable,
 *  used for other PT_* checks. Always set to true by this function.
 *
 * @param[in] i The table index of `phdr`.
 *
 * @param[in] off The offset within the file data of `phdr`.
 *
 * @return 0 if `phdr` is valid, non-zero if any check fails.
 */
static int validate_pt_load_phdr(const Elf64_Phdr *phdr,
                                 uint64_t *prev_vaddr_p, bool *found_p,
                                 Elf64_Xword i, uint64_t off);

/**
 * Validates the PT_DYNAMIC-specific information in a PT_DYNAMIC program header.
 * Part of `read_validate_phdrs`.
 *
 * Note: The header's generic information should have been previously checked
 * by `validate_phdr_generic`.
 *
 * What's checked:
 *  - That there aren't multiple occurences of a `PT_DYNAMIC` segment.
 *
 * @param[in] phdr The program header to validate.
 *
 * @param[out] found_p Non-NULL pointer to a `found_pt_dynamic` variable,
 *  used for the no duplicates check.
 *
 * @param[out] out_pt_dynamic Non-NULL output pointer for this program header,
 *  used for other checks. `phdr` is always copied into it.
 *
 * @param[in] i The table index of `phdr`.
 *
 * @param[in] off The offset within the file data of `phdr`.
 *
 * @return 0 if `phdr` is valid, non-zero if any check fails.
 */
static int validate_pt_dynamic_phdr(const Elf64_Phdr *phdr,
                                    bool *found_p, Elf64_Phdr *out_pt_dynamic,
                                    Elf64_Xword i, uint64_t off);

/**
 * Validates the PT_INTERP-specific information in a PT_INTERP program header.
 * Part of `read_validate_phdrs`.
 *
 * Note: The header's generic information should have been previously checked
 * by `validate_phdr_generic`.
 *
 * What's checked:
 *  - That there aren't multiple occurences of a `PT_INTERP` segment,
 *  - That no `PT_LOAD` segments occur before a `PT_INTERP` segment,
 *  - If `toplevel_ok == true`,
 *      that the pointed-to program interpreter string is valid.
 *
 * If all checks succeed, the program interpreter is printed to stdout.
 *
 * @param[in] phdr The program header to validate.
 *
 * @param[out] found_p Non-NULL pointer to a `found_pt_interp` variable,
 *  used for the no duplicates check.
 *
 * @param[in] found_pt_load Whether a PT_LOAD segment has been previously found.
 *  Used for the 2nd check (no `PT_LOAD` segments can precede a `PT_INTERP`).
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] toplevel_ok Whether the general parsing of the whole
 *  program header table has not encountered any issues up to this point.
 *
 * @param[in] i The table index of `phdr`.
 *
 * @param[in] off The offset within the file data of `phdr`.
 *
 * @return 0 if `phdr` is valid, non-zero if any check fails.
 */
static int validate_pt_interp_phdr(const Elf64_Phdr *phdr,
                                   bool *found_p, bool found_pt_load,
                                   const struct blob *data, bool toplevel_ok,
                                   Elf64_Xword i, uint64_t off);

/**
 * Validates the PT_PHDR-specific information in a PT_PHDR program header.
 * Part of `read_validate_phdrs`.
 *
 * Note: The header's generic information should have been previously checked
 * by `validate_phdr_generic`.
 *
 * What's checked:
 *  - That there aren't multiple occurences of a `PT_PHDR` segment,
 *  - That no `PT_LOAD` segments occur before a `PT_PHDR` segment,
 *  - That the offset and size matches the information in the ELF header.
 *
 * @param[in] phdr The program header to validate.
 *
 * @param[out] found_p Non-NULL pointer to a `found_pt_phdr` variable,
 *  used for the no duplicates check.
 *
 * @param[out] out_pt_phdr Non-NULL output pointer for this program header,
 *  used for other checks. `phdr` is always copied into it.
 *
 * @param[in] found_pt_load Whether a PT_LOAD segment has been previously found.
 *  Used for the 2nd check (no `PT_LOAD` segments can precede a `PT_PHDR`).
 *
 * @param[in] ehdr The (valid) ELF header. Must not be NULL.
 *
 * @param[in] phsize The total size of the program header table.
 *
 * @param[in] i The table index of `phdr`.
 *
 * @param[in] off The offset within the file data of `phdr`.
 *
 * @return 0 if `phdr` is valid, non-zero if any check fails.
 */
static int validate_pt_phdr_phdr(
        const Elf64_Phdr *phdr,
        bool *found_p, Elf64_Phdr *out_pt_phdr,
        bool found_pt_load, const Elf64_Ehdr *ehdr, Elf64_Xword phsize,
        Elf64_Xword i, uint64_t off
);

/**
 * Parses the ELF header to obtain the number of entries and the size
 * of the section header table, validating everything needed along the way.
 * Part of `read_validate_shdrs`.
 *
 * @param[in] ehdr The (valid) ELF header. Must not be NULL.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding Data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[out] out_shnum Output pointer for the real number of section headers.
 *  Must not be NULL.
 *
 * @param[out] out_shsize Output pointer for
 *  the size of the section header table. Must not be NULL.
 *
 * @param[out] out_shstrndx Output pointer for the section name string table
 *  section header index (shstrndx). Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int parse_shdr_tbl_data_from_ehdr(
        const Elf64_Ehdr *ehdr,
        const struct blob *data, int clazz, int encoding,
        Elf64_Xword *out_shnum, uint64_t *out_shsize, Elf64_Xword *out_shstrndx
);

/**
 * Reads and validates the shstrtab section. Part of `read_validate_shdrs`.
 *
 * Note: The shstrtab must exist, i.e. (`ehdr->e_shstrndx != SHN_UNDEF`).
 *
 * @param[in] ehdr The (valid) ELF header. Must not be NULL.
 *
 * @param[in] shnum The real number of section headers,
 *  parsed and validated by `parse_shdr_tbl_data_from_ehdr`.
 *
 * @param[in] shstrndx The real shstrtab section index,
 *  parsed and validated by `parse_shdr_tbl_data_from_ehdr`.
 *
 * @param[in] data The ELF file data to read from. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding Data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_validate_shstrtab_shdr(
        const Elf64_Ehdr *ehdr, Elf64_Xword shnum, Elf64_Word shstrndx,
        const struct blob *data, int clazz, int encoding,
        Elf64_Shdr *out
);

/**
 * Validates the generic (non-shdr-type-specific) information
 * in a section header. Part of `read_validate_shdrs`.
 *
 * @param[in] ehdr The (valid) ELF header. Must not be NULL.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] i The section header's table index.
 *
 * @param[in] off The section header's offset within `data`.
 *
 * @param[in] shstrtab The shstrtab section header or NULL if not present.
 *
 * @param[in] shdr The section header to validate. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_shdr(
        const Elf64_Ehdr *ehdr, const struct blob *data,
        Elf64_Xword i, uint64_t off, const Elf64_Shdr *shstrtab,
        const Elf64_Shdr *shdr
);

int read_validate_ehdr(const struct blob *data, int clazz, int encoding,
                       Elf64_Ehdr *out)
{
    if ((clazz == ELFCLASS32 && data->size < sizeof(Elf32_Ehdr)) ||
        (clazz == ELFCLASS64 && data->size < sizeof(Elf64_Ehdr)))
    {
        pr_error("File too small to be an ELF file\n");
        return 1;
    }

    uint64_t off = UINT64_C(0);
    memcpy(&out->e_ident, data->data, EI_NIDENT);
    off += EI_NIDENT;

    if (read_Half(data, &off, clazz, encoding, &out->e_type) ||
        read_Half(data, &off, clazz, encoding, &out->e_machine) ||
        read_Word(data, &off, clazz, encoding, &out->e_version) ||
        read_Addr(data, &off, clazz, encoding, &out->e_entry) ||
        read_Off(data, &off, clazz, encoding, &out->e_phoff) ||
        read_Off(data, &off, clazz, encoding, &out->e_shoff) ||
        read_Word(data, &off, clazz, encoding, &out->e_flags) ||
        read_Half(data, &off, clazz, encoding, &out->e_ehsize) ||
        read_Half(data, &off, clazz, encoding, &out->e_phentsize) ||
        read_Half(data, &off, clazz, encoding, &out->e_phnum) ||
        read_Half(data, &off, clazz, encoding, &out->e_shentsize) ||
        read_Half(data, &off, clazz, encoding, &out->e_shnum) ||
        read_Half(data, &off, clazz, encoding, &out->e_shstrndx))
    {
        return 1;
    }

    int ret = 0;

    pr_debug("ELF type: 0x%" PRIx16 " (%s)\n",
            out->e_type, elf_type_toString(out->e_type));
    if (out->e_type != ET_DYN) {
        pr_error("Unsupported ELF type 0x%" PRIx16 " (%s); must be ET_DYN "
                "(Dynamic executable or shared library)\n",
                out->e_type, elf_type_toString(out->e_type));
        ret = 1;
    }

    pr_debug("ELF version: 0x%" PRIx32 "\n", out->e_version);
    if (out->e_version != EV_CURRENT) {
        pr_error("Invalid ELF version (must be 1)\n");
        ret = 1;
    }

    pr_debug("Entry point: 0x%" PRIx64 "\n", out->e_entry);
    pr_debug("Program headers offset: 0x%" PRIx64 "\n", out->e_phoff);
    if (out->e_phoff == 0) {
        pr_error("No program headers!\n");
        ret = 1;
    }
    pr_debug("Section headers offset: 0x%" PRIx64 "\n", out->e_shoff);
    pr_debug("Flags: 0x%" PRIx32 "\n", out->e_flags);

    pr_debug("ELF header size: 0x%" PRIx16 "\n", out->e_ehsize);
    if ((clazz == ELFCLASS32 && out->e_ehsize != sizeof(Elf32_Ehdr)) ||
        (clazz == ELFCLASS64 && out->e_ehsize != sizeof(Elf64_Ehdr)))
    {
        pr_error("Invalid ELF header size\n");
        ret = 1;
    }

    pr_debug("Program header size: 0x%" PRIx16 "\n", out->e_phentsize);
    if ((clazz == ELFCLASS32 && out->e_phentsize != sizeof(Elf32_Phdr)) ||
        (clazz == ELFCLASS64 && out->e_phentsize != sizeof(Elf64_Phdr)))
    {
        pr_error("Invalid program header size\n");
        ret = 1;
    }

    pr_debug("Number of program headers: %" PRIu16 "\n", out->e_phnum);
    if (out->e_phnum >= PN_XNUM) {
        if (out->e_shoff == 0 /* || out->e_shnum < 1 */) {
            pr_error("Section headers required for PN_XNUM (2^16 - 1) "
                    "or more program headers\n");
            ret = 1;
        }
    }

    pr_debug("Section header size: 0x%" PRIx16 "\n", out->e_shentsize);
    if ((clazz == ELFCLASS32 && out->e_shentsize != sizeof(Elf32_Shdr)) ||
        (clazz == ELFCLASS64 && out->e_shentsize != sizeof(Elf64_Shdr)))
    {
        pr_error("Invalid section header size\n");
        ret = 1;
    }

    pr_debug("Number of section headers: %" PRIu16 "\n", out->e_shnum);
    if (out->e_shnum >= SHN_LORESERVE) {
        pr_error("Invalid section header count\n");
        ret = 1;
    }
    /* if the number of section headers is >= SHN_LORESERVE,
     * `e_shnum` holds the value zero and the real number of section headers
     * is stored in the `sh_size` member of the first section header.
     *
     * However, since this special case involves parsing the section headers,
     * we leave that out of the scope of this routine
     * (specifically, this is handled in `parse_shdr_tbl_data_from_ehdr`
     *  in `read_validate_shdrs`).
     */

    pr_debug("Section header string table index: 0x%" PRIx16 "\n",
            out->e_shstrndx);
    if (out->e_shnum != 0 && out->e_shstrndx >= out->e_shnum) {
        pr_error("Section header string table index out of bounds\n");
        ret = 1;
    } else if (out->e_shoff == 0 && out->e_shstrndx != 0) {
        pr_error("Section header string table index non-zero "
                "when section headers aren't present\n");
        ret = 1;
    }
    if (out->e_shstrndx >= SHN_LORESERVE &&
        out->e_shstrndx != SHN_XINDEX)
    {
        pr_error("Invalid section header string table index\n");
        ret = 1;
    }

    return ret;
}

int read_validate_phdrs(const struct blob *data, struct elf_phdrs *out,
                        const Elf64_Ehdr *ehdr, const struct elf_shdrs *shdrs,
                        int clazz, int encoding)
{
    out->arr = NULL;
    out->num = 0;
    out->size = 0;
    out->dirty = false;

    Elf64_Xword phnum = 0;
    uint64_t phsize = 0;
    const Elf64_Shdr *const first_shdr = shdrs->num > 0 ? &shdrs->arr[0] : NULL;
    if (parse_phdr_tbl_data_from_ehdr(ehdr, first_shdr, data, &phnum, &phsize)) {
        pr_error("Invalid program header table information in ELF header\n");
        return 1;
    }

    Elf64_Phdr *arr = calloc(phnum, sizeof(Elf64_Phdr));
    if (arr == NULL) {
        pr_error("Failed to allocate the program header array\n");
        return 1;
    }
    /* from this point onward, no `return` without freeing `arr` first */
    int ret = 0;

    uint64_t off = ehdr->e_phoff;
    Elf64_Phdr phdr = { 0 };

    /* type-specific context */
    uint64_t prev_pt_load_vaddr = 0;
    bool found_pt_load = false, found_pt_interp = false,
         found_pt_phdr = false, found_pt_dynamic = false;
    Elf64_Phdr pt_phdr = { 0 }, pt_dynamic = { 0 };

    for (Elf64_Xword i = 0; i < phnum; i++) {
        if (read_phdr(data, &off, clazz, encoding, &phdr)) {
            pr_error("Couldn't read program header no %" PRIu64
                     " (offset 0x%" PRIx64 ")\n", i, off);
            ret = 1;
            break;
        }

        if (validate_phdr_generic(ehdr, data, i, off, &phdr)) {
            pr_error("Program header no %" PRIu64 " invalid\n", i);
            ret = 1;
            continue;
        }

        pr_debug("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                 " Header type: 0x%" PRIx32 " (%s)\n",
                 i, off,
                 phdr.p_type, program_header_type_toString(phdr.p_type)
        );

        switch (phdr.p_type) {
        case PT_LOAD:
            if (validate_pt_load_phdr(&phdr, &prev_pt_load_vaddr,
                                      &found_pt_load, i, off))
            {
                ret = 1;
                continue;
            }
            break;
        case PT_DYNAMIC:
            if (validate_pt_dynamic_phdr(&phdr, &found_pt_dynamic,
                                         &pt_dynamic, i, off))
            {
                ret = 1;
                continue;
            }
            break;
        case PT_INTERP:
            if (validate_pt_interp_phdr(&phdr, &found_pt_interp,
                                        found_pt_load, data, ret == 0, i, off))
            {
                ret = 1;
                continue;
            }
            break;
        case PT_PHDR:
            if (validate_pt_phdr_phdr(&phdr, &found_pt_phdr, &pt_phdr,
                                      found_pt_load, ehdr, phsize, i, off))
            {
                ret = 1;
                continue;
            }
            break;
        case PT_SHLIB:
            pr_error("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type PT_SHLIB reserved/unsupported\n", i, off);
            ret = 1;
            continue;

        case PT_NULL:
        case PT_NOTE:
        case PT_TLS:
            break;
        default:
            /* unknown processor- or OS-specific phdr; ignore */
            if (phdr.p_type >= PT_LOOS && phdr.p_type <= PT_HIPROC)
                break;

            pr_error("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                     "Invalid program header type: 0x%" PRIx32 "\n", i, off,
                     phdr.p_type);
            ret = 1;
            continue;
        }

        if (!ret)
            memcpy(&arr[i], &phdr, sizeof(Elf64_Phdr));
    }

    /* Validate that any `PT_PHDR` and `PT_DYNAMIC` segments
     * are inside another `PT_LOAD` segment */
    if (!ret) {
        struct elf_phdrs tmp = { .arr = arr, .num = phnum, .size = phsize };
        if (found_pt_phdr &&
                find_containing_mem_ptload(&tmp,
                        pt_phdr.p_vaddr, pt_phdr.p_memsz) == ELF_IDX_NULL)
        {
            pr_error("PT_PHDR is not contained in any PT_LOAD segment\n");
            ret = 1;
        }
        if (found_pt_dynamic &&
                find_containing_mem_ptload(&tmp,
                    pt_dynamic.p_vaddr, pt_dynamic.p_memsz) == ELF_IDX_NULL)
        {
            pr_error("PT_DYNAMIC is not contained in any PT_LOAD segment\n");
            ret = 1;
        }
        tmp.arr = NULL;
    }

    if (ret) {
        if (arr != NULL) {
            free(arr);
            arr = NULL;
        }
    } else {
        out->arr = arr; arr = NULL;
        out->num = phnum;
        out->size = phsize;
        out->dirty = false;
    }

    return ret;
}

int read_validate_shdrs(const struct blob *data,
                        struct elf_shdrs *out, Elf64_Word *out_shstrndx,
                        const Elf64_Ehdr *ehdr, int clazz, int encoding)
{
    out->arr = NULL;
    out->num = 0;
    out->size = 0;
    out->dirty = false;
    *out_shstrndx = 0;

    Elf64_Xword shnum = 0; /**< Total number of section headers */
    uint64_t shsize = 0; /**< Total size of section headers
                              (ehdr->e_shentsize * shnum) */
    Elf64_Xword shstrndx = 0; /**< Real index of the shstrtab section */
    if (parse_shdr_tbl_data_from_ehdr(ehdr, data, clazz, encoding,
                                      &shnum, &shsize, &shstrndx))
    {
        pr_error("Invalid section header table information in ELF header\n");
        return 1;
    } else if (shnum == 0 || shsize == 0) {
        pr_error("WARNING: The ELF has no section headers!\n");
        return 0;
    }

    Elf64_Shdr shstrtab = { 0 }; /**< Section header of the shstrtab section,
                                  * which contains all sections' name strings */
    if (shstrndx != 0) {
        if (read_validate_shstrtab_shdr(ehdr, shnum, shstrndx,
                                        data, clazz, encoding, &shstrtab))
        {
            pr_error("Invalid shstrtab section header\n");
            return 1;
        }
    }

    Elf64_Shdr *arr = calloc(shnum, sizeof(Elf64_Shdr));
    if (arr == NULL) {
        pr_error("Failed to allocate program section array\n");
        return 1;
    }
    /* from this point onward, no `return` without freeing `arr` first */
    int ret = 0;

    const Elf64_Shdr *const shstrtab_p =
        shstrndx == SHN_UNDEF ? NULL : &shstrtab;

    uint64_t off = ehdr->e_shoff;
    Elf64_Shdr shdr = { 0 };

    for (Elf64_Xword i = 0; i < shnum; i++) {
        if (read_shdr(data, &off, clazz, encoding, &shdr)) {
            pr_error("Couldn't read section header no %" PRIu64
                     " (offset 0x%" PRIx64 ")\n", i, off);
            ret = 1;
            break;
        }

        if (validate_shdr(ehdr, data, i, off, shstrtab_p, &shdr)) {
            pr_error("Section header %" PRIu64 " invalid\n", i);
            ret = 1;
            break;
        }

        if (!ret)
            memcpy(&arr[i], &shdr, sizeof(Elf64_Shdr));
    }

    if (ret) {
        if (arr != NULL) {
            free(arr);
            arr = NULL;
        }
    } else {
        out->arr = arr; arr = NULL;
        out->num = shnum;
        out->size = shsize;
        out->dirty = false;
        *out_shstrndx = shstrndx;
    }

    return ret;
}

int parse_elf(struct blob *data, struct elf *out, bool move)
{
    if (data == NULL || data->data == NULL) {
        pr_error("`data` is NULL\n");
        return -1;
    }

    struct elf e = { 0 };
    memset(&e, 0, sizeof(struct elf));

    if (read_validate_ident(data, &e.ident)) {
        pr_error("Not an ELF file (invalid magic)\n");
        goto err;
    }
    const int c = e.ident.clazz;
    const int d = e.ident.data;

    if (read_validate_ehdr(data, c, d, &e.ehdr)) {
        pr_error("Invalid ELF header\n");
        goto err;
    }

    if (read_validate_shdrs(data, &e.shdrs, &e.shstrndx, &e.ehdr, c, d)) {
        pr_error("Invalid section headers\n");
        goto err;
    }

    if (read_validate_phdrs(data, &e.phdrs, &e.ehdr, &e.shdrs, c, d)) {
        pr_error("Invalid program headers\n");
        goto err;
    }

    if (parse_dyn(data, c, d, &e.phdrs, &e.shdrs, &e.dyn, &e.dynentsize)) {
        pr_error("Invalid or missing dynamic linking information\n");
        goto err;
    }

    if (move) {
        e.data = *data;
        *data = (struct blob) { .data = NULL, .size = 0 };
    } else {
        e.data.size = data->size;
        e.data.data = malloc(data->size);
        if (e.data.data == NULL) {
            pr_error("Failed to allocate a copy of the data\n");
            goto err;
        }
        memcpy(e.data.data, data->data, data->size);
    }

    e.orig.ehdr = e.ehdr;
    e.orig.phnum = e.phdrs.num;
    e.orig.phsize = e.phdrs.size;
    e.orig.shnum = e.shdrs.num;
    e.orig.shsize = e.shdrs.size;
    e.orig.shstrndx = e.shstrndx;
    e.orig.dyn_strtab_off = e.dyn.strtab.off;
    e.orig.dyn_strtab_sz = e.dyn.strtab.size;
    e.orig.dyn_strtab_vaddr = e.dyn.strtab.vaddr;
    e.phentsize = e.ehdr.e_phentsize;
    e.shentsize = e.ehdr.e_shentsize;

    if (out != NULL)
        memcpy(out, &e, sizeof(struct elf));
    else
        destroy_elf(&e);

    printf("Successfully parsed ELF%s-%s data\n",
           (c == ELFCLASS32 ? "32" : "64"),
           (d == ELFDATA2MSB ? "BE" : "LE")
    );
    return 0;

err:
    destroy_elf(&e);
    return 1;
}

int read_elf(const char *path, struct elf *out)
{
    struct blob data = { 0 };
    if (read_file(path, &data)) {
        pr_error("Couldn't read input file \"%s\"\n", path);
        return 1;
    }

    if (parse_elf(&data, out, true)) {
        pr_error("Couldn't parse ELF file \"%s\"\n", path);
        free(data.data);
        data = (struct blob) { 0 };
        return 1;
    }

    data = (struct blob) { 0 };
    return 0;
}

static int read_validate_ident(const struct blob *data, struct elf_ident *out)
{
    if (data->size < EI_NIDENT) {
        pr_error("File too small to be an ELF file\n");
        return -1;
    }
    memcpy(out, data->data, EI_NIDENT);

    int ret = 0;

    if (memcmp(&out->magic, ELFMAG, SELFMAG)) {
        pr_error("Invalid ELF magic!\n");
        ret = 1;
    }

    if (out->version != EV_CURRENT) {
        pr_error("Invalid version: 0x%" PRIx8 "\n",
                out->version);
        ret = 1;
    }

    if (out->clazz != ELFCLASS32 &&
        out->clazz != ELFCLASS64)
    {
        pr_error("Invalid class: 0x%" PRIx8 "\n",
                out->clazz);
        ret = 1;
    } else {
        pr_debug("Class: %s\n",
                out->clazz == ELFCLASS32 ? "ELFCLASS32": "ELFCLASS64");
    }

    if (out->data != ELFDATA2LSB &&
        out->data != ELFDATA2MSB)
    {
        pr_error("Invalid data: 0x%" PRIx8 "\n",
                out->data);
        ret = 1;
    } else {
        pr_debug("Data: 2's complement, %s endian\n",
                out->data == ELFDATA2MSB ? "big": "little");
    }

    /* We don't care about ABIs */
    (void) out->os_abi;
    (void) out->abi_version;

    return ret;
}

static int parse_phdr_tbl_data_from_ehdr(
        const Elf64_Ehdr *ehdr,
        const Elf64_Shdr *first_shdr, const struct blob *data,
        Elf64_Xword *out_phnum, uint64_t *out_phsize
)
{
    *out_phnum = 0;
    *out_phsize = 0;

    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phentsize == 0) {
        pr_error("No program headers!\n");
        return 0;
    }

    /* Get the real value of `phnum` */
    Elf64_Xword phnum = 0;
    if (ehdr->e_phnum >= PN_XNUM) {
        if (first_shdr == NULL) {
            pr_error("No initial section header while `e_phnum == PN_XNUM`");
            return 1;
        }

        phnum = first_shdr->sh_info;
    } else {
        phnum = ehdr->e_phnum;
    }
    /* `ehdr->e_phentsize` is guaranteed to be either
     * `sizeof(Elf32_Phdr)` or `sizeof(Elf64_Phdr)`
     * by `read_validate_ehdr`. */
    if (phnum >= SIZE_MAX / ehdr->e_phentsize ||
        phnum >= UINT64_MAX / ehdr->e_phentsize)
    {
        pr_error("Number of program headers too large "
                "(integer overflow)\n");
        return -1;
    }

    const uint64_t phsize = phnum * ehdr->e_phentsize;
    if (phsize > data->size || data->size - phsize < ehdr->e_phoff) {
        pr_error("Program headers overflow data buffer\n");
        return 1;
    }

    *out_phnum = phnum;
    *out_phsize = phsize;

    if (phnum == 0) {
        pr_error("No program headers!\n");
        return 1;
    }

    return 0;
}

static int validate_phdr_generic(
        const Elf64_Ehdr *ehdr, const struct blob *data,
        Elf64_Xword i, uint64_t off,
        const Elf64_Phdr *phdr
)
{
    /* `(i + 1) * ehdr->e_phentsize` can be at most `phsize`
     * which by previous logic is validated to not overflow `data->size`
     * and in consequence, the uint64 limit. */
    if (off != ehdr->e_phoff + (((uint64_t)i + 1) * ehdr->e_phentsize)) {
        pr_error("Invalid offset 0x%" PRIx64
                 " after reading program header no %" PRIu64
                 " (impossible outcome)\n",
                 off, i);
        fflush(stderr);
        abort();
    }

    int ret = 0;

    if (phdr->p_offset >= data->size ||
        data->size - phdr->p_offset < phdr->p_filesz)
    {
        pr_error("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                 "Segment overflows data buffer\n", i, off);
        ret = 1;
    }

    if (phdr->p_vaddr > UINT64_MAX - phdr->p_memsz) {
        pr_error("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                 "Segment overflows address space\n", i, off);
        ret = 1;
    }

    return ret;
}

static int validate_pt_load_phdr(const Elf64_Phdr *phdr,
                                 uint64_t *prev_vaddr_p, bool *found_p,
                                 Elf64_Xword i, uint64_t off)
{
    int ret = 0;

    /* PT_LOAD segments must appear in ascending order,
     * sorted by `p_vaddr` */
    if (phdr->p_vaddr < *prev_vaddr_p) {
        pr_error("[Program header no %" PRIu64
                 " (offset 0x%" PRIx64 ")]: "
                 "PT_LOAD vaddr (0x%" PRIx64 ") "
                 "smaller than previous (0x%" PRIx64 ")\n",
                 i, off, phdr->p_vaddr, *prev_vaddr_p);
        ret = 1;
    }

    /* Memory size cannot be smaller than file size */
    if (phdr->p_memsz < phdr->p_filesz) {
        pr_error("[Program header no %" PRIu64
                 " (offset 0x%" PRIx64 ")]: "
                 "PT_LOAD memsz (0x%" PRIx64 ") "
                 "cannot be smaller than filesz (0x%" PRIx64 ")\n",
                 i, off, phdr->p_memsz, phdr->p_filesz);
        ret = 1;
    }

    /* Alignment must be 0, 1, or a power of two */
    if (phdr->p_align > 1) {
        if ((phdr->p_align & (phdr->p_align - 1)) != 0) {
            pr_error("[Program header no %" PRIu64
                     " (offset 0x%" PRIx64 ")]: "
                     "PT_LOAD alignment (0x%" PRIx64 ") "
                     "must be a 0, 1, or power of two\n",
                     i, off, phdr->p_align);
            ret = 1;
        }

        /* vaddr and file offset must be congruent modulo p_align */
        const uint64_t d = phdr->p_vaddr > phdr->p_offset ?
            phdr->p_vaddr - phdr->p_offset :
            phdr->p_offset - phdr->p_vaddr;
        if (d % phdr->p_align != 0) {
            pr_error("[Program header no %" PRIu64
                     " (offset 0x%" PRIx64 ")]: "
                     "PT_LOAD p_vaddr (0x%" PRIx64 ") "
                     "and p_offset (0x%" PRIx64 ") are not congruent "
                     "modulo alignment (0x%" PRIx64 ")\n",
                     i, off, phdr->p_vaddr, phdr->p_offset, phdr->p_align);
            ret = 1;
        }
    }

    *prev_vaddr_p = phdr->p_vaddr;
    *found_p = true;
    return ret;
}

static int validate_pt_dynamic_phdr(const Elf64_Phdr *phdr,
                                    bool *found_p, Elf64_Phdr *out_pt_dynamic,
                                    Elf64_Xword i, uint64_t off)
{
    int ret = 0;

    if (*found_p) {
        pr_error(
                "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                "Multiple PT_DYNAMIC segments are not supported\n", i, off
                );
        ret = 1;
    }

    *found_p = true;
    *out_pt_dynamic = *phdr;
    return ret;
}

static int validate_pt_interp_phdr(const Elf64_Phdr *phdr,
                                   bool *found_p, bool found_pt_load,
                                   const struct blob *data, bool toplevel_ok,
                                   Elf64_Xword i, uint64_t off)
{
    int ret = 0;
    if (*found_p) {
        pr_error(
            "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
            "More than one PT_INTERP header\n", i, off
        );
        ret = 1;
    }
    if (found_pt_load) {
        pr_error(
            "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
            "PT_INTERP header found after a PT_LOAD\n", i, off
        );
        ret = 1;
    }

    if (phdr->p_filesz < 1) {
        pr_error(
            "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
            "PT_INTERP segment size is 0\n", i, off
        );
        ret = 1;
    }

    if (toplevel_ok && !ret) {
        if (data->data[phdr->p_offset + phdr->p_filesz - 1] != '\0') {
            pr_error(
                "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                "PT_INTERP string is not NULL-terminated\n", i, off
            );
            ret = 1;
        } else {
            printf("Program interpreter: %s\n",
                   (const char *)&data->data[phdr->p_offset]);
        }
    } else {
        ret = 1;
    }

    *found_p = true;
    return ret;
}

static int validate_pt_phdr_phdr(
        const Elf64_Phdr *phdr,
        bool *found_p, Elf64_Phdr *out_pt_phdr,
        bool found_pt_load, const Elf64_Ehdr *ehdr, Elf64_Xword phsize,
        Elf64_Xword i, uint64_t off
)
{
    int ret = 0;

    if (*found_p) {
        pr_error(
            "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
            "More than one PT_PHDR header\n", i, off
        );
        ret = 1;
    }
    if (found_pt_load) {
        pr_error(
            "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
            "PT_PHDR header found after a PT_LOAD\n", i, off
        );
        ret = 1;
    }

    if (phdr->p_offset != ehdr->e_phoff || phdr->p_filesz != phsize) {
        pr_error(
            "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                "Invalid PT_PHDR header extents "
                "(offset: 0x%" PRIx64 ", size: 0x%" PRIx64 "\n",
                i, off, phdr->p_offset, phdr->p_filesz
        );
        ret = 1;
    }

    *found_p = true;
    *out_pt_phdr = *phdr;
    return ret;
}

static int parse_shdr_tbl_data_from_ehdr(
        const Elf64_Ehdr *ehdr,
        const struct blob *data, int clazz, int encoding,
        Elf64_Xword *out_shnum, uint64_t *out_shsize, Elf64_Xword *out_shstrndx
)
{
    if (ehdr->e_shoff == 0 || ehdr->e_shentsize == 0) {
        *out_shnum = 0;
        *out_shsize = 0;
        return 0;
    }

    Elf64_Shdr first_shdr = { 0 };
    if (read_shdr(data, &(uint64_t) { ehdr->e_shoff },
                  clazz, encoding, &first_shdr))
    {
        pr_error("Couldn't read the first section header\n");
        return 1;
    }

    /** From `man 5 elf`, `ELF header (Ehdr)`:
     * If the number of entries in the shdr table is >= SHN_LORESERVE,
     * `e_shnum` holds the value zero and the real number of entries
     * is held in the `sh_size` member of the initial entry in the shdr table.
     */
    Elf64_Xword shnum = 0;
    if (ehdr->e_shnum == 0)
        shnum = first_shdr.sh_size;
    else
        shnum = ehdr->e_shnum;

    /** From `man 5 elf`, `ELF header (Ehdr)`:
     * If the index of the .shstrtab section is >= `SHN_LORESERVE`,
     * `e_shstrndx` holds `SHN_XINDEX` and the real index of .shstrtab
     * is held in the `sh_link` member of the initial entry in the shdr table.
     */
    Elf64_Word shstrndx = 0;
    if (ehdr->e_shstrndx >= SHN_XINDEX)
        shstrndx = first_shdr.sh_link;
    else
        shstrndx = ehdr->e_shstrndx;

    if (shnum == 0 && shstrndx != 0) {
        pr_error("No section headers while shstrndx != 0\n");
        return 1;
    }

    /* `ehdr->e_shentsize` is guaranteed to be either
     * `sizeof(Elf32_Shdr)` or `sizeof(Elf64_Shdr)`
     * by `read_validate_ehdr`. */
    if (shnum >= SIZE_MAX / ehdr->e_shentsize ||
        shnum >= UINT64_MAX / ehdr->e_shentsize)
    {
        pr_error("Number of section headers too large "
                "(integer overflow)\n");
        return 1;
    }

    const uint64_t shsize = (uint64_t)ehdr->e_shentsize * shnum;
    if (shsize > data->size || data->size - shsize < ehdr->e_shoff) {
        pr_error("Section headers overflow data buffer\n");
        return 1;
    }

    *out_shnum = shnum;
    *out_shsize = shsize;
    *out_shstrndx = shstrndx;
    return 0;
}

static int read_validate_shstrtab_shdr(
        const Elf64_Ehdr *ehdr, Elf64_Xword shnum, Elf64_Word shstrndx,
        const struct blob *data, int clazz, int encoding,
        Elf64_Shdr *out
)
{
    if (shstrndx == SHN_UNDEF) {
        pr_error("No shstrtab section\n");
        return 1;
    } else if (shstrndx >= shnum) {
        pr_error("shstrtab section out of table bounds\n");
        return 1;
    }

    /* this arithmetic can not overflow because
     * `ehdr->e_shoff + (shnum * ehdr->e_shentsize)`
     * has been validated in the above `parse_shdr_tbl_data_from_ehdr`
     * to not overflow `data->size` as well as `UINT64_MAX` and `SIZE_MAX`. */
    uint64_t shstrtaboff = ehdr->e_shoff + (shstrndx * ehdr->e_shentsize);
    if (read_shdr(data, &shstrtaboff, clazz, encoding, out)) {
        pr_error("Couldn't read the shstrtab section header\n");
        return 1;
    }

    if (out->sh_type != SHT_STRTAB) {
        pr_error("Invalid section type for .shstrtab\n");
        return 1;
    }

    if (out->sh_offset >= data->size ||
            out->sh_size > data->size - out->sh_offset) {
        pr_error("Section .shstrtab bounds are invalid\n");
        return 1;
    }

    if (out->sh_size < 1) {
        pr_error("Section .shstrtab size is 0\n");
        return 1;
    }

    if (data->data[out->sh_offset] != '\0') {
        pr_error("Section .shstrtab doesn't start with a NULL character\n");
        return 1;
    }

    if (data->data[out->sh_offset + out->sh_size - 1] != '\0') {
        pr_error("Section .shstrtab is not NULL-terminated\n");
        return 1;
    }

    return 0;
}

static int validate_shdr(
        const Elf64_Ehdr *ehdr, const struct blob *data,
        Elf64_Xword i, uint64_t off, const Elf64_Shdr *shstrtab,
        const Elf64_Shdr *shdr
)
{
    /* `(i + 1) * ehdr->e_shentsize` can be at most `shsize`
     * which by previous logic is validated to not overflow `data->size`
     * and in consequence, the uint64 limit. */
    if (off != ehdr->e_shoff + (((uint64_t)i + 1) * ehdr->e_shentsize)) {
        pr_error("Invalid offset 0x%" PRIx64
                 " after reading section header no %" PRIu64
                 " (impossible outcome)\n",
                 off, i);
        fflush(stderr);
        abort();
    }

    int ret = 0;

    if (shdr->sh_type != SHT_NOBITS &&
            (shdr->sh_offset >= data->size ||
             data->size - shdr->sh_offset < shdr->sh_size))
    {
        pr_error("[Section header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                 "Section overflows data buffer\n", i, off);
        ret = 1;
    }

    if (shdr->sh_addr > UINT64_MAX - shdr->sh_size) {
        pr_error("[Section header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                "Section overflows address space\n", i, off);
        ret = 1;
    }

    if (shstrtab != NULL && shdr->sh_name >= shstrtab->sh_size) {
        pr_error("[Section header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                 "Section name outside of the .shstrtab section bounds\n",
                 i, off);
        ret = 1;
    } else if (shstrtab == NULL && shdr->sh_name != 0) {
        pr_error("[Section header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                 "WARNING: sh_name not zero even though "
                    "the shstrtab section is missing\n",
                i, off);
        /* not technically invalid */
    }

    return ret;
}
