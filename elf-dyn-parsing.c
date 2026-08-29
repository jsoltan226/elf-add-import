#include "elf-dyn-parsing.h"
#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include <string.h>
#include <inttypes.h>

int read_validate_dynamic_section(
        const struct blob *data, int clazz, int encoding,
        struct elf_phdrs *phdrs, struct elf_shdrs *shdrs,

        struct elf_dynamic *out
)
{
    if (data == NULL || phdrs == NULL || shdrs == NULL) {
        pr_error("%s: Invalid parameters!\n", __func__);
        return -1;
    }

    if (out != NULL)
        memset(out, 0, sizeof(struct elf_dynamic));

    const size_t entsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);

    /** Find and validate the PT_DYNAMIC program header **/
    Elf64_Phdr *pt_dynamic = NULL;
    {
        for (Elf64_Xword i = 0; i < phdrs->num; i++) {
            if (phdrs->arr[i].p_type == PT_DYNAMIC) {
                pt_dynamic = &phdrs->arr[i];
                break;
            }
        }
        if (pt_dynamic == NULL) {
            pr_error("No PT_DYNAMIC header; "
                     "the ELF is probably not dynamically linked\n");
            return 1;
        } else if (validate_pt_dynamic(pt_dynamic, entsize)) {
            pr_error("Invalid PT_DYNAMIC segment header\n");
            return 1;
        }
    }
    const Elf64_Xword dynnum = pt_dynamic->p_filesz / entsize;

    /** If present, validate the .dynamic section header against PT_DYNAMIC **/
    Elf64_Shdr *sht_dynamic = NULL;
    {
        for (Elf64_Xword i = 0; i < shdrs->num; i++) {
            if (shdrs->arr[i].sh_type == SHT_DYNAMIC) {
                if (sht_dynamic != NULL) {
                    pr_error("Multiple SHT_DYNAMIC section headers\n");
                    return 1;
                }
                sht_dynamic = &shdrs->arr[i];
            }
        }
        if (sht_dynamic) {
            if (validate_sht_dynamic(sht_dynamic, pt_dynamic, entsize)) {
                pr_error("Invalid SHT_DYNAMIC section header\n");
                return 1;
            }
        }
    }

    /** Parse the ElfXX_Dyn entries **/
    Elf64_Dyn *arr = NULL;
    if (parse_dyn_array(data, clazz, encoding, dynnum, pt_dynamic, &arr)) {
        pr_error("Failed to parse the dynamic entry array\n");
        return 1;
    }
    pr_debug("Number of dynamic entries: %" PRIu64 "\n", dynnum);

    /** Locate the dynstr string table **/
    Elf64_Addr strtab_addr = 0;
    Elf64_Xword strtab_size = 0;
    {
        Elf64_Dyn *dt_strtab = NULL, *dt_strsz = NULL;
        for (Elf64_Xword i = 0; i < dynnum; i++) {
            if (arr[i].d_tag == DT_STRTAB) {
                if (dt_strtab != NULL) {
                    pr_error("Multiple DT_STRTAB entries\n");
                    goto err;
                }
                dt_strtab = &arr[i];
            } else if (arr[i].d_tag == DT_STRSZ) {
                if (dt_strsz != NULL) {
                    pr_error("Multiple DT_STRSZ entries\n");
                    goto err;
                }
                dt_strsz = &arr[i];
            }
        }
        if (dt_strtab == NULL || dt_strsz == NULL) {
            pr_error("Couldn't find DT_STRTAB and/or DT_STRSZ\n");
            goto err;
        }
        strtab_addr = dt_strtab->d_un.d_ptr;
        strtab_size = dt_strsz->d_un.d_val;
    }

    /** Ensure that the string table is within a PT_LOAD segment **/
    const Elf64_Phdr *strtab_load_seg =
        find_containing_mem_ptload(phdrs, strtab_addr, strtab_size);
    if (strtab_load_seg == NULL) {
        pr_error("Dynamic string table not within any PT_LOAD segment\n");
        goto err;
    }

    /* Deduce the strtab's file offset from the PT_LOAD segment header */
    const Elf64_Off off_in_load_seg = strtab_addr - strtab_load_seg->p_vaddr;
    const Elf64_Off strtab_off = strtab_load_seg->p_offset + off_in_load_seg;

    /** If there's any .dynstr section header, validate it **/
    Elf64_Shdr *strtab_shdr = NULL;
    if (find_validate_strtab_shdr(shdrs->arr, shdrs->num,
                                  strtab_addr, strtab_off, strtab_size,
                                  &strtab_shdr))
    {
        pr_error("Invalid .dynstr section header\n");
        goto err;
    }

    if (out != NULL) {
        out->entries.arr = arr; arr = NULL;
        out->entries.num = dynnum;
        out->entries.dirty = false;

        out->phdr = pt_dynamic;
        out->shdr = sht_dynamic;

        out->strtab_vaddr = strtab_addr;
        out->strtab_sz = strtab_size;
        out->strtab_off = strtab_off;
        out->strtab_shdr = strtab_shdr;
    } else {
        free(arr);
        arr = NULL;
    }
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

int validate_pt_dynamic(const Elf64_Phdr *pt_dynamic, size_t entsize)
{
    if (pt_dynamic == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }
    if (pt_dynamic->p_type != PT_DYNAMIC) {
        pr_error("Program header is not PT_DYNAMIC\n");
        return -1;
    }

    /* Segment bounds already checked in `read_validate_phdrs` */

    if (pt_dynamic->p_filesz % entsize != 0) {
        pr_error("PT_DYNAMIC segment size (%" PRIu64 ") "
                 "is not a multiple of ElfXX_Dyn (%" PRIu64 ")\n",
                 pt_dynamic->p_filesz, entsize);
        return 1;
    } else if (pt_dynamic->p_filesz != pt_dynamic->p_memsz) {
        pr_error("PT_DYNAMIC filesz != memsz\n");
        return 1;
    }

    const Elf64_Xword dynnum = pt_dynamic->p_filesz / entsize;
    if (dynnum > SIZE_MAX) {
        pr_error("Number of dynamic entries overflows size_t");
        return 1;
    }

    return 0;
}

int validate_sht_dynamic(const Elf64_Shdr *sht_dynamic,
                         const Elf64_Phdr *pt_dynamic, size_t entsize)
{
    if (sht_dynamic == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

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
    sht_pt_val_cmp(addralign, PRIu64,   align, PRIu64);

#undef sht_pt_val_cmp

    if (sht_dynamic->sh_entsize != entsize) {
        pr_error("Unexpected value of SHT_DYNAMIC sh_entsize\n");
        return 1;
    }

    return 0;
}

int parse_dyn_array(const struct blob *data, int clazz, int encoding,
                    Elf64_Xword count, const Elf64_Phdr *pt_dynamic,
                    Elf64_Dyn **out)
{
    Elf64_Dyn *arr = NULL;
    *out = NULL;

    if (count == 0) {
        pr_error("Number of dynamic entries is 0!\n");
        goto err;
    }

    arr = calloc(count, sizeof(Elf64_Dyn));
    if (arr == NULL) {
        pr_error("Failed to allocate the dynamic entries array\n");
        goto err;
    }

    Elf64_Xword off = pt_dynamic->p_offset;

    bool terminated = false;
    for (Elf64_Xword i = 0; i < count; i++) {
        if (read_dyn(data, &off, clazz, encoding, &arr[i])) {
            pr_error("Failed to parse dynamic entry "
                     "no %" PRIu64 " at offset 0x%" PRIx64 "\n", i, off);
            goto err;
        }

        if (arr[i].d_tag == DT_NULL && !terminated) {
            terminated = true;
        } else if (terminated && arr[i].d_tag != DT_NULL) {
            pr_error("Entries after DT_NULL terminator\n");
            goto err;
        }
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

    *out = arr; arr = NULL;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

int find_validate_strtab_shdr(Elf64_Shdr *shdrs, Elf64_Xword shnum,
                              Elf64_Addr addr, Elf64_Off off,
                              Elf64_Xword size, Elf64_Shdr **out)
{
    Elf64_Shdr *shdr = NULL;
    for (Elf64_Xword i = 0; i < shnum; i++) {
        Elf64_Shdr *const curr = &shdrs[i];

        if (ranges_overlap(curr->sh_addr, curr->sh_size, addr, size) ||
            ranges_overlap(curr->sh_offset, curr->sh_size, off, size))
        {
            if (shdr != NULL) {
                pr_error("Multiple sections contain "
                         "the .dynamic string table\n");
                return 1;
            }
            shdr = curr;
        }
    }
    if (shdr == NULL) {
        /* no .dynstr section was found */
        if (out != NULL) *out = NULL;
        return 0;
    }

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
        pr_error("Invalid .dynstr sectoin size\n");
        ret = 1;
    }

    if (!ret && out != NULL)
        *out = shdr;

    return ret;
}
