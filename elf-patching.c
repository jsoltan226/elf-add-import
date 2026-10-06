#include "elf-patching.h"
#include "elf.h"
#include "ctx.h"
#include "util.h"
#include "elf-types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

static int find_unique_phdr(const struct elf_phdrs *phdrs, Elf64_Word type,
                            elf_idx_t *out)
{
    if (out != NULL) *out = ELF_IDX_NULL;

    elf_idx_t idx = ELF_IDX_NULL;
    for (Elf64_Xword i = 0; i < phdrs->num; i++) {
        if (phdrs->arr[i].p_type == type) {
            if (idx != ELF_IDX_NULL) {
                pr_error("Duplicate \"%s\" program header\n",
                         program_header_type_toString(type));
                return -1;
            }
            idx = i;
        }
    }
    if (idx == ELF_IDX_NULL) {
        pr_debug("No \"%s\" program header\n",
                 program_header_type_toString(type));
        return 1;
    }

    if (out != NULL) *out = idx;
    return 0;
}

int update_phnum(struct elf *elf, Elf64_Xword new_phnum)
{
    if (elf == NULL || new_phnum == 0) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    elf_idx_t pt_phdr_idx = ELF_IDX_NULL;
    const int r = find_unique_phdr(&elf->phdrs, PT_PHDR, &pt_phdr_idx);
    if (r < 0) /* duplicate PT_PHDR */
        return -1;
    else if (r == 0)
        pr_debug("PT_PHDR is present\n");

    /* Only require PT_LOAD containment of the phdr table if PT_PHDR exists */
    const struct elf_phdrs *phdrs_for_ptload_check =
        (pt_phdr_idx != ELF_IDX_NULL) ? &elf->phdrs : NULL;

    Elf64_Xword new_phdr_tbl_size = 0;
    if (resize_table("program headers", sizeof(Elf64_Phdr), elf->phentsize,
                     elf->ehdr.e_phoff, elf->phdrs.num, new_phnum,
                     phdrs_for_ptload_check, &elf->data,
                     (void **)&elf->phdrs.arr, &new_phdr_tbl_size))
    {
        pr_error("Failed to resize the program header table\n");
        goto err;
    }

    /* Update the headers' fields */

    if (new_phnum < PN_XNUM) {
        /* "normal" case */
        elf->ehdr.e_phnum = (Elf64_Half)new_phnum;
    } else /* if (val >= PN_XNUM) */ {
        if (elf->shdrs.arr == NULL || elf->shdrs.num < 1) {
            pr_error("%s: No section headers; can't resize past PN_XNUM\n",
                     __func__);
            goto err;
        }

        if (new_phnum > UINT32_MAX) {
            pr_error("%s: New number of program headers too large "
                    " to represent in sh_info which is a uint32_t; "
                    "integer overflow\n", __func__);
            goto err;
        }

        /**
         * The spec says that if the phnum is >= PN_XNUM,
         * `e_phnum` should contain `PN_XNUM` while the real number of phdrs
         * should be stored in the `sh_info` field of the first section header.
         */
        elf->ehdr.e_phnum = PN_XNUM;
        elf->shdrs.arr[0].sh_info = (Elf64_Word)new_phnum;
        elf->shdrs.dirty = true;
    }
    elf->ehdr_dirty = true;

    /* Also update the "self-reference" PT_PHDR, if present */
    if (pt_phdr_idx != ELF_IDX_NULL) {
        Elf64_Phdr *const pt_phdr = get_phdr_rw(elf, pt_phdr_idx);
        pt_phdr->p_filesz = new_phdr_tbl_size;
        pt_phdr->p_memsz = new_phdr_tbl_size;
    }

    elf->phdrs.num = new_phnum;
    elf->phdrs.size = new_phnum * elf->phentsize;
    elf->phdrs.dirty = true;
    return 0;

err:
    if (elf->phdrs.arr != NULL) {
        free(elf->phdrs.arr);
        elf->phdrs.arr = NULL;
    }
    elf->phdrs.num = 0;
    elf->phdrs.size = 0;
    elf->phdrs.dirty = false;
    elf->ehdr_dirty = false;
    return 1;
}

int update_phoff(struct elf *elf, Elf64_Off new_off)
{
    pr_debug("[%s] new_off: 0x%" PRIx64 "\n", __func__, new_off);
    if (elf == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }
    const Elf64_Xword phsize = elf->phdrs.size;
    if (new_off > elf->data.size || phsize > elf->data.size - new_off) {
        pr_error("New program header location would overflow file data\n");
        return 1;
    }

    /* Find PT_PHDR, if present */
    elf_idx_t pt_phdr_idx = ELF_IDX_NULL;
    Elf64_Addr new_vaddr = 0;
    const int r = find_unique_phdr(&elf->phdrs, PT_PHDR, &pt_phdr_idx);
    if (r < 0) /* duplicate PT_PHDR */
        return -1;

    /* Only require PT_LOAD containment of the phdr table if PT_PHDR exists */
    if (pt_phdr_idx != ELF_IDX_NULL) {
        if (find_ptload_and_vaddr_from_off(new_off, phsize, &elf->phdrs,
                                           &new_vaddr, NULL))
        {
            pr_error("New program header location not fully contained within "
                     "any single PT_LOAD segment while PT_PHDR exists\n");
            return 1;
        }
    }

    /* Update the ELF header */
    elf->ehdr.e_phoff = new_off;
    elf->ehdr_dirty = true;

    /* Update the "self-reference" PT_PHDR if it exists */
    if (pt_phdr_idx != ELF_IDX_NULL) {
        Elf64_Phdr *const pt_phdr = get_phdr_rw(elf, pt_phdr_idx);
        pt_phdr->p_offset = new_off;
        pt_phdr->p_filesz = phsize;
        pt_phdr->p_memsz = phsize;
        /* `new_vaddr` always initialized when `pt_phdr_idx != NULL` */
        pt_phdr->p_vaddr = new_vaddr;
        pt_phdr->p_paddr = new_vaddr;
    }

    elf->phdrs.dirty = true;

    return 0;
}

int update_shnum(struct elf *elf, Elf64_Xword new_shnum)
{
    if (elf == NULL || new_shnum == 0) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    Elf64_Xword new_shdr_tbl_size = 0;
    if (resize_table("section headers", sizeof(Elf64_Shdr), elf->shentsize,
                     elf->ehdr.e_shoff, elf->shdrs.num, new_shnum, NULL,
                     &elf->data, (void **)&elf->shdrs.arr, &new_shdr_tbl_size))
    {
        pr_error("Failed to resize the section header table\n");
        goto err;
    }

    /* Update the headers' fields */
    if (new_shnum < SHN_LORESERVE) {
        /* "normal" case */
        elf->ehdr.e_shnum = (Elf64_Half)new_shnum;
    } else /* if (new_size >= SHN_LORESERVE) */ {
        /**
         * The spec says that if the shnum is >= SHN_LORESERVE,
         * `e_shnum` should contain the value `0` while the real number of shdrs
         * should be stored in the `sh_size` field of the first section header.
         */
        elf->ehdr.e_shnum = 0;
        elf->shdrs.arr[0].sh_size = new_shnum;
    }
    elf->ehdr_dirty = true;

    elf->shdrs.num = new_shnum;
    elf->shdrs.size = new_shdr_tbl_size;
    elf->shdrs.dirty = true;
    return 0;

err:
    if (elf->shdrs.arr != NULL) {
        free(elf->shdrs.arr);
        elf->shdrs.arr = NULL;
    }
    elf->shdrs.num = 0;
    elf->shdrs.size = 0;
    elf->shdrs.dirty = false;
    return 1;
}

int update_shoff(struct elf *elf, Elf64_Off new_off)
{
    pr_debug("[%s] new_off: 0x%" PRIx64 "\n", __func__, new_off);
    if (elf == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    const Elf64_Xword shsize = elf->shdrs.size;
    const Elf64_Xword data_size = elf->data.size;
    if (shsize > data_size || new_off > data_size - shsize) {
        pr_error("The section header table at the given offset "
                 "would overflow file data\n");
        return -1;
    }

    /* Update the ELF header */
    elf->ehdr.e_shoff = new_off;
    elf->ehdr_dirty = true;
    elf->shdrs.dirty = true;
    return 0;
}

int update_shstrndx(struct elf *elf, Elf64_Word new_shstrndx)
{
    if (elf == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    Elf64_Shdr *const first_shdr =
        (elf->shdrs.num > 0 && elf->shdrs.arr != NULL) ?
            &elf->shdrs.arr[0] : NULL;

    if (new_shstrndx < SHN_LORESERVE) {
        /** Normal case; ehdr->e_shstrndx = new_shstrndx */

        if (first_shdr != NULL && first_shdr->sh_link != 0) {
            first_shdr->sh_link = 0;
            elf->shdrs.dirty = true;
        }

        elf->shstrndx = new_shstrndx;
        elf->ehdr.e_shstrndx = (Elf64_Half)new_shstrndx;
        elf->ehdr_dirty = true;
        return 0;
    } else /* if (val >= SHN_LORESERVE) */ {
        /**
         * new_shstrndx >= SHN_LORESERVE;
         *  ehdr->e_shstrndx = `SHN_XINDEX` and
         *  shdrs->arr[0].sh_link = new_shstrndx
         */

        if (first_shdr == NULL) {
            pr_error("%s: No section headers; "
                    "can't set index past `SHN_LORESERVE`\n",
                    __func__);
            return 1;
        }

        first_shdr->sh_link = new_shstrndx;
        elf->shdrs.dirty = true;

        elf->ehdr.e_shstrndx = SHN_XINDEX;
        elf->ehdr_dirty = true;

        elf->shstrndx = new_shstrndx;
        return 0;
    }
}

int update_dynstr_range(struct elf *elf,
                        Elf64_Addr new_addr, Elf64_Xword new_size)
{
    if (elf == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    Elf64_Off new_off = 0;
    if (find_ptload_and_off_from_vaddr(new_addr, new_size, &elf->phdrs,
                                       &new_off, NULL))
    {
        pr_error("The provided new dynstr range "
                 "is not fully contained by any single PT_LOAD segment\n");
        return 1;
    }

    enum { DT_STRTAB_IDX = 0, DT_STRSZ_IDX = 1 };
    elf_idx_t idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };
    if (find_unique_dyn_entries(&elf->dyn.entries, 2,
                                (Elf64_Sxword[]){ DT_STRTAB, DT_STRSZ }, idxs))
    {
        pr_error("Couldn't find the DT_STRTAB and/or DT_STRSZ entries\n");
        return 1;
    }

    get_dyn_rw(elf, idxs[DT_STRTAB_IDX])->d_un.d_ptr = new_addr;
    get_dyn_rw(elf, idxs[DT_STRSZ_IDX])->d_un.d_val = new_size;
    elf->dyn.entries.dirty = true;

    elf->dyn.strtab.vaddr = new_addr;
    elf->dyn.strtab.size = new_size;
    elf->dyn.strtab.off = new_off;

    if (elf->dyn.strtab.shdr != ELF_IDX_NULL) {
        Elf64_Shdr *const strtab_shdr = get_shdr_rw(elf, elf->dyn.strtab.shdr);
        strtab_shdr->sh_addr = new_addr;
        strtab_shdr->sh_offset = new_off;
        strtab_shdr->sh_size = new_size;
        elf->shdrs.dirty = true;
    }

    return 0;
}

int update_dyn_tbl_num(struct elf *elf, Elf64_Xword new_dynnum)
{
    Elf64_Phdr *pt_dynamic = NULL;
    if (elf == NULL || elf->dyn.phdr == ELF_IDX_NULL ||
        (pt_dynamic = get_phdr_rw(elf, elf->dyn.phdr)) == NULL)
    {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    Elf64_Xword new_dyn_tbl_size = 0;
    if (resize_table("DYNAMIC entries", sizeof(Elf64_Dyn), elf->dynentsize,
                     pt_dynamic->p_offset, elf->dyn.entries.num, new_dynnum,
                     &elf->phdrs, &elf->data, (void **)&elf->dyn.entries.arr,
                     &new_dyn_tbl_size))
    {
        pr_error("Failed to resize the DYNAMIC entries table\n");
        return 1;
    }

    elf->dyn.entries.num = new_dynnum;
    elf->dyn.entries.size = new_dyn_tbl_size;

    pt_dynamic->p_filesz = new_dyn_tbl_size;
    pt_dynamic->p_memsz = new_dyn_tbl_size;
    elf->phdrs.dirty = true;

    if (elf->dyn.shdr != ELF_IDX_NULL) {
        get_shdr_rw(elf, elf->dyn.shdr)->sh_size = new_dyn_tbl_size;
        elf->shdrs.dirty = true;
    }

    pr_debug("[%s] New DYNAMIC table size: %" PRIu64 " (%" PRIu64 " entries)\n",
             __func__, new_dyn_tbl_size, new_dynnum);
    return 0;
}

int update_dyn_tbl_off(struct elf *elf, Elf64_Off new_off)
{
    if (elf == NULL || elf->dyn.phdr == ELF_IDX_NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    Elf64_Phdr *const pt_dynamic = get_phdr_rw(elf, elf->dyn.phdr);

    Elf64_Addr new_vaddr = 0;
    if (find_ptload_and_vaddr_from_off(new_off, elf->dyn.entries.size,
                                       &elf->phdrs, &new_vaddr, NULL))
    {
        pr_error("No single PT_LOAD segment would fully contain the "
                 "dynamic table at the given new offset\n");
    }

    pt_dynamic->p_offset = new_off;
    pt_dynamic->p_vaddr = new_vaddr;
    pt_dynamic->p_paddr = new_vaddr;
    elf->phdrs.dirty = true;

    if (elf->dyn.shdr != ELF_IDX_NULL) {
        Elf64_Shdr *const sht_dynamic = get_shdr_rw(elf, elf->dyn.shdr);
        sht_dynamic->sh_offset = new_off;
        sht_dynamic->sh_addr = new_vaddr;
        elf->shdrs.dirty = true;
    }

    pr_debug("[%s] New DYNAMIC table offset: 0x%" PRIx64 " "
             "(vaddr: 0x%" PRIx64 ")\n",
             __func__, new_off, new_vaddr);
    return 0;
}

int update_dyn_sym_count(struct elf *elf, Elf64_Xword new_nsyms)
{
    if (elf == NULL ||
        elf->dyn.symtab.nsyms < 1 || elf->dyn.symtab.syms == NULL)
    {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }
    struct elf_dyn_symtab *const symtab = &elf->dyn.symtab;

    Elf64_Xword new_symtab_size = 0;
    if (resize_table("dynsym", sizeof(Elf64_Sym), elf->dynsymentsize,
                     symtab->off, symtab->nsyms, new_nsyms, &elf->phdrs,
                     &elf->data, (void **)&symtab->syms, &new_symtab_size))
    {
        pr_error("Failed to resize the dynamic symbol table\n");
        return 1;
    }

    symtab->nsyms = new_nsyms;
    symtab->size = new_symtab_size;

    if (symtab->shdr != ELF_IDX_NULL) {
        get_shdr_rw(elf, symtab->shdr)->sh_size = new_symtab_size;
        elf->shdrs.dirty = true;
    }

    pr_debug("[%s] New dyn symtab size: 0x%" PRIx64 " "
             "(%" PRIu64 " symbols)\n",
             __func__, new_symtab_size, new_nsyms);
    return 0;
}

int update_dyn_symtab_off(struct elf *elf, Elf64_Off new_off)
{
    if (elf == NULL ||
        elf->dyn.symtab.nsyms < 1 || elf->dyn.symtab.syms == NULL)
    {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }
    struct elf_dyn_symtab *const symtab = &elf->dyn.symtab;

    Elf64_Addr new_vaddr = 0;
    if (find_ptload_and_vaddr_from_off(new_off, elf->dyn.entries.size,
                                       &elf->phdrs, &new_vaddr, NULL))
    {
        pr_error("No single PT_LOAD segment would fully contain the "
                 "dynamic symbol table at the given offset\n");
        return 1;
    }

    get_dyn_rw(elf, symtab->dt_symtab)->d_un.d_ptr = new_vaddr;
    elf->dyn.entries.dirty = true;
    symtab->off = new_off;
    symtab->vaddr = new_vaddr;

    if (symtab->shdr != ELF_IDX_NULL) {
        Elf64_Shdr *const sht_dynsym = get_shdr_rw(elf, symtab->shdr);
        sht_dynsym->sh_offset = new_off;
        sht_dynsym->sh_addr = new_vaddr;
        elf->shdrs.dirty = true;
    }

    pr_debug("[%s] New dyn symtab offset: 0x%" PRIx64 " "
             "(vaddr: 0x%" PRIx64 ")\n",
             __func__, new_off, new_vaddr);
    return 0;
}

int serialize_arr(struct blob *data, serializer_proc_t serializer,
                  const void *arr, size_t mementsize, Elf64_Half fileentsize,
                  uint64_t off, Elf64_Xword size, int clazz, int encoding)
{
    if (mementsize == 0 || fileentsize == 0) {
        pr_error("Element size is 0\n");
        return -1;
    }
    if (arr == NULL) {
        pr_error("Unexpected NULL pointer (arr)\n");
        return -1;
    }
    if (size > UINT64_MAX / fileentsize ||
        size > UINT64_MAX / mementsize)
    {
        pr_error("Invalid element count (integer overflow)\n");
        return -1;
    }
    const uint64_t filesize = size * fileentsize;

    const uint64_t start = off;
    if (filesize > UINT64_MAX - start) {
        pr_error("Invalid offset (integer overflow)\n");
        return -1;
    }

    if (filesize > data->size ||
        start > data->size - filesize)
    {
        pr_error("filesize: %lu, start: %lu, data->size: %lu\n",
                filesize, start, data->size);
        pr_error("Not enough space in data buffer\n");
        return 1;
    }

    for (Elf64_Xword i = 0; i < size; i++) {
        const void *ptr = (const uint8_t *)arr + (i * mementsize);
        if (serializer(data, &off, clazz, encoding, ptr)) {
            pr_error("Failed to serialize element no %" PRIu64 "\n", i);
            return 1;
        }
    }

    if (off != start + filesize) {
        pr_error("Invalid offset after serialization "
                "(0x%" PRIx64 ", expected 0x%" PRIx64 ")\n",
                off, start + filesize);
        return 1;
    }

    return 0;
}

/**
 * Wrapper for `write_phdr`, used to suppress the
 * incompatible function pointer types warning in `serialize_elf`.
 */
static inline int write_phdr_wrapper(struct blob *data, uint64_t *off_p,
                                     int clazz, int encoding, const void *arr)
{
    return write_phdr(data, off_p, clazz, encoding, (const Elf64_Phdr *)arr);
}

/**
 * Wrapper for `write_shdr`, used to suppress the
 * incompatible function pointer types warning in `serialize_elf`.
 */
static inline int write_shdr_wrapper(struct blob *data, uint64_t *off_p,
                                     int clazz, int encoding, const void *arr)
{
    return write_shdr(data, off_p, clazz, encoding, (const Elf64_Shdr *)arr);
}

/**
 * Wrapper for `write_dyn`, used to suppress the
 * incompatible function pointer types warning in `serialize_elf`.
 */
static inline int write_dyn_wrapper(struct blob *data, uint64_t *off_p,
                                    int clazz, int encoding, const void *arr)
{
    return write_dyn(data, off_p, clazz, encoding, (const Elf64_Dyn *)arr);
}

int serialize_elf(struct elf *elf, bool reset_dirty_flags)
{
    const int c = elf->ident.clazz, d = elf->ident.data;

    pr_debug("ELF header dirty: %d\n", !!elf->ehdr_dirty);
    if (elf->ehdr_dirty) {
        uint64_t off = 0;
        if (write_ehdr(&elf->data, &off, c, d, &elf->ehdr)) {
            pr_error("Failed to rewrite the ELF header\n");
            return 1;
        }
        printf("Successfully rewrote ELF header\n");
        if (reset_dirty_flags) elf->ehdr_dirty = false;
    }

    pr_debug("Program headers dirty: %d\n", !!elf->phdrs.dirty);
    if (elf->phdrs.dirty) {
        if (serialize_arr(&elf->data,
                          write_phdr_wrapper, elf->phdrs.arr,
                          sizeof(Elf64_Phdr), elf->phentsize,
                          elf->ehdr.e_phoff, elf->phdrs.num, c, d))
        {
            pr_error("Failed to rewrite the program headers\n");
            return 1;
        }
        printf("Successfully rewrote program headers\n");
        if (reset_dirty_flags) elf->phdrs.dirty = false;
    }

    pr_debug("Section headers dirty: %d\n", !!elf->shdrs.dirty);
    if (elf->shdrs.dirty) {
        if (serialize_arr(&elf->data,
                          write_shdr_wrapper, elf->shdrs.arr,
                          sizeof(Elf64_Shdr), elf->shentsize,
                          elf->ehdr.e_shoff, elf->shdrs.num, c, d))
        {
            pr_error("Failed to rewrite the section headers\n");
            return 1;
        }
        printf("Successfully rewrote section headers\n");
        if (reset_dirty_flags) elf->shdrs.dirty = false;
    }

    pr_debug("Dynamic entries dirty: %d\n", !!elf->dyn.entries.dirty);
    if (elf->dyn.entries.dirty) {
        const Elf64_Phdr *const pt_dynamic = get_phdr_ro(elf, elf->dyn.phdr);
        const Elf64_Half fileentsize =
            c == ELFCLASS32 ? sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);
        if (serialize_arr(&elf->data,
                          write_dyn_wrapper, elf->dyn.entries.arr,
                          sizeof(Elf64_Dyn), fileentsize,
                          pt_dynamic->p_offset, elf->dyn.entries.num, c, d))
        {
            pr_error("Failed to serialize the dynamic entries\n");
            return 1;
        }
        printf("Successfully rewrote the dynamic entries\n");
        if (reset_dirty_flags) elf->dyn.entries.dirty = false;
    }

    return 0;
}
