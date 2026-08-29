#include "elf-patching.h"
#include "elf.h"
#include "ctx.h"
#include "util.h"
#include "elf-types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

int update_phnum(struct elf *elf, Elf64_Xword new_phnum)
{
    if (elf == NULL || new_phnum == 0) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    if (new_phnum > UINT64_MAX / elf->orig.ehdr.e_phentsize) {
        pr_error("%s: New number of program headers too large "
                "(integer overflow)\n", __func__);
        goto err;
    }

    const Elf64_Xword old_phnum = elf->phdrs.num;

    /** Resize the phdrs array **/
    if ((elf->phdrs.arr = safe_realloc((void **)&elf->phdrs.arr,
                                   new_phnum, sizeof(Elf64_Phdr))) == NULL)
    {
        pr_error("Failed to resize (realloc) the program headers array\n");
        goto err;
    }
    /* zero out the new entries if growing */
    if (new_phnum > old_phnum) {
        /* neither can overflow */
        const size_t newsz = new_phnum * sizeof(Elf64_Shdr);
        const size_t prevsz = old_phnum * sizeof(Elf64_Shdr);
        memset((uint8_t *)elf->phdrs.arr + prevsz, 0, newsz - prevsz);
    }

    /** Update the headers' fields */

    if (new_phnum < PN_XNUM) {
        /* "normal" case */
        elf->ehdr.e_phnum = (Elf64_Half)new_phnum;
    } else /* if (val >= PN_XNUM) */ {
        if (elf->shdrs.arr == NULL || elf->shdrs.num < 1) {
            pr_error("%s: No section headers; can't resize past PN_XNUM\n",
                     __func__);
            goto err;
        }

        /**
         * The spec says that if the phnum is >= PN_XNUM,
         * `e_phnum` should contain `PN_XNUM` while the real number of phdrs
         * should be stored in the `sh_info` field of the first section header.
         */
        elf->ehdr.e_phnum = PN_XNUM;
        elf->shdrs.arr[0].sh_info = new_phnum;
        elf->shdrs.dirty = true;
    }

    elf->phdrs.num = new_phnum;
    elf->phdrs.size = new_phnum * elf->orig.ehdr.e_phentsize;
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

    const Elf64_Phdr *ptload =
        find_containing_file_ptload(&elf->phdrs, new_off, phsize);
    if (ptload == NULL) {
        pr_error("New program header location not inside any PT_LOAD segment\n");
        return -1;
    }

    const Elf64_Xword data_size = elf->data.size;
    if (phsize > data_size || new_off > data_size - phsize) {
        pr_error("New program header location would overflow file data\n");
        return -1;
    }

    /* Update the ELF header */
    elf->ehdr.e_phoff = new_off;
    elf->ehdr_dirty = true;

    /* Update the "self-reference" PT_PHDR if it exists */
    const Elf64_Off off_in_seg = new_off - ptload->p_offset;
    const Elf64_Addr new_vaddr = ptload->p_vaddr + off_in_seg;
    for (Elf64_Xword i = 0; i < elf->phdrs.num; i++) {
        Elf64_Phdr *const phdr = &elf->phdrs.arr[i];
        if (phdr->p_type != PT_PHDR)
            continue;

        phdr->p_offset = new_off;
        phdr->p_filesz = phsize;
        phdr->p_memsz = phsize;
        phdr->p_vaddr = new_vaddr;
        phdr->p_paddr = new_vaddr;
        elf->phdrs.dirty = true;
    }

    return 0;
}

int update_shnum(struct elf *elf, Elf64_Xword new_shnum)
{
    if (elf == NULL || new_shnum == 0) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    if (new_shnum > UINT64_MAX / elf->orig.ehdr.e_shentsize) {
        pr_error("%s: New number of section headers too large "
                "(integer overflow)\n", __func__);
        goto err;
    }

    const Elf64_Xword old_shnum = elf->shdrs.num;

    /** Resize the `shdrs` array **/
    if ((elf->shdrs.arr = safe_realloc((void **)&elf->shdrs.arr,
                                   new_shnum, sizeof(Elf64_Shdr))) == NULL)
    {
        pr_error("Failed to resize (realloc) the section headers array\n");
        goto err;
    }
    /* checked by `safe_realloc` */

    if (old_shnum > SIZE_MAX / sizeof(Elf64_Shdr)) {
        pr_error("%s: Old size too large (integer overflow)\n", __func__);
        goto err;
    }
    /* append zeroized entries if growing */
    if (new_shnum > old_shnum) {
        /* neither can overflow */
        const size_t newsz = new_shnum * sizeof(Elf64_Shdr);
        const size_t prevsz = old_shnum * sizeof(Elf64_Shdr);
        memset((uint8_t *)elf->shdrs.arr + prevsz, 0, newsz - prevsz);
    }

    /** Update the headers' fields **/
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

    elf->shdrs.num = new_shnum;
    elf->shdrs.size = new_shnum * elf->orig.ehdr.e_shentsize;
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

    const Elf64_Phdr *ptload =
        find_containing_file_ptload(&elf->phdrs, new_off, shsize);
    if (ptload == NULL) {
        pr_error("New section header location not inside any PT_LOAD segment\n");
        return -1;
    }

    const Elf64_Xword data_size = elf->data.size;
    if (shsize > data_size || new_off > data_size - shsize) {
        pr_error("New section header location would overflow file data\n");
        return -1;
    }

    /* Update the ELF header */
    elf->ehdr.e_shoff = new_off;
    elf->ehdr_dirty = true;
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

static int find_unique_dynamic_entry(const struct elf_dynamic *dyn,
                                     Elf64_Sxword tag, Elf64_Dyn **out)
{
    Elf64_Dyn *found = NULL;
    for (Elf64_Xword i = 0; i < dyn->entries.num; i++) {
        Elf64_Dyn *const curr = &dyn->entries.arr[i];
        if (curr->d_tag != tag)
            continue;

        if (found != NULL) {
            pr_error("Duplicate %s dynamic entry\n",
                     dynamic_tag_to_string(tag));
            return 1;
        }

        found = curr;
    }
    if (found == NULL) {
        pr_error("No %s dynamic entry was found\n",
                 dynamic_tag_to_string(tag));
        return 1;
    }

    *out = found;
    return 0;
}

int update_dynstr_range(struct elf *elf,
                        Elf64_Addr new_addr, Elf64_Xword new_size)
{
    if (elf == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    const Elf64_Phdr *const pt_load =
        find_containing_mem_ptload(&elf->phdrs, new_addr, new_size);
    if (pt_load == NULL) {
        pr_error("The provided new dynstr range "
                "is not within any PT_LOAD segment\n");
        return 1;
    }

    Elf64_Dyn *dt_strtab = NULL, *dt_strsz = NULL;
    if (find_unique_dynamic_entry(&elf->dyn, DT_STRTAB, &dt_strtab) ||
        find_unique_dynamic_entry(&elf->dyn, DT_STRSZ, &dt_strsz))
    {
        pr_error("Couldn't find the DT_STRTAB and DT_STRSZ dynamic entries\n");
        return 1;
    }

    dt_strtab->d_un.d_ptr = new_addr;
    dt_strsz->d_un.d_val = new_size;
    elf->dyn.entries.dirty = true;

    elf->dyn.strtab_vaddr = new_addr;
    elf->dyn.strtab_sz = new_size;

    const Elf64_Off new_off = pt_load->p_offset + (new_addr - pt_load->p_vaddr);
    elf->dyn.strtab_off = new_off;

    if (elf->dyn.strtab_shdr != NULL) {
        elf->dyn.strtab_shdr->sh_addr = new_addr;
        elf->dyn.strtab_shdr->sh_offset = new_off;
        elf->dyn.strtab_shdr->sh_size = new_size;
        elf->shdrs.dirty = true;
    }

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
                          (serializer_proc_t)write_phdr, elf->phdrs.arr,
                          sizeof(Elf64_Phdr), elf->ehdr.e_phentsize,
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
                          (serializer_proc_t)write_shdr, elf->shdrs.arr,
                          sizeof(Elf64_Shdr), elf->ehdr.e_shentsize,
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
        const Elf64_Xword fileentsize =
            c == ELFCLASS32 ? sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);
        if (serialize_arr(&elf->data,
                          (serializer_proc_t)write_dyn, elf->dyn.entries.arr,
                          sizeof(Elf64_Dyn), fileentsize,
                          elf->dyn.phdr->p_offset, elf->dyn.entries.num, c, d))
        {
            pr_error("Failed to serialize the dynamic entries\n");
            return 1;
        }
        printf("Successfully rewrote the dynamic entries\n");
        if (reset_dirty_flags) elf->dyn.entries.dirty = false;
    }

    return 0;
}
