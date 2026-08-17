#include "elf-patching.h"
#include "elf.h"
#include "ctx.h"
#include "util.h"
#include "elf-types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

int update_phnum(struct elf_phdrs *phdrs, Elf64_Xword new_size,
                 Elf64_Half *out_ehdr_e_phnum_p, struct elf_shdrs *shdrs)
{
    /* see `update_shnum`, does almost the same thing
     * but is a more pleasant to read */

    if (new_size == 0) {
        pr_error("%s: Resizing to 0 means the program headers "
                "would have to be deleted entirely, "
                "which is not supported here.\n",
                __func__);
        goto err;
    }

    /** Resize the phdrs array **/

    if (phdrs->num > SIZE_MAX / sizeof(Elf64_Phdr)) {
        pr_error("%s: Old size too large (integer overflow)\n",
                __func__);
        goto err;
    }
    if (new_size > SIZE_MAX / sizeof(Elf64_Phdr)) {
        pr_error("%s: New size too large (integer overflow)\n",
                __func__);
        goto err;
    }
    const size_t prevsz = phdrs->num * sizeof(Elf64_Phdr);
    const size_t newsz = new_size * sizeof(Elf64_Phdr);

    if ((phdrs->arr = safe_realloc((void **)&phdrs->arr,
                                   new_size, sizeof(Elf64_Phdr))) == NULL)
    {
        pr_error("Failed to resize (realloc) the program headers array\n");
        goto err;
    }
    /* append zeroized entries if growing */
    if (newsz > prevsz)
        memset((uint8_t *)phdrs->arr + prevsz, 0, newsz - prevsz);

    /** Update the headers' fields */

    if (new_size < PN_XNUM) {
        /* "normal" case */
        *out_ehdr_e_phnum_p = (Elf64_Half)new_size;
    } else /* if (val >= PN_XNUM) */ {
        if (shdrs == NULL || shdrs->arr == NULL || shdrs->num < 1) {
            pr_error("%s: No section headers; can't resize past PN_XNUM\n",
                     __func__);
            goto err;
        }

        /**
         * The spec says that if the phnum is >= PN_XNUM,
         * `e_phnum` should contain `PN_XNUM` while the real number of phdrs
         * should be stored in the `sh_info` field of the first section header.
         */
        *out_ehdr_e_phnum_p = PN_XNUM;
        shdrs->arr[0].sh_info = new_size;
        shdrs->dirty = true;
    }

    phdrs->num = new_size;
    phdrs->dirty = true;
    return 0;

err:
    if (phdrs->arr != NULL) {
        free(phdrs->arr);
        phdrs->arr = NULL;
    }
    phdrs->num = 0;
    phdrs->dirty = false;
    return 1;
}

int update_shnum(struct elf_shdrs *shdrs, Elf64_Xword new_size,
                 Elf64_Half *out_ehdr_e_shnum_p)
{
    if (new_size == 0) {
        pr_error("%s: Resizing to 0 means the section headers "
                "would have to be deleted entirely, "
                "which is not supported here.\n",
                __func__);
        goto err;
    }

    /** Resize the `shdrs` array **/
    if ((shdrs->arr = safe_realloc((void **)&shdrs->arr,
                                   new_size, sizeof(Elf64_Shdr))) == NULL)
    {
        pr_error("Failed to resize (realloc) the section headers array\n");
        goto err;
    }
    /* checked by `safe_realloc` */
    const size_t newsz = new_size * sizeof(Elf64_Shdr);

    if (shdrs->num > SIZE_MAX / sizeof(Elf64_Shdr)) {
        pr_error("%s: Old size too large (integer overflow)\n", __func__);
        goto err;
    }
    const size_t prevsz = shdrs->num * sizeof(Elf64_Shdr);
     /* append zeroized entries if growing */
    if (newsz > prevsz)
        memset((uint8_t *)shdrs->arr + prevsz, 0, newsz - prevsz);

    /** Update the headers' fields **/
    if (new_size < SHN_LORESERVE) {
        /* "normal" case */
        *out_ehdr_e_shnum_p = (Elf64_Half)new_size;
    } else /* if (new_size >= SHN_LORESERVE) */ {
        /**
         * The spec says that if the shnum is >= SHN_LORESERVE,
         * `e_shnum` should contain the value `0` while the real number of shdrs
         * should be stored in the `sh_size` field of the first section header.
         */
        *out_ehdr_e_shnum_p = 0;
        shdrs->arr[0].sh_size = new_size;
    }

    shdrs->num = new_size;
    shdrs->dirty = true;
    return 0;

err:
    if (shdrs->arr != NULL) {
        free(shdrs->arr);
        shdrs->arr = NULL;
    }
    shdrs->num = 0;
    shdrs->dirty = false;
    return 1;
}

int update_shstrndx(Elf64_Word val, Elf64_Word *out,
                    Elf64_Half *out_ehdr_shstrndx_p, struct elf_shdrs *shdrs)
{
    if (val == 0) {
        /* just for good measure */
        if (shdrs != NULL && shdrs->num > 0 && shdrs->arr != NULL)
            shdrs->arr[0].sh_link = 0;

        *out = 0;
        *out_ehdr_shstrndx_p = SHN_UNDEF;
        return 0;
    } else if (val < SHN_LORESERVE) {
        if (shdrs != NULL && shdrs->num > 0 && shdrs->arr != NULL)
            shdrs->arr[0].sh_link = 0;

        *out = val;
        *out_ehdr_shstrndx_p = (Elf64_Half)val;
        return 0;
    } else /* if (val >= SHN_LORESERVE) */ {
        if (shdrs == NULL || shdrs->num < 1 || shdrs->arr == NULL) {
            pr_error("%s: No section headers; "
                    "can't set index past `SHN_LORESERVE`\n",
                    __func__);
            return -1;
        }

        shdrs->arr[0].sh_link = val;
        shdrs->dirty = true;
        *out_ehdr_shstrndx_p = SHN_XINDEX;
        *out = val;
        return 0;
    }
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
