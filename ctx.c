#include "ctx.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

Elf64_Phdr * get_phdr_rw(struct elf *elf, elf_idx_t idx)
{
    if (idx == ELF_IDX_NULL) {
        pr_error("%s: NULL index\n", __func__);
        return NULL;
    } else if (elf == NULL || idx >= elf->phdrs.num || elf->phdrs.arr == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return NULL;
    }

    return &elf->phdrs.arr[idx];
}

const Elf64_Phdr * get_phdr_ro(const struct elf *elf, elf_idx_t idx)
{
    if (idx == ELF_IDX_NULL) {
        pr_error("%s: NULL index\n", __func__);
        return NULL;
    } else if (elf == NULL || idx >= elf->phdrs.num || elf->phdrs.arr == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return NULL;
    }

    return &elf->phdrs.arr[idx];
}

Elf64_Shdr * get_shdr_rw(struct elf *elf, elf_idx_t idx)
{
    if (idx == ELF_IDX_NULL) {
        pr_error("%s: NULL index\n", __func__);
        return NULL;
    } else if (elf == NULL || idx >= elf->shdrs.num || elf->shdrs.arr == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return NULL;
    }

    return &elf->shdrs.arr[idx];
}

const Elf64_Shdr * get_shdr_ro(const struct elf *elf, elf_idx_t idx)
{
    if (idx == ELF_IDX_NULL) {
        pr_error("%s: NULL index\n", __func__);
        return NULL;
    } else if (elf == NULL || idx >= elf->shdrs.num || elf->shdrs.arr == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return NULL;
    }

    return &elf->shdrs.arr[idx];
}

Elf64_Dyn * get_dyn_rw(struct elf *elf, elf_idx_t idx)
{
    if (idx == ELF_IDX_NULL) {
        pr_error("%s: NULL index\n", __func__);
        return NULL;
    } else if (elf == NULL || idx >= elf->dyn.entries.num ||
               elf->dyn.entries.arr == NULL)
    {
        pr_error("%s: Invalid parameters\n", __func__);
        return NULL;
    }

    return &elf->dyn.entries.arr[idx];
}

const Elf64_Dyn * get_dyn_ro(const struct elf *elf, elf_idx_t idx)
{
    if (idx == ELF_IDX_NULL) {
        pr_error("%s: NULL index\n", __func__);
        return NULL;
    } else if (elf == NULL || idx >= elf->dyn.entries.num ||
               elf->dyn.entries.arr == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return NULL;
    }

    return &elf->dyn.entries.arr[idx];
}

void destroy_elf(struct elf *elf)
{
#define free_if_null(ptr) \
    if (ptr != NULL) {    \
        free(ptr);        \
        ptr = NULL;       \
    }

    free_if_null(elf->data.buf);

    free_if_null(elf->phdrs.arr);
    free_if_null(elf->shdrs.arr);

    free_if_null(elf->dyn.entries.arr);

    free_if_null(elf->dyn.symtab.syms);

    free_if_null(elf->dyn.hash.buckets);
    free_if_null(elf->dyn.hash.chain);
    free_if_null(elf->dyn.gnu_hash.bloom);
    free_if_null(elf->dyn.gnu_hash.buckets);
    free_if_null(elf->dyn.gnu_hash.chain);

    free_if_null(elf->dyn.symtab_shndx.arr);

#undef free_if_null

    *elf = (struct elf) { 0 };
}
