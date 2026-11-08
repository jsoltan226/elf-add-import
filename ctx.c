#include "ctx.h"
#include "util.h"
#include "elf-dyn-parsing.h"
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
    if (elf->data.buf != NULL)
        free(elf->data.buf);

    if (elf->phdrs.arr != NULL)
        free(elf->phdrs.arr);
    if (elf->shdrs.arr != NULL)
        free(elf->shdrs.arr);

    destroy_dyn(&elf->dyn);

    *elf = empty_elf_ctx_st;
}
