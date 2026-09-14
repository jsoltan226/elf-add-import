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
    if (elf->data.data != NULL)
        free(elf->data.data);

    if (elf->phdrs.arr != NULL)
        free(elf->phdrs.arr);

    if (elf->shdrs.arr != NULL)
        free(elf->shdrs.arr);

    if (elf->dyn.entries.arr != NULL)
        free(elf->dyn.entries.arr);

    if (elf->dyn.hash.buckets != NULL)
        free(elf->dyn.hash.buckets);

    if (elf->dyn.hash.chains != NULL)
        free(elf->dyn.hash.chains);

    memset(elf, 0, sizeof(struct elf));
}
