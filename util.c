#include "util.h"
#include "elf.h"
#include "ctx.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int read_file(const char *path, struct blob *out)
{
    if (path == NULL || out == NULL) {
        pr_error("[%s] Invalid parameters\n", __func__);
        return -1;
    }

    FILE *fp = NULL;
    uint8_t *buf = NULL;

    out->data = NULL;
    out->size = 0;

    if ((fp = fopen(path, "rb")) == NULL) {
        pr_error("Failed to open input file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    }

    if (fseek(fp, 0, SEEK_END)) {
        pr_error("Failed to seek to the end of input file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    }
    long pos = ftell(fp);
    if (pos < 0 ||
            (unsigned long)pos > SIZE_MAX || (unsigned long)pos > UINT64_MAX)
    {
        pr_error("Invalid file position: %ld\n", pos);
        goto err;
    }
    const size_t size = (size_t)pos;

    if (fseek(fp, 0, SEEK_SET)) {
        pr_error("Failed to seek to the start of input file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    }

    if ((buf = malloc(size)) == NULL) {
        pr_error("Failed to allocate ELF file data buffer\n");
        goto err;
    }

    if (fread(buf, size, 1, fp) != 1) {
        pr_error("Failed to read %zu bytes from input file "
                        "\"%s\": %d (%s)\n",
                (size_t)size, path, errno, strerror(errno)
        );
        goto err;
    }

    if (fclose(fp)) {
        pr_error("Failed to close the input file: %d (%s)\n",
                errno, strerror(errno));
        fp = NULL;
        goto err;
    }
    fp = NULL;

    out->data = buf; buf = NULL;
    out->size = size;

    return 0;

err:
    if (buf != NULL) {
        free(buf);
        buf = NULL;
    }

    if (fp != NULL) {
        if (fclose(fp)) {
            pr_error("Failed to close the input file: %d (%s)\n",
                    errno, strerror(errno));
        }
        fp = NULL;
    }

    return 1;
}

int write_file(const char *path, const struct blob *data)
{
    if (path == NULL || data == NULL) {
        pr_error("[%s] Invalid parameters\n", __func__);
        return -1;
    }

    FILE *fp = NULL;

    if ((fp = fopen(path, "wb")) == NULL) {
        pr_error("Failed to open output file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    }

    if (data->size > SIZE_MAX || data->size == 0 || data->data == NULL) {
        pr_error("Invalid data blob\n");
        goto err;
    }

    if (fwrite(data->data, data->size, 1, fp) != 1) {
        pr_error("Failed to write to output file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    }

    if (fclose(fp)) {
        pr_error("Failed to close the output file: %d (%s)\n",
                errno, strerror(errno));
        fp = NULL;
        goto err;
    }

    printf("Successfully wrote file \"%s\"\n", path);
    return 0;

err:
    if (fp != NULL) {
        if (fclose(fp)) {
            pr_error("Failed to close the output file: %d (%s)\n",
                    errno, strerror(errno));
        }
        fp = NULL;
    }

    return 1;
}

void * safe_realloc(void **ptr_p, size_t new_n, size_t size)
{
    pr_debug("[%s] new_n: %zu, size: %zu\n", __func__, new_n, size);

    if (size == 0 || new_n == 0) {
        pr_error("[%s] Invalid new size (0)\n", __func__);
        goto err;
    } else if (new_n > SIZE_MAX / size) {
        pr_error("[%s] Size %zu*%zu too large (integer overflow)\n",
                 __func__, new_n, size);
        goto err;
    }

    void *const ptr = ptr_p != NULL ? *ptr_p : NULL;
    const size_t newsize = new_n * size;

    void *tmp = realloc(ptr, newsize);
    if (tmp == NULL) {
        pr_error("[%s] Failed to realloc to size %zu\n", __func__, newsize);
        goto err;
    }

    if (ptr_p != NULL) *ptr_p = NULL;
    return tmp;

err:
    if (ptr_p != NULL && *ptr_p != NULL) {
        free(*ptr_p);
        *ptr_p = NULL;
    }

    return NULL;
}

elf_idx_t
find_containing_mem_ptload(const struct elf_phdrs *phdrs,
                           Elf64_Addr start, Elf64_Xword size)
{
    if (phdrs == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return ELF_IDX_NULL;
    }
    if (start > UINT64_MAX - size) {
        pr_error("[%s] Span too large (integer overflow)\n", __func__);
        return ELF_IDX_NULL;
    }

    for (Elf64_Xword i = 0; i < phdrs->num; i++) {
        const Elf64_Phdr *const curr = &phdrs->arr[i];

        /* anything `curr` is assumed to be bounds-checked and validated
         * earlier by `read_validate_phdrs` */
        if (curr->p_type == PT_LOAD &&
            start >= curr->p_vaddr &&
            start + size <= curr->p_vaddr + curr->p_memsz)
        {
            return i;
        }
    }

    return ELF_IDX_NULL;
}

elf_idx_t
find_containing_file_ptload(const struct elf_phdrs *phdrs,
                            Elf64_Off off, Elf64_Xword size)
{
    if (phdrs == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return ELF_IDX_NULL;
    }
    if (off > UINT64_MAX - size) {
        pr_error("[%s] Span too large (integer overflow)\n", __func__);
        return ELF_IDX_NULL;
    }

    for (Elf64_Xword i = 0; i < phdrs->num; i++) {
        const Elf64_Phdr *const curr = &phdrs->arr[i];

        /* anything `curr` is assumed to be bounds-checked and validated
         * earlier by `read_validate_phdrs` */
        if (curr->p_type == PT_LOAD &&
            off >= curr->p_offset &&
            off + size <= curr->p_offset + curr->p_filesz)
        {
            return i;
        }
    }

    return ELF_IDX_NULL;
}

Elf64_Off find_next_segment_start(const struct elf_phdrs *phdrs, Elf64_Off pos)
{
    if (phdrs == NULL || phdrs->arr == NULL || phdrs->num < 1) {
        pr_error("%s: No program headers to search\n", __func__);
        return 0;
    }

    Elf64_Off ret = 0;
    for (Elf64_Xword i = 0; i < phdrs->num; i++) {
        const Elf64_Phdr *const curr = &phdrs->arr[i];

        if (curr->p_offset > pos && curr->p_offset < ret)
            ret = curr->p_offset;
    }

    pr_debug("[%s] pos: 0x%" PRIx64 ", next: 0x%" PRIx64 "\n",
             __func__, pos, ret);
    return ret;
}

const char * section_name_strptr(const struct elf *elf, Elf64_Addr sh_name)
{
    if (elf == NULL || elf->shdrs.arr == NULL ||
        elf->ehdr.e_shstrndx == SHN_UNDEF ||
        elf->shstrndx >= elf->shdrs.num)
    {
        return "N/A (missing or invalid shstrtab section)";
    }

    const Elf64_Shdr *shstrtab = &elf->shdrs.arr[elf->ehdr.e_shstrndx];
    if (shstrtab->sh_offset >= elf->data.size ||
        shstrtab->sh_size >= elf->data.size - shstrtab->sh_offset ||
        elf->data.data == NULL)
    {
        return "N/A (shstrtab section overflows ELF file)";
    }

    if (shstrtab->sh_size < 1)
        return "N/A (shstrtab section size is 0)";

    if (sh_name >= shstrtab->sh_size)
        return "N/A (section name offset overflows shstrtab section)";

    if (elf->data.data[shstrtab->sh_offset + shstrtab->sh_size - 1] != '\0')
        return "N/A (shstrtab not NULL-terminated)";

    return (const char *)&elf->data.data[shstrtab->sh_offset + sh_name];
}

void find_load_segment_limits(const struct elf *elf,
                              uint64_t *out_vaddr, uint64_t *out_align)
{
    uint64_t max_vaddr = 0;
    /* fall back to the standard 4k page size if nothing is found */
    uint64_t max_align = 4096;

    for (Elf64_Xword i = 0; i < elf->phdrs.num; i++) {
        const Elf64_Phdr *const phdr = &elf->phdrs.arr[i];
        if (phdr->p_type != PT_LOAD)
            continue;

        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr)
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        if (phdr->p_align > max_align)
            max_align = phdr->p_align;
    }

    *out_vaddr = max_vaddr;
    *out_align = max_align;
}
