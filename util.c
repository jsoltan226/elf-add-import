#include "util.h"
#include "elf.h"
#include "ctx.h"
#include "elf-types.h"
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
    size_t size = 0;

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
    {
        long pos = ftell(fp);
        if (pos < 0 ||
                (unsigned long)pos > SIZE_MAX ||
                (unsigned long)pos > UINT64_MAX)
        {
            pr_error("Invalid file position: %ld\n", pos);
            goto err;
        }
        size = (size_t)pos;
    }

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
    pr_debug("realloc: new_n: %zu, size: %zu\n", new_n, size);

    if (size == 0 || new_n == 0) {
        pr_error("[%s] Invalid new size (0)\n", __func__);
        return NULL;
    } else if (new_n > SIZE_MAX / size) {
        pr_error("[%s] Size %zu*%zu too large (integer overflow)\n",
                 __func__, new_n, size);
        return NULL;
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

int resize_table(const char *name, size_t mementsz, Elf64_Xword fileentsz,
                 Elf64_Off off, Elf64_Xword old_n_ents, Elf64_Xword new_n_ents,
                 const struct elf_phdrs *phdrs, const struct blob *data,
                 void **ptr_p, Elf64_Xword *out_new_file_size)
{
    if (mementsz == 0 || fileentsz == 0 || ptr_p == NULL ||
        new_n_ents > SIZE_MAX)
    {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    /* Calculate sizes */
    if (old_n_ents > UINT64_MAX / fileentsz
#if SIZE_MAX < UINT64_MAX
        || old_n_ents > SIZE_MAX / entsize
#endif /* SIZE_MAX < UINT64_MAX */
    ) {
        pr_error("%s: Old table size too large (integer overflow)\n", __func__);
        return -1;
    }
    const Elf64_Xword old_total_file_size = old_n_ents * fileentsz;

    if (new_n_ents > UINT64_MAX / fileentsz
#if SIZE_MAX < UINT64_MAX
        || new_n_ents > SIZE_MAX / entsize
#endif /* SIZE_MAX < UINT64_MAX */
    ) {
        pr_error("%s: New table size too large (integer overflow)\n", __func__);
        return 1;
    }
    const Elf64_Xword new_total_file_size = new_n_ents * fileentsz;

    /* Do bounds checks */
    if (data != NULL) {
        if (off > data->size || old_total_file_size > data->size - off) {
            pr_error("The table (at the current location!) "
                     "overflows file data\n");
            return -1;
        }
        if (off > data->size || new_total_file_size > data->size - off) {
            pr_error("The table at the new location "
                     "would overflow file data\n");
            return 1;
        }
    }
    if (phdrs != NULL) {
        if (find_ptload_and_vaddr_from_off(off, new_total_file_size, phdrs,
                                           NULL, NULL))
        {
            pr_error("No single PT_LOAD segment would fully contain the table "
                     "after resizing (to %" PRIu64 " entries)\n", new_n_ents);
            return 1;
        }
    }

    /* Actually realloc (and zero out) the data */

    if (old_n_ents > new_n_ents) {
        memset((uint8_t *)*ptr_p + (new_n_ents * mementsz), 0,
                (old_n_ents - new_n_ents) * mementsz);
    }

    *ptr_p = safe_realloc(ptr_p, (size_t)new_n_ents, mementsz);
    if (*ptr_p == NULL) {
        pr_error("%s: Realloc (to %" PRIu64 " entries) failed\n",
                 __func__, new_n_ents);
        return 1;
    }

    if (new_n_ents > old_n_ents) {
        memset(((uint8_t *)*ptr_p) + (old_n_ents * mementsz), 0,
               (new_n_ents - old_n_ents) * mementsz);
    }

    pr_debug("[%s] Resized table \"%s\" from "
             "0x%" PRIx64 " bytes (%" PRIu64 " entries) to "
             "0x%" PRIx64 " bytes (%" PRIu64 " entries) "
             "with bounds checks: data: %d, ptload: %d\n", __func__, name,
             old_total_file_size, old_n_ents, new_total_file_size, new_n_ents,
             (data != NULL), (phdrs != NULL)
    );
    if (out_new_file_size != NULL) *out_new_file_size = new_total_file_size;
    return 0;
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

int find_unique_dyn_entries(
        const struct elf_dyn_entries *entries, size_t count,
        const Elf64_Sxword *tags /* [count] */, elf_idx_t *out /* [count] */
)
{
    if (count < 1 || tags == NULL || out == NULL || entries == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

    bool ok = true;
    bool all_missing = true;

    for (size_t i = 0; i < count; i++)
        out[i] = ELF_IDX_NULL;

    for (Elf64_Xword i = 0; i < entries->num; i++) {
        const Elf64_Sxword t = entries->arr[i].d_tag;
        for (size_t j = 0; j < count; j++) {
            if (t == tags[j]) {
                all_missing = false;
                if (out[j] != ELF_IDX_NULL) {
                    pr_error("Duplicate dynamic entry %" PRIi64 " (%s)\n",
                             t, dynamic_tag_to_string(t));
                    ok = false;
                }
                out[j] = i;
                break;
            }
        }
    }

    for (size_t i = 0; i < count; i++) {
        if (out[i] == ELF_IDX_NULL) {
            pr_debug("Missing dynamic entry %" PRIi64 " (%s)\n",
                     tags[i], dynamic_tag_to_string(tags[i]));
            ok = false;
        }
    }

    if (ok)
        return 0;
    else
        return all_missing ? 1 : -1;
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
                              Elf64_Addr *out_vaddr, Elf64_Xword *out_align)
{
    Elf64_Addr max_vaddr = 0;
    /* fall back to the standard 4k page size if nothing is found */
    Elf64_Xword max_align = 4096;

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

int find_ptload_and_off_from_vaddr(Elf64_Addr vaddr, Elf64_Xword size,
                                   const struct elf_phdrs *phdrs,
                                   Elf64_Off *out_off,
                                   elf_idx_t *out_pt_load_idx)
{
    if (out_off != NULL) *out_off = 0;
    if (out_pt_load_idx != NULL) *out_pt_load_idx = ELF_IDX_NULL;

    const elf_idx_t ptload_idx = find_containing_mem_ptload(phdrs, vaddr, size);
    if (ptload_idx == ELF_IDX_NULL) {
        pr_error("Given range not inside any PT_LOAD segment\n");
        return 1;
    }
    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];

    const Elf64_Off off_in_load_seg = vaddr - ptload->p_vaddr;
    if (off_in_load_seg > UINT64_MAX - ptload->p_offset) {
        pr_error("Offset in load segment too large (integer overflow)\n");
        return 1;
    }
    const Elf64_Off off = ptload->p_offset + off_in_load_seg;

    if (find_containing_file_ptload(phdrs, off, size) != ptload_idx) {
        pr_error("Given range not file-backed by its PT_LOAD segment\n");
        return 1;
    }

    if (out_off != NULL) *out_off = off;
    if (out_pt_load_idx != NULL) *out_pt_load_idx = ptload_idx;
    return 0;
}

int find_ptload_and_vaddr_from_off(Elf64_Off off, Elf64_Xword size,
                                   const struct elf_phdrs *phdrs,
                                   Elf64_Off *out_vaddr,
                                   elf_idx_t *out_pt_load_idx)
{
    if (out_vaddr != NULL) *out_vaddr = 0;
    if (out_pt_load_idx != NULL) *out_pt_load_idx = ELF_IDX_NULL;

    const elf_idx_t ptload_idx = find_containing_file_ptload(phdrs, off, size);
    if (ptload_idx == ELF_IDX_NULL) {
        pr_error("Given range not inside any PT_LOAD segment\n");
        return 1;
    }
    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];

    const Elf64_Off off_in_load_seg = off - ptload->p_offset;
    if (off_in_load_seg > UINT64_MAX - ptload->p_vaddr) {
        pr_error("Offset in load segment too large (integer overflow)\n");
        return 1;
    }
    const Elf64_Addr vaddr = ptload->p_vaddr + off_in_load_seg;

    if (find_containing_mem_ptload(phdrs, vaddr, size) != ptload_idx) {
        pr_error("Given range not memory-backed by its PT_LOAD segment\n");
        return 1;
    }

    if (out_vaddr != NULL) *out_vaddr = vaddr;
    if (out_pt_load_idx != NULL) *out_pt_load_idx = ptload_idx;
    return 0;
}

elf_idx_t find_unique_shdr_by_type(const struct elf_shdrs *shdrs,
                                   enum shdr_unique_type type)
{
    Elf64_Word sht = SHT_NULL;
    switch (type) {
#define X_(name) case shdr_unique_##name: sht = name; break;
        SHDR_UNIQUE_TYPES_LIST__
#undef X_
        default:
            pr_error("Invalid unique shdr type\n");
            abort();
    }

    for (elf_idx_t i = 0; i < shdrs->num; i++) {
        if (shdrs->arr[i].sh_type == sht)
            return i;
    }

    return ELF_IDX_NULL;
}
