#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include "elf-parsing.h"
#include "elf-patching.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifndef SUS_REPLACEMENT_STRING
#define SUS_REPLACEMENT_STRING "TEST"
#endif /* SUS_REPLACEMENT_STRING */

static int alloc_range(Elf64_Off *off_p, Elf64_Xword size, Elf64_Off *out)
{
    if (*off_p > UINT64_MAX || size > UINT64_MAX - *off_p) {
        pr_error("Can't alloc new range (integer overflow)\n");
        return 1;
    }

    *out = *off_p;
    *off_p += size;
    return 0;
}

static int calculate_new_phsize(const struct elf *elf, int n_new_segments,
                                Elf64_Xword *out);

static int append_new_ptload_segment(struct elf *elf, Elf64_Off end, int flags,
                                     Elf64_Phdr **out);

static int move_program_headers(struct elf *elf,
                                Elf64_Xword new_phsize,
                                const Elf64_Phdr *new_seg,
                                Elf64_Off phdrs_off_in_seg);

static int move_dynstr(struct elf *elf, Elf64_Xword new_dynstr_sz,
                       const Elf64_Phdr *new_seg, Elf64_Off dynstr_off_in_seg);

static void list_sections(const struct elf *elf);

int main(int argc, char **argv)
{
    struct elf elf = { 0 };

    if (argc <= 2) {
        pr_error("Not enough args\n"
                        "Usage: %s <in ELF file> <out ELF file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    /** Parse the ELF **/
    if (read_elf(argv[1], &elf)) goto err;

    if (elf.ehdr.e_phoff > elf.data.size * 3/4) {
        pr_error("WARNING: Program headers are close to the end of the file, "
                 "it might be already patched!\n");
    }

    list_sections(&elf);

    if (elf.dyn.shdr != NULL) {
        printf("Dynamic section name: \"%s\"\n",
                section_name_strptr(&elf, elf.dyn.shdr->sh_name));
    }
    if (elf.dyn.strtab_shdr != NULL) {
        printf("Dynamic string table section name: \"%s\"\n",
                section_name_strptr(&elf, elf.dyn.strtab_shdr->sh_name));
    }

    /** Calculate the amount of needed space in the new segment **/
    Elf64_Off r = 0;
    Elf64_Phdr *first_new_ptload_p = NULL;

#define N_NEW_SEGMENTS 1
    Elf64_Xword new_phsize;
    if (calculate_new_phsize(&elf, N_NEW_SEGMENTS, &new_phsize))
        goto err;

    /* reserve space for the modified phdrs themselves */
    Elf64_Off phdrs_off_in_seg = 0;
    if (alloc_range(&r, new_phsize, &phdrs_off_in_seg))
        goto err;

    const Elf64_Xword old_dynstr_sz = elf.dyn.strtab_sz;
    const Elf64_Xword new_dynstr_sz = sizeof("sus") + old_dynstr_sz;
    Elf64_Addr new_dynstr_off_in_seg;
    if (alloc_range(&r, new_dynstr_sz, &new_dynstr_off_in_seg))
        goto err;


    /** Create the new segment **/
    if (append_new_ptload_segment(&elf, r, PF_R, &first_new_ptload_p))
        goto err;

    /** Modify the data, moving it to the new segment **/
    if (move_dynstr(&elf, new_dynstr_sz,
                     first_new_ptload_p, new_dynstr_off_in_seg))
        goto err;
    memcpy(&elf.data.data[elf.dyn.strtab_off + old_dynstr_sz],
            "sus", sizeof("sus"));

    if (move_program_headers(&elf, new_phsize,
                             first_new_ptload_p, phdrs_off_in_seg))
        goto err;

    /** Re-serialize every structure that was modified **/
    if (serialize_elf(&elf, true))
        goto err;

    /** Validate the newly serialized ELF **/
    printf("Validating patched data... ");
    if (parse_elf(&elf.data, NULL, false)) {
        printf("Sanity check failed\n");
        (void) write_file(argv[2], &elf.data);
        goto err;
    }

    if (write_file(argv[2], &elf.data))
        goto err;

    destroy_elf(&elf);
    return EXIT_SUCCESS;

err:
    destroy_elf(&elf);
    return EXIT_FAILURE;
}

static void list_sections(const struct elf *elf)
{
    for (Elf64_Xword i = 0; i < elf->shdrs.num; i++) {
        const Elf64_Shdr *const shdr = &elf->shdrs.arr[i];

        pr_debug("Section: %-20s \"%s\"\n",
                 section_header_type_toString(shdr->sh_type),
                 section_name_strptr(elf, shdr->sh_name)
        );
    }
}

static int construct_appended_ptload_phdr(const struct elf *elf,
                                          Elf64_Xword total_content_size,
                                          Elf64_Word flags,
                                          Elf64_Phdr *out)
{
    if (elf->phdrs.num >= UINT64_MAX ||
        elf->phdrs.num + 1 > UINT64_MAX / elf->ehdr.e_phentsize ||
        elf->phdrs.num + 1 > SIZE_MAX / sizeof(Elf64_Phdr))
    {
        pr_error("Too many program headers (integer overflow)\n");
        return -1;
    }

    uint64_t new_align = 0;
    uint64_t vaddr = 0;
    /* `read_validate_phdrs` validates that every PT_LOAD's
     * `align` value is a power of two */
    find_load_segment_limits(elf, &vaddr, &new_align);

    if (total_content_size > UINT64_MAX ||
        total_content_size > SIZE_MAX)
    {
        pr_error("New PT_LOAD segment content size too large "
                 "(integer overflow)\n");
        return -1;
    }

    const uint64_t new_ptload_vaddr = align_pow2(vaddr, new_align);
    const uint64_t new_ptload_size = align_pow2(total_content_size, new_align);

    /* new *file* offset */
    const Elf64_Off new_ptload_off = align_pow2(elf->data.size, new_align);

    *out = (Elf64_Phdr) {
        .p_type = PT_LOAD,
        .p_flags = flags,
        .p_offset = new_ptload_off,
        .p_vaddr = new_ptload_vaddr,
        .p_paddr = new_ptload_vaddr,
        .p_filesz = total_content_size,
        .p_memsz = new_ptload_size,
        .p_align = new_align
    };
    pr_debug("[%s] New PT_LOAD off: 0x%" PRIx64 ", vaddr: 0x%" PRIx64 ", "
                "size: 0x%" PRIx64 ", align: 0x%" PRIx64 "\n", __func__,
            new_ptload_off, new_ptload_vaddr,
            new_ptload_size, new_align);

    return 0;
}

static int update_phdr_tbl_location(struct elf *elf, Elf64_Addr new_addr)
{
    pr_debug("[%s] new_addr: 0x%" PRIx64 "\n", __func__, new_addr);

    const Elf64_Phdr *ptload = get_load_segment_containing_range(
            elf->phdrs.arr, elf->phdrs.num,
            new_addr, elf->phdrs.size
    );
    if (ptload == NULL) {
        pr_error("New program header location not inside any PT_LOAD segment\n");
        return -1;
    }

    const Elf64_Xword phsize = elf->phdrs.size;

    const Elf64_Off off_in_seg = new_addr - ptload->p_vaddr;
    const Elf64_Off off_in_file = ptload->p_offset + off_in_seg;
    if (phsize > elf->data.size ||
        off_in_file > elf->data.size - phsize)
    {
        pr_error("New program header location would overflow file data\n");
        return -1;
    }

    /* Update the ELF header */
    elf->ehdr.e_phoff = off_in_file;

    /* Update the "self-reference" PT_PHDR if it exists */
    for (Elf64_Xword i = 0; i < elf->phdrs.num; i++) {
        Elf64_Phdr *const phdr = &elf->phdrs.arr[i];
        if (phdr->p_type != PT_PHDR)
            continue;

        phdr->p_offset = off_in_file;
        phdr->p_filesz = phsize;
        phdr->p_memsz = phsize;
        phdr->p_vaddr = new_addr;
        phdr->p_paddr = new_addr;
    }

    elf->phdrs.dirty = true;
    elf->ehdr_dirty = true;
    return 0;
}

static int prepare_elf_data_for_rewrite(bool wipe, struct blob *data,
                                        Elf64_Off src_off, Elf64_Xword src_size,
                                        Elf64_Off dst_off, Elf64_Xword dst_size)
{
    if (src_size > data->size || src_off > data->size - src_size) {
        pr_error("Source range overflows data buffer\n");
        return -1;
    }

    if (dst_size > SIZE_MAX || dst_off > SIZE_MAX - dst_size ||
        dst_size > UINT64_MAX || dst_off > UINT64_MAX - dst_size)
    {
        pr_error("Destination range too large (integer overflow)\n");
        return -1;
    }

    const Elf64_Off src_end = src_off + src_size;
    const Elf64_Off dst_end = dst_off + dst_size;

    if (dst_end > data->size) {
        if ((data->data = safe_realloc((void **)&data->data, dst_end, 1))
                == NULL)
        {
            pr_error("Failed to grow (realloc) the ELF file data\n");
            return 1;
        }
        pr_debug("[%s] Grew data from 0x%" PRIx64 " to 0x%" PRIx64 "\n",
                 __func__, data->size, dst_end);
        /* zero out the newly allocated block */
        memset(data->data + data->size, 0, dst_end - data->size);
        data->size = dst_end;
    }

    if (wipe) {
        memset(data->data + dst_off, 0, dst_size);
    } else {
        memmove(data->data + dst_off, data->data + src_off,
                u_min(src_size, dst_size));
    }

    /* Clean up the old data */
    {
        Elf64_Off clean_start, clean_end;
        if (dst_end > src_end) {
            /* moving "to the right" */
            clean_start = src_off;
            clean_end = u_min(src_end, dst_off);
        } else /* if (new_end <= old_end) */ {
            /* moving "to the left" */
            clean_start = u_max(src_end, dst_off);
            clean_end = dst_end;
        }

        Elf64_Off off = clean_start;
        while (off < clean_end) {
            const size_t n = u_min(clean_end - off,
                                    sizeof(SUS_REPLACEMENT_STRING) - 1);
            memcpy(data->data + off, SUS_REPLACEMENT_STRING, n);
            off += n;
        }

        pr_debug("[%s] Cleaned range <0x%" PRIx64 ", 0x%" PRIx64 ">\n",
                 __func__, clean_start, clean_end);
    }

    pr_debug("[%s] Prepared for move & reserialization "
             "from <0x%" PRIX64 ", 0x%" PRIx64"> "
             "to <0x%" PRIx64 ", 0x%" PRIx64 ">\n",
             __func__, src_off, src_end, dst_off, dst_end);

    return 0;
}

static int calculate_new_phsize(const struct elf *elf, int n_new_segments,
                                Elf64_Xword *out)
{
    if (elf->phdrs.num > UINT64_MAX - n_new_segments ||
        (elf->phdrs.num + n_new_segments) >
            UINT64_MAX / elf->orig.ehdr.e_phentsize)
    {
        pr_error("New program header table size too large "
                "(integer overflow)\n");
        return 1;
    }

    *out = (elf->phdrs.num + n_new_segments) * elf->orig.ehdr.e_phentsize;
    return 0;
}

static int append_new_ptload_segment(struct elf *elf, Elf64_Off end, int flags,
                                     Elf64_Phdr **out)
{
    *out = NULL;

    if (elf->phdrs.num == UINT64_MAX) {
        pr_error("Can't add another program header (integer overflow)\n");
        return 1;
    }

    const Elf64_Xword new_phnum = elf->phdrs.num + 1;
    const Elf64_Half phentsize = elf->orig.ehdr.e_phentsize;

    if (update_phnum(&elf->phdrs, new_phnum, phentsize,
                     &elf->ehdr.e_phnum, &elf->shdrs))
    {
        pr_error("Failed to grow the program headers array\n");
        return 1;
    }

    Elf64_Phdr *const new_ptload_p = &elf->phdrs.arr[new_phnum - 1];
    if (construct_appended_ptload_phdr(elf, end, flags, new_ptload_p)) {
        pr_error("Failed to construct a new PT_LOAD segment header\n");
        return 1;
    }

    *out = new_ptload_p;
    return 0;
}

static int move_program_headers(struct elf *elf,
                                Elf64_Xword new_phsize,
                                const Elf64_Phdr *new_seg,
                                Elf64_Off phdrs_off_in_seg)
{
    pr_debug("new_phsize: %" PRIu64 " (num: %" PRIu64 ")\n",
             new_phsize, new_phsize / elf->ehdr.e_phentsize);

    const Elf64_Off old_phoff = elf->orig.ehdr.e_phoff;
    const Elf64_Off new_phoff = new_seg->p_offset + phdrs_off_in_seg;

    if (prepare_elf_data_for_rewrite(true, &elf->data, old_phoff,
                                    elf->orig.phsize, new_phoff, new_phsize))
    {
        pr_error("Failed to prepare the program header data "
                "for moving and reserialization");
        return 1;
    }

    const Elf64_Addr new_ph_vaddr = new_seg->p_vaddr + phdrs_off_in_seg;
    if (update_phdr_tbl_location(elf, new_ph_vaddr)) {
        pr_error("Failed to update the program header table location");
        return 1;
    }

    return 0;
}

static int move_dynstr(struct elf *elf, Elf64_Xword new_dynstr_sz,
                       const Elf64_Phdr *new_seg, Elf64_Off dynstr_off_in_seg)
{
    pr_debug("new_dynstr_sz: %" PRIu64 "\n", new_dynstr_sz);

    const Elf64_Off old_off = elf->orig.dyn_strtab_off;
    const Elf64_Xword old_size = elf->orig.dyn_strtab_sz;

    const Elf64_Off new_off = new_seg->p_offset + dynstr_off_in_seg;

    if (prepare_elf_data_for_rewrite(false, &elf->data, old_off, old_size,
                                     new_off, new_dynstr_sz))
    {
        pr_error("Failed to prepare & move the dynamic string table data\n");
        return 1;
    }

    const Elf64_Addr new_vaddr = new_seg->p_vaddr + dynstr_off_in_seg;
    if (update_dynstr_range(new_vaddr, new_dynstr_sz,
                            &elf->dyn, &elf->shdrs, &elf->phdrs))
    {
        pr_error("Failed to update the dynamic string table location\n");
        return 1;
    }

    return 0;
}
