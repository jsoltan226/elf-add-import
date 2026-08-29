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

/**
 * @file The main file.
 *  Here resides the core logic of the modifications.
 *  All other files contain helpers and utilities used here.
 */

#ifndef SUS_REPLACEMENT_STRING
#define SUS_REPLACEMENT_STRING "TEST"
#endif /* SUS_REPLACEMENT_STRING */

/**
 * Prints out a list of the sections present in `elf`, if any.
 *
 * @param[in] elf The ELF context. Must not be NULL.
 */
static void list_sections(const struct elf *elf);

/**
 * @struct Context for the modifications done to an ELF file in `main`.
 */
struct mod_ctx {
    /**
     * The modified data will be moved to new segments, appended to the end
     * of the file and address space. The data is layed out as follows:
     *
     * - [...] Original ELF segments
     * - New Segment 1: Read-only
     *   1) Program headers
     *   2) Dynamic string table (.dynstr)
     */
#define N_NEW_SEGMENTS 1

    /**
     * Anything that will be contained in the first (read-only) segment
     */
    struct first_new_ptload {
        /**
         * The new segment's header; a reference into `elf->phdrs`.
         */
        Elf64_Phdr *phdr_p;

        /** Offset of the new phdr table in the new segment. Typically 0. */
        Elf64_Off new_phoff_in_seg;
        Elf64_Xword new_phsize; /**< New size of the program header table. */

        /** Offset of the new dynamic string table in the new segment. */
        Elf64_Off new_dynstr_off_in_seg;
        Elf64_Xword new_dynstr_sz; /**< New size of the dynamic string table. */

    } first_new_ptload; /**< Contents of the first (read-only) new segment. */
};

/**
 * Performs all size calculations for the new modified data
 * and allocates the new segments, populating the modifications context
 * in preparation for `perform_modifications`.
 *
 * @param[in,out] elf The ELF context. Must not be NULL.
 *
 * @param[out] out The modifications context to populate. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int prepare_modifications(struct elf *elf, struct mod_ctx *out);

/**
 * Calculates the new program header table size in advance,
 * based on how many new segments will be needed.
 * Part of `prepare_modifications`.
 *
 * @param[in] elf The ELF context. Must not be NULL.
 *
 * @param[in] n_new_segments The number of new segments that will be needed.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero in case of integer overflow.
 */
static int calculate_new_phsize(const struct elf *elf, int n_new_segments,
                                Elf64_Xword *out);

/**
 * Allocates and appends a new PT_LOAD segment.
 * Part of `prepare_modifications`.
 *
 * @param[in,out] elf The ELF context. Must not be NULL.
 *
 * @param[in] end The calculated offset of last byte of the new segment.
 *
 * @param[in] flags The flags of the new segment (e.g. `PF_R | PF_X`).
 *
 * @param[out] out_idx Output pointer for the index of the newly allocated
 *  program header; a reference into `elf->phdrs`. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int append_new_ptload_segment(struct elf *elf, Elf64_Off end, int flags,
                                     Elf64_Xword *out_idx);

/**
 * Performs the modifications calculated by `prepare_modifications`.
 *
 * Data which can be easily moved (such as string tables) is directly copied
 * into the new segments, while for the complex structures
 * the modifications are done in the in-memory representations in `elf`
 * and space is prepared in `elf->data` to be filled out be `serialize_elf`.
 *
 * @param[in,out] elf The ELF context. Must not be NULL.
 *
 * @param[in] ctx The modifications context. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int perform_modifications(struct elf *elf, const struct mod_ctx *ctx);

/**
 * Updates the location of the program headers, allocates new space for them
 * and erases the bytes at the old offset.
 *
 * This function only prepares space for the new bytes;
 * they are be written during `serialize_elf`.
 * Part of `perform_modifications`.
 *
 * @param[in,out] elf The ELF context. Must not be NULL.
 *
 * @param[in] new_seg The new first (read-only) PT_LOAD segment program header.
 *  Must not be NULL.
 *
 * @param[in] new_phoff_in_seg The previously calculated phdrs table's offset
 *  within the new segment (usually 0 as they are added first).
 *
 * @param[in] new_phsize The calculated new size of the program header table.
 *
 * @return 0 on success, non-zero on failure.
 */
static int move_program_headers(
        struct elf *elf, const Elf64_Phdr *new_seg,
        Elf64_Off new_phoff_in_seg, Elf64_Xword new_phsize
);

/**
 * Allocates new space for the dynstr section, moves the data there
 * erasing the old bytes and adds a test modification at the end.
 *
 * The data is just a string table, so it's moved directly in this function
 * and won't be further populated by `serialize_elf`.
 * Part of `perform_modifications`.
 *
 * @param[in,out] elf The ELF context. Must not be NULL.
 *
 * @param[in] new_seg The new first (read-only) PT_LOAD segment program header.
 *  Must not be NULL.
 *
 * @param[in] new_dynstr_off_in_seg The previously calculated
 *  dynamic string table's (".dynstr"'s) offset within the new segment.
 *
 * @param[in] new_dynstr_sz The calculated new size of the
 *  dynamic string table (".dynstr").
 *
 * @return 0 on success, non-zero on failure.
 */
static int grow_move_modify_dynstr(
        struct elf *elf, const Elf64_Phdr *new_seg,
        Elf64_Off new_dynstr_off_in_seg, Elf64_Xword new_dynstr_sz
);

/**
 * Cleans up the modifications context.
 *
 * @param[in,out] ctx The context to clean up.
 */
static void destroy_modifications(struct mod_ctx *ctx);

/**
 * Constructs a new PT_LOAD segment
 * at the end of the file and address space (after the last segment) of `elf`.
 *
 * @param[in] elf The ELF file context. Must not be NULL.
 *
 * @param[in] total_content_size
 *  The total size of the content of the new segment.
 *
 * @param[in] flags The flags of the new segment (e.g. `PF_R | PF_W`).
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int construct_appended_ptload_phdr(const struct elf *elf,
        Elf64_Xword total_content_size, Elf64_Word flags, Elf64_Phdr *out);

/**
 * Moves and/or wipes bytes, growing `data` if needed.
 * The core of `perform_modifications`.
 *
 * For data that can be directly moved like string tables, set `wipe` to `false`
 * and space for the new bytes will be prepared and populated
 * with the original contents via `memmove`.
 *
 * For complex structures that require reserialization, set `wipe` to `true`
 * and the space for the new bytes will be prepared and cleaned,
 * to be populated by `serialize_elf`.
 *
 * In either case, the old bytes are replaced with a repeating pattern
 * (`SUS_REPLACEMENT_STRING`).
 *
 * @param[in] wipe Whether to move or wipe the data.
 *
 * @param[in,out] data The data buffer to process. Must not be NULL.
 *
 * @param[in] src_off Start of the original data range,
 *  which must be contained within the bounds of `data`.
 *
 * @param[in] src_size Size (length) of the original data range,
 *  which must be contained within the bounds of `data`.
 *
 * @param[in] dst_off Start of the new data range.
 *  May overflow `data`, which in that case will be expanded accordingly.
 *
 * @param[in] dst_size Size (length) of the original data range.
 *  May overflow `data`, which in that case will be expanded accordingly.
 *
 * @return 0 on success, non-zero on failure.
 */
static int prepare_move_data(bool wipe, struct blob *data,
                             Elf64_Off src_off, Elf64_Xword src_size,
                             Elf64_Off dst_off, Elf64_Xword dst_size);

int main(int argc, char **argv)
{

    if (argc <= 2) {
        pr_error("Not enough args\n"
                        "Usage: %s <in ELF file> <out ELF file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    /** Parse the ELF **/
    struct elf elf = { 0 };
    {
        if (read_elf(argv[1], &elf)) goto err;

        if (elf.ehdr.e_phoff > elf.data.size * 3/4) {
            pr_error("WARNING: Program headers are close to the end "
                     "of the file, it might be already patched!\n");
        }
        list_sections(&elf);
    }

    /** Modify the ELF **/
    {
        /** Calculate where we want to move the modified data as well as
         * how large it is, then create new PT_LOAD segments for it */
        struct mod_ctx m = { 0 };
        if (prepare_modifications(&elf, &m)) {
            destroy_modifications(&m);
            goto err;
        }

        /** Based on the previous calculations, move the data to the new segments
         * and modify it */
        if (perform_modifications(&elf, &m)) {
            destroy_modifications(&m);
            goto err;
        }

        destroy_modifications(&m);

        /** Re-serialize every structure that was modified **/
        if (serialize_elf(&elf, true))
            goto err;
    }

    /** Validate the newly serialized ELF **/
    {
        printf("Validating patched data... ");
        if (parse_elf(&elf.data, NULL, false)) {
            printf("Sanity check failed\n");
            (void) write_file(argv[2], &elf.data);
            goto err;
        }
    }

    /** Write the result and clean up **/
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

    if (elf->dyn.shdr != NULL) {
        printf("Dynamic section name: \"%s\"\n",
                section_name_strptr(elf, elf->dyn.shdr->sh_name));
    }
    if (elf->dyn.strtab_shdr != NULL) {
        printf("Dynamic string table section name: \"%s\"\n",
                section_name_strptr(elf, elf->dyn.strtab_shdr->sh_name));
    }
}

static int prepare_modifications(struct elf *elf, struct mod_ctx *out)
{
    memset(out, 0, sizeof(struct mod_ctx));


    Elf64_Xword new_phsize;
    if (calculate_new_phsize(elf, N_NEW_SEGMENTS, &new_phsize))
        return 1;

    /* The first segment (read-only) */
    Elf64_Xword first_ptload_idx = -1;
    {
        Elf64_Off r = 0;

        /* 1) The phdrs themselves */
        Elf64_Off phdrs_off_in_seg = 0;
        if (reserve_range(&r, new_phsize, &phdrs_off_in_seg))
            return 1;

        /* 2) The .dynstr section */
        const Elf64_Xword old_dynstr_sz = elf->orig.dyn_strtab_sz;
        const Elf64_Xword new_dynstr_sz = sizeof("sus") + old_dynstr_sz;
        Elf64_Addr new_dynstr_off_in_seg;
        if (reserve_range(&r, new_dynstr_sz, &new_dynstr_off_in_seg))
            return 1;

        /** Create the new segment **/
        if (append_new_ptload_segment(elf, r, PF_R, &first_ptload_idx))
            return 1;

        out->first_new_ptload = (struct first_new_ptload) {
            .new_phoff_in_seg = phdrs_off_in_seg,
            .new_phsize = new_phsize,

            .new_dynstr_off_in_seg = new_dynstr_off_in_seg,
            .new_dynstr_sz = new_dynstr_sz
        };
    }

    out->first_new_ptload.phdr_p = &elf->phdrs.arr[first_ptload_idx];

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
                                     Elf64_Xword *out_idx)
{
    *out_idx = -1;

    if (elf->phdrs.num == UINT64_MAX) {
        pr_error("Can't add another program header (integer overflow)\n");
        return 1;
    }

    const Elf64_Xword new_phnum = elf->phdrs.num + 1;
    if (update_phnum(elf, new_phnum)) {
        pr_error("Failed to grow the program headers array\n");
        return 1;
    }

    Elf64_Phdr *const new_ptload_p = &elf->phdrs.arr[new_phnum - 1];
    if (construct_appended_ptload_phdr(elf, end, flags, new_ptload_p)) {
        pr_error("Failed to construct a new PT_LOAD segment header\n");
        return 1;
    }

    *out_idx = new_phnum - 1;
    return 0;
}

static int perform_modifications(struct elf *elf, const struct mod_ctx *ctx)
{
    /** Modify the data, moving it to the new segment **/

    /* The first segment (read-only) */
    {
        const struct first_new_ptload *const f = &ctx->first_new_ptload;

        /* 1) The phdrs */
        if (move_program_headers(elf, f->phdr_p,
                                 f->new_phoff_in_seg, f->new_phsize))
            return 1;

        /* 2) The .dynstr section */
        if (grow_move_modify_dynstr(elf, f->phdr_p,
                                    f->new_dynstr_off_in_seg, f->new_dynstr_sz))
            return 1;
    }

    return 0;
}

static int move_program_headers(
        struct elf *elf, const Elf64_Phdr *new_seg,
        Elf64_Off new_phoff_in_seg, Elf64_Xword new_phsize
)
{
    pr_debug("new_phsize: %" PRIu64 " (num: %" PRIu64 ")\n",
             new_phsize, new_phsize / elf->orig.ehdr.e_phentsize);

    const Elf64_Off old_phoff = elf->orig.ehdr.e_phoff;
    const Elf64_Off new_phoff = new_seg->p_offset + new_phoff_in_seg;

    if (prepare_move_data(true, &elf->data,
                          old_phoff, elf->orig.phsize, new_phoff, new_phsize))
    {
        pr_error("Failed to prepare the program header data "
                "for moving and reserialization");
        return 1;
    }

    if (update_phoff(elf, new_phoff)) {
        pr_error("Failed to update the program header table location");
        return 1;
    }

    return 0;
}

static int grow_move_modify_dynstr(
        struct elf *elf, const Elf64_Phdr *new_seg,
        Elf64_Off new_dynstr_off_in_seg, Elf64_Xword new_dynstr_sz
)
{
    pr_debug("new_dynstr_sz: %" PRIu64 "\n", new_dynstr_sz);

    const Elf64_Off old_off = elf->orig.dyn_strtab_off;
    const Elf64_Xword old_size = elf->orig.dyn_strtab_sz;

    const Elf64_Off new_off = new_seg->p_offset + new_dynstr_off_in_seg;
    const Elf64_Addr new_vaddr = new_seg->p_vaddr + new_dynstr_off_in_seg;

    if (prepare_move_data(false, &elf->data,
                          old_off, old_size, new_off, new_dynstr_sz))
    {
        pr_error("Failed to prepare & move the dynamic string table data\n");
        return 1;
    }

    if (update_dynstr_range(elf, new_vaddr, new_dynstr_sz)) {
        pr_error("Failed to update the dynamic string table location\n");
        return 1;
    }

    memcpy(&elf->data.data[new_off + old_size], "sus", sizeof("sus"));

    return 0;
}

static void destroy_modifications(struct mod_ctx *ctx)
{
    if (ctx == NULL)
        return;

    /* right now `ctx` contains only references to `elf`,
     * it doesn't actually own any resources */
    memset(ctx, 0, sizeof(struct mod_ctx));
}

static int construct_appended_ptload_phdr(const struct elf *elf,
        Elf64_Xword total_content_size, Elf64_Word flags, Elf64_Phdr *out)
{
    if (elf->phdrs.num >= UINT64_MAX ||
        elf->phdrs.num + 1 > UINT64_MAX / elf->orig.ehdr.e_phentsize ||
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

static int prepare_move_data(bool wipe, struct blob *data,
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
