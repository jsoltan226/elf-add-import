#include "ctx.h"
#include "elf-dyn-parsing.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include "elf-parsing.h"
#include "elf-patching.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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
     *   3) _DYNAMIC entry table (if needed)
     */
#define N_NEW_SEGMENTS 1

    /**
     * Anything that will be contained in the first (read-only) segment
     */
    struct first_new_ptload {
        /**
         * The new segment's header; a reference into `elf->phdrs`.
         */
        elf_idx_t phdr;

        /** Offset of the new phdr table in the new segment. Typically 0. */
        Elf64_Off new_phoff_in_seg;
        Elf64_Xword new_phsize; /**< New size of the program header table. */

        /** Offset of the new dynamic string table in the new segment. */
        Elf64_Off new_dynstr_off_in_seg;
        Elf64_Xword new_dynstr_sz; /**< New size of the dynamic string table. */

        /**
         * Whether the PT_DYNAMIC dynamic entries table needs to be moved
         * (sometimes there's enough slack space at the end which enables
         * adding entries without having to grow the segment itself)
         */
        bool dyn_tbl_move_required;
        /**
         * If `dyn_tbl_move_required`, the offset of the new dynamic table
         * within the new PT_LOAD segment.
         */
        Elf64_Off new_dyn_tbl_off_in_seg;
        /** If `dyn_tbl_move_required`, the size of the new dynamic table. */
        Elf64_Xword new_dyn_tbl_sz;

    } first_new_ptload; /**< Contents of the first (read-only) new segment. */

    /** All other metadata **/

    /**
     * Addidtional intermediate modifications state.
     *
     * This should store the data that cannot just be passed as simple offsets
     * or indices and must instead be dynamically allocated and prepared.
     */
    struct mod_state {
        struct dyn_mod_state {
            /**
             * The number of spare DT_NULL entries at the end of the _DYNAMIC array
             * which can be replaced without needing to grow the entire segment.
             */
            Elf64_Xword n_spare_entries;

            struct dynstr_mod_state {
                Elf64_Xword *str_offsets;
                Elf64_Xword n_str_offsets;
            } dynstr;

            struct dyn_tbl_mod_state {
                /**
                 * Array of new _DYNAMIC entries which are to be appended to the array.
                 */
                Elf64_Dyn *new_entries;
                Elf64_Xword n_new_entries; /**< Count of new _DYNAMIC entries. */
            } tbl;
        } dyn; /**< Intermediate dynamic section modifications state. */
    } state; /**< Intermediate modifications state. */
};

/**
 * @struct Configuration info for the `mod_ctx` struct.
 */
struct mod_cfg {
    /** Configuration data for the dynamic string table modifications. */
    struct dynstr_mod_cfg {
        /**
         * An array with `n_strings` members which contains strings
         * to be appended to the dynamic string table.
         */
        const char **strings;
        Elf64_Xword n_strings; /**< Count of strings to append to .dynstr. */
    } dynstr; /**< dynstr modifications info. */

    /** Configuration data for the DT_* _DYNAMIC table modifications. */
    struct dyn_entries_mod_cfg {
        /** Configuration data for a single DT_* dynamic entry. */
        struct dyn_entry_cfg {
            /**
             * The DT_* tag (type) of the new entry.
             * Currently supported:
             *  - DT_NEEDED
             */
            Elf64_Sxword tag;

            union dyn_entry_val_u {
                /**
                 * An index into the `dynstr.strings` array.
                 * The new entry's `d_un.d_ptr` value will be set to point
                 * to the place where `dynstr.strings[str_idx]` was appended.
                 * Used with:
                 *  - DT_NEEDED
                 */
                Elf64_Xword str_idx;
            } val; /**< Info about the desired value of the new entry. */

        } *arr; /**< Array of new DT_* entries to append. */
        Elf64_Xword num; /**< Count of new DT_* entries to append. */
    } entries; /**< _DYNAMIC entries modifications info */
};

/**
 * Validates a user-specified modifications configuration.
 *
 * @param[in] cfg The configuration to validate.
 *
 * @return 0 if the configuration is valid, non-zero otherwise.
 */
static int validate_mod_cfg(const struct mod_cfg *cfg);

/**
 * Performs all size calculations for the new modified data
 * and allocates the new segments, populating the modifications context
 * in preparation for `perform_modifications`.
 *
 * @param[in] cfg The configuration info based on which
 *  the modifications are to be done. Must not be NULL.
 *
 * @param[in,out] elf The ELF context. Must not be NULL.
 *
 * @param[out] out The modifications context to populate. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int prepare_modifications(const struct mod_cfg *cfg,
                                 struct elf *elf, struct mod_ctx *out);

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
 * Calculates the new _DYNAMIC table's size as well as whether it can be
 * modified in place (if there are enough free `DT_NULL` entries at the end),
 * based on the user's configuration.
 * Part of `prepare_modifications`.
 *
 * @param[in] elf The ELF context. Must not be NULL.
 *
 * @param[in] cfg Valid user configuration. Must not be NULL.
 *
 * @param[out] out_move_required Output pointer for whether the _DYNAMIC table
 *  needs to be grown & moved (`true`) or can be modified in-place (`false`).
 *  Must not be NULL.
 *
 * @param[out] out_new_size If `*out_move_required == true`,
 *  output pointer for the new file size of the _DYNAMIC table.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int calculate_dyn_tbl_mod(
        const struct elf *elf, const struct mod_cfg *cfg,
        bool *out_move_required, Elf64_Xword *out_new_size
);

/**
 * Based on the current size of the string table,
 * calculates where the user's new strings will be appended
 * and stores that information so that it can be later used to populate
 * new dynamic entries in `perform_modifications`.
 * Part of `prepare_modifications`.
 *
 * @param[in] cfg Valid user-specified modifications configuration
 *  containing the strings to be later appended to the dynamic string table.
 *  Must not be NULL.
 *
 * @param[in] old_strtab_sz The previous size of the dynamic string table
 *  (before any modifications).
 *
 * @param[out] out_new_sz Output pointer for the new size of `.dynstr`
 *  (set to `old_strtab_sz + <sum of (strlen(...cfg->strings) + 1)>`).
 *  Must not be NULL.
 *
 * @param[out] out The intermediate state to be populated
 *  (the to-be-appended strings' offsets). Must not be NULL.
 */
static int prepare_dynstr_offsets(
        const struct mod_cfg *cfg, Elf64_Off old_strtab_sz,
        Elf64_Xword *out_new_sz, struct dynstr_mod_state *out
);

/**
 * Resolves the contents of new dynamic entries based on
 * previously computed data and the user's configuration.
 * Part of `prepare_modifications`.
 *
 * @param[in] cfg Valid user-specified modifications configuration
 *  containing information to be resolved into dynamic entries.
 *  Must not be NULL.
 *
 * @param[in] dynstr_state Previously computed dynamic string table state
 *  (see `prepare_dynstr_offsets`). Must not be NULL.
 *
 * @param[out] out The intermediate state to be populated
 *  (the new _DYNAMIC entries). Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int prepare_dyn_entries(
        const struct mod_cfg *cfg,
        const struct dynstr_mod_state *dynstr_state,
        struct dyn_tbl_mod_state *out
);

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
 * @param[in] cfg The user-specified configuration of the modifications
 *  to be performed. Must be the exact same one that was passed to
 *  `prepare_modifications`. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int perform_modifications(struct elf *elf, const struct mod_ctx *ctx,
                                 const struct mod_cfg *cfg);

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
 * erasing the old bytes and appends whatever is specified in the mod config.
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
 * @param[in] state Intermediate dynstr modifications state,
 *  populated by `prepare_dynstr_offsets`. Must not be NULL.
 *
 * @param[in] cfg User-specified configuration information, previously
 *  validated by `validate_mod_cfg`, containing the strings to be appended.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int grow_move_modify_dynstr(
        struct elf *elf, const Elf64_Phdr *new_seg,
        Elf64_Off new_dynstr_off_in_seg, Elf64_Xword new_dynstr_sz,
        const struct dynstr_mod_state *state,
        const struct dynstr_mod_cfg *cfg
);

/**
 * Based on the state computed in `prepare_modifications`:
 *  - If needed, moves the dynamic table to the new segment & grows it,
 *  - Resolves the entries' contents and appends them to the end of the table.
 *
 * Part of `perform_modifications`.
 *
 * @param[in,out] elf The ELF context. Must not be NULL.
 *
 * @param[in] new_seg The new first (read-only) PT_LOAD segment program header.
 *  Must not be NULL.
 *
 * @param[in] new_dyn_tbl_off_in_seg The previously calculated
 *  dynamic table's offset within the new segment.
 *
 * @param[in] new_dyn_tbl_sz The previously calculated
 *  dynamic table's new file size.
 *
 * @param[in] move_required A flag indicating whether the table needs to be
 *  resized & moved. Set to `false` if there are enough slack `DT_NULL`s
 *  already present at the end of the table which can be replaced to acommodate
 *  the new entries. Set to `true` otherwise.
 *
 * @param[in] state Intermediate _DYNAMIC table modifications state,
 *  containing the to-be-appended new dynamic entries' contents,
 *  previously populated by `prepare_dyn_entries`. Must not be NULL.
 */
static int add_new_dynamic_entries(
        struct elf *elf, const Elf64_Phdr *new_seg,
        Elf64_Off new_dyn_tbl_off_in_seg, Elf64_Xword new_dyn_tbl_sz,
        bool move_required, const struct dyn_tbl_mod_state *state
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

#if 0
        if (parse_dynsym(&elf.data, elf.ident.clazz, elf.ident.data,
                         &elf.phdrs, &elf.shdrs, &elf.dyn.entries))
            goto err;
#endif /* 0 */
    }

    const struct mod_cfg cfg = {
        .dynstr = {
            .n_strings = 1,
            .strings = (const char *[]) {
                (elf.ident.clazz == ELFCLASS32) ?
                    "bin/libsus32.so" :
                    "bin/libsus.so"
            }
        },
        .entries = {
            .num = 1,
            .arr = &(struct dyn_entry_cfg) {
                    .tag = DT_NEEDED,
                    .val.str_idx = 0
             }
        }
    };

    /** Modify the ELF **/
    {
        /** Calculate where we want to move the modified data as well as
         * how large it is, then create new PT_LOAD segments for it */
        struct mod_ctx m = { 0 };
        if (prepare_modifications(&cfg, &elf, &m)) {
            destroy_modifications(&m);
            goto err;
        }

        /** Based on the previous calculations, move the data to the new segments
         * and modify it */
        if (perform_modifications(&elf, &m, &cfg)) {
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
            /* write the corrupted file anyway for inspection */
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
    for (elf_idx_t i = 0; i < elf->shdrs.num; i++) {
        const Elf64_Shdr *const shdr = get_shdr_ro(elf, i);

        pr_debug("Section: %-20s \"%s\"\n",
                 section_header_type_toString(shdr->sh_type),
                 section_name_strptr(elf, shdr->sh_name)
        );
    }

    if (elf->dyn.shdr != ELF_IDX_NULL) {
        const Elf64_Shdr *const shdr = get_shdr_ro(elf, elf->dyn.shdr);
        printf("Dynamic section name: \"%s\"\n",
                section_name_strptr(elf, shdr->sh_name));
    }
    if (elf->dyn.strtab.shdr != ELF_IDX_NULL) {
        const Elf64_Shdr *const shdr = get_shdr_ro(elf, elf->dyn.strtab.shdr);
        printf("Dynamic string table section name: \"%s\"\n",
                section_name_strptr(elf, shdr->sh_name));
    }
}

static int validate_mod_cfg(const struct mod_cfg *cfg)
{
    if (cfg == NULL) {
        pr_error("Mod config is NULL\n");
        return -1;
    }

    if (cfg->dynstr.strings == NULL && cfg->dynstr.n_strings > 0) {
        pr_error("New dynstr strings array is NULL while count > 0\n");
        return 1;
    }
    if (cfg->entries.arr == NULL && cfg->entries.num > 0) {
        pr_error("New dynamic entries array is NULL while count > 0\n");
        return 1;
    }

    if (cfg->entries.num > SIZE_MAX || cfg->dynstr.n_strings > SIZE_MAX) {
        pr_error("Number of array members too large (integer overflow)\n");
        return 1;
    }

    for (Elf64_Xword i = 0; i < cfg->dynstr.n_strings; i++) {
        if (cfg->dynstr.strings[i] == NULL) {
            pr_error("String @ idx %" PRIu64 " is NULL\n", i);
            return 1;
        }
    }

    for (Elf64_Xword i = 0; i < cfg->entries.num; i++) {
        const struct dyn_entry_cfg *const curr = &cfg->entries.arr[i];

        switch (curr->tag) {
            case DT_NEEDED:
                if (curr->val.str_idx >= cfg->dynstr.n_strings) {
                    pr_error("Entry @ idx %" PRIu64 " (tag: %s): "
                             "Invalid string table index\n",
                             i, dynamic_tag_to_string(curr->tag));
                    return 1;
                }
                break;
            default:
                pr_error("Unsupported dynamic tag: %s\n",
                         dynamic_tag_to_string(curr->tag));
                return 1;
        }
    }

    return 0;
}

static int prepare_modifications(const struct mod_cfg *cfg,
                                 struct elf *elf, struct mod_ctx *out)
{
    memset(out, 0, sizeof(struct mod_ctx));

    if (validate_mod_cfg(cfg)) {
        pr_error("Invalid modifications configuration data\n");
        return -1;
    }

    /* Calculate the sizes and prepare state
     * for `perform_modifications` (`out->state`) */
    Elf64_Xword new_phsize = 0;
    bool dyn_tbl_move_needed = false;
    Elf64_Xword new_dyn_tbl_sz = 0;
    Elf64_Xword new_dynstr_sz = 0;
    {
        if (calculate_new_phsize(elf, N_NEW_SEGMENTS, &new_phsize))
            return 1;

        if (calculate_dyn_tbl_mod(elf, cfg,
                    &dyn_tbl_move_needed, &new_dyn_tbl_sz))
            return 1;

        if (prepare_dynstr_offsets(cfg, elf->dyn.strtab.size,
                                   &new_dynstr_sz, &out->state.dyn.dynstr))
            return 1;

        if (prepare_dyn_entries(cfg, &out->state.dyn.dynstr,
                                &out->state.dyn.tbl))
            return 1;
    }

    /* The first segment (read-only) */
    {
        Elf64_Off r = 0;

        /* 1) The phdrs themselves */
        Elf64_Off phdrs_off_in_seg = 0;
        if (reserve_range(&r, new_phsize, &phdrs_off_in_seg))
            return 1;

        /* 2) The .dynstr section */
        Elf64_Addr new_dynstr_off_in_seg = 0;
        if (reserve_range(&r, new_dynstr_sz, &new_dynstr_off_in_seg))
            return 1;

        /* 3) The _DYNAMIC entry table (if needed) */
        Elf64_Off new_dyn_tbl_off_in_seg = 0;
        if (dyn_tbl_move_needed) {
            if (reserve_range(&r, new_dyn_tbl_sz, &new_dyn_tbl_off_in_seg))
                return 1;
        }

        /** Create the new segment **/
        Elf64_Xword first_ptload_idx = -1;
        if (append_new_ptload_segment(elf, r, PF_R, &first_ptload_idx))
            return 1;

        out->first_new_ptload = (struct first_new_ptload) {
            .phdr = first_ptload_idx,

            .new_phoff_in_seg = phdrs_off_in_seg,
            .new_phsize = new_phsize,

            .new_dynstr_off_in_seg = new_dynstr_off_in_seg,
            .new_dynstr_sz = new_dynstr_sz,

            .dyn_tbl_move_required = dyn_tbl_move_needed,
            .new_dyn_tbl_off_in_seg = new_dyn_tbl_off_in_seg,
            .new_dyn_tbl_sz = new_dyn_tbl_sz,
        };
    }

    return 0;
}

static int calculate_new_phsize(const struct elf *elf, int n_new_segments,
                                Elf64_Xword *out)
{
    if (elf->phdrs.num > UINT64_MAX - n_new_segments ||
        (elf->phdrs.num + n_new_segments) >
            UINT64_MAX / elf->phentsize)
    {
        pr_error("New program header table size too large "
                "(integer overflow)\n");
        return 1;
    }

    *out = (elf->phdrs.num + n_new_segments) * elf->phentsize;
    return 0;
}

static int calculate_dyn_tbl_mod(
        const struct elf *elf, const struct mod_cfg *cfg,
        bool *out_move_required, Elf64_Xword *out_new_size
)
{
    const struct elf_dyn_entries *const entries = &elf->dyn.entries;

    if (entries->num > UINT64_MAX - cfg->entries.num ||
        entries->num > SIZE_MAX - cfg->entries.num)
    {
        pr_error("Can't add more dynamic entries (integer overflow)\n");
        return 1;
    }
    const Elf64_Xword new_num = entries->num + cfg->entries.num;

    if (new_num > UINT64_MAX / elf->dynentsize) {
        pr_error("Can't add more dynamic entries (integer overflow)\n");
        return 1;
    }

    Elf64_Xword n_spare = 0;
    if (entries->num > 0) {
        Elf64_Xword n_dt_null = 0;
        for (Elf64_Xword i = entries->num - 1; i-- > 0; ) {
            if (entries->arr[i].d_tag == DT_NULL)
                n_dt_null++;
            else
                break;
        }

        if (n_dt_null > 1) {
            /* we need at least one DT_NULL entry to terminate the array */
            n_spare = n_dt_null - 1;
        }
    }

    if ((*out_move_required = n_spare < 1)) {
        *out_new_size = new_num * elf->dynentsize;
    } else {
        *out_new_size = 0;
    }

    return 0;
}

static int prepare_dynstr_offsets(
        const struct mod_cfg *cfg, Elf64_Off old_strtab_sz,
        Elf64_Xword *out_new_sz, struct dynstr_mod_state *out
)
{
    out->n_str_offsets = 0;
    out->str_offsets = NULL;

    out->str_offsets = calloc(cfg->dynstr.n_strings, sizeof(Elf64_Xword));
    if (out->str_offsets == NULL) {
        pr_error("Failed to allocate the dynstr offsets array\n");
        return 1;
    }
    out->n_str_offsets = cfg->dynstr.n_strings;

    Elf64_Off r = old_strtab_sz;
    for (Elf64_Xword i = 0; i < cfg->dynstr.n_strings; i++) {
        size_t len;
        if ((len = strlen(cfg->dynstr.strings[i])) > UINT64_MAX - 1) {
            pr_error("String too long (integer overflow)\n");
            return 1;
        }

        if (reserve_range(&r, len + 1, &out->str_offsets[i]))
            return 1;
    }

    *out_new_sz = r;

    return 0;
}

static int prepare_dyn_entries(
        const struct mod_cfg *cfg,
        const struct dynstr_mod_state *dynstr_state,
        struct dyn_tbl_mod_state *out
)
{
    out->n_new_entries = 0;
    out->new_entries = NULL;

    out->new_entries = calloc((size_t)cfg->entries.num, sizeof(Elf64_Dyn));
    if (out->new_entries == NULL) {
        pr_error("Failed to allocate the new DYNAMIC entries array\n");
        return 1;
    }
    out->n_new_entries = cfg->entries.num;

    for (Elf64_Xword i = 0; i < cfg->entries.num; i++) {
        Elf64_Dyn *const o = &out->new_entries[i];
        const struct dyn_entry_cfg *const c = &cfg->entries.arr[i];

        o->d_tag = c->tag;
        switch (c->tag) {
            case DT_NEEDED: {
                if (c->val.str_idx >= dynstr_state->n_str_offsets) {
                    pr_error("dynstr relocation index out of bounds\n");
                    return 1;
                }
                o->d_un.d_ptr = dynstr_state->str_offsets[c->val.str_idx];
                break;
            }
            default:
                pr_error("%s: Invalid state\n", __func__);
                return -1;
        }
    }

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
    Elf64_Phdr *const new_ptload_p = get_phdr_rw(elf, new_phnum - 1);

    if (construct_appended_ptload_phdr(elf, end, flags, new_ptload_p)) {
        pr_error("Failed to construct a new PT_LOAD segment header\n");
        return 1;
    }

    *out_idx = new_phnum - 1;
    return 0;
}


static int perform_modifications(struct elf *elf, const struct mod_ctx *ctx,
                                 const struct mod_cfg *cfg)
{
    /** Modify the data, moving it to the new segment **/

    /* The first segment (read-only) */
    {
        const struct first_new_ptload *const f = &ctx->first_new_ptload;
        const Elf64_Phdr *const phdr = get_phdr_ro(elf, f->phdr);

        /* 1) The phdrs */
        if (move_program_headers(elf, phdr,
                                 f->new_phoff_in_seg, f->new_phsize))
            return 1;

        /* 2) The .dynstr section */
        if (grow_move_modify_dynstr(elf, phdr,
                                    f->new_dynstr_off_in_seg, f->new_dynstr_sz,
                                    &ctx->state.dyn.dynstr, &cfg->dynstr))
            return 1;

        /* 3) The _DYNAMIC entries */
        if (add_new_dynamic_entries(elf, phdr,
                    f->new_dyn_tbl_off_in_seg, f->new_dyn_tbl_sz,
                    f->dyn_tbl_move_required, &ctx->state.dyn.tbl))
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
             new_phsize, new_phsize / elf->phentsize);

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
        Elf64_Off new_dynstr_off_in_seg, Elf64_Xword new_dynstr_sz,
        const struct dynstr_mod_state *state,
        const struct dynstr_mod_cfg *cfg
)
{
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

    for (Elf64_Xword i = 0; i < state->n_str_offsets; i++) {
        memcpy(&elf->data.data[new_off + state->str_offsets[i]],
               cfg->strings[i], strlen(cfg->strings[i]));
    }

    return 0;
}

static int add_new_dynamic_entries(
        struct elf *elf, const Elf64_Phdr *new_seg,
        Elf64_Off new_dyn_tbl_off_in_seg, Elf64_Xword new_size,
        bool move_required, const struct dyn_tbl_mod_state *state
)
{
    /** First, if needed, move & resize the _DYNAMIC table **/
    if (move_required) {
        Elf64_Off old_off;
        Elf64_Xword old_size;
        {
            const Elf64_Phdr *const pt_dynamic =
                get_phdr_ro(elf, elf->dyn.phdr);
            old_off = pt_dynamic->p_offset;
            old_size = pt_dynamic->p_filesz;
        }

        const Elf64_Off new_off = new_seg->p_offset + new_dyn_tbl_off_in_seg;

        /* already checked in `prepare_modifications`
         * (`calculate_dyn_tbl_mod`) */
        const size_t new_dynnum = elf->dyn.entries.num + state->n_new_entries;
        const Elf64_Xword calculated_new_size = new_dynnum * elf->dynentsize;
        assert(calculated_new_size == new_size);

        pr_debug("old_off: %lu, new_off: %lu\n", old_off, new_off);

        if (prepare_move_data(true, &elf->data,
                              old_off, old_size, new_off, new_size))
        {
            pr_error("Failed to prepare the dynamic table data "
                    "for moving & reserialization\n");
            return 1;
        }

        if (update_dyn_tbl_off(elf, new_off)) {
            pr_error("Failed to move the dynamic array\n");
            return 1;
        }

        if (update_dyn_tbl_num(elf, new_dynnum)) {
            pr_error("Failed to grow the dynamic array\n");
            return 1;
        }
    }

    /** Now, append the new entries in place of the free DT_NULL ones **/

    Elf64_Xword first_dt_null_idx = 0;
    for (Elf64_Xword i = 0; i < elf->dyn.entries.num; i++) {
        if (elf->dyn.entries.arr[i].d_tag == DT_NULL) {
            first_dt_null_idx = i;
            break;
        }
    }

    memcpy(
           &elf->dyn.entries.arr[first_dt_null_idx],
           state->new_entries,
           state->n_new_entries * sizeof(Elf64_Dyn)
    );

    return 0;
}

static void destroy_modifications(struct mod_ctx *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->state.dyn.tbl.new_entries != NULL)
        free(ctx->state.dyn.tbl.new_entries);

    if (ctx->state.dyn.dynstr.str_offsets != NULL)
        free(ctx->state.dyn.dynstr.str_offsets);

    /* right now `ctx` contains only references to `elf`,
     * it doesn't actually own any resources */
    memset(ctx, 0, sizeof(struct mod_ctx));
}

static int construct_appended_ptload_phdr(const struct elf *elf,
        Elf64_Xword total_content_size, Elf64_Word flags, Elf64_Phdr *out)
{
    if (elf->phdrs.num >= UINT64_MAX ||
        elf->phdrs.num + 1 > UINT64_MAX / elf->phentsize ||
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
                "size: 0x%" PRIx64 " (0x%" PRIx64 "), align: 0x%" PRIx64 "\n",
            __func__, new_ptload_off, new_ptload_vaddr,
            new_ptload_size, total_content_size, new_align);

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
