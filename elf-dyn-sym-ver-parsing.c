#include "elf-dyn-sym-ver-parsing.h"
#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>

static_assert(sizeof(Elf64_Verdef) == sizeof(Elf32_Verdef),
              "sizeof(ElfXX_Verdef) must be the same for both classes");
#define VERDEF_ENTSIZE (sizeof(Elf64_Verdef))

static_assert(sizeof(Elf64_Verdaux) == sizeof(Elf32_Verdaux),
              "sizeof(ElfXX_Verdaux) must be the same for both classes");
#define VERDAUX_ENTSIZE (sizeof(Elf64_Verdaux))

static_assert(sizeof(Elf64_Verneed) == sizeof(Elf32_Verneed),
              "sizeof(ElfXX_Verneed) must be the same for both classes");
#define VERNEED_ENTSIZE (sizeof(Elf64_Verneed))

static_assert(sizeof(Elf64_Vernaux) == sizeof(Elf32_Vernaux),
              "sizeof(ElfXX_Vernaux) must be the same for both classes");
#define VERNAUX_ENTSIZE (sizeof(Elf64_Vernaux))

/* (2^16 / 2), because the highest bit in version indices is reserved.
 * Technically, the values `0` and `1` are in some cases reserved too,
 * but two wasted bits are not worth the added complexity. */
#define VERNDX_BITS (0x8000)
#define WORD_BITS (sizeof(size_t) * CHAR_BIT)

/* ceil(VERNDX_BITS / 64), on 64-bit systems */
#define VERNDX_BITMAP_WORDS ((VERNDX_BITS + WORD_BITS - 1) / WORD_BITS)

/**
 * @typedef Bitmap for seen version information entry identifiers.
 *
 * DT_VERSYM contains an array of 16-bit words which refer
 * to either some version definition or some version dependency.
 *
 * Verdef/Verneed are essentially built like this:
 *  DT_VERDEF:
 *      Verdef[0]
 *          (vd_ndx: 2)
 *          [...]
 *      Verdef[1]
 *          (vd_ndx: 3)
 *          [...]
 *  DT_VERNEED:
 *      Verneed[0]
 *          [...]
 *          vn_aux:
 *              Vernaux[0]:
 *                  (vna_other: 7)
 *                  [...]
 *              Vernaux[1]:
 *                  (vna_other: 8)
 *                  [...]
 *      Verneed[1]
 *          [...]
 *          vn_aux:
 *              Vernaux[0]:
 *                  (vna_other: 9)
 *                  [...]
 *
 *  And then DT_VERSYM, which "assigns" version information
 *  to every dynamic symbol in .dynsym:
 *
 *  (For symbol [1]): `2` - Refers to Verdef[0] (vd_ndx == `2`)
 *  (For symbol [2]): `3` - Refers to Verdef[1] (vd_ndx == `3`)
 *  (For symbol [3]): `7` - Refers to Verneed[0].aux[0] (vna_other == `7`)
 *  (For symbol [4]): `8` - Refers to Verneed[0].aux[1] (vna_other == `8`)
 *  (For symbol [5]): `9` - Refers to Verneed[1].aux[0] (vna_other == `9`)
 *  (For symbol [6]): `1` - `VER_NDX_GLOBAL` - global symbol w/o version info
 *  (For symbol [7]): `0` - `VER_NDX_LOCAL` - local, non-exported symbol
 *
 * For this model to make sense, every distinct effective nonreserved
 * version index in VERSYM must resolve to exactly one
 * version definition (`vd_ndx`) or version dependency (`vna_other`).
 *
 * This bitmap is used to track which values of `vd_ndx` or `vna_other`
 * have or have not appeared, to weed out duplicates and to ensure that
 * every DT_VERSYM entry refers to exactly one valid dependency or definition.
 *
 * Vndxs are 16-bit values with the upper bit reserved as a "hidden" flag,
 * so there are 2^15 = 32768 possible effective indices.
 *
 * While values 0 and 1 are reserved too, retaining their two bitmap slots
 * as unused simplifies indexing.
 *
 * Because 32768 bits (which fits in 512 64-bit words) is not too much,
 * we can just create a bitmap on the stack for all possible
 * states and not worry about making some dynamically growing set.
 */
typedef size_t verndx_bitmap_t[VERNDX_BITMAP_WORDS];

/** @struct Common state/information used in version information parsing. */
struct ver_parsing_ctx {
    /* Immutable data, used for reading/parsing */

    const ElfFileData *data; /**< ELF file data. */

    /** The parsed dynamic string table (.dynstr) */
    const struct elf_dyn_strtab *strtab;

    /* Mutable data; parsing context */

    /**
     * Bitmap of seen version information entry identifiers.
     * See the typedef for `verndx_bitmap_t` for more info.
     */
    verndx_bitmap_t seen_vndx_bitmap;
};

/**
 * Helper for getting pointers to strings from the dynamic string table.
 *
 * @param ctx Version information parsing context. Must not be NULL.
 *
 * @param off Offset into the dynamic string table.
 *
 * @return Pointer to a string (into `ctx->strtab`) or
 *  `NULL` if `off` is out of dynstr's bounds.
 */
static inline const uint8_t *
strtab_strptr(const struct ver_parsing_ctx *ctx, Elf64_Off off)
{
    if (off >= ctx->strtab->size) {
        pr_error("Offset outside of string table bounds\n");
        return NULL;
    }

    return ctx->data->buf + ctx->strtab->off + off;
}

/**
 * Helper for setting a bit in the `seen_bits` bitmap.
 * See the typedef for `verndx_bitmap_t` for more info.
 *
 * @param[in,out] seen_bits The bitmap in which to test/set a bit.
 *
 * @param[in] vndx_val The index of the bit to test/set.
 *
 * @return The previous value of the bit at index `vndx_val`,
 *  so `true` if it was previously set and `false` if not.
 */
static inline bool
claim_version_index(verndx_bitmap_t seen_bits, Elf64_Half vndx_val)
{
    /* The highest bit is a "hidden" flag */
    const Elf64_Half real_vndx = vndx_val & UINT16_C(0x7fff);

    const size_t wordidx = real_vndx / WORD_BITS;
    const size_t bitidx = real_vndx % WORD_BITS;
    const size_t mask = (size_t)1 << bitidx;

    if (seen_bits[wordidx] & mask)
        return true;

    seen_bits[wordidx] |= mask;
    return false;
}

/**
 * Helper for testing whether a bit is set in the `seen_bits` bitmap.
 * See the typedef for `verndx_bitmap_t` for more info.
 *
 * @param[in] seen_bits The bitmap in which to test the bit.
 *
 * @param[in] vndx_val The index of the bit to test.
 *
 * @return `true` if the bit is set, `false` if not.
 */
static inline bool
check_version_index(const verndx_bitmap_t seen_bits, Elf64_Half vndx_val)
{
    /* The highest bit is a "hidden" flag */
    const Elf64_Half real_vndx = vndx_val & UINT16_C(0x7fff);

    const size_t wordidx = real_vndx / WORD_BITS;
    const size_t bitidx = real_vndx % WORD_BITS;
    const size_t mask = (size_t)1 << bitidx;

    return !!(seen_bits[wordidx] & mask);
}

/**
 * Finds the version information-related dynamic entries.
 * Part of `parse_ver`.
 *
 * Ensures that:
 *  - `DT_VERDEF`/`DT_VERDEFNUM` as well as `DT_VERNEED`/`DT_VERNEEDNUM`
 *  appear together - either both from the pair are present, or none of them is.
 *  - If either `DT_VERDEF`/`DT_VERDEFNUM` or `DT_VERNEED`/`DT_VERNEEDNUM`
 *  exist, `DT_VERSYM` must be present too.
 *
 * The only case where `DT_VERSYM` is not present is where none
 * of the other entries are present either, i.e. there's no version information
 * at all.
 *
 * So, after this function successfully returns,
 * the following invariants can be considered true:
 *  `DT_VERSYM == ELF_IDX_NULL` means that there is no version information
 *                              at all;
 *  `DT_VERDEF != ELF_IDX_NULL` means the version _definitions_ are present;
 *  `DT_VERNEED != ELF_IDX_NULL` means the version _dependencies_ are present.
 *
 * @param[in] entries The parsed dynamic entries array to search.
 *  Must not be NULL.
 *
 * @param[out] out_dt_versym Output pointer for the index (into `entries`)
 *  of the `DT_VERSYM` entry, or `ELF_IDX_NULL` if absent.
 *  Must not be NULL.
 *
 * @param[out] out_dt_verdef Output pointer for the index (into `entries`)
 *  of the `DT_VERDEF` entry, or `ELF_IDX_NULL` if absent.
 *  Must not be NULL.
 *
 * @param[out] out_dt_verdefnum Output pointer for the index (into `entries`)
 *  of the `DT_VERDEFNUM` entry, or `ELF_IDX_NULL` if absent.
 *  Must not be NULL.
 *
 * @param[out] out_dt_verneed Output pointer for the index (into `entries`)
 *  of the `DT_VERNEED` entry, or `ELF_IDX_NULL` if absent.
 *  Must not be NULL.
 *
 * @param[out] out_dt_verneednum Output pointer for the index (into `entries`)
 *  of the `DT_VERNEEDNUM` entry, or `ELF_IDX_NULL` if absent.
 *  Must not be NULL.
 *
 * @return 0 on success (does not necessarily mean that version info exists),
 *  non-zero if one or more of the aforementioned invariants is violated.
 */
static int find_ver_info_dyn_entries(
        const struct elf_dyn_entries *entries,
        elf_idx_t *out_dt_versym,
        elf_idx_t *out_dt_verdef, elf_idx_t *out_dt_verdefnum,
        elf_idx_t *out_dt_verneed, elf_idx_t *out_dt_verneednum
);

/**
 * Top-level version definition information parsing function.
 * Part of `parse_ver`.
 *
 * Uses the `DT_VERDEF` and `DT_VERDEFNUM` entries as well as the `PT_LOAD`
 * program headers to locate the version definitions list and then
 * parses and validates it.
 * Also parses the `SHT_GNU_verdef` section (if it's present) and cross-checks
 * it against the information from the phdrs and dyn entries.
 *
 * @param[in] phdrs Parsed array of program headers. Must not be NULL.
 *
 * @param[in] shdrs Parsed array of section headers. Must not be NULL.
 *
 * @param[in] entries Parsed array of dynamic entries. Must not be NULL.
 *
 * @param[in] dt_verdef_idx Index of the `DT_VERDEF` dynamic entry.
 *  Must be a valid index into `entries`.
 *
 * @param[in] dt_verdefnum_idx Index of the `DT_VERDEFNUM` dynamic entry.
 *  Must be a valid index into `entries`.
 *
 * @param[in,out] ctx Version information parsing context. Must not be NULL.
 *  `data` and `strtab` are read to parse the entries and
 *  `seen_vndx_bitmap` is used to eliminate version index duplicates.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *  Initialized to `empty_verdef_st`. Populated only on success.
 *  In case of failure, all allocated resources are freed.
 *
 * @return 0 on success, non-zero on failure (malformed/invalid data).
 */
static int parse_verdef(const struct elf_phdrs *phdrs,
                        const struct elf_shdrs *shdrs,
                        const struct elf_dyn_entries *entries,
                        elf_idx_t dt_verdef_idx, elf_idx_t dt_verdefnum_idx,
                        struct ver_parsing_ctx *ctx,
                        struct elf_dyn_sym_ver_def *out);

/**
 * Parses the version definition entry list.
 * Part of `parse_verdef`.
 *
 * @param[in] phdrs Parsed array of program headers. Must not be NULL.
 *
 * @param[in] ptload_idx Valid index (into `phdrs`) of the `PT_LOAD` segment
 *  that contains the version definition list bytes.
 *
 * @param[in] start_off The base offset of the verdef list, computed from
 *  `DT_VERDEF` and `p_offset` of the `PT_LOAD` referred to by `ptload_idx`.
 *
 * @param[in] num Total number of verdef entries to parse
 *  (the value of `DT_VERDEFNUM`). Must be greater than 0.
 *
 * @param[in,out] ctx Version information parsing context. Must not be NULL.
 *  `data` and `strtab` are read to parse the entries and
 *  `seen_vndx_bitmap` is used to eliminate version index duplicates.
 *
 * @param[out] out Output pointer for the new array of parsed verdef entries.
 *  Must not be NULL. Written to only on success.
 *
 * @param[out] out_max_end Output pointer for the absolute file offset
 *  immediately past the highest-addressed parsed Verdef/Verdaux entry,
 *  marking the upper bound of the entire Verdef table. Must not be NULL.
 *
 * @param[out] out_base_idx Output pointer for the index (into `*out`)
 *  of the BASE verdef entry. (On success) this value is always
 *  a valid index; never `ELF_IDX_NULL`.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_verdef_entries(
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        Elf64_Off start_off, size_t num, struct ver_parsing_ctx *ctx,

        struct elf_dyn_sym_ver_def_ent **out, Elf64_Off *out_max_end,
        elf_idx_t *out_base_idx
);

/**
 * Parses a single version definition entry and its auxiliary list.
 * Part of `read_verdef_entries`.
 *
 * @param[in] seg_end Upper bound of the `PT_LOAD` segment
 *  that contains the verdef table.
 *
 * @param[in] is_last_entry Whether the entry is the last one in the list.
 *
 * @param[in,out] ctx Version information parsing context. Must not be NULL.
 *  `data` and `strtab` are read to parse the entry and
 *  `seen_vndx_bitmap` is used to eliminate version index duplicates.
 *
 * @param[in,out] max_end_p Pointer to the value containing the
 *  highest seen end offset of a Verdef/Verdaux entry. Must not be NULL.
 *
 * @param[in,out] off_p Pointer to a variable containing current entry's offset.
 *  On success, the value is modified to point to the next Verdef entry,
 *  i.e. the current one's `vd_next` is added to it. Must not be NULL.
 *
 * @param[out] out Output pointer for the parsed Verdef entry
 *  along with its Verdaux list. Must not be NULL.
 *  Populated only on success; on failure all allocated resources are freed.
 *
 * @param[out] out_is_base Output pointer for whether the parsed Verdef entry
 *  is the base entry, i.e. has the `VER_FLG_BASE` flag set.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_validate_verdef_entry(
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p,

        struct elf_dyn_sym_ver_def_ent *out, bool *out_is_base
);

/**
 * Parses a Verdef entry's Verdaux list.
 * Part of `read_validate_verdef_entry`.
 *
 * @param[in] ctx Version information parsing context. Must not be NULL.
 *  `data` and `strtab` are read to parse the entries.
 *
 * @param[in] vd_hash The value of the parent Verdef's `vd_hash` field.
 *  Used to check that the first Verdaux's `vda_name` hash matches
 *  that value.
 *
 * @param[in] seg_end Upper bound of the `PT_LOAD` segment
 *  that contains the verdef table. Must be >= `VERDAUX_ENTSIZE`
 *  and >= `VERDEF_ENTSIZE`.
 *
 * @param[in] start_off Absolute file offset of the start of the Verdaux list.
 *  This value should be computed from the parent Verdef's own absolute offset
 *  and its `vd_aux` value.
 *
 * @param[in] cnt The number of Verdaux entries in the list.
 *  Must be greater than 0, as per the spec requirements.
 *
 * @param[in,out] max_end_p Pointer to the value containing the
 *  highest seen end offset of a Verdef/Verdaux entry. Must not be NULL.
 *
 * @param[out] out Output pointer for the new list of `cnt` Verdaux entries.
 *  Must not be NULL. Only written to on success; on failure, all allocated
 *  resources are freed.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_verdaux_list(
        const struct ver_parsing_ctx *ctx, Elf64_Word vd_hash,
        Elf64_Off seg_end, Elf64_Off start_off, Elf64_Half cnt,
        Elf64_Off *max_end_p, Elf64_Verdaux **out
);

/**
 * Parses and validates a single version definition auxiliary information entry.
 * Part of `read_verdaux_list`.
 *
 * @param[in] ctx Version information parsing context. Must not be NULL.
 *  `data` and `strtab` are read to parse the entries.
 *
 * @param[in] vd_hash The value of the parent Verdef's `vd_hash` field.
 *  Used to check that the first Verdaux's `vda_name` hash matches
 *  that value, which means that it's only used when `is_first_entry == true`.
 *
 * @param[in] seg_end Upper bound of the `PT_LOAD` segment
 *  that contains the verdef table. Must be >= `VERDAUX_ENTSIZE`.
 *
 * @param[in] is_first_entry Whether the entry is the first one in the list.
 *
 * @param[in] is_last_entry Whether the entry is the last one in the list.
 *
 * @param[in,out] max_end_p Pointer to the value containing the
 *  highest seen end offset of a Verdef/Verdaux entry. Must not be NULL.
 *
 * @param[in,out] off_p Pointer to a variable containing current entry's offset.
 *  On success, the value is modified to point to the next Verdaux entry,
 *  i.e. the current one's `vda_next` is added to it. Must not be NULL.
 *
 * @param[out] out Output pointer for the parsed Verdaux structure.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_validate_verdaux_entry(
        const struct ver_parsing_ctx *ctx, Elf64_Word vd_hash,
        Elf64_Off seg_end, bool is_first_entry, bool is_last_entry,
        Elf64_Off *max_end_p, Elf64_Off *off_p, Elf64_Verdaux *out
);

/**
 * @struct Container for a Verdef's name.
 * Used for validating Verdef relations' structure in `validate_verdef_names`.
 */
struct verdef_name_ref {
    /**
     * The SysV-style hash of `name`; the value of `vd_hash`.
     * Since it's already there, we might as well use it to our advantage
     * to speed up string lookups/comparisons.
     */
    Elf64_Word vd_hash;

    /**
     * The name of the Verdef.
     * This field holds the string pointer referred to by the Verdef's
     * first auxiliary entry's `vda_name`.
     */
    const char *name;

    /**
     * Index (into the parsed array) of the Verdef
     * whose name this struct refers to.
     */
    size_t self_idx;

    /**
     * @enum Three color DFS state of the reference.
     * Used to check for cycles in verdef dependency relations.
     * See `do_verdef_dfs_cycle_check`.
     */
    enum verdef_dfs_state {
        VERDEF_DFS_UNSEEN = 0,  /**< White */
        VERDEF_DFS_VISITING,    /**< Gray */
        VERDEF_DFS_DONE         /**< Black */
    } dfs_state; /**< Three color DFS state, used for cycle detection. */
};

/**
 * Validates the Verdef table structure by ensuring that the relations
 * created with their names are correct and consistent.
 * Part of `parse_verdef`.
 *
 * Because Verdaux structs are just:
 *  typedef struct ElfXX_Verdaux {
 *      ElfXX_Word vda_name; // Name of this entry; offset into .dynstr
 *      ElfXX_Word vda_next; // Offset to the next entry
 *  } ElfXX_Verdaux;
 * They are effectively a linked list of `vda_name`s AKA strings.
 * Therefore, for simplicity, we'll refer to a Verdaux's `vda_name`
 * as its "value".
 *
 * Recall that version definitions' auxiliary entry lists are canonically
 * structured such that the first (0th) entry, let's call it the "Primary",
 * labels the parent Verdef itself by its `vda_name`. Its role is similar
 * to that of a Primary Key in a database in that:
 *  - Every Primary Verdaux's value must be unique;
 *  - Every Verdef ("record") must have exactly one Primary Verdaux.
 *
 * The later Verdauxs (idxs 1..n), let's call them "Additional".
 * fulfill a role similar to that of database Foreign Keys:
 *  - For every Additional Verdaux's value, there exists some different
 *      Verdef (record) with a matching Primary Verdaux;
 *  - Any number of them may exist, including none at all.
 *
 * These above points are exactly what the function validates.
 *
 * And yes, because the first (Primary) Verdaux entry is always required
 * to be present, they could've just made it a part of the Verdef struct itself
 * (like a `vd_name` field), but oh well, this is the ELF spec.
 *
 * The actual relation between the Verdefs/Verdauxs is that the Additional
 * (Foreign Key) Verdauxes refer to other Verdefs which the current one
 * depends on/inherits from, e.g.:
 *  Verdef[0]: (VER_0);    Verdef[1]: (VER_1);    Verdef[2]: (VER_2);
 *   PK: "VER_0"            PK: "VER_1",           PK: "VER_2",
 *                          FK: "VER_0"            FK: "VER_1"
 * The above structure creates a dependency graph like this:
 *  VER_0 <- VER_1 <- VER_2
 * where VER_0 is standalone (requires: VER_0 - only itself),
 * VER_1 depends on VER_0 (requires: VER_1, VER_0)
 * and VER_2 depends on VER_1 which depends on VER_0
 *  (requires: VER_2, VER_1, VER_0)
 *
 * Verdefs express the above relationship in a smart,
 * yet unnecessarily annoying way.
 *
 * Another thing in Verdefs that would need to be validated is that every verndx
 * referenced by the them (with their `vd_ndx` fields) is globally unique,
 * but that's already done during initial parsing with the `seen_vndx_bitmap`.
 *
 * @param[in] arr The array of `num` verdef entries to validate.
 *  Must not be NULL.
 *
 * @param[in] num The number of entries (in `arr`) to be validated.
 *
 * @param[in] ctx The version information parsing context. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_verdef_relations(
        const struct elf_dyn_sym_ver_def_ent *arr, size_t num,
        const struct ver_parsing_ctx *ctx
);

/**
 * Checks for cycles in a Verdef's dependency graph
 * using three-color depth-first search.
 * Part of `validate_verdef_relations`.
 *
 * This function is an iterative implementation of the recursive
 * three-color depth-first algorithm. It uses an explicit stack
 * to simulate recursion while avoiding the risk of stack overflows.
 *
 * Note: This routine requires that:
 *  - Every Verdef's name (Primary Verdaux's `vda_name`) be unique;
 *  - Every Verdef's dependencies (Additional Verdaux entries' `vda_name`s)
 *      resolve to some Verdef's name (Primary Verdaux's `vda_name`).
 * It may only be run when the above conditions are met.
 *
 * @param[in] ctx The version information parsing context. Must not be NULL.
 *
 * @param[in] arr The parsed array of `num` Verdef entries
 *  (along with their corresponding aux lists). Must not be NULL.
 *
 * @param[in,out] refs Array of `num` Verdef name references.
 *  Must not be NULL. The refs' `dfs_state`s are used and modified.
 *
 * @param[in] num Number of Verdef entries; the size of `arr` and `refs`.
 *
 * @param[in,out] root Name reference of the Verdef whose dependency graph
 *  to validate. Must not be NULL. The ref's `dfs_state` is used and modified.
 *
 * @return 0 on success,
 *  positive value (>0) if a cycle is detected,
 *  negative value (<0) if some other error occurs.
 */
static int do_verdef_dfs_cycle_check(const struct ver_parsing_ctx *ctx,
                                     const struct elf_dyn_sym_ver_def_ent *arr,
                                     struct verdef_name_ref *refs, size_t num,
                                     struct verdef_name_ref *root);

/**
 * Used to `qsort` and `bsearch` Verdaux names in `validate_verdef_relations`.
 * Part of `validate_verdef_relations`.
 *
 * Sorts the entries by their (`vd_hash`, `aux[0].vda_name`), i.e.
 * first compares the `vd_hash`es and if they are equal, `strcmp`s the names.
 *
 * @param[in] a_ Pointer to the lhs `verdef_name_ref` struct. Must not be NULL.
 *
 * @param[in] b_ Pointer to the rhs `verdef_name_ref` struct. Must not be NULL.
 *
 * @return `-1` if `a < b`, `0` if `a == b`, `1` if `a > b`.
 */
static int verdef_name_ref_cmp(const void *a_, const void *b_);

/**
 * Top-level version dependency information parsing function.
 * Part of `parse_ver`.
 *
 * Uses the `DT_VERNEED` and `DT_VERNEEDNUM` entries as well as the `PT_LOAD`
 * program headers to locate the version dependency list and then
 * parses and validates it.
 * Also, if present, parses the `SHT_GNU_verneed` section header
 * and cross-checks it against the information from the phdrs and dyn entries.
 *
 * @param[in] phdrs Parsed array of program headers. Must not be NULL.
 *
 * @param[in] shdrs Parsed array of section headers. Must not be NULL.
 *
 * @param[in] entries Parsed array of dynamic entries. Must not be NULL.
 *
 * @param[in] dt_verneed_idx Index of the `DT_VERNEED` dynamic entry.
 *  Must be a valid index into `entries`.
 *
 * @param[in] dt_verneednum_idx Index of the `DT_VERNEEDNUM` dynamic entry.
 *  Must be a valid index into `entries`.
 *
 * @param[in,out] ctx Version information parsing context. Must not be NULL.
 *  `data` and `strtab` are read to parse the entries and
 *  `seen_vndx_bitmap` is used to eliminate version index duplicates.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *  Initialized to `empty_verneed_st`. Populated only on success.
 *  In case of failure, all allocated resources are freed.
 *
 * @return 0 on success, non-zero on failure (malformed/invalid data).
 */
static int parse_verneed(
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries,
        elf_idx_t dt_verneed_idx, elf_idx_t dt_verneednum_idx,
        struct ver_parsing_ctx *ctx,

        struct elf_dyn_sym_ver_need *out
);

/**
 * Parses the version dependency entry list.
 * Part of `parse_verneed`.
 *
 * @param[in] phdrs Parsed array of program headers. Must not be NULL.
 *
 * @param[in] ptload_idx Valid index (into `phdrs`) of the `PT_LOAD` segment
 *  that contains the version dependency list bytes.
 *
 * @param[in] tbl_off The base offset of the verneed list, computed from
 *  `DT_VERNEED` and `p_offset` of the `PT_LOAD` referred to by `ptload_idx`.
 *
 * @param[in] num Total number of verneed entries to parse
 *  (the value of `DT_VERNEEDNUM`). Must be greater than 0.
 *
 * @param[in,out] ctx Version information parsing context. Must not be NULL.
 *  `data` and `strtab` are read to parse the entries and
 *  `seen_vndx_bitmap` is used to eliminate version index duplicates.
 *
 * @param[out] out Output pointer for the new array of parsed verneed entries.
 *  Must not be NULL. Written to only on success.
 *
 * @param[out] out_max_end Output pointer for the absolute file offset
 *  immediately past the highest-addressed parsed Verneed/Vernaux entry,
 *  marking the upper bound of the entire Verneed table. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_verneed_entries(
        struct ver_parsing_ctx *ctx,
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        const struct elf_dyn_entries *entries,
        Elf64_Off tbl_off, size_t num,

        struct elf_dyn_sym_ver_need_ent **out, Elf64_Off *out_max_end
);

/**
 * @struct Container for the value of a DT_NEEDED entry.
 *
 * Used by `read_verneed_entries` to check that every Verneed's `vn_file`
 * refers to a valid and existing DT_NEEDED entry.
 */
struct dt_needed_name {
    /**
     * The `d_un.d_val` value of the `DT_NEEDED` entry;
     * offset into the dynamic string table (.dynstr).
     */
    Elf64_Xword entry_val;

    /**
     * GNU-style hash of the string pointed to by `entry_val`,
     * used to speed up comparisons in `name_is_dt_needed`.
     */
    Elf32_Word hash;
};

/**
 * Initializes a sorted list of DT_NEEDED entries.
 *
 * Used by `read_verneed_entries` to create the array that
 * `read_validate_verneed_entry` then uses to check that each
 * Verneed's `vn_file` refers to a valid and existing DT_NEEDED entry.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[in] strtab The dynamic string table (.dynstr)
 *  associated with `entries`. Must not be NULL.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[out] out Output pointer for the new (malloc'd) sorted array
 *  of `*out_num` DT_NEEDED entry references (see the struct definition).
 *  Must not be NULL.
 *
 * @param[out] out_num Output pointer for the number of found
 *  DT_NEEDED entries, i.e. the size of `*out`. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int init_dt_needed_name_table(
        const struct elf_dyn_entries *entries,
        const struct elf_dyn_strtab *strtab, const ElfFileData *data,
        struct dt_needed_name **out, size_t *out_num
);

/**
 * Checks whether a Verneed's `vn_file` refers to a valid DT_NEEDED entry,
 * by `bsearch`ing a sorted array of references created with
 * `init_dt_needed_name_table`. Used by `read_validate_verneed_entry`.
 *
 * @param[in] dt_needed_tbl The sorted array of `n_dt_needed` references
 *  to DT_NEEDED entries. Must not be NULL (if `n_dt_needed > 0`).
 *
 * @param[in] n_dt_needed The size of `dt_needed_tbl`.
 *
 * @param[in] ctx The version information parsing context. Must not be NULL.
 *
 * @param[in] vn_file The Verneed `vn_file` value to validate.
 *
 * @return `true` if `vn_file` refers to a DT_NEEDED entry
 *  present in `dt_needed_tbl`, `false` if not.
 */
static bool name_is_dt_needed(
        const struct dt_needed_name *dt_needed_tbl, size_t n_dt_needed,
        const struct ver_parsing_ctx *ctx, Elf64_Word vn_file
);

/**
 * Comparison function for the `bsearch` in `name_is_dt_needed`.
 *
 * Compares two DT_NEEDED entry references by their `d_un.d_val` values,
 * essentially checking for "pointer equality".
 *
 * @param[in] a_ Pointer to lhs `struct dt_needed_name`. Must not be NULL.
 *
 * @param[in] b_ Pointer to rhs `struct dt_needed_name`. Must not be NULL.
 *
 * @return `-1` if `a < b`, `0` if `a == b`, `1` if `a > b`.
 */
static int dt_needed_name_cmp(const void *a_, const void *b_);

/**
 * Parses and validates the structural consistency of a single Verneed entry.
 * Part of `read_verneed_entries`.
 *
 * @param[in] dt_needed_tbl The sorted array of DT_NEEDED entry references,
 *  created with `init_dt_needed_name_table`, used to validate that
 *  the Verneed's `vn_file` refers to an existing DT_NEEDED entry.
 *  Must not be NULL (if `n_dt_needed > 0`).
 *
 * @param[in] n_dt_needed The size of `dt_needed_tbl`.
 *
 * @param[in] seg_end High bound of the PT_LOAD segment
 *  containing the Verneed table. Must be >= `VERNAUX_ENTSIZE`
 *  and >= `VERNEED_ENTSIZE`.
 *
 * @param[in] is_last_entry Whether the current Verneed entry
 *  is supposed to be the last one.
 *
 * @param[in,out] ctx Version information parsing context. Must not be NULL.
 *
 * @param[in,out] max_end_p Pointer to the value containing the
 *  highest seen end offset of a Verneed/Vernaux entry. Must not be NULL.
 *
 * @param[in,out] off_p Pointer to a variable containing current entry's offset.
 *  On success, the value is modified to point to the next Verneed entry,
 *  i.e. the current one's `vn_next` is added to it. Must not be NULL.
 *
 * @param[out] out Output pointer for the parsed Verneed entry
 *  and its auxiliary information list. Must not be NULL.
 *  Only populated on success.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_validate_verneed_entry(
        const struct dt_needed_name *dt_needed_tbl, size_t n_dt_needed,
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p,

        struct elf_dyn_sym_ver_need_ent *out
);

/**
 * Parses and validates a single Verneed's auxiliary information entry list.
 * Part of `read_validate_verneed_entry`.
 *
 * @param[in,out] ctx The version information parsing context. Must not be NULL.
 *
 * @param[in] seg_end High bound of the PT_LOAD segment
 *  containing the Verneed table. Must be >= `VERNAUX_ENTSIZE`.
 *
 * @param[in] start_off Absolute offset of the start of the Vernaux list.
 *
 * @param[in] cnt Expected number of Vernaux entries; the value of `vn_cnt`
 *  and the size of `*out`. Must be greater than 0.
 *
 * @param[in,out] max_end_p Pointer to the value containing the
 *  highest seen end offset of a Verneed/Vernaux entry. Must not be NULL.
 *
 * @param[out] out Output pointer for the newly allocated array of `cnt`
 *  Vernaux entries. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_vernaux_list(
        struct ver_parsing_ctx *ctx, Elf64_Off seg_end,
        Elf64_Off start_off, Elf64_Half cnt, Elf64_Off *max_end_p,
        Elf64_Vernaux **out
);

/**
 * Parses and validates a single version dependency auxiliary information entry.
 * Part of `read_vernaux_list`.
 *
 * @param[in] seg_end High bound of the PT_LOAD segment
 *  containing the Verneed table. Must be >= `VERNAUX_ENTSIZE`.
 *
 * @param[in] is_last_entry Whether the current Vernaux entry
 *  is supposed to be the last one.
 *
 * @param[in,out] ctx The version information parsing context. Must not be NULL.
 *
 * @param[in,out] max_end_p Pointer to the value containing the
 *  highest seen end offset of a Verneed/Vernaux entry. Must not be NULL.
 *
 * @param[in,out] off_p Pointer to the offset of the Vernaux entry to read.
 *  On success, set to point to the next entry. Must not be NULL.
 *
 * @param[out] out Output pointer for the parsed Vernaux. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_validate_vernaux_entry(
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p, Elf64_Vernaux *out
);

/**
 * @struct Container for a version dependency name.
 *
 * Used to `qsort` an array of version dependency names
 * so that it can be easily checked for duplicates.
 *
 * Note that both the parent Verneed `vn_file` and the Vernaux `vna_name`
 * are used as the key, because this is what's incorrect:
 *  ("lib1.so", "VER_1"), ("lib1.so", "VER_1")
 * while this is normal and allowed:
 *  ("lib1.so", "VER"), ("lib2.so", "VER")
 */
struct verneed_name_ref {
    /**
     * The string referenced by the parent Verneed's `vn_file`;
     * pointer into the dynamic string table (.dynstr) data.
     */
    const char *vn_file;

    /**
     * The string referenced by the Vernaux's `vna_name`;
     * pointer into the dynamic string table (.dynstr) data.
     */
    const char *vna_name;

    /**
     * SysV-style hash of `vna_name`; the value of the Vernaux's `vna_hash`.
     * Used to speed up comparisons of (`vn_file`, `vna_name`) pairs.
     */
    Elf64_Word vna_hash;
};

/**
 * Validates that there are no duplicate version dependencies.
 * See the definition of `struct verneed_name_ref`.
 * Part of `parse_verneed`.
 *
 * @param[in] arr The parsed array of `num` Verneed entries
 *  (along with their Vernaux lists) to be validated. Must not be NULL.
 *
 * @param[in] num The size of `arr`.
 *
 * @param[in] ctx The version parsing context. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_verneed_names_uniqueness(
        const struct elf_dyn_sym_ver_need_ent *arr, size_t num,
        const struct ver_parsing_ctx *ctx
);

/**
 * Comparison function for the `qsort` that sorts an array of
 * version dependency names so that it can be easily checked for duplicates.
 *
 * Compares two version dependencies as whole (`vn_file`, `vna_name`) pairs
 * (see the definition of `struct verneed_name_ref`).
 * Uses the `vna_hash` to more quickly reject definitely differing pairs.
 *
 * @param[in] a_ Pointer to the lhs `struct verneed_name_ref`. Must not be NULL.
 *
 * @param[in] b_ Pointer to the rhs `struct verneed_name_ref`. Must not be NULL.
 *
 * @return `-1` if `a < b`, `0` if `a == b`, `1` if `a > b`.
 */
static int verneed_name_ref_cmp(const void *a_, const void *b_);

/**
 * Generic validation function for `SHT_GNU_verdef` and `SHT_GNU_verneed`
 * section headers. Used in `parse_verdef` and `parse_verneed`.
 *
 * Searches for the respective section header and if found, cross-checks it
 * against the data found from the phdrs, dynamic entries and the
 * verdef/verneed table itself.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] dynstr_idx Index (into `shdrs`) of the dynamic string table
 *  (".dynstr") section, or `ELF_IDX_NULL` if not present.
 *
 * @param[in] vaddr Expected virtual address of the section; the value of
 *  the respective `DT_VERDEF`/`DT_VERNEED` dynamic entry.
 *
 * @param[in] off Expected file offset of the section.
 *
 * @param[in] min_size Minimal size of the section, inferred from
 *  the highest seen end offset of a Verdef/Verdaux or Verneed/Vernaux entry.
 *
 * @param[in] num The number of Verdef/Verneed entries;
 *  the value of the respective `DT_VERDEFNUM`/`DT_VERNEEDNUM` dynamic entry.
 *
 * @param[out] out Output pointer for the index (into `shdrs`) of the found
 *  section header, or for `ELF_IDX_NULL` if invalid or not present.
 *  Must not be NULL.
 *
 * @param[in] is_verdef Set to `true` for `SHT_GNU_verdef`
 *  and `false` for `SHT_GNU_verneed`.
 *
 * @return 0 on success (nothing is found OR a valid section header is found),
 *  non-zero on failure (an invalid section header is found).
 */
static int validate_sht_gnu_verXXX_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword min_size, Elf64_Xword num,
        elf_idx_t *out, bool is_verdef
);

/**
 * Parses the DT_VERSYM array which ties the symbol table to version information
 * in DT_VERDEF and DT_VERNEED. Part of `parse_ver`.
 *
 * Uses the `DT_VERSYM` entry as well as the `PT_LOAD` program headers
 * to locate the versym array and then ensures that the references it contains
 * are all valid (resolve to some valid version definition or dependency).
 *
 * Also parses the `SHT_GNU_versym` section (if it's present) and cross-checks
 * it against the information from the phdrs and dyn entries.
 *
 * @param[in] phdrs Parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs Parsed section headers array. Must not be NULL.
 *
 * @param[in] entries Parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] dt_versym_idx Valid index (into `entries`) of the DT_VERSYM entry.
 */
static int parse_versym(
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t dt_versym_idx,
        const ElfFileData *data, const struct elf_dyn_symtab *symtab,
        const struct ver_parsing_ctx *ctx, struct elf_dyn_sym_ver_sym *out
);

/**
 * Reads the `DT_VERSYM` entries and validates them against
 * the previously populated `ctx->seen_vndx_bitmap`.
 * Part of `parse_versym`.
 *
 * The function checks that every entry which is an effective "version index"
 * (see the typedef for `verndx_bitmap_t`), references some version
 * definition or dependency by ensuring that the bit corresponding to
 * the entry's value is set in `ctx->seen_vndx_bitmap`.
 *
 * @param[in] data The ELF file data to read from. Must not be NULL.
 *
 * @param[in] ctx The version parsing context with a populated
 *  `seen_vndx_bitmap`. Must not be NULL.
 *
 * @param[in] num The number of entries in the versym array;
 *  the count of dynamic symbols in the dynamic symbol table.
 *
 * @param[in] tbl_off The file offset at which the Versym table starts.
 *
 * @param[out] out Output pointer for the new parsed array of
 * `num` versym (Elf64_Half) entries. Must not be NULL.
 *  On failure, NULL is written here and all allocated resources are freed.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_validate_versym_words(
        const ElfFileData *data, const struct ver_parsing_ctx *ctx,
        size_t num, Elf64_Off tbl_off, Elf64_Half **out
);

/**
 * Tries to find a `SHT_GNU_versym` section header and validates it if present.
 * Part of `parse_versym`.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] sht_dynsym_idx Index (into `shdrs`) of the dynamic symbol table
 *  (".dynsym") section, or `ELF_IDX_NULL` if not present.
 *
 * @param[in] vaddr Expected virtual address of the section;
 *  the value of the `DT_VERSYM` dynamic entry.
 *
 * @param[in] off Expected file offset of the section.
 *
 * @param[in] num The number of versym entries;
 *  equal to the number of dynamic symbols.
 *
 * @param[out] out Output pointer for the index (into `shdrs`) of the found
 *  section header, or for `ELF_IDX_NULL` if invalid or not present.
 *  Must not be NULL.
 *
 * @return 0 on success (nothing is found OR a valid section header is found),
 *  non-zero on failure (an invalid section header is found).
 */
static int validate_sht_gnu_versym_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t sht_dynsym_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword num,
        elf_idx_t *out
);

int parse_ver(const ElfFileData *data,
              const struct elf_phdrs *phdrs,
              const struct elf_shdrs *shdrs,
              const struct elf_dyn_entries *entries,
              const struct elf_dyn_strtab *strtab,
              const struct elf_dyn_symtab *symtab,
              struct elf_dyn_sym_ver *out)
{
    if (out != NULL)
        *out = empty_ver_st;

    /* Find the DT_VERSYM, DT_VERDEF(NUM) and DT_VERNEED(NUM) entries */
    elf_idx_t dt_versym_idx = ELF_IDX_NULL,
              dt_verdef_idx = ELF_IDX_NULL, dt_verdefnum_idx = ELF_IDX_NULL,
              dt_verneed_idx = ELF_IDX_NULL, dt_verneednum_idx = ELF_IDX_NULL;
    if (find_ver_info_dyn_entries(entries, &dt_versym_idx,
                &dt_verdef_idx, &dt_verdefnum_idx,
                &dt_verneed_idx, &dt_verneednum_idx))
    {
        pr_error("Invalid version information location in dynamic entries\n");
        return -1;
    } else if (dt_versym_idx == ELF_IDX_NULL &&
               dt_verdef_idx == ELF_IDX_NULL && dt_verneed_idx == ELF_IDX_NULL)
    {
        pr_debug("No dynamic symbol version information\n");
        return 1;
    }
    /* From this point, use `goto err` instead of `return`ing directly */

    struct elf_dyn_sym_ver ver = empty_ver_st;
    struct ver_parsing_ctx ver_parsing_ctx = {
        .data = data,
        .strtab = strtab,
        .seen_vndx_bitmap = { 0 }
    };

    /* Parse the Verdef table if DT_VERDEF(NUM) exist */
    if (dt_verdef_idx != ELF_IDX_NULL &&
        parse_verdef(phdrs, shdrs, entries, dt_verdef_idx, dt_verdefnum_idx,
                     &ver_parsing_ctx, &ver.def))
    {
        pr_error("Failed to parse symbol version definition information\n");
        goto err;
    }
    /* Parse the Verneed table if DT_VERNEED(NUM) exist */
    if (dt_verneed_idx != ELF_IDX_NULL &&
        parse_verneed(phdrs, shdrs, entries, dt_verneed_idx, dt_verneednum_idx,
                      &ver_parsing_ctx, &ver.need))
    {
        pr_error("Failed to parse symbol version dependency information\n");
        goto err;
    }

    /* Parse the versym array, validating it against VERDEF/VERNEED */
    if (parse_versym(phdrs, shdrs, entries, dt_versym_idx, data, symtab,
                     &ver_parsing_ctx, &ver.sym))
    {
        pr_error("Failed to parse the symbol version index (versym) array\n");
        goto err;
    }

    ver.present = true;
    *out = ver;
    return 0;

err:
    ver_parsing_ctx = (struct ver_parsing_ctx) { 0 };

    if (ver.def.arr != NULL) {
        for (Elf64_Xword i = 0; i < ver.def.num; i++) {
            if (ver.def.arr[i].aux_list != NULL) {
                free(ver.def.arr[i].aux_list);
                ver.def.arr[i].aux_list = NULL;
            }
        }
        free(ver.def.arr);
        ver.def.arr = NULL;
    }
    if (ver.need.arr != NULL) {
        for (Elf64_Xword i = 0; i < ver.need.num; i++) {
            if (ver.need.arr[i].aux_list != NULL) {
                free(ver.need.arr[i].aux_list);
                ver.need.arr[i].aux_list = NULL;
            }
        }
        free(ver.need.arr);
        ver.need.arr = NULL;
    }
    if (ver.sym.arr != NULL) {
        free(ver.sym.arr);
        ver.sym.arr = NULL;
    }
    ver = empty_ver_st;
    return -1;
}

static int find_ver_info_dyn_entries(
        const struct elf_dyn_entries *entries,
        elf_idx_t *out_dt_versym,
        elf_idx_t *out_dt_verdef, elf_idx_t *out_dt_verdefnum,
        elf_idx_t *out_dt_verneed, elf_idx_t *out_dt_verneednum
)
{
    *out_dt_versym = ELF_IDX_NULL;
    *out_dt_verdef = *out_dt_verdefnum = ELF_IDX_NULL;
    *out_dt_verneed = *out_dt_verneednum = ELF_IDX_NULL;

    bool versym_present = false,
         verdef_present = false,
         verneed_present = false;

    elf_idx_t dt_versym_idx = ELF_IDX_NULL;
    enum { DT_VERDEF_IDX = 0, DT_VERDEFNUM_IDX = 1 };
    elf_idx_t verdef_idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };
    enum { DT_VERNEED_IDX = 0, DT_VERNEEDNUM_IDX = 1 };
    elf_idx_t verneed_idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };

    int r = 0;

    r = find_unique_dyn_entry(entries, DT_VERSYM, &dt_versym_idx);
    if (r < 0) {
        pr_error("Duplicate DT_VERSYM entry\n");
        return 1;
    }
    versym_present = r == 0;

    r = find_unique_dyn_entries(entries, 2,
            (Elf64_Sxword[]) { DT_VERDEF, DT_VERDEFNUM }, verdef_idxs);
    if (r < 0) {
        pr_error("Duplicate and/or missing DT_VERDEF and/or DT_VERDEFNUM "
                 "entries");
        return 1;
    }
    verdef_present = r == 0;

    r = find_unique_dyn_entries(entries, 2,
            (Elf64_Sxword[]) { DT_VERNEED, DT_VERNEEDNUM }, verneed_idxs);
    if (r < 0) {
        pr_error("Duplicate and/or missing DT_VERNEED and/or DT_VERNEEDNUM "
                 "entries");
        return 1;
    }
    verneed_present = r == 0;

    if ((verdef_present || verneed_present) && !versym_present) {
        pr_error("DT_VERDEF and/or DT_VERNEED present without DT_VERSYM\n");
        return 1;
    } else if (!verdef_present && !verneed_present && !versym_present) {
        return 0;
    }

    *out_dt_versym = dt_versym_idx;
    if (verdef_present) {
        *out_dt_verdef = verdef_idxs[DT_VERDEF_IDX];
        *out_dt_verdefnum = verdef_idxs[DT_VERDEFNUM_IDX];
    }
    if (verneed_present) {
        *out_dt_verneed = verneed_idxs[DT_VERNEED_IDX];
        *out_dt_verneednum = verneed_idxs[DT_VERNEEDNUM_IDX];
    }
    return 0;
}

static int parse_verdef(const struct elf_phdrs *phdrs,
                        const struct elf_shdrs *shdrs,
                        const struct elf_dyn_entries *entries,
                        elf_idx_t dt_verdef_idx, elf_idx_t dt_verdefnum_idx,
                        struct ver_parsing_ctx *ctx,
                        struct elf_dyn_sym_ver_def *out)
{
    *out = empty_verdef_st;

    const Elf64_Addr vaddr = entries->arr[dt_verdef_idx].d_un.d_ptr;
    const Elf64_Xword num = entries->arr[dt_verdefnum_idx].d_un.d_val;

    Elf64_Xword min_tbl_size = 0;
    elf_idx_t ptload_idx = ELF_IDX_NULL;
    Elf64_Off tbl_off = 0;
    struct elf_dyn_sym_ver_def_ent *arr = NULL;
    Elf64_Off max_end = 0;
    elf_idx_t vd_base_idx = ELF_IDX_NULL;
    elf_idx_t sht_gnu_verdef_idx = ELF_IDX_NULL;

    if (num == 0) {
        /* If version definitions are present at all, the `VER_FLG_BASE` entry
         * must exist, therefore `num` must be greater than 0. */
        pr_error("Empty DT_VERDEF list\n");
        goto err;
    } else if (num > UINT64_MAX / VERDEF_ENTSIZE || num > SIZE_MAX) {
        pr_error("Number of verdef entries too large (integer overflow)\n");
        goto err;
    }
    /**
     * Since `VERDEF_ENTSIZE` > `VERDAUX_ENTSIZE`,
     * this guarantees that whatever segment we find can contain
     * at least one ElfXX_Verdef or ElfXX_Verdaux, which means that
     * `seg_end - VERDEF_ENTSIZE` as well as `seg_end - VERDAUX_ENTSIZE`
     * never underflow.
     */
    min_tbl_size = num * VERDEF_ENTSIZE;

    if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                       &tbl_off, &ptload_idx))
    {
        pr_error("Verdef table not contained in any PT_LOAD segment\n");
        goto err;
    }

    if (read_verdef_entries(phdrs, ptload_idx, tbl_off, (size_t)num, ctx,
                            &arr, &max_end, &vd_base_idx))
    {
        pr_error("Failed to parse the version definition list\n");
        goto err;
    }
    if (max_end < tbl_off || max_end - tbl_off < min_tbl_size) {
        pr_error("Read an incorrect number of bytes "
                 "(something has gone seriously wrong)\n");
        goto err;
    }
    min_tbl_size = max_end - tbl_off;

    /* Sanity check */
    {
        elf_idx_t tmp = ELF_IDX_NULL;
        if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                           NULL, &tmp) || tmp != ptload_idx)
        {
            pr_error("Full verdef table not backed by the "
                     "correct PT_LOAD segment\n");
            goto err;
        }
    }

    if (validate_verdef_relations(arr, num, ctx)) {
        pr_error("Invalid verdef name relations\n");
        goto err;
    }

    if (validate_sht_gnu_verXXX_if_exists(shdrs, ctx->strtab->shdr,
                                          vaddr, tbl_off, min_tbl_size, num,
                                          &sht_gnu_verdef_idx, true))
    {
        pr_error("Invalid SHT_GNU_verdef section\n");
        goto err;
    }

    out->present = true;
    out->num = num;
    out->arr = arr; arr = NULL;
    out->base_idx = vd_base_idx;
    out->vaddr = vaddr;
    out->off = tbl_off;
    out->dt_verdef_idx = dt_verdef_idx;
    out->dt_verdefnum_idx = dt_verdefnum_idx;
    out->shdr = sht_gnu_verdef_idx;
    return 0;

err:
    if (arr != NULL) {
        for (Elf64_Xword i = 0; i < num; i++) {
            if (arr[i].aux_list != NULL) {
                free(arr[i].aux_list);
                arr[i].aux_list = NULL;
            }
        }
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_verdef_entries(
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        Elf64_Off start_off, size_t num, struct ver_parsing_ctx *ctx,

        struct elf_dyn_sym_ver_def_ent **out, Elf64_Off *out_max_end,
        elf_idx_t *out_base_idx
)
{
    *out = NULL;
    *out_base_idx = ELF_IDX_NULL;
    *out_max_end = 0;
    struct elf_dyn_sym_ver_def_ent *arr = NULL;
    Elf64_Off max_end = 0;

    elf_idx_t vd_base_idx = ELF_IDX_NULL;
    Elf64_Off off;

    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];
    const Elf64_Off ptload_end = ptload->p_offset + ptload->p_filesz;

    assert(ptload_end >= VERDEF_ENTSIZE && ptload_end >= VERDAUX_ENTSIZE);
    assert(num > 0);

    arr = calloc(num, sizeof(struct elf_dyn_sym_ver_def_ent));
    if (arr == NULL) {
        pr_error("Failed to allocate the verdef entries array\n");
        goto err;
    }
    for (size_t i = 0; i < num; i++) arr[i].aux_list = NULL;

    off = start_off;
    for (size_t i = 0; i < num; i++) {
        const bool is_last = (i == num - 1);
        bool is_base = false;
        if (read_validate_verdef_entry(ptload_end, is_last, ctx, &max_end, &off,
                                       &arr[i], &is_base))
        {
            pr_error("Failed to parse version definition entry no %zu\n", i);
            goto err;
        }

        if (is_base) {
            if (vd_base_idx != ELF_IDX_NULL) {
                pr_error("More than one verdef entry has the BASE flag set\n");
                goto err;
            }
            vd_base_idx = i;
        }
    }

    if (vd_base_idx == ELF_IDX_NULL) {
        pr_error("No BASE verdef entry\n");
        goto err;
    } else {
        pr_debug("BASE Verdef entry: \"%s\"\n", (const char *)
                 strtab_strptr(ctx, arr[vd_base_idx].aux_list[0].vda_name));
    }

    *out = arr; arr = NULL;
    *out_base_idx = vd_base_idx;
    *out_max_end = max_end;
    return 0;

err:
    if (arr != NULL) {
        for (size_t i = 0; i < num; i++) {
            if (arr[i].aux_list != NULL) {
                free(arr[i].aux_list);
                arr[i].aux_list = NULL;
            }
        }
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_validate_verdef_entry(
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p,

        struct elf_dyn_sym_ver_def_ent *out, bool *out_is_base
)
{
    Elf64_Verdef vd = { 0 };
    Elf64_Verdaux *aux_list = NULL;
    Elf64_Off aux_list_off = 0;

    *out = (struct elf_dyn_sym_ver_def_ent) { 0 };

    if (*off_p > seg_end - VERDEF_ENTSIZE) {
        pr_error("Next verdef entry would overflow segment bounds\n");
        goto err;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verdef(ctx->data, &tmp, &vd)) {
            pr_error("Failed to read verdef entry from file data\n");
            goto err;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    /* `vd.vd_version` */
    if (vd.vd_version != VER_DEF_CURRENT) {
        pr_error("Invalid struct version\n");
        goto err;
    }

    /* `vd.vd_flags` */
    {
        const Elf64_Half allowed = VER_FLG_BASE | VER_FLG_WEAK;
        if (vd.vd_flags & (Elf64_Half)~allowed) {
            pr_error("Invalid vd_flags\n");
            goto err;
        }
        if (vd.vd_flags & VER_FLG_BASE)
            *out_is_base = true;
    }

    /* `vd.vd_ndx` */
    {
        /* The 15th bit in VERSYM entries is reserved as a "hidden" flag,
         * so if any `vd_ndx` has it set it can't be referenced at all.
         *
         * Also, the values `0` and `1` are reserved for the values
         * `VER_NDX_LOCAL` and `VER_NDX_GLOBAL`, respectively,
         * with `VER_NDX_LOCAL` always being invalid,
         * while `VER_NDX_GLOBAL` being assigned to the base symbol. */
        if (vd.vd_ndx & UINT16_C(0x8000)) {
            pr_error("Highest bit set in vd_ndx making the verdef entry "
                     "unreferenceable from VERSYM\n");
            goto err;
        } else if (vd.vd_ndx == VER_NDX_LOCAL ||
                ((vd.vd_flags & VER_FLG_BASE) != (vd.vd_ndx == VER_NDX_GLOBAL)))
        {
            pr_error("vd_ndx set to a reserved or invalid value\n");
            goto err;
        } else if (claim_version_index(ctx->seen_vndx_bitmap, vd.vd_ndx)) {
            pr_error("Duplicate version index in vd_ndx\n");
            goto err;
        }
    }

    /* `vd.vd_aux`, `vd.vd_cnt`, `vd.vd_hash` */
    aux_list = NULL;
    aux_list_off = 0;
    {
        if (vd.vd_cnt == 0) {
            pr_error("Number of auxiliary entries is 0\n");
            goto err;
        }

        if (vd.vd_aux < VERDEF_ENTSIZE) {
            pr_error("Start of auxiliary array inside of verdef entry\n");
            goto err;
        } else if (*off_p > seg_end || vd.vd_aux > seg_end - *off_p) {
            pr_error("Auxiliary array offset overflows load segment\n");
            goto err;
        }
        aux_list_off = *off_p + vd.vd_aux;

        /* also validates `vd_hash` */
        if (read_verdaux_list(ctx, vd.vd_hash, seg_end, aux_list_off,
                              vd.vd_cnt, max_end_p, &aux_list))
        {
            pr_error("Failed to read auxiliary information entry list\n");
            goto err;
        }
    }

    /* `vd.vd_next` */
    {
        if (vd.vd_next != 0 && vd.vd_next < VERDEF_ENTSIZE) {
            pr_error("Invalid value of vd_next\n");
            goto err;
        }

        if (is_last_entry) {
            if (vd.vd_next != 0) {
                pr_error("Unterminated verdef entries list\n");
                goto err;
            }
        } else /* if (!is_last_entry) */ {
            if (vd.vd_next == 0) {
                pr_error("Early termination of verdef entries list\n");
                goto err;
            }

            if (*off_p > seg_end || vd.vd_next > seg_end - *off_p) {
                pr_error("Next verdef entry offset overflows load segment\n");
                goto err;
            }

            *off_p += vd.vd_next;
        }
    }

    out->vd = vd;
    out->aux_list = aux_list; aux_list = NULL;
    return 0;

err:
    if (aux_list != NULL) {
        free(aux_list);
        aux_list = NULL;
    }
    return 1;
}

static int read_verdaux_list(
        const struct ver_parsing_ctx *ctx, Elf64_Word vd_hash,
        Elf64_Off seg_end, Elf64_Off start_off, Elf64_Half cnt,
        Elf64_Off *max_end_p, Elf64_Verdaux **out
)
{
    *out = NULL;
    Elf64_Off off = 0;
    Elf64_Verdaux *arr = NULL;

    assert(seg_end >= VERDAUX_ENTSIZE);
    assert(cnt > 0);

    /* `size_t` is guaranteed to be at least 16 bits wide */
    arr = calloc((size_t)cnt, sizeof(Elf64_Verdaux));
    if (arr == NULL) {
        pr_error("Failed to allocate verdef auxiliary info entries list\n");
        goto err;
    }

    off = start_off;
    for (Elf64_Half i = 0; i < cnt; i++) {
        const bool is_first = (i == 0);
        const bool is_last = (i == cnt - 1);

        if (read_validate_verdaux_entry(ctx, vd_hash, seg_end,
                                        is_first, is_last, max_end_p,
                                        &off, &arr[i]))
        {
            pr_error("Failed to parse verdef auxiliary info entry "
                     "no %" PRIu16 "\n", i);
            goto err;
        }
        if (is_first) {
            pr_debug("Verdef entry aux[0]: \"%s\"\n", (const char *)
                     strtab_strptr(ctx, arr[i].vda_name));
        } else {
            pr_debug("    -> aux[%" PRIu16 "]: \"%s\"\n", i,
                     (const char *)strtab_strptr(ctx, arr[i].vda_name));
        }
    }

    *out = arr; arr = NULL;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_validate_verdaux_entry(
        const struct ver_parsing_ctx *ctx, Elf64_Word vd_hash,
        Elf64_Off seg_end, bool is_first_entry, bool is_last_entry,
        Elf64_Off *max_end_p, Elf64_Off *off_p, Elf64_Verdaux *out
)
{
    *out = (Elf64_Verdaux) { 0 };

    assert(seg_end >= VERDAUX_ENTSIZE);
    if (*off_p > seg_end - VERDAUX_ENTSIZE) {
        pr_error("Verdaux entry would overflow segment bounds\n");
        return 1;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verdaux(ctx->data, &tmp, out)) {
            pr_error("Failed to read verdaux entry from file data\n");
            return 1;
        }
        if (tmp < *off_p || tmp - *off_p != VERDAUX_ENTSIZE) {
            pr_error("Incorrect number of bytes read (impossible outcome)\n");
            return -1;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    /* `vda_name` */
    {
        const uint8_t *const vda_name_str = strtab_strptr(ctx, out->vda_name);
        if (vda_name_str == NULL) {
            pr_error("vda_name outside string table bounds\n");
            return 1;
        }

        /* Parent verdef's `vd_hash` should match
         * `sysv_hash(first_aux->vda_name)` */
        if (is_first_entry) {
            if (sysv_hash(vda_name_str) != vd_hash) {
                pr_error("Hash of vda_name doesn't match "
                         "parent verdef vd_hash\n");
                return 1;
            }
        }
    }

    /* `vda_next` */
    {
        if (out->vda_next != 0 && out->vda_next < VERDAUX_ENTSIZE) {
            pr_error("The value of vda_next places the next entry "
                     "inside the current one\n");
            return 1;
        }
        if (is_last_entry) {
            if (out->vda_next != 0) {
                pr_error("Unterminated verdaux entry list\n");
                return 1;
            }
        } else /* if (!is_last_entry) */ {
            if (out->vda_next == 0) {
                pr_error("Early termination of verdaux entry list\n");
                return 1;
            }

            if (*off_p > seg_end || out->vda_next > seg_end - *off_p) {
                pr_error("Next verdaux entry offset overflows load segment\n");
                return 1;
            }
            *off_p += out->vda_next;
        }
    }
    return 0;
}

static int validate_verdef_relations(
        const struct elf_dyn_sym_ver_def_ent *arr, size_t num,
        const struct ver_parsing_ctx *ctx
)
{
    int ret = 0;
    struct verdef_name_ref *refs = NULL;

    refs = calloc(num, sizeof(*refs));
    if (refs == NULL) {
        pr_error("Failed to allocate verdef name ref structs array\n");
        ret = -1;
        goto out;
    }
    for (size_t i = 0; i < num; i++) {
        const Elf64_Word vd_hash = arr[i].vd.vd_hash;
        const Elf64_Verdaux *const first_aux = &arr[i].aux_list[0];

        refs[i] = (struct verdef_name_ref) {
            .vd_hash = vd_hash,
            .name = (const char *)strtab_strptr(ctx, first_aux->vda_name),
            .self_idx = i,
            .dfs_state = VERDEF_DFS_UNSEEN
        };
    }

    qsort(refs, num, sizeof(*refs), verdef_name_ref_cmp);

    /* Check for duplicates */
    for (size_t i = 1; i < num; i++) {
        const struct verdef_name_ref *const curr = &refs[i];
        const struct verdef_name_ref *const prev = &refs[i - 1];

        if (prev->vd_hash == curr->vd_hash &&
            !strcmp(prev->name, curr->name))
        {
            pr_error("Duplicate verdef name \"%s\"\n", curr->name);
            ret = 1;
        }
    }

    /* Resolve every verdef's Additional (1..nth) verdaux's vda_names
     * against some other verdef's Primary (0th) verdaux vda_name.
     *
     * This is easy because we conveniently have exactly what we need:
     * a (sorted!) array of verdefs with their verdaux[0] entries. */
    for (size_t i = 0; i < num; i++) {
        const struct verdef_name_ref *const curr_ref = &refs[i];

        const struct elf_dyn_sym_ver_def_ent *const curr_verdef =
            &arr[curr_ref->self_idx];

        for (Elf64_Half j = 1; j < curr_verdef->vd.vd_cnt; j++) {

            const Elf64_Verdaux *const curr_1_n_aux = &curr_verdef->aux_list[j];

            const char *const vda_name = (const char *)
                strtab_strptr(ctx, curr_1_n_aux->vda_name);
            assert(vda_name != NULL);

            const struct verdef_name_ref key = {
                .vd_hash = sysv_hash((const uint8_t *)vda_name),
                .name = vda_name
            };
            const struct verdef_name_ref *const res =
                bsearch(&key, refs, num, sizeof(*refs), verdef_name_ref_cmp);

            if (res == NULL) {
                pr_error("Additional verdaux entry \"%s\" doesn't resolve "
                         "to any verdef's first verdaux entry\n", vda_name);
                ret = 1;
            }
        }
    }

    /* Check that the Verdef dependency graph is acyclic using
     * three-color depth-first search. */

    /* Verdef relation must be valid in order for us to be able to
     * perform depth-first search */
    if (ret)
        goto out;
    for (size_t i = 0; i < num; i++) {
        struct verdef_name_ref *const curr_ref = &refs[i];
        const int r = do_verdef_dfs_cycle_check(ctx, arr, refs, num,
                                                curr_ref);
        if (r > 0) {
            pr_error("Verdef \"%s\" has circular dependency graph\n",
                     curr_ref->name);
            ret = 1;
        } else if (r < 0) {
            /* some other (e.g. allocation) error; already logged */
            ret = -1;
            goto out;
        }
    }

out:
    if (refs != NULL) {
        free(refs);
        refs = NULL;
    }
    return ret;
}

static int do_verdef_dfs_cycle_check(const struct ver_parsing_ctx *ctx,
                                     const struct elf_dyn_sym_ver_def_ent *arr,
                                     struct verdef_name_ref *refs, size_t num,
                                     struct verdef_name_ref *root)
{
    struct dfs_frame {
        struct verdef_name_ref *ref;
        Elf64_Half next_aux_idx;
    };
    struct stack st = { 0 };
    bool cycle_found = false;

    /* already visited this node and its whole subtree */
    if (root->dfs_state == VERDEF_DFS_DONE)
        return 0;

    if (stack_init(&st, sizeof(struct dfs_frame))) {
        pr_error("Failed to initialize the DFS stack\n");
        return -1;
    }

    /* Visit the first node */
    root->dfs_state = VERDEF_DFS_VISITING;
    const struct dfs_frame root_frame = {
        .ref = root,
        .next_aux_idx = 1 /* start from the first "non-primary" aux */
    };
    if (stack_push(&st, &root_frame))
        goto err;

    while (st.size > 0) {
        struct dfs_frame frame;
        if (stack_peek(&st, &frame))
            goto err;

        struct verdef_name_ref *const parent_ref = frame.ref;
        assert(parent_ref != NULL);
        assert(parent_ref->self_idx < num);
        assert(parent_ref->dfs_state == VERDEF_DFS_VISITING);
        const struct elf_dyn_sym_ver_def_ent *const parent_ent =
            &arr[parent_ref->self_idx];

        if (frame.next_aux_idx >= parent_ent->vd.vd_cnt) {
            /* We've visited all dependencies of this node */
            parent_ref->dfs_state = VERDEF_DFS_DONE;
            if (stack_pop(&st, NULL))
                goto err;

            continue;
        }

        /* We're in the process of visiting this node's subtrees;
         * process the next one */

        const Elf64_Half curr_aux_idx = frame.next_aux_idx;
        frame.next_aux_idx++;
        if (stack_poke(&st, &frame))
            goto err;

        /* Find the child Verdef */
        struct verdef_name_ref *child_ref = NULL;
        {
            const Elf64_Verdaux *const curr_aux =
                &parent_ent->aux_list[curr_aux_idx];

            const uint8_t *const child_name =
                strtab_strptr(ctx, curr_aux->vda_name);
            assert(child_name != NULL);

            const struct verdef_name_ref key = {
                .name = (const char *)child_name,
                .vd_hash = sysv_hash(child_name)
            };
            child_ref = bsearch(&key, refs, num, sizeof(*refs),
                                verdef_name_ref_cmp);
            /* Verdef relations' validity has already been established */
            assert(child_ref != NULL);
        }



        /* this child's subtree has already been cleared;
         * skip visiting it */
        if (child_ref->dfs_state == VERDEF_DFS_DONE)
            continue;

        /* We are in the process of descending this child's subtree,
         * and yet we've somehow climbed back up to it. That's a cycle! */
        else if (child_ref->dfs_state == VERDEF_DFS_VISITING) {
            pr_error("Verdef dependency cycle detected "
                     "(\"%s\" -> \"%s\" -> ... -> \"%s\")\n",
                    parent_ref->name, child_ref->name, parent_ref->name);
            cycle_found = true;
            continue;
        }

        else if (child_ref->dfs_state == VERDEF_DFS_UNSEEN) {
            /* We're seeing this node for the first time;
             * mark it visited and add it to the stack,
             * so that on the next iteration
             * we start descending its subtree */
            child_ref->dfs_state = VERDEF_DFS_VISITING;

            /* We're basically making this `child` a new `root`
             * and doing a recursive call */
            const struct dfs_frame new_subtree = {
                .ref = child_ref,
                .next_aux_idx = 1 /* start from the first "non-primary" aux */
            };
            if (stack_push(&st, &new_subtree))
                goto err;
        }

        else {
            pr_error("Invalid DFS state (impossible outcome)\n");
            goto err;
        }
    }

    stack_destroy(&st);
    return cycle_found ? 1 : 0;

err:
    stack_destroy(&st);
    return -1;
}

static int verdef_name_ref_cmp(const void *a_, const void *b_)
{
    const struct verdef_name_ref *const a = a_;
    const struct verdef_name_ref *const b = b_;

    /* Sort the verdef entries by their first aux entries' `vda_name`
     * while using the `vd_hash` to our advantage */

    if (a->vd_hash < b->vd_hash) return -1;
    if (a->vd_hash > b->vd_hash) return 1;

    return strcmp(a->name, b->name);
}

static int parse_verneed(
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries,
        elf_idx_t dt_verneed_idx, elf_idx_t dt_verneednum_idx,
        struct ver_parsing_ctx *ctx,

        struct elf_dyn_sym_ver_need *out
)
{
    *out = empty_verneed_st;

    const Elf64_Addr vaddr = entries->arr[dt_verneed_idx].d_un.d_ptr;
    const Elf64_Xword num = entries->arr[dt_verneednum_idx].d_un.d_val;

    if (num == 0)
        pr_error("WARNING: Empty DT_VERNEED list\n");

    Elf64_Xword min_tbl_size = 0;
    elf_idx_t ptload_idx = ELF_IDX_NULL;
    Elf64_Off tbl_off = 0;
    struct elf_dyn_sym_ver_need_ent *arr = NULL;
    Elf64_Off max_end = 0;
    elf_idx_t sht_gnu_verneed_idx = ELF_IDX_NULL;

    if (num > UINT64_MAX / VERNEED_ENTSIZE || num > SIZE_MAX) {
        pr_error("Number of verneed entries too large (integer overflow)\n");
        goto err;
    }
    /**
     * Since `VERNEED_ENTSIZE` is the same as `VERNAUX_ENTSIZE`,
     * this guarantees that whatever segment we find can contain
     * at least one ElfXX_Verneed or ElfXX_Vernaux, which means that
     * `seg_end - VERNEED_ENTSIZE` as well as `seg_end - VERNAUX_ENTSIZE`
     * never underflow.
     */
    min_tbl_size = num * VERNEED_ENTSIZE;

    if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                       &tbl_off, &ptload_idx))
    {
        pr_error("Verneed table not contained in any PT_LOAD segment\n");
        goto err;
    }

    if (num > 0) {
        if (read_verneed_entries(ctx, phdrs, ptload_idx, entries,
                                 tbl_off, (size_t)num, &arr, &max_end))
        {
            pr_error("Failed to parse the version dependency list\n");
            goto err;
        }
        if (max_end < tbl_off || max_end - tbl_off < min_tbl_size) {
            pr_error("Read an incorrect number of bytes "
                     "(something has gone seriously wrong)\n");
            goto err;
        }
        min_tbl_size = max_end - tbl_off;
        /* Sanity check */
        {
            elf_idx_t tmp = ELF_IDX_NULL;
            if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                               NULL, &tmp) || tmp != ptload_idx)
            {
                pr_error("Full verneed table not backed by the "
                         "correct PT_LOAD segment\n");
                goto err;
            }
        }

        if (validate_verneed_names_uniqueness(arr, (size_t)num, ctx)) {
            pr_error("Duplicate verneed names\n");
            goto err;
        }
    }

    if (validate_sht_gnu_verXXX_if_exists(shdrs, ctx->strtab->shdr,
                                          vaddr, tbl_off, min_tbl_size, num,
                                          &sht_gnu_verneed_idx, false))
    {
        pr_error("Invalid SHT_GNU_verneed section\n");
        goto err;
    }

    out->present = true;
    out->num = num;
    out->arr = arr; arr = NULL;
    out->vaddr = vaddr;
    out->off = tbl_off;
    out->dt_verneed_idx = dt_verneed_idx;
    out->dt_verneednum_idx = dt_verneednum_idx;
    out->shdr = sht_gnu_verneed_idx;
    return 0;

err:
    if (arr != NULL) {
        for (Elf64_Xword i = 0; i < num; i++) {
            if (arr[i].aux_list != NULL) {
                free(arr[i].aux_list);
                arr[i].aux_list = NULL;
            }
        }
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_verneed_entries(
        struct ver_parsing_ctx *ctx,
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        const struct elf_dyn_entries *entries,
        Elf64_Off tbl_off, size_t num,

        struct elf_dyn_sym_ver_need_ent **out, Elf64_Off *out_max_end
)
{
    *out = NULL;
    *out_max_end = 0;
    struct elf_dyn_sym_ver_need_ent *arr = NULL;
    Elf64_Off max_end = 0;
    Elf64_Off off = 0;
    struct dt_needed_name *dt_needed_tbl = NULL;
    size_t n_dt_needed = 0;

    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];
    const Elf64_Off ptload_end = ptload->p_offset + ptload->p_filesz;

    assert(num > 0);
    assert(ptload_end >= VERNEED_ENTSIZE && ptload_end >= VERNAUX_ENTSIZE);

    if (init_dt_needed_name_table(entries, ctx->strtab, ctx->data,
                                  &dt_needed_tbl, &n_dt_needed))
    {
        pr_error("Failed to initialize the DT_NEEDED names hash table\n");
        goto err;
    }

    arr = calloc(num, sizeof(struct elf_dyn_sym_ver_need_ent));
    if (arr == NULL) {
        pr_error("Failed to allocate the version dependency entries array\n");
        goto err;
    }
    for (size_t i = 0; i < num; i++) arr[i].aux_list = NULL;

    off = tbl_off;
    for (size_t i = 0; i < num; i++) {
        const bool is_last = (i == num - 1);
        if (read_validate_verneed_entry(dt_needed_tbl, n_dt_needed,
                                        ptload_end, is_last, ctx, &max_end,
                                        &off, &arr[i]))
        {
            pr_error("Failed to parse version dependency information entry "
                     "no %zu\n", i);
            goto err;
        }
    }

    free(dt_needed_tbl); dt_needed_tbl = NULL;
    *out = arr; arr = NULL;
    *out_max_end = max_end;
    return 0;

err:
    if (arr != NULL) {
        for (size_t i = 0; i < num; i++) {
            if (arr[i].aux_list != NULL) {
                free(arr[i].aux_list);
                arr[i].aux_list = NULL;
            }
        }
        free(arr);
        arr = NULL;
    }
    if (dt_needed_tbl != NULL) {
        free(dt_needed_tbl);
        dt_needed_tbl = NULL;
    }
    return 1;
}

static int init_dt_needed_name_table(
        const struct elf_dyn_entries *entries,
        const struct elf_dyn_strtab *strtab, const ElfFileData *data,
        struct dt_needed_name **out, size_t *out_num
)
{
    *out = NULL;
    *out_num = 0;

    struct dt_needed_name *new_tbl = NULL;
    Elf64_Xword n_dt_needed = 0;

    for (Elf64_Xword i = 0; i < entries->num; i++) {
        if (entries->arr[i].d_tag == DT_NEEDED) {
            n_dt_needed++;
        }
    }
    if (n_dt_needed == 0) {
        pr_error("Number of DT_NEEDED entries cannot be 0 "
                 "with version dependency information present\n");
        goto err;
    } else if (n_dt_needed > SIZE_MAX) {
        pr_error("Number of DT_NEEDED entries too large (integer overflow)\n");
        goto err;
    }


    new_tbl = calloc((size_t)n_dt_needed, sizeof(*new_tbl));
    if (new_tbl == NULL) {
        pr_error("Failed to allocate the DT_NEEDED name hash table\n");
        goto err;
    }
    {
        Elf64_Xword all_entries_idx = 0;
        Elf64_Xword dt_needed_idx = 0;
        do {
            const Elf64_Dyn *const curr_entry = &entries->arr[all_entries_idx];
            if (curr_entry->d_tag != DT_NEEDED)
                continue;

            assert(dt_needed_idx < n_dt_needed);

            new_tbl[dt_needed_idx].entry_val = curr_entry->d_un.d_val;

            if (curr_entry->d_un.d_val >= strtab->size) {
                pr_error("DT_NEEDED entry value overflows string table\n");
                goto err;
            }
            const uint8_t *str_ptr = data->buf +
                                     strtab->off + curr_entry->d_un.d_val;
            new_tbl[dt_needed_idx].hash = gnu_hash(str_ptr);

            dt_needed_idx++;
        } while (++all_entries_idx < entries->num);
    }
    qsort(new_tbl, (size_t)n_dt_needed, sizeof(*new_tbl), dt_needed_name_cmp);

    *out = new_tbl; new_tbl = NULL;
    *out_num = (size_t)n_dt_needed;
    return 0;

err:
    if (new_tbl != NULL) {
        free(new_tbl);
        new_tbl = NULL;
    }
    return 1;
}

static bool name_is_dt_needed(
        const struct dt_needed_name *dt_needed_tbl, size_t n_dt_needed,
        const struct ver_parsing_ctx *ctx, Elf64_Word vn_file
)
{
    /* `vn_file` guaranteed to not overflow `strtab` */
    assert(vn_file < ctx->strtab->size);

    /**
     * First, try to check for a DT_NEEDED entry whose value (dynstr offset)
     * is the exact same as `curr->vn_file`, in which case we definitely know
     * that the names match.
     *
     * The `dt_needed_tbl` is sorted by the `entry_val` members,
     * which represent the values of DT_NEEDED entries.
     */
    bool found = false;
    const struct dt_needed_name tmp = { .entry_val = vn_file };
    const struct dt_needed_name *const res =
        bsearch(&tmp, dt_needed_tbl, n_dt_needed, sizeof(*res),
                dt_needed_name_cmp);
    if (res != NULL) {
        pr_debug("Verneed \"%s\": matching DT_NEEDED found "
                 "using pointer equality\n",
                 (const char *)strtab_strptr(ctx, vn_file));
        found = true;
    } else {
        /* If we don't find a matching name by exact "pointer equality",
         * just loop through the table and compare hashes. */
        const uint8_t *const vn_file_str = strtab_strptr(ctx, vn_file);
        const Elf32_Word vn_file_hash = gnu_hash(vn_file_str);

        for (size_t j = 0; j < n_dt_needed; j++) {
            if (dt_needed_tbl[j].hash == vn_file_hash) {
                /* Do a strcmp in case of a hash collision */
                const char *const dt_needed_str = (const char *)
                    strtab_strptr(ctx, dt_needed_tbl[j].entry_val);

                if (!strcmp((const char *)vn_file_str, dt_needed_str)) {
                    pr_debug("Verneed \"%s\": matching DT_NEEDED found "
                             "using hash comparison\n",
                             (const char *)vn_file_str);
                    found = true;
                    break;
                }
            }
        }
    }
    return found;
}

static int dt_needed_name_cmp(const void *a_, const void *b_)
{
    const struct dt_needed_name *const a = a_;
    const struct dt_needed_name *const b = b_;

    if (a->entry_val < b->entry_val) return -1;
    else if (a->entry_val == b->entry_val) return 0;
    else /* if (a->entry_val > b->entry_val) */ return 1;
}

static int read_validate_verneed_entry(
        const struct dt_needed_name *dt_needed_tbl, size_t n_dt_needed,
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p,

        struct elf_dyn_sym_ver_need_ent *out
)
{
    Elf64_Verneed vn = { 0 };
    Elf64_Vernaux *aux_list = NULL;
    Elf64_Off aux_list_off = 0;

    *out = (struct elf_dyn_sym_ver_need_ent) { 0 };

    if (*off_p > seg_end - VERNEED_ENTSIZE) {
        pr_error("Next verneed entry would overflow segment bounds\n");
        goto err;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verneed(ctx->data, &tmp, &vn)) {
            pr_error("Failed to read version dependency entry "
                     "from file data\n");
            goto err;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    /* `vn.vn_version` */
    if (vn.vn_version != VER_NEED_CURRENT) {
        pr_error("Invalid struct version\n");
        goto err;
    }

    /* `vn.vn_file` */
    {
        if (vn.vn_file >= ctx->strtab->size) {
            pr_error("vn_file outside of string table bounds\n");
            goto err;
        }
        if (!name_is_dt_needed(dt_needed_tbl, n_dt_needed, ctx, vn.vn_file)) {
            pr_error("vn_file not referenced by any DT_NEEDED entry\n");
            goto err;
        }
    }

    /* `vn.vn_aux`, `vn.vn_cnt` */
    aux_list = NULL;
    aux_list_off = 0;
    {
        if (vn.vn_aux < VERNEED_ENTSIZE) {
            pr_error("Start of auxiliary list inside verneed entry\n");
            goto err;
        } else if (*off_p > seg_end || vn.vn_aux > seg_end - *off_p) {
            pr_error("Start of auxiliary list outside of load segment bounds\n");
            goto err;
        }
        aux_list_off = *off_p + vn.vn_aux;

        if (vn.vn_cnt == 0) {
            pr_error("Number of auxiliary entries is 0\n");
            goto err;
        }

        if (read_vernaux_list(ctx, seg_end, aux_list_off, vn.vn_cnt, max_end_p,
                              &aux_list))
        {
            pr_error("Failed to read the auxiliary information entries list\n");
            goto err;
        }
    }

    /* `vn.vn_next` */
    {
        if (vn.vn_next != 0 && vn.vn_next < VERNEED_ENTSIZE) {
            pr_error("Invalid value of vn_next\n");
            goto err;
        }
        if (is_last_entry) {
            if (vn.vn_next != 0) {
                pr_error("Unterminated verneed array\n");
                goto err;
            }
        } else /* if (!is_last_entry) */ {
            if (vn.vn_next == 0) {
                pr_error("Early termination of verneed array\n");
                goto err;
            }

            if (*off_p > seg_end || vn.vn_next > seg_end - *off_p) {
                pr_error("Next vernaux entry offset overflows load segment\n");
                goto err;
            }

            *off_p += vn.vn_next;
        }
    }

    out->vn = vn;
    out->aux_list = aux_list; aux_list = NULL;
    return 0;

err:
    if (aux_list != NULL) {
        free(aux_list);
        aux_list = NULL;
    }
    return 1;
}

static int read_vernaux_list(
        struct ver_parsing_ctx *ctx, Elf64_Off seg_end,
        Elf64_Off start_off, Elf64_Half cnt, Elf64_Off *max_end_p,
        Elf64_Vernaux **out
)
{
    Elf64_Off off = 0;
    Elf64_Vernaux *arr = NULL;
    *out = NULL;

    assert(seg_end >= VERNAUX_ENTSIZE);
    assert(cnt > 0);

    /* `size_t` is guaranteed to be at least 16 bits wide */
    arr = calloc((size_t)cnt, sizeof(Elf64_Vernaux));
    if (arr == NULL) {
        pr_error("Failed to allocate verneed auxiliary info entries list\n");
        goto err;
    }

    off = start_off;
    for (Elf64_Half i = 0; i < cnt; i++) {
        const bool is_last = (i == cnt - 1);
        if (read_validate_vernaux_entry(seg_end, is_last, ctx, max_end_p,
                                        &off, &arr[i]))
        {
            pr_error("Failed to read verneed auxiliary info entry "
                     "no %" PRIu16 "\n", i);
            goto err;
        }

        pr_debug("    -> aux[%" PRIu16 "]: \"%s\"\n", i,
                 (const char *)strtab_strptr(ctx, arr[i].vna_name));
    }

    *out = arr; arr = NULL;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_validate_vernaux_entry(
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p, Elf64_Vernaux *out
)
{
    *out = (Elf64_Vernaux) { 0 };

    assert(seg_end >= VERNAUX_ENTSIZE);
    if (*off_p > seg_end - VERNAUX_ENTSIZE) {
        pr_error("Vernaux entry overflows segment bounds\n");
        return 1;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_vernaux(ctx->data, &tmp, out)) {
            pr_error("Failed to read vernaux entry from file data\n");
            return 1;
        }
        if (tmp < *off_p || tmp - *off_p != VERNAUX_ENTSIZE) {
            pr_error("Incorrect number of bytes read (impossible outcome)\n");
            return -1;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    /* `vna_name`, `vna_hash` */
    {
        const uint8_t *const vna_name_str = strtab_strptr(ctx, out->vna_name);
        if (vna_name_str == NULL) {
            pr_error("vna_name points outside of string table bounds\n");
            return 1;
        }
        if (sysv_hash(vna_name_str) != out->vna_hash) {
            pr_error("vna_hash doesn't match the hash of the string "
                     "referenced by vna_name\n");
            return 1;
        }
    }

    /* `vna_flags` */
    {
        const Elf64_Half allowed = VER_FLG_WEAK | VER_FLG_INFO;
        if (out->vna_flags & (Elf64_Half)~allowed) {
            pr_error("Invalid vna_flags\n");
            return 1;
        }
    }

    /* `vna_other` */
    {
        /* The values `0` and `1` are reserved for the values
         * `VER_NDX_LOCAL` and `VER_NDX_GLOBAL`, respectively.
         * However, on some solaris systems the value `0` was historically used
         * as a placeholder because the linker didn't assign any value then,
         * so treat that case only as a warning.
         *
         * As for the "hidden" flag (bit 15),
         * there's a difference between how GNU and Solaris systems treat it,
         * so just let `claim_version_index` ignore it. */
        const Elf64_Half raw_vndx = out->vna_other;
        const Elf64_Half real_vndx = out->vna_other & UINT16_C(0x7fff);
        if (raw_vndx == VER_NDX_LOCAL) {
            pr_error("WARNING: vna_other is set to the reserved value 0\n");
        } else if (real_vndx == VER_NDX_LOCAL || real_vndx == VER_NDX_GLOBAL) {
            pr_error("vna_other is set to a reserved value\n");
            return 1;
        } else if (claim_version_index(ctx->seen_vndx_bitmap, raw_vndx)) {
            pr_error("Duplicate version index in the vna_other field\n");
            return 1;
        }
    }

    /* `vna_next` */
    {
        if (out->vna_next != 0 && out->vna_next < VERNAUX_ENTSIZE) {
            pr_error("The value of vna_next places the next entry "
                     "inside the current one\n");
            return 1;
        }
        if (is_last_entry) {
            if (out->vna_next != 0) {
                pr_error("Unterminated of vernaux entry list\n");
                return 1;
            }
        } else {
            if (out->vna_next == 0) {
                pr_error("Early termination of vernaux entry list\n");
                return 1;
            }

            if (*off_p > seg_end || out->vna_next > seg_end - *off_p) {
                pr_error("Next vernaux entry offset overflows load segment\n");
                return 1;
            }
            *off_p += out->vna_next;
        }
    }

    return 0;
}

static int validate_verneed_names_uniqueness(
        const struct elf_dyn_sym_ver_need_ent *arr, size_t num,
        const struct ver_parsing_ctx *ctx
)
{
    struct verneed_name_ref *refs = NULL;
    int ret = 0;

    size_t total_aux = 0;
    for (size_t i = 0; i < num; i++) {
        const Elf64_Half vn_cnt = arr[i].vn.vn_cnt;

        /* 16-bit values never overflow size_t */
        if ((size_t)vn_cnt > SIZE_MAX - total_aux) {
            pr_error("Too many vernaux entries (integer overflow)\n");
            ret = -1;
            goto out;
        }

        total_aux += (size_t)vn_cnt;
    }

    /* Allocation and initialization */
    refs = calloc(total_aux, sizeof(*refs));
    if (refs == NULL) {
        pr_error("Failed to allocate the verneed name ref structs array\n");
        ret = -1;
        goto out;
    }
    {
        size_t refs_idx = 0;
        for (size_t i = 0; i < num; i++) {
            const uint8_t *const vn_file_strptr =
                strtab_strptr(ctx, arr[i].vn.vn_file);

            for (Elf64_Half j = 0; j < arr[i].vn.vn_cnt; j++) {
                const Elf64_Vernaux *const curr_aux = &arr[i].aux_list[j];

                const uint8_t *const vna_name_strptr =
                    strtab_strptr(ctx, curr_aux->vna_name);

                assert(refs_idx < total_aux);
                refs[refs_idx] = (struct verneed_name_ref) {
                    .vn_file = (const char *)vn_file_strptr,
                    .vna_name = (const char *)vna_name_strptr,
                    .vna_hash = curr_aux->vna_hash,
                };
                refs_idx++;
            }
        }
        assert(refs_idx == total_aux);
    }

    qsort(refs, total_aux, sizeof(*refs), verneed_name_ref_cmp);

    /* Duplicates check */
    for (size_t i = 1; i < total_aux; i++) {
        const struct verneed_name_ref *const prev = &refs[i - 1];
        const struct verneed_name_ref *const curr = &refs[i];

        if (!strcmp(prev->vn_file, curr->vn_file) &&
            prev->vna_hash == curr->vna_hash &&
            !strcmp(prev->vna_name, curr->vna_name))
        {
            pr_error("Duplicate version dependency: \"%s\" -> \"%s\"\n",
                     curr->vn_file, curr->vna_name);
            ret = 1;
        }
    }

out:
    if (refs != NULL) {
        free(refs);
        refs = NULL;
    }
    return ret;
}

static int verneed_name_ref_cmp(const void *a_, const void *b_)
{
    const struct verneed_name_ref *const a = a_;
    const struct verneed_name_ref *const b = b_;

    /* Sort the vernaux entries by (parent vn_file, vna_name)
     * while using the `vna_hash` to our advantage */

    /* Different parent `vn_file` */
    int r = strcmp(a->vn_file, b->vn_file);
    if (r != 0)
        return r;

    /* Different `vna_hash` */
    if (a->vna_hash < b->vna_hash) return -1;
    if (a->vna_hash > b->vna_hash) return 1;

    /* Same `vna_hash`, different `vna_name` */
    return strcmp(a->vna_name, b->vna_name);
}

static int validate_sht_gnu_verXXX_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword min_size, Elf64_Xword num,
        elf_idx_t *out, bool is_verdef
)
{
    *out = ELF_IDX_NULL;

    const enum shdr_unique_type type = is_verdef ? shdr_unique_SHT_GNU_verdef :
                                                   shdr_unique_SHT_GNU_verneed;
    const char *const name = is_verdef ? "SHT_GNU_verdef" : "SHT_GNU_verneed";

    const elf_idx_t shdr_idx = find_unique_shdr_by_type(shdrs, type);
    if (shdr_idx == ELF_IDX_NULL) {
        pr_debug("No %s section\n", name);
        return 0;
    }
    const Elf64_Shdr *const shdr = &shdrs->arr[shdr_idx];

    if (dynstr_idx == ELF_IDX_NULL) {
        pr_error("%s exists without a dynstr section\n", name);
        return 1;
    }

    int ret = 0;

    if (shdr->sh_addr != vaddr) {
        pr_error("Invalid %s virtual address\n", name);
        ret = 1;
    }

    if (shdr->sh_offset != off) {
        pr_error("Invalid %s offset\n", name);
        ret = 1;
    }

    if (shdr->sh_size < min_size) {
        pr_error("Invalid %s size\n", name);
        ret = 1;
    }

    if (shdr->sh_info != num) {
        pr_error("Invalid value of %s sh_info\n", name);
        ret = 1;
    }

    if (shdr->sh_link != dynstr_idx) {
        pr_error("%s sh_link doesn't point to the dynstr section\n", name);
        ret = 1;
    }

    if (shdr->sh_entsize != 0) {
        pr_error("Invalid %s entsize\n", name);
        ret = 1;
    }

    if (!ret)
        *out = shdr_idx;
    return ret;
}

static int parse_versym(
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t dt_versym_idx,
        const ElfFileData *data, const struct elf_dyn_symtab *symtab,
        const struct ver_parsing_ctx *ctx, struct elf_dyn_sym_ver_sym *out
)
{
    const Elf64_Addr vaddr = entries->arr[dt_versym_idx].d_un.d_ptr;
    elf_idx_t ptload = ELF_IDX_NULL;
    Elf64_Off tbl_off = 0;
    Elf64_Xword size = 0;
    Elf64_Half *arr = NULL;
    elf_idx_t sht_gnu_versym_idx = ELF_IDX_NULL;

    *out = empty_versym_st;

    if (symtab->nsyms > UINT64_MAX / sizeof(Elf64_Half) ||
        symtab->nsyms > SIZE_MAX)
    {
        pr_error("Number of versyms too large (integer overflow)\n");
        goto err;
    }
    size = symtab->nsyms * sizeof(Elf64_Half);
    if (find_ptload_and_off_from_vaddr(vaddr, size, phdrs, &tbl_off, &ptload)) {
        pr_error("Versym array not contained in a PT_LOAD segment\n");
        goto err;
    }

    if (read_validate_versym_words(data, ctx, (size_t)symtab->nsyms, tbl_off,
                                   &arr))
    {
        pr_error("Failed to read the versym array\n");
        goto err;
    }

    if (validate_sht_gnu_versym_if_exists(shdrs, symtab->shdr, vaddr, tbl_off,
                                          symtab->nsyms, &sht_gnu_versym_idx))
    {
        pr_error("Invalid SHT_GNU_versym section header\n");
        goto err;
    }

    out->vaddr = vaddr;
    out->dt_versym_idx = dt_versym_idx;
    out->off = tbl_off;
    out->size = size;
    out->num = symtab->nsyms;
    out->arr = arr; arr = NULL;
    out->shdr = sht_gnu_versym_idx;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_validate_versym_words(
        const ElfFileData *data, const struct ver_parsing_ctx *ctx,
        size_t num, Elf64_Off tbl_off, Elf64_Half **out
)
{
    Elf64_Half *arr = NULL;
    Elf64_Off off = tbl_off;

    arr = calloc(num, sizeof(Elf64_Half));
    if (arr == NULL) {
        pr_error("Failed to allocate the versyms array\n");
        goto err;
    }

    for (Elf64_Xword i = 0; i < num; i++) {
        Elf64_Half val = 0;
        if (read_Half(data, &off, &val)) {
            pr_error("Failed to read versym entry no %" PRIu64 "\n", i);
            goto err;
        }

        /* Valid, reserved values with no additional semantics;
         * skip the rest of the checks */
        if (val == VER_NDX_LOCAL || val == VER_NDX_GLOBAL)
            continue;

        /* Check that this vndx is taken in the bitmap,
         * i.e. some version definition or dependency has it */
        if (!check_version_index(ctx->seen_vndx_bitmap, val)) {
            const Elf64_Half real_vndx = val & UINT16_C(0x7fff);
            const bool hidden = !!(val & UINT16_C(0x8000));
            pr_error("Versym entry no %" PRIu64 "'s value "
                     "(vndx: %" PRIu16 "; hidden: %d) doesn't reference "
                     "any version definition or dependency\n",
                     i, real_vndx, hidden);
            goto err;
        }

        arr[i] = val;
    }

    *out = arr; arr = NULL;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int validate_sht_gnu_versym_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t sht_dynsym_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword num,
        elf_idx_t *out
)
{
    *out = ELF_IDX_NULL;

    elf_idx_t sht_gnu_versym_idx =
        find_unique_shdr_by_type(shdrs, shdr_unique_SHT_GNU_versym);
    if (sht_gnu_versym_idx == ELF_IDX_NULL) {
        pr_debug("No SHT_GNU_versym section\n");
        return 0;
    }

    const Elf64_Shdr *const shdr = &shdrs->arr[sht_gnu_versym_idx];
    int ret = 0;

    if (shdr->sh_addr != vaddr) {
        pr_error("Invalid SHT_GNU_versym vaddr\n");
        ret = 1;
    }
    if (shdr->sh_offset != off) {
        pr_error("Invalid SHT_GNU_versym file offset\n");
        ret = 1;
    }
    if (shdr->sh_entsize != sizeof(Elf64_Half)) {
        pr_error("Invalid SHT_GNU_versym entsize\n");
        ret = 1;
    }
    if (shdr->sh_size % sizeof(Elf64_Half) != 0 ||
        shdr->sh_size / sizeof(Elf64_Half) != num)
    {
        pr_error("Invalid SHT_GNU_versym size\n");
        ret = 1;
    }
    if ((sht_dynsym_idx == ELF_IDX_NULL && shdr->sh_link != SHN_UNDEF) ||
        (sht_dynsym_idx != ELF_IDX_NULL && shdr->sh_link != sht_dynsym_idx))
    {
        pr_error("Invalid SHT_GNU_versym sh_link value\n");
        ret = 1;
    }

    if (!ret)
        *out = sht_gnu_versym_idx;
    return ret;
}
