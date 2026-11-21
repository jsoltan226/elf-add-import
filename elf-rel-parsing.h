#ifndef ELF_DYN_REL_PARSING_H_
#define ELF_DYN_REL_PARSING_H_

#include "util.h"

/**
 * @file Module that parses ELF relocations,
 *  including REL, RELA, PLTREL, etc.
 */

struct elf_phdrs;
struct elf_shdrs;
struct elf_dyn_entries;

/* @struct Container for all data related to ELF relocations. */
struct elf_reloc {
    /**
     * @struct Container for data related to the `DT_REL` table.
     *
     * It contains relocation-without-addend entries
     * which reference the dynamic symbol table.
     * The corresponding section name is (conventionally) ".rel.dyn".
     *
     * Mostly used on 32-bit binaries.
     */
    struct elf_reloc_rel {
        /**
         * Indicates whether a DT_RELA table is present
         * and was successfully parsed.
         *
         * When false, all other members are semantically empty and must not
         * be used. When true, the table and its associated metadata are valid.
         */
        bool present;

        /**
         * Virtual address of the dynsym relocation-without-addend table;
         * the value of `DT_REL`.
         */
        Elf64_Addr vaddr;

        /** File offset of the dynsym relocation-without-addend table. */
        Elf64_Off off;

        /**
         * Size of the dynsym relocation-without-addend table;
         * the value of `DT_RELSZ`.
         */
        Elf64_Xword size;

        /** Size of each ElfXX_Rel entry; the value of `DT_RELENT`. */
        Elf64_Half entsize;

        /**
         * The array of `num` parsed `ElfXX_Rel` entries,
         * normalized to `Elf64_Rel` (see `read_rel` in `elf-types.c`).
         */
        Elf64_Rel *arr;

        /**
         * The number of entries in `arr`; equal to `DT_RELSZ / DT_RELENT`.
         * Always greater than 0.
         */
        size_t num;

        /**
         * Index into the dynamic entries array of the `DT_REL` entry,
         * whose value is equal to that of `vaddr`.
         * Always a valid index if `present == true`
         */
        elf_idx_t dt_rel_idx;

        /**
         * Index into the dynamic entries array of the `DT_RELSZ` entry,
         * whose value is equal to that of `size`.
         * Always a valid index if `present == true`
         */
        elf_idx_t dt_relsz_idx;

        /**
         * Index into the dynamic entries array of the `DT_RELENT` entry,
         * whose value is equal to that of `entsize`.
         * Always a valid index if `present == true`
         */
        elf_idx_t dt_relent_idx;

        /**
         * Index into the dynamic entries array of the optional `DT_RELCOUNT`
         * entry, whose value is equal to that of `relcount`.
         * Since the entry is an extension, this field might be `ELF_IDX_NULL`.
         */
        elf_idx_t dt_relcount_idx;

        /**
         * If the `DT_RELCOUNT` entry exists, the relocation entries must be
         * sorted such that all the `R_*_RELATIVE` relocations are placed
         * together (contiguously) at the start of the array.
         *
         * This is used for optimisation, as it allows the loader to perform
         * the relative relocations (which need to be handled at startup)
         * much quicker because the whole table doesn't need to be searched
         * and filtered for only relative relocations - they are all
         * neatly packed together in one place.
         *
         * @brief
         * This value represents the number of relative (`R_*_RELATIVE`)
         * relocations packed together at the start of the table,
         * and is meaningful iff `DT_RELCOUNT` exists
         * (`dt_relcount_idx != ELF_IDX_NULL`). Always `<= num`.
         */
        Elf64_Xword relcount;

        /**
         * Number of SHT_REL section headers describing portions of the DT_REL
         * table. May be zero if no matching section headers exist.
         */
        size_t n_shdrs;

        /**
         * The array of `num` `SHT_REL` section indices which
         * describe the DT_REL table, or `NULL` if none do.
         *
         * Multiple sections are permitted, provided their ranges are valid,
         * contained within the DT_REL table, and non-overlapping,
         * although in `ET_DYN` files it's usually just one - ".rel.dyn".
         */
        elf_idx_t *shdrs;
    } rel; /**< The dynsym relocation-without-addend table. */

    /**
     * @struct Container for data related to the `DT_RELA` table.
     *
     * It contains relocation-with-addend entries
     * which reference the dynamic symbol table.
     * The corresponding section name is (conventionally) ".rela.dyn".
     *
     * Mostly used in 64-bit binaries.
     */
    struct elf_reloc_rela {
        /**
         * Indicates whether a DT_REL table is present
         * and was successfully parsed.
         *
         * When false, all other members are semantically empty and must not
         * be used. When true, the table and its associated metadata are valid.
         */
        bool present;

        /**
         * Virtual address of the dynsym relocation-with-addend table;
         * the value of `DT_RELA`.
         */
        Elf64_Addr vaddr;

        /** File offset of the dynsym relocation-with-addend table. */
        Elf64_Off off;

        /**
         * Size of the dynsym relocation-with-addend table;
         * the value of `DT_RELASZ`.
         */
        Elf64_Xword size;

        /** Size of each ElfXX_Rela entry; the value of `DT_RELAENT`. */
        Elf64_Half entsize;

        /**
         * The array of `num` parsed `ElfXX_Rela` entries,
         * normalized to `Elf64_Rela` (see `read_rela` in `elf-types.c`).
         */
        Elf64_Rela *arr;

        /**
         * The number of entries in `arr`; equal to `DT_RELASZ / DT_RELAENT`.
         * Always greater than 0.
         */
        size_t num;

        /**
         * Index into the dynamic entries array of the `DT_RELA` entry,
         * whose value is equal to that of `vaddr`.
         * Always a valid index if `present == true`
         */
        elf_idx_t dt_rela_idx;

        /**
         * Index into the dynamic entries array of the `DT_RELASZ` entry,
         * whose value is equal to that of `size`.
         * Always a valid index if `present == true`
         */
        elf_idx_t dt_relasz_idx;

        /**
         * Index into the dynamic entries array of the `DT_RELAENT` entry,
         * whose value is equal to that of `entsize`.
         * Always a valid index if `present == true`
         */
        elf_idx_t dt_relaent_idx;

        /**
         * Index into the dynamic entries array of the optional `DT_RELACOUNT`
         * entry, whose value is equal to that of `relacount`.
         * Since the entry is an extension, this field might be `ELF_IDX_NULL`.
         */
        elf_idx_t dt_relacount_idx;

        /**
         * If the `DT_RELACOUNT` entry exists, the relocation entries must be
         * sorted such that all the `R_*_RELATIVE` relocations are placed
         * together (contiguously) at the start of the array.
         *
         * This is used for optimisation, as it allows the loader to perform
         * the relative relocations (which need to be handled at startup)
         * much quicker because the whole table doesn't need to be searched
         * and filtered for only relative relocations - they are all
         * neatly packed together in one place.
         *
         * @brief
         * This value represents the number of relative (`R_*_RELATIVE`)
         * relocations packed together at the start of the table,
         * and is meaningful iff `DT_RELACOUNT` exists
         * (`dt_relacount_idx != ELF_IDX_NULL`). Always `<= num`.
         */
        Elf64_Xword relacount;

        /**
         * Number of SHT_RELA section headers describing portions of the DT_RELA
         * table. May be zero if no matching section headers exist.
         */
        size_t n_shdrs;

        /**
         * The array of `num` `SHT_RELA` section indices which
         * describe the DT_RELA table, or `NULL` if none do.
         *
         * Multiple sections are permitted, provided their ranges are valid,
         * contained within the DT_RELA table, and non-overlapping,
         * although in `ET_DYN` files it's usually just one - ".rela.dyn".
         */
        elf_idx_t *shdrs;
    } rela; /**< The dynsym relocation-with-addend table. */

    /**
     * @struct Container for data related to the `DT_JMPREL` table.
     *
     * It contains a table of either REL or RELA relocation entries
     * which are specifically related to the Procedure Linkage Table (PLT).
     *
     * This separation of R_*_JUMP_SLOT relocations from the main DT_REL(A)
     * is done to enable lazy binding, i.e. the symbol resolution not being
     * performed immediately at startup, but instead when the corresponding
     * PLT function gets called for the first time.
     *
     * While today a lot of ELFs disable lazy binding for security reasons,
     * the separation of the tables is kept for historical and
     * optimisation-related reasons.
     *
     * On another note, the authors of the spec made the naming quite a mess.
     * For all intents and purposes, names with `JMP` and `PLT` all refer
     * to the PLT, or in this case, the table of relocations associated with it.
     * I decided to stick to the "JMPREL" naming for variable/field/function
     * names, but keep in mind that it all refers to the PLT relocation table.
     */
    struct elf_reloc_jmprel {
        /**
         * Indicates whether a DT_JMPREL table is present
         * and was successfully parsed.
         *
         * When false, all other members are semantically empty and must not
         * be used. When true, the table and its associated metadata are valid.
         */
        bool present;

        /**
         * Virtual address of the PLT relocation table;
         * the value of the DT_JMPREL entry.
         */
        Elf64_Addr vaddr;

        /** File offset of the PLT relocation table. */
        Elf64_Off off;

        /**
         * Size (in bytes) of the entire PLT relocation table;
         * the value of DT_PLTRELSZ.
         * Guaranteed to be greater than 0 and divisible by `entsize`.
         */
        Elf64_Xword size;

        /**
         * Size of each relocation entry.
         * Depending on `enttype`, it may be one of:
         *  - For `enttype == DT_REL`: `sizeof(ElfXX_Rel)`,
         *  - For `enttype == DT_RELA`: `sizeof(ElfXX_Rela)`.
         */
        Elf64_Half entsize;

        /**
         * The value of `DT_PLTREL`, which determines the type of relocations
         * that the PLT relocation table stores.
         *
         * May be either `DT_REL` or `DT_RELA`, for ElfXX_Rel and ElfXX_Rela
         * relocations, respectively.
         *
         * Note that while an ELF may theoretically contain both `DT_REL` and
         * `DT_RELA` tables, `DT_JMPREL` must "select" only one of the types.
         *
         * The value of this field determines which member of the `arr` union
         * is used, and in case of overlap with the main DT_REL(A) table,
         * which one of the two is referenced by `relX_overlap_start_idx`.
         */
        Elf64_Xword enttype;

        /**
         * @union Container for the array of relocation entries in DT_JMPREL.
         *
         * The JMPREL table may hold either `ElfXX_Rel` or `ElfXX_Rela` entries,
         * and so the value of `enttype` dictates which one of the two
         * members shall be used.
         *
         * The number of entries in the respective array is `num`.
         *
         * Since zero-sized JMPREL tables are rejected by the parser,
         * these arrays are guaranteed to always be non-NULL.
         *
         * The semantically empty version of this union is
         *  `(union elf_reloc_jmprel_arr) { 0 }`.
         */
        union elf_reloc_jmprel_arr {
            Elf64_Rel *rel; /**< The `ElfXX_Rel` relocation entries array. */
            Elf64_Rela *rela; /**< The `ElfXX_Rela` relocation entries array. */
        } arr; /**< Array of `num` `enttype` relocations stored in DT_JMPREL. */

        /**
         * The number of entries in the PLT relocation table; the size of `arr`.
         * Guaranteed to be greater than 0 (empty tables are rejected).
         */
        size_t num;

        /**
         * Index into the dynamic entries array of the `DT_JMPREL` entry,
         * which holds the virtual address of the PLT relocation table.
         * Its `d_un.d_ptr` is equal to `vaddr`.
         */
        elf_idx_t dt_jmprel_idx;

        /**
         * Index into the dynamic entries array of the `DT_PLTREL` entry,
         * which holds the type of relocation entries stored in the
         * PLT relocation table; either `DT_REL` or `DT_RELA`.
         * Its `d_un.d_val` is equal to `enttype`.
         */
        elf_idx_t dt_pltrel_idx;

        /**
         * Index into the dynamic entries array of the `DT_PLTRELSZ` entry,
         * which holds the size in bytes of the PLT relocation table.
         * Its `d_un.d_val` is equal to `size`.
         */
        elf_idx_t dt_pltrelsz_idx;

        /**
         * Number of section headers overlapping the PLT relocation table;
         * the size of `shdrs`.
         */
        size_t n_shdrs;

        /**
         * Array of `n_shdrs` indices of the sections that overlap the
         * PLT relocation table. If `n_shdrs == 0`, this member holds `NULL`.
         */
        elf_idx_t *shdrs;

        /**
         * If the PLT relocation table is part of the main DT_REL(A) table,
         * this member holds the index into the respective (selected `enttype`)
         * array of the first PLT-related relocation.
         * Otherwise, and this is the usual case, this value is `ELF_IDX_NULL`.
         *
         * The ELF spec allows the PLT-related relocation table to overlap
         * the main DT_REL(A) table. Since the whole implementation of the PLT
         * is processor-specific, the generic ELF ABI spec is intentionally
         * ambiguous regarding any further details here.
         *
         * In practice, however, only a handful of architectures do this,
         * with the only notable one being Sun SPARC.
         * There, the JMPREL table is placed as the "suffix" of the main
         * DT_REL(A) table, like so:
         *  { DT_REL(A).....      { DT_JMPREL...  }}
         *
         * In this arrangement, both tables have the same end address.
         * Consequently, storing the index of the first JMPREL entry is
         * sufficient to describe the overlap; the end of the overlapping
         * region is implied by the end of the main relocation table.
         *
         * Glibc assumes this to be the only possible case where
         * the two tables overlap, therefore I'm comfortable doing the same.
         *
         * All of the above assumptions and semantics are obviously validated.
         */
        elf_idx_t relX_overlap_start_idx;
    } jmprel; /**< The table of relocations related to the PLT. */
};

/**
 * Finds and parses all the different relocation tables.
 *
 * @return 0 on success, non-zero on failure.
 */
int parse_reloc(const ElfFileData *data,
                const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
                const struct elf_dyn_entries *entries,
                struct elf_reloc *out, Elf64_Word *out_max_symidx);

/**
 * Releases all dynamically allocated resources
 * owned by an `elf_reloc` struct.
 *
 * After this function returns, the structure is reset to its
 * semantically empty state (`empty_reloc_st`).
 *
 * A NULL argument is permitted. Calling this function repeatedly
 * on an initialized or previously destroyed structure is safe.
 *
 * @param[in,out] rel Structure to destroy, or NULL.
 */
void destroy_rel(struct elf_reloc *rel);

/**
 * The `elf_reloc_rel` struct initialized to semantically empty (NULL) values.
 */
__attribute__((unused))
static const struct elf_reloc_rel empty_reloc_rel_st = {
    .present = false,
    .vaddr = 0, .off = 0, .size = 0, .entsize = 0,
    .arr = NULL, .num = 0,
    .dt_rel_idx = ELF_IDX_NULL,
    .dt_relsz_idx = ELF_IDX_NULL,
    .dt_relent_idx = ELF_IDX_NULL,
    .dt_relcount_idx = ELF_IDX_NULL,
    .relcount = 0,
    .n_shdrs = 0, .shdrs = NULL
};

/**
 * The `elf_reloc_rela` struct initialized to semantically empty (NULL) values.
 */
__attribute__((unused))
static const struct elf_reloc_rela empty_reloc_rela_st = {
    .present = false,
    .vaddr = 0, .off = 0, .size = 0, .entsize = 0,
    .arr = NULL, .num = 0,
    .dt_rela_idx = ELF_IDX_NULL,
    .dt_relasz_idx = ELF_IDX_NULL,
    .dt_relaent_idx = ELF_IDX_NULL,
    .dt_relacount_idx = ELF_IDX_NULL,
    .relacount = 0,
    .n_shdrs = 0, .shdrs = NULL
};

/**
 * The `elf_reloc_jmprel_arr` union
 * initialized to semantically empty (NULL) values.
 */
__attribute__((unused))
static const union elf_reloc_jmprel_arr empty_reloc_jmprel_arr_un = { 0 };

/**
 * The `elf_reloc_jmprel` struct
 * initialized to semantically empty (NULL) values.
 */
__attribute__((unused))
static const struct elf_reloc_jmprel empty_reloc_jmprel_st = {
    .present = false,

    .vaddr = 0, .off = 0, .size = 0, .entsize = 0,
    .enttype = DT_NULL,

    .arr = empty_reloc_jmprel_arr_un,
    .num = 0,

    .dt_jmprel_idx = ELF_IDX_NULL,
    .dt_pltrel_idx = ELF_IDX_NULL,
    .dt_pltrelsz_idx = ELF_IDX_NULL,

    .n_shdrs = 0,
    .shdrs = NULL,

    .relX_overlap_start_idx = ELF_IDX_NULL
};

/** The `elf_reloc` struct initialized to semantically empty (NULL) values. */
__attribute__((unused))
static const struct elf_reloc empty_reloc_st = {
    .rel = empty_reloc_rel_st,
    .rela = empty_reloc_rela_st,
    .jmprel = empty_reloc_jmprel_st
};

#endif /* ELF_DYN_REL_PARSING_H_ */
