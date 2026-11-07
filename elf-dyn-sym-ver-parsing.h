#ifndef ELF_DYN_SYM_VER_PARSING_H_
#define ELF_DYN_SYM_VER_PARSING_H_

/**
 * @file The module that parses GNU-style dynamic symbol version information.
 */

#include "util.h"

struct elf_phdrs;
struct elf_shdrs;
struct elf_dyn_strtab;
struct elf_dyn_symtab;
struct elf_dyn_entries;

/** @struct In-memory representation of dynamic symbol version information. */
struct elf_dyn_sym_ver {
    /**
     * True iff dynamic symbol versioning information is present in the ELF.
     *
     * In a valid parsed object, this means that `DT_VERSYM` is present;
     * `def.present` and/or `need.present` indicate the associated definition
     * and dependency tables.
     */
    bool present;

    /**
     * @struct In-memory representation of dynamic symbol
     * version definition information.
     */
    struct elf_dyn_sym_ver_def {
        /**
         * True iff version definition information is present, i.e. the
         * `DT_VERDEF`/`DT_VERDEFNUM` dynamic entry pair was found
         * and the verdef list is structurally valid.
         */
        bool present;

        /**
         * Number of verdef entries in `arr`; the value of `DT_VERDEFNUM`.
         * If version definitions are `present` at all, this value is
         * always >= 1. See the comment on `base_idx` for the reason why.
         */
        Elf64_Xword num;

        /** @struct A struct coupling a verdef entry with its aux info list. */
        struct elf_dyn_sym_ver_def_ent {
            Elf64_Verdef vd; /**< The verdef entry. */

            /**
             * Collected list of auxiliary information entries for `vd`,
             * of size `vd.vd_cnt`.
             *
             * Since the spec requires that every verdef have at least one
             * auxiliary entry, this array is never set to NULL
             * when version definitions are `present` at all.
             */
            Elf64_Verdaux *aux_list;
        } *arr; /**< Collected list of `num` verdefs. Never NULL (see `num`). */

        /**
         * @brief Index (into `arr`) of the "base" entry.
         *
         * The base entry has the `VER_FLG_BASE` flag set and it represents
         * the base version definition of the ELF object itself.
         * If a file has version definitions, exactly one base entry must exist,
         * therefore `base_idx` is never `ELF_IDX_NULL` when `present == true`.
         */
        elf_idx_t base_idx;

        /**
         * Virtual address of the start of the version definition entry list;
         * the value of `DT_VERDEF`.
         */
        Elf64_Addr vaddr;

        /** File offset of the start of the version definition entry list. */
        Elf64_Off off;

        /**
         * Index of the `DT_VERDEF` dynamic entry, which holds the
         * virtual address of the start of the version definition entry list.
         * Its `d_un.d_ptr` equals `vaddr`.
         * Always exists when version definitions are `present`.
         */
        elf_idx_t dt_verdef_idx;

        /**
         * Index of the `DT_VERDEFNUM` dynamic entry, which holds the count
         * of version definition entries. Its `d_un.d_val` is equal to `num`.
         * Always exists when version definitions are `present`.
         */
        elf_idx_t dt_verdefnum_idx;

        /**
         * Index of the `SHT_GNU_verdef` section header, if present,
         * or `ELF_IDX_NULL` if absent.
         */
        elf_idx_t shdr;
    } def; /**< Version definition information. */

    /**
     * @struct In-memory representation of dynamic symbol
     * version dependency information.
     */
    struct elf_dyn_sym_ver_need {
        /**
         * True iff version dependency information is present, i.e. the
         * `DT_VERNEED`/`DT_VERNEEDNUM` dynamic entry pair was found
         * and the verneed list is structurally valid.
         */
        bool present;

        /**
         * Number of version dependency entries;
         * the value of `DT_VERNEEDNUM`.
         */
        Elf64_Xword num;

        /** @struct A struct coupling a verneed entry with its aux info list. */
        struct elf_dyn_sym_ver_need_ent {
            Elf64_Verneed vn; /**< The verneed entry. */

            /**
             * Collected list of auxiliary information entries for `vn`,
             * of size `vn.vn_cnt`.
             *
             * Every Verneed is required to have at least one Vernaux entry,
             * so this pointer is never NULL for an element of `arr`.
             */
            Elf64_Vernaux *aux_list;
        } *arr; /**< Collected list of `num` verneeds or NULL if `num == 0`. */

        /**
         * Virtual address of the start of the version dependency entry list;
         * the value of `DT_VERNEED`.
         */
        Elf64_Addr vaddr;

        /** File offset of the start of the version dependency entry list. */
        Elf64_Off off;

        /**
         * Index of the `DT_VERNEED` dynamic entry, which holds the
         * virtual address of the start of the version dependency entry list.
         * Its `d_un.d_ptr` equals `vaddr`.
         * Always exists if version dependencies are `present`.
         */
        elf_idx_t dt_verneed_idx;

        /**
         * Index of the `DT_VERNEEDNUM` dynamic entry, which holds the count
         * of version dependency entries. Its `d_un.d_val` is equal to `num`.
         * Always exists if version dependencies are `present`.
         */
        elf_idx_t dt_verneednum_idx;

        /**
         * Index of the `SHT_GNU_verneed` section header, if present,
         * or `ELF_IDX_NULL` if absent.
         */
        elf_idx_t shdr;
    } need; /**< Version dependency information. */

    /**
     * @struct In-memory representation of the versym array.
     * It ties every dynamic symbol to a version definition or dependency,
     * from the above `def` and `need` tables.
     */
    struct elf_dyn_sym_ver_sym {
        /* No `present` flag because this structure must be present when
         * any version info is present at all, so if the top-level `present`
         * is set, this struct can be considered populated and valid. */

        /**
         * Number of versym entries; equal to the number of dynamic symbols
         * (`symtab.nsyms`).
         */
        Elf64_Xword num;

        /** The array of `num` version indices (identifiers). */
        Elf64_Half *arr;

        /** Virtual address of the versym array; the value of `DT_VERSYM`. */
        Elf64_Addr vaddr;

        /** File offset of the versym array. */
        Elf64_Off off;

        /**
         * Total size (in bytes) of the versym array.
         * Equal to `num * sizeof(Elf64_Half)`.
         */
        Elf64_Xword size;

        /**
         * Index of the `DT_VERSYM` dynamic entry, which holds
         * the virtual address of the versym array.
         * Its `d_un.d_ptr` is equal to `vaddr`.
         */
        elf_idx_t dt_versym_idx;

        /**
         * Index of the `SHT_GNU_versym` section header,
         * or `ELF_IDX_NULL` if not present.
         */
        elf_idx_t shdr;
    } sym;
};

/**
 * Finds and parses the GNU-style dynamic symbol versioning information.
 *
 * This function establishes the structural correctness of all found
 * dynamic symbol versioning data. On success and when specified,
 * it writes the parsed data to the output parameter.
 * In every other case, all allocated resources are freed.
 *
 * Both version definitions (exports) and dependencies (imports) are parsed.
 * Version information is considered present whenever `DT_VERSYM` exists,
 * even if neither `DT_VERDEF` nor `DT_VERNEED` is present.
 * However, `DT_VERDEF` and `DT_VERNEED` cannot exist without `DT_VERSYM`.
 *
 * @param[in] phdrs Parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs Parsed section headers array. Must not be NULL.
 *
 * @param[in] strtab Parsed dynamic string table (.dynstr). Must not be NULL.
 *
 * @param[in] symtab Parsed dynamic symbol table (.dynsym). Must not be NULL.
 *
 * @param[in] entries Parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] data ELF file data. Must not be NULL.
 *
 * @param[out] out Output pointer. May be NULL, in which case
 *  the function runs normally but all allocated resources are freed
 *  before returning. The struct is only populated on success.
 *
 * @return 0 on success (valid version info),
 *         1 if no version info is found,
 *         -1 if the version info is malformed or some other error occurs.
 */
int parse_ver(const struct elf_phdrs *phdrs,
              const struct elf_shdrs *shdrs,
              const struct elf_dyn_strtab *strtab,
              const struct elf_dyn_symtab *symtab,
              const struct elf_dyn_entries *entries,
              const ElfFileData *data,
              struct elf_dyn_sym_ver *out);

/**
 * The verdef `elf_dyn_sym_ver_def` struct
 * initialized to semantically empty values.
 */
__attribute__((unused))
static const struct elf_dyn_sym_ver_def empty_verdef_st = {
    .present = false,
    .num = 0, .arr = NULL,
    .base_idx = ELF_IDX_NULL,
    .vaddr = 0, .off = 0,
    .dt_verdef_idx = ELF_IDX_NULL, .dt_verdefnum_idx = ELF_IDX_NULL,
    .shdr = ELF_IDX_NULL
};

/**
 * The verneed `elf_dyn_sym_ver_need` struct
 * initialized to semantically empty values.
 */
__attribute__((unused))
static const struct elf_dyn_sym_ver_need empty_verneed_st = {
    .present = false,
    .num = 0, .arr = NULL,
    .vaddr = 0, .off = 0,
    .dt_verneed_idx = ELF_IDX_NULL, .dt_verneednum_idx = ELF_IDX_NULL,
    .shdr = ELF_IDX_NULL
};

/**
 * The versym `elf_dyn_sym_ver_sym` struct
 * initialized to semantically empty values.
 */
__attribute__((unused))
static const struct elf_dyn_sym_ver_sym empty_versym_st = {
    .num = 0, .arr = NULL,
    .vaddr = 0, .off = 0, .size = 0,
    .dt_versym_idx = ELF_IDX_NULL,
    .shdr = ELF_IDX_NULL
};

/**
 * The top-level `elf_dyn_sym_ver` struct
 * initialized to semantically empty values.
 */
__attribute__((unused))
static const struct elf_dyn_sym_ver empty_ver_st = {
    .present = false,
    .def = empty_verdef_st,
    .need = empty_verneed_st,
    .sym = empty_versym_st
};


#endif /* ELF_DYN_SYM_VER_PARSING_H_ */
