#ifndef ELF_DYN_PARSING_H_
#define ELF_DYN_PARSING_H_

/**
 * @file Dynamic section parsing module,
 *  separated from `elf-parsing` due to complexity.
 */

#include "elf.h"
#include "util.h"
#include "elf-dyn-sym-parsing.h"
#include "elf-dyn-sym-ver-parsing.h"

struct elf_phdrs;
struct elf_shdrs;

/**
 * @brief Everything related to the dynamic section that's relevant here.
 * @struct PT_DYNAMIC segment / SHT_DYNAMIC ".dynamic" section.
 *
 * Because we're working with dynamically linked ELFs, this segment
 * is mandatory and this struct will therefore always be populated
 * by `parse_elf`, even if there are no section headers.
 */
struct elf_dynamic {
    /**
     * Array of parsed DT_* dynamic entries (in-memory representation).
     * Always populated by `parse_elf`.
     */
    struct elf_dyn_entries {
        /** The real number of entries in the _DYNAMIC array */
        Elf64_Xword num;

        /**
         * Equal to `num` * `dynentsize`.
         *
         * Meant to provide a way to delegate integer overflow validation
         * exclusively to functions that mutate the dynamic entries struct,
         * saving on complexity in code which just needs to read this value.
         */
        Elf64_Xword size;

        /**
         * In-memory array of parsed dynamic entries.
         * Note: DO NOT ACCESS DIRECTLY. See `get_dyn_rw`/`get_dyn_ro`.
         */
        Elf64_Dyn *arr;

        bool dirty; /**< Dirty flag (see `serialize_elf`). */
    } entries; /**< In-memory representation of the _DYNAMIC array. */

    /* Index of the PT_DYNAMIC program header (reference into `phdrs`).
     * On success, `read_validate_dynamic_section`
     * will always write a valid value here. */
    elf_idx_t phdr;

    /* Index of the SHT_DYNAMIC section header (reference into `shdrs`).
     * `read_validate_dynamic_section` might write `ELF_IDX_NULL` here. */
    elf_idx_t shdr;

    /** @struct Data related to the `.dynstr` dynamic string table. */
    struct elf_dyn_strtab {
        /* The value of the DT_STRTAB entry;
         * contains the virtual addres of the .dynamic string table. */
        Elf64_Addr vaddr;

        /* The offset of the dynamic string table within the ELF data */
        Elf64_Off off;

        /* The value of the DT_STRSZ entry;
         * the size of the dynamic string table (`.dynstr`). */
        Elf64_Xword size;

        /* Index of the .dynstr section header (reference into `shdrs`).
         * Might be NULL if there's no .dynstr section. */
        elf_idx_t shdr;

        /* string tables don't need any re-serialization
         * as the singular bytes (characters) that make them up are
         * the same across all platforms, which means no `dirty` flag. */

    } strtab; /**< Data related to the `.dynstr` dynamic string table. */


    /** DYNAMIC SYMBOL DATA **/
    /** See `elf-dyn-sym-parsing.h` */

    /** Data related to the legacy DT_HASH symbol lookup table. */
    struct elf_dt_hash hash;

    /** Data related to the new DT_GNU_HASH symbol lookup table. */
    struct elf_dt_gnu_hash gnu_hash;

    /** Data related to the dynamic symbol table (`.dynsym`). */
    struct elf_dyn_symtab symtab;

    /** Data related to the dynsym SYMTAB_SHNDX section. */
    struct elf_dyn_symtab_shndx symtab_shndx;

    /** DYNAMIC SYMBOL VERSION INFORMATION **/
    /** See `elf-dyn-sym-ver-parsing.h` */

    /** Dynamic symbol version information. */
    struct elf_dyn_sym_ver sym_ver;
};

/**
 * @brief Parses .dynamic and all related sections.
 * Part of `parse_elf` (`elf-parsing.h`).
 *
 * The parsing is done using only the PT_DYNAMIC program headers
 * (without relying on the section headers),
 * but if section headers are present they will be checked
 * against the data in the phdrs.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] phdrs Array of parsed and validated program headers.
 *  Must not be NULL.
 *
 * @param[in] shdrs Array of parsed and validated section headers.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer.
 *  May be NULL, in which case it simply won't be written to
 *  and all allocated resources will be freed automatically.
 *
 * @param[out] out_dynentsize Output pointer for the size of a dynamic entry
 *  (`sizeof(Elf32_Dyn)` for 32-bit and `sizeof(Elf64_Dyn)` for 64-bit).
 *  May be NULL, in which case it simply won't be written to.
 *
 * @param[out] out_dynsymentsize Output pointer for the size of a dynamic symbol
 *  (`sizeof(Elf32_Sym)` for 32-bit and `sizeof(Elf64_Sym)` for 64-bit);
 *  the value of the `DT_SYMENT` entry.
 *  May be NULL, in which case it simply won't be written to.
 *
 * @return 0 on success, non-zero if the dynamic linking data is
 *  absent or malformed.
 */
int parse_dyn(const ElfFileData *data,
              const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,

              struct elf_dynamic *out,
              Elf64_Half *out_dynentsize, Elf64_Half *out_dynsymentsize);


/**
 * Frees all resources associated with a dynamic linking data struct.
 *
 * Only frees resources when their references in the struct are actually there,
 * and if so, the references are later destroyed.
 * Therefore, it is safe to call this function even multiple times
 * on structs that may have already been destroyed without risking double-frees.
 *
 * @param[in,out] dyn The struct to destroy.
 *  May be NULL, in which case the call is a no-op.
 */
void destroy_dyn(struct elf_dynamic *dyn);


/**
 * The `elf_dyn_entries` structure
 * initialized to semantically empty (NULL) values.
 * Functionally equivalent to just `(struct elf_dyn_entries) { 0 }`.
 */
__attribute__((unused))
static const struct elf_dyn_entries empty_dyn_entries_st = {
    .num = 0, .size = 0,
    .arr = NULL,
    .dirty = false
};

/**
 * The `elf_dyn_strtab` structure
 * initialized to semantically empty (NULL) values.
 */
__attribute__((unused))
static const struct elf_dyn_strtab empty_dyn_strtab_st = {
    .vaddr = 0, .off = 0, .size = 0,
    .shdr = ELF_IDX_NULL
};

/**
 * The `elf_dynamic` structure
 * initialized to semantically empty (NULL) values.
 */
__attribute__((unused))
static const struct elf_dynamic empty_elf_dynamic_st = {
    .entries = empty_dyn_entries_st,
    .phdr = ELF_IDX_NULL,
    .shdr = ELF_IDX_NULL,
    .strtab = empty_dyn_strtab_st,

    .hash = empty_hash_st,
    .gnu_hash = empty_gnu_hash_st,
    .symtab = empty_symtab_st,
    .symtab_shndx = empty_symtab_shndx_st,

    .sym_ver = empty_ver_st
};

#endif /* ELF_DYN_PARSING_H_ */
