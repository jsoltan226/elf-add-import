#ifndef ELF_DYN_SYM_PARSING_H_
#define ELF_DYN_SYM_PARSING_H_

/**
 * @file Module that parses the ".dynsym" dynamic symbol table.
 * Factored out of `elf-dyn-parsing` due to relative complexity.
 */

#include "ctx.h"

/**
 * @brief
 * Locates and parses the dynamic symbol table, and the `DT_*HASH` table(s),
 * as well as all other related data. Part of `parse_dyn` (`elf-dyn-parsing.h`).
 *
 * Due to the questionable way the relevant part of the ELF spec is structured,
 * this function ended up being way more complex than anticipated.
 * Parsed dynamic entries include:
 *  `DT_SYMTAB`, `DT_SYMENT`, `DT_HASH`, `DT_GNU_HASH`, `DT_SYMTAB_SHNDX`
 * Parsed sections:
 *  `SHT_DYNSYM`, `SHT_HASH`, `SHT_GNU_HASH`, dynsym `SHT_SYMTAB_SHNDX`
 *
 * For more info, see the source file (`elf-dyn-sym-parsing.c`),
 * as well definitions of `struct elf_dyn_symtab`, `struct elf_dt_hash`,
 * `struct elf_dt_gnu_hash` and `struct elf_dyn_symtab_shndx` in `ctx.h`.
 *
 * All the output structs (`out_hash`, `out_gnu_hash`, `out_symtab_shndx`
 * and `out`) are either populated by this function from scratch (on success),
 * or fully cleaned (on failure).
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file.
 *
 * @param[in] encoding Data (byte) order of the ELF file.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[in] strtab The dynamic string table (.dynstr). Must not be NULL.
 *
 * @param[out] out_hash Output pointer for the parsed (legacy) `DT_HASH`
 *  symbol lookup table structure. Must not be NULL. If the ELF doesn't have
 *  a `DT_HASH`, the `present` flag in this struct is set to `false`.
 *
 * @param[out] out_gnu_hash Output pointer for the parsed (modern) `DT_GNU_HASH`
 *  symbol lookup table structure. Must not be NULL. If the ELF doesn't have
 *  a `DT_GNU_HASH`, the `present` flag in this struct is set to `false`.
 *
 * @param[out] out_symtab_shndx Output pointer for the SYMTAB_SHNDX data,
 *  which contains extended section indices for dynamic symbols whose
 *  `st_shndx` field is `SHN_XINDEX`. Must not be NULL.
 *  If the ELF file doesn't have SYMTAB_SHNDX data associated with the
 *  dynamic symbol table, the `present` flag in this struct is set to `false`.
 *
 * @param[out] out Output pointer for the parsed dynamic symbol table.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int parse_dynsym(
    const struct blob *data, int clazz, int encoding,
    const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
    const struct elf_dyn_entries *entries, const struct elf_dyn_strtab *strtab,

    struct elf_dt_hash *out_hash, struct elf_dt_gnu_hash *out_gnu_hash,
    struct elf_dyn_symtab_shndx *out_symtab_shndx, struct elf_dyn_symtab *out
);

#endif /* ELF_DYN_SYM_PARSING_H_ */
