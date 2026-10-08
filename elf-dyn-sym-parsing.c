#include "elf-dyn-sym-parsing.h"
#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/**
 * Locates the dynamic symbol table by finding the `DT_SYMTAB` entry.
 * Also finds and validates `DT_SYMENT` (size of one symbol struct).
 * Part of `parse_dynsym`.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (for validation of `DT_SYMENT`).
 *
 * @param[out] out_vaddr Output pointer for the virtual address of the
 *  dynamic symbol table; the value of `DT_SYMTAB`. Must not be NULL.
 *
 * @param[out] out_symentsize Output pointer for the size of a single symbol
 *  (`sizeof(Elf32_Sym)` for `clazz == ELFCLASS32` and
 *   `sizeof(Elf64_Sym)` for `clazz == ELFCLASS64`);
 *  the value of `DT_SYMENT`. Must not be NULL.
 *
 * @param[out] out_dt_symtab Output pointer for the index of the found
 *  `DT_SYMTAB` entry (a reference into `entries`). Must not be NULL.
 *
 * @param[out] out_dt_syment Output pointer for the index of the found
 *  `DT_SYMENT` entry (a reference into `entries`). Must not be NULL.
 *
 * @return 0 on success, non-zero if any of the entries aren't found
 *  or if `DT_SYMENT` is invalid.
 */
static int find_symtab(const struct elf_dyn_entries *entries, int clazz,
                       Elf64_Addr *out_vaddr, Elf64_Half *out_symentsize,
                       elf_idx_t *out_dt_symtab, elf_idx_t *out_dt_syment);

/**
 * Locates and parses the `DT_HASH` and/or `DT_GNU_HASH` symbol lookup tables,
 * determining the number of dynamic symbols in the process.
 * Part of `parse_dynsym`.
 *
 * At least one of the two (`DT_HASH` - legacy, or `DT_GNU_HASH` - modern)
 * hash tables must be present in a dynamically linked ELF binary.
 * If both are found, the inferred symbol counts are cross-checked
 * against each other.
 *
 * Note: Due to there being no `nchain` (or similar) field in the `DT_GNU_HASH`
 * structure, the table has to be validated against the symtab it indexes.
 *
 * Since there's also no `DT_SYMTABSZ` or similar entry which would tell us
 * the number of dynamic symbols ahead of time, a kind of circular dependency
 * is created where our only option is to first parse `DT_GNU_HASH`,
 * hope the terminator entry we hit is valid and the hash table
 * size matches the symtab, then based on that uncertain information
 * parse the symtab and cross-check every symbol against the hash table.
 *
 * This means that the procedure goes basically like this:
 *  1) `parse_dynamic_hash_tables()`
 *  2) `read_dynamic_symbol_table()`
 *  3) `validate_dynamic_hash_tables()`
 *
 * Only after that one can be relatively sure that both
 * the symtab and the hash table(s) are valid and consistent.
 *
 * Good job, whoever was writing the spec.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] entries The array of parsed dynamic entries. Must not be NULL.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[out] out_hash Output pointer for the parsed `DT_HASH` structure.
 *  If no `DT_HASH` is found, default (empty) values are written here
 *  and the `present` field is set to `false`. Must not be NULL.
 *
 * @param[out] out_gnu_hash Output pointer for the parsed `DT_GNU_HASH`
 *  structure. If no `DT_GNU_HASH` is found, default (empty) values
 *  are written here and the `present` field is set to `false`.
 *  Must not be NULL.
 *
 * @param[out] out_dynsym_count Output pointer for the number of dynamic symbols
 *  inferred from the hash tables' contents. Must not be NULL.
 *
 * @return 0 on success (one or both hash tables are found and valid),
 *  non-zero on failure (one or more tables invalid or both missing).
 */
static int parse_dynamic_hash_tables(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,

        struct elf_dt_hash *out_hash, struct elf_dt_gnu_hash *out_gnu_hash,
        Elf64_Xword *out_dynsym_count
);

/**
 * Finds and parses the DT_HASH structure - the legacy dynamic symbol lookup
 * hash table. For the modern DT_GNU_HASH, see `parse_dt_gnu_hash`.
 * Part of `parse_dynamic_hash_tables`, which is part of `parse_dynsym`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[out] out Output pointer (see the definition of `struct elf_dt_hash`).
 *  Must not be NULL.
 *
 * @return 0 on success,
 *  positive value if not found,
 *  negative value if found but malformed.
 */
static int parse_dt_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_hash *out
);

/**
 * Finds the DT_HASH dynamic entry and using that,
 * locates and validates the bounds of the DT_HASH table structure.
 * Part of `parse_dt_hash`.
 *
 * Initializes the `struct elf_dt_hash`.
 * The following fields are populated with validated values:
 *  - vaddr, off, total_size, dyn_entry,
 *  - hdr.nbucket, hdr.nchain,
 * The following fields are initialized to empty values:
 *  - buckets (array), chain (array) - NULL,
 *  - shdr (shdr table index) - ELF_IDX_NULL.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success,
 *  positive value if not found,
 *  negative value if found but malformed.
 */
static int find_dt_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_dyn_entries *entries,
        struct elf_dt_hash *out
);

/**
 * Based on the data from `find_dt_hash`, reads and validates the contents
 * of the DT_HASH `buckets` and `chain` arrays.
 * Part of `parse_dt_hash`.
 *
 * All temporary resources are freed in case of failure.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[in] hdr The DT_HASH header containing the number of entries
 *  in `buckets` and `chain`. Must not be NULL.
 *
 * @param[in] end The byte right after the end of the whole structure,
 *  i. e. the offset + size. Used to validate the value of `*off_p`
 *  after reading.
 *
 * @param[out] out_buckets Output pointer for the buckets array.
 *  On success, will contain `hdr->nbucket` entries. Must not be NULL.
 *
 * @param[out] out_chain Output pointer for the chain array.
 *  On success, will contain `hdr->nchain` entries. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_dt_hash_contents(
        const struct blob *data, int clazz, int encoding, uint64_t *off_p,
        const struct elf_dt_hash_hdr *hdr, Elf64_Off end,
        Elf32_Word **out_buckets, Elf32_Word **out_chain
);

/**
 * Tries to find a `SHT_HASH` section header and validates it if present.
 * Part of `parse_dt_hash`.
 *
 * Also validates that the SHT_DYNSYM table size matches the value
 * derived from the DT_HASH data.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] dt_hash The DT_HASH data previously populated by
 *  `find_dt_hash` and `read_dt_hash_contents`.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[in] clazz Class of the ELF file.
 *
 * @param[out] out Output pointer for the found SHT_HASH section header's index
 *  (a reference into `shdrs`), or `ELF_IDX_NULL` if nothing is found.
 *  Must not be NULL.
 *
 * @return 0 on success (either nothing or a valid shdr is found),
 *  non-zero on failure (an invalid shdr is found).
 */
static int validate_sht_hash_if_exists(const struct elf_shdrs *shdrs,
                                       const struct elf_dt_hash *dt_hash,
                                       elf_idx_t sht_dynsym_idx, int clazz,
                                       elf_idx_t *out);

/**
 * Parses the DT_GNU_HASH structure - the modern dynamic symbol lookup
 * hash table. For the legacy DT_HASH, see `parse_dt_hash`.
 * Part of `parse_dynamic_hash_tables`, which is part of `parse_dynsym`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success,
 *  positive value if not found,
 *  negative value if found but malformed.
 */
static int parse_dt_gnu_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_gnu_hash *out
);

/**
 * Reads the DT_GNU_HASH structure's header,
 * also validating that the `nbuckets` and `bloom_size` fields
 * are representable as `size_t` (they are later used in allocations).
 * Part of `find_dt_gnu_hash`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 */
static int read_dt_gnu_hash_hdr(
        const struct blob *data, int clazz, int encoding, uint64_t *off_p,
        struct elf_dt_gnu_hash_hdr *out
);

/**
 * Finds the `DT_GNU_HASH` dynamic entry and based on it,
 * locates and parses the GNU hash structure header, validating
 * that it fits within its PT_LOAD segment's file range and address space.
 * Part of `parse_dt_gnu_hash`.
 *
 * The following fields of `struct elf_dt_hash` are parsed:
 *  - vaddr, off
 *  - dyn_entry,
 *  - hdr,
 *  - bloomentsize
 * The rest are initialized to default values:
 *  - bloom (array), buckets (array), chain (array) - NULL,
 *  - nchain, total_size - 0,
 *  - shdr (shdr table index) - ELF_IDX_NULL
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @param[out] out_pt_load_idx Output pointer for the index of the PT_LOAD
 *  segment that contains the GNU hash header (a reference into `phdrs`).
 *  Must not be NULL.
 *
 * @return 0 on success,
 *  positive value if not found,
 *  negative value if found but malformed.
 */
static int find_dt_gnu_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_dyn_entries *entries,
        struct elf_dt_gnu_hash *out, elf_idx_t *out_pt_load_idx
);

/**
 * Based on the information from the GNU hash structure
 * header (`find_dt_gnu_hash`), parses the bloom filter and buckets array.
 * Part of `parse_dt_gnu_hash`.
 *
 * The following fields in `struct elf_dt_gnu_hash` are read:
 *  - off, vaddr,
 *  - hdr,
 *  - bloomentsize
 * The following fields are populated:
 *  - buckets (array),
 *  - bloom (array)
 *
 * The rest of the fields are unused.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in,out] ctx The DT_GNU_HASH structure context.
 *  See the details of this function's description for info
 *  on which fields are used and written to. Must not be NULL.
 *
 * @param[in] pt_load_idx The index of the PT_LOAD segment that contains
 *  the GNU hash structure. Must be the one obtained from `find_dt_gnu_hash`.
 *
 * @param[out] out_max_bucket Output pointer for the highest value
 *  in the `buckets` array. This is used in later steps; computed here
 *  for convenience since we're parsing the buckets array anyways.
 *  Must not be NULL.
 *
 * @param[out] out_chain_off Output pointer for the offset of the `chain`
 *  array. This is also used in later steps and similarly; computed here
 *  for convenience. This value will points past the read `bloom` and `buckets`
 *  arrays. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_bloom_and_buckets(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, struct elf_dt_gnu_hash *ctx,
        elf_idx_t pt_load_idx, Elf32_Word *out_max_bucket,
        Elf64_Off *out_chain_off
);

/**
 * Based on the information from the GNU hash header and buckets array,
 * locates and traverses the chain array to find its length.
 * Part of `parse_dt_gnu_hash`.
 *
 * The traversal is bounds-checked against the PT_LOAD segment
 * that contains the rest of the GNU hash structure.
 * Due to the... questionable way the spec is written (not specifying
 * the length of this array in the header), the value obtained from this
 * function can only really be finally trusted after trying to look up
 * every symbol that the hash table indexes.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] containing_phdr_idx The index of the PT_LOAD segment that contains
 *  the GNU hash structure. Must be the one obtained from `find_dt_gnu_hash`.
 *
 * @param[in] ctx The GNU hash structure data, populated by
 *  `find_dt_gnu_hash` and `read_bloom_and_buckets`. Must not be NULL.
 *
 * @param[in] max_bucket The highest value in the `buckets` array.
 *  Must be the value obtained from `read_bloom_and_buckets`.
 *
 * @param[in] chain_off Offset of the chain array.
 *  Must be the value obtained from `read_bloom_and_buckets`.
 *
 * @param[out] out Output pointer for the found number of chain array entries.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero if the chain array doesn't terminate properly
 *  before reaching the segment bounds.
 */
static int find_gnu_hash_nchain(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t containing_phdr_idx,
        const struct elf_dt_gnu_hash *ctx, Elf32_Word max_bucket,
        Elf64_Off chain_off, Elf32_Word *out
);

/**
 * Reads the GNU hash `chain` array.
 * Part of `parse_dt_gnu_hash`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] chain_off Offset of the chain array (at which to start reading).
 *  Must be the value obtained from `read_bloom_and_buckets`.
 *
 * @param[in] nchain The number of entries to read.
 *  Must be the value obtained from `find_gnu_hash_nchain`.
 *
 * @param[out] out Output pointer for the read chain array of `nchain` entries.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_gnu_hash_chain(
        const struct blob *data, int clazz, int encoding,
        Elf64_Off chain_off, Elf32_Word nchain, Elf32_Word **out
);

/**
 * Tries to find a `SHT_GNU_HASH` section header and validates it if present.
 * Part of `parse_dt_gnu_hash`.
 *
 * Also validates that the SHT_DYNSYM table size matches the value
 * derived from the DT_GNU_HASH data.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] ctx The DT_GNU_HASH data previously populated by
 *  `find_dt_hash`, `read_bloom_and_buckets` and `read_gnu_hash_chain`.
 *  Must not be NULL.
 *
 * @param[in] sht_dynsym_idx The index of a `SHT_DYNSYM` section, if it exists.
 *  Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[in] clazz Class of the ELF file.
 *
 * @param[out] out_sht_gnu_hash_idx Output pointer for the found SHT_GNU_HASH
 *  section header's index (a reference into `shdrs`),
 *  or `ELF_IDX_NULL` if nothing is found. Must not be NULL.
 *
 * @return 0 on success (either nothing or a valid shdr is found),
 *  non-zero on failure (an invalid shdr is found).
 */
static int validate_sht_gnu_hash_if_exists(const struct elf_dt_gnu_hash *ctx,
                                           const struct elf_shdrs *shdrs,
                                           elf_idx_t sht_dynsym_idx, int clazz,
                                           elf_idx_t *out_sht_gnu_hash_idx);

/**
 * Reads and performs basic validation of the dynamic symbol table (.dynsym).
 * Part of `parse_dynsym`.
 *
 * Note: If `n_shdrs == 0` (the section header table has been fully stripped),
 * ordinary section indices cannot be validated. Such references are retained
 * and accepted with a warning, and must not be trusted without additional
 * information.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] tbl_offset Offset of the symtab; the value of `DT_SYMTAB`.
 *
 * @param[in] nsyms Number of dynamic symbols inferred from the
 *  `DT_(GNU_)HASH` table(s).
 *
 * @param[in] dynstr_size Size of the dynamic string table (.dynstr),
 *  used for validation of the symbols' `st_name` fields.
 *
 * @param[in] n_shdrs Number of section headers,
 *  used for validation of the symbols' `st_shndx` fields.
 *
 * @param[out] out Output pointer for the array of `nsyms`
 *  parsed dynamic symbols. Only written to on success;
 *  in case of failure everything is freed & cleaned up before returning.
 *  Must not be NULL.
 *
 * @param[out] out_uses_symtab_shndx Output pointer for
 *  whether some symbol's `st_shndx` value is set to `SHN_XINDEX`,
 *  necessitating the presence of a SYMTAB_SHNDX section.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_dynamic_symbol_table(
        const struct blob *data, int clazz, int encoding,
        Elf64_Off tbl_offset, Elf64_Xword nsyms,
        Elf64_Xword dynstr_size, Elf64_Xword n_shdrs,
        Elf64_Sym **out, bool *out_uses_symtab_shndx
);

/**
 * Validates the structural consistency
 * of the `DT_HASH` and/or `DT_GNU_HASH` tables.
 * Part of `parse_dynsym`.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] strtab The parsed dynamic string table (.dynstr).
 *  Must not be NULL.
 *
 * @param[in] hash The parsed `DT_HASH` structure. Must not be NULL,
 *  but may have its `present` field set to `false` in which case
 *  it won't be checked.
 *
 * @param[in] gnu_hash The parsed `DT_GNU_HASH` structure. Must not be NULL,
 *  but may have its `present` field set to `false` in which case
 *  it won't be checked.
 *
 * @param[in] symtab The parsed dynamic symbol table. Must not be NULL.
 *
 * @param[in] nsyms The number of entries in `symtab`.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_dynamic_hash_tables(
        const struct blob *data, const struct elf_dyn_strtab *strtab,
        const struct elf_dt_hash *hash, const struct elf_dt_gnu_hash *gnu_hash,
        const Elf64_Sym *symtab, Elf64_Xword nsyms, int clazz
);

/**
 * The legacy SysV `DT_HASH` symbol lookup table hash function.
 * Part of `validate_sysv_hash`.
 *
 * @param[in] name The NULL-terminated name of the symbol to hash.
 *  Must not be NULL.
 *
 * @return The hash of `name`.
 */
static inline Elf32_Word sysv_hash(const uint8_t *name);

/**
 * Validates the legacy SysV-style `DT_HASH` symbol name lookup hash table.
 * Part of `validate_dynamic_hash_tables`, which is part of `parse_dynsym`.
 *
 * Checks that every indexed symbol is reachable through the table
 * and ensures that the structure itself is consistent.
 *
 * Note: This function only establishes _structural_ correctness,
 * not _semantic_ correctness. That is, it ensures that every symbol
 * that should be able to be looked up - can be looked up;
 * not that the symbols themselves actually should or should not
 * participate in dynamic linking and be indexed in the table.
 *
 * Basically, it only checks that the lookup machine works,
 * not that it's used correctly.
 *
 * @param[in] hash The SysV hash structure to validate. Must not be NULL.
 *
 * @param[in] symtab The parsed dynamic symbol table array of count `nsyms`.
 *  Must not be NULL when `nsyms > 0`.
 *
 * @param[in] nsyms The number of dynamic symbol structs in the table.
 *
 * @param[in] strtab The parsed dynamic string table structure (.dynstr).
 *  Must not be NULL.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @return 0 on success (hash table valid or not present at all),
 *  non-zero if the table is invalid.
 */
static int validate_sysv_hash(const struct elf_dt_hash *hash,
                              const Elf64_Sym *symtab, Elf64_Xword nsyms,
                              const struct elf_dyn_strtab *strtab,
                              const struct blob *data);

/**
 * The modern GNU `DT_GNU_HASH` symbol lookup table hash function.
 * Part of `validate_gnu_hash`.
 *
 * @param[in] name The NULL-terminated name of the symbol to hash.
 *  Must not be NULL.
 *
 * @return The hash of `name`.
 */
static inline Elf32_Word gnu_hash(const uint8_t *name);

/**
 * Validates the modern GNU-style `DT_GNU_HASH` symbol name lookup hash table.
 * Part of `validate_dynamic_hash_tables`, which is part of `parse_dynsym`.
 *
 * Checks that every indexed symbol is reachable through the table
 * and ensures that the structure itself is consistent.
 *
 * Note: This function only establishes _structural_ correctness,
 * not _semantic_ correctness. That is, it ensures that every symbol
 * that should be able to be looked up - can be looked up;
 * not that the symbols themselves actually should or should not
 * participate in dynamic linking and be indexed in the table.
 *
 * Basically, it only checks that the lookup machine works,
 * not that it's used correctly.
 *
 * @param[in] hash The GNU hash structure to validate. Must not be NULL.
 *
 * @param[in] symtab The parsed dynamic symbol table array of count `nsyms`.
 *  Must not be NULL when `nsyms > 0`.
 *
 * @param[in] nsyms The number of dynamic symbol structs in the table.
 *
 * @param[in] strtab The parsed dynamic string table structure (.dynstr).
 *  Must not be NULL.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class, used for the bloom filter test.
 *
 * @return 0 on success (hash table valid or not present at all),
 *  non-zero if the table is invalid.
 */
static int validate_gnu_hash(const struct elf_dt_gnu_hash *hash,
                             const Elf64_Sym *symtab, Elf64_Xword nsyms,
                             const struct elf_dyn_strtab *strtab,
                             const struct blob *data, int clazz);

/**
 * Validates the `SHT_DYNSYM` (".dynsym") section header, if present.
 * Part of `parse_dynsym`.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] sht_dynsym_idx Index of the SHT_DYNSYM section to be validated
 *  (a reference into `shdrs`). Set to `ELF_IDX_NULL` if not present.
 *
 * @param[in] symtab_vaddr Address of the dynamic symbol table;
 *  the value of `DT_SYMTAB`.
 *
 * @param[in] symtab_off File offset of the dynamic symbol table.
 *
 * @param[in] symtab The parsed dynamic symbol array of `nsyms` entries.
 *  Must not be NULL.
 *
 * @param[in] symentsize Size of a single dynamic symbol struct;
 *  the value of `DT_SYMENT`.
 *
 * @param[in] nsyms The number of dynamic symbols in the table.
 *
 * @param[in] dynstr_shdr_idx The index of the dynamic string table (".dynstr")
 *  section (a reference into `shdrs`). Set to `ELF_IDX_NULL` if not present.
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_sht_dynsym_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t sht_dynsym_idx,
        Elf64_Addr symtab_vaddr, Elf64_Off symtab_off,
        const Elf64_Sym *symtab, Elf64_Xword symentsize, Elf64_Xword nsyms,
        elf_idx_t dynstr_shdr_idx
);

/**
 * Locates and parses the SYMTAB_SHNDX section, which supplies
 * extended indices for symbols whose `st_shndx == SHN_XINDEX`
 * (those that need to be >= `SHN_LORESERVE`).
 * Part of `parse_dynsym`.
 *
 * Note: If `shdrs->num == 0` (the shdr table has been fully stripped),
 * section indices cannot be validated. Such references are retained
 * and accepted with a warning, and must not be trusted without additional
 * information.
 *
 * @param[in] entries The dynamic entries array. Must not be NULL.
 *
 * @param[in] phdrs The program headers array. Must not be NULL.
 *
 * @param[in] shdrs The section headers array. Must not be NULL.
 *
 * @param[in] sht_dynsym_idx Index of the `SHT_DYNSYM` (".dynsym") section,
 *  if present. Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[in] data The data of the ELF file. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file.
 *
 * @param[in] encoding Byte order of the ELF file.
 *
 * @param[in] symtab The parsed dynamic symbol table (of count `nsyms`).
 *  Must not be NULL if `nsyms > 0`.
 *
 * @param[in] nsyms The number of dynamic symbols in `symtab`.
 *
 * @param[in] must_exist Whether this section must exist because
 *  one ore more symbols in `symtab` have their `st_shndx == SHN_XINDEX`.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *  The `present` flag in it will be set to indicate whether
 *  the section was found and parsed.
 *
 * @return
 *  0 on success:
 *      - SYMTAB_SHNDX was found and is valid,
 *      - SYMTAB_SHNDX was not found but `must_exist == false`
 *  non-zero on failure:
 *      - SYMTAB_SHNDX was found but is malformed,
 *      - SYMTAB_SHNDX was not found despite `must_exist == true`.
 */
static int parse_dyn_symtab_shndx_if_exists(
        const struct elf_dyn_entries *entries, const struct elf_phdrs *phdrs,
        const struct elf_shdrs *shdrs, elf_idx_t sht_dynsym_idx,
        const struct blob *data, int clazz, int encoding,
        Elf64_Sym *symtab, Elf64_Xword nsyms, bool must_exist,

        struct elf_dyn_symtab_shndx *out
);

/**
 * Reads the contents of the SYMTAB_SHNDX section, i.e.
 * the array of alternative values for corresponding dynamic symbols'
 * `st_shndx` fields which are set to `SHN_XINDEX`.
 * Part of `parse_dyn_symtab_shndx_if_exists`.
 *
 * Note: If `n_shdrs == 0` (stripped out section headers),
 * invalid section references are only treated as warnings,
 * which means that the values in the array cannot yet be trusted.
 *
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file.
 *
 * @param[in] encoding Byte order of the ELF file.
 *
 * @param[in] symtab The parsed dynamic symbol table of `nsyms` entries.
 *  Must not be NULL if `nsyms > 0`.
 *
 * @param[in] nsyms Number of dynamic symbols in `symtab`.
 *
 * @param[in] start File offset (of the SYMTAB_SHNDX section)
 *  at which to start reading.
 *
 * @param[in] size Total file size of the SYMTAB_SHNDX section;
 *  `nsyms * sizeof(Elf32_Word)`.
 *
 * @param[in] shdrs The section headers array. Used to validate
 *  that every entry points to a valid section. Must not be NULL.
 *
 * @param[out] out Output pointer for the array of `nsyms` section indices
 *  corresponding to the dynamic symbols in `symtab`, and referencing
 *  `shdrs`. Will be written to only on success; on failure everything
 *  is freed & cleaned up. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_symtab_shndx_contents(
        const struct blob *data, int clazz, int encoding,
        Elf64_Sym *symtab, Elf64_Xword nsyms, Elf64_Off start, Elf64_Xword size,
        const struct elf_shdrs *shdrs,
        Elf32_Word **out
);

/**
 * Finds and, if present, validates the `SHT_SYMTAB_SHNDX` section
 * corresponding to the dynamic symbol table ".dynsym".
 * Part of `parse_dyn_symtab_shndx_if_exists`.
 *
 * @param[in] shdrs The section headers array.
 *
 * @param[in] sht_dynsym_idx Index of the `SHT_DYNSYM` (".dynsym") section,
 *  if present. Set to `ELF_IDX_NULL` otherwise.
 *
 * @param[in] nsyms Number of symbols in the dynamic symbol table.
 *
 * @param[in] dt_symtab_shndx_exists Whether the `DT_SYMTAB_SHNDX`,
 *  and in consequence, the SYMTAB_SHNDX section, exist.
 *
 * @param[in] vaddr The virtual address of the SYMTAB_SHNDX section;
 *  the value of `DT_SYMTAB_SHNDX`.
 *
 * @param[in] off The file offset of the SYMTAB_SHNDX section.
 *
 * @param[out] out Output pointer for the found
 *  dynsym `SHT_SYMTAB_SHNDX` section header's index.
 *  Will contain `ELF_IDX_NULL` if no such section is found.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_dyn_sht_symtab_shndx_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t sht_dynsym_idx,
        Elf64_Xword nsyms, bool dt_symtab_shndx_exists,
        Elf64_Addr vaddr, Elf64_Off off,
        elf_idx_t *out
);

int parse_dynsym(
    const struct blob *data, int clazz, int encoding,
    const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
    const struct elf_dyn_entries *entries, const struct elf_dyn_strtab *strtab,

    struct elf_dt_hash *out_hash, struct elf_dt_gnu_hash *out_gnu_hash,
    struct elf_dyn_symtab_shndx *out_symtab_shndx, struct elf_dyn_symtab *out
)
{
    *out_hash = (struct elf_dt_hash) { 0 };
    out_hash->dyn_entry = ELF_IDX_NULL;
    out_hash->shdr = ELF_IDX_NULL;

    *out_gnu_hash = (struct elf_dt_gnu_hash) { 0 };
    out_gnu_hash->dyn_entry = ELF_IDX_NULL;
    out_gnu_hash->shdr = ELF_IDX_NULL;

    *out_symtab_shndx = (struct elf_dyn_symtab_shndx) { 0 };
    out_symtab_shndx->dyn_entry = ELF_IDX_NULL;
    out_symtab_shndx->shdr = ELF_IDX_NULL;

    *out = (struct elf_dyn_symtab) { 0 };
    out->dt_symtab = ELF_IDX_NULL;
    out->dt_syment = ELF_IDX_NULL;
    out->shdr = ELF_IDX_NULL;

    Elf64_Sym *sym_arr = NULL;

    Elf64_Addr symtab_vaddr = 0;
    Elf64_Half symentsize = 0;
    elf_idx_t dt_symtab_idx = ELF_IDX_NULL, dt_syment_idx = ELF_IDX_NULL;

    elf_idx_t sht_dynsym_idx = ELF_IDX_NULL;
    Elf64_Xword nsyms = 0;
    Elf64_Off symtab_off = 0;
    Elf64_Xword symtab_size = 0;
    bool uses_symtab_shndx = false;

    /* First, get the vaddr of the dynsym table from the `DT_SYMTAB` entry */
    if (find_symtab(entries, clazz,
                    &symtab_vaddr, &symentsize, &dt_symtab_idx, &dt_syment_idx))
    {
        /* error already printed */
        goto err;
    }

    /* Find the SHT_DYNSYM section if it exists now, it's needed for
     * validation of other related sections like SHT_(GNU_)HASH.
     *
     * The functions that use this correctly handle
     * this value being `ELF_IDX_NULL` as well. */
    sht_dynsym_idx = find_unique_shdr_by_type(shdrs, shdr_unique_SHT_DYNSYM);

    /* Now, since there's no way to directly get the size of the symtab,
     * we must infer it from the DT_HASH and/or DT_GNU_HASH structure(s).
     * What a great spec... */
    if (parse_dynamic_hash_tables(data, clazz, encoding, phdrs, shdrs, entries,
                                  sht_dynsym_idx, out_hash, out_gnu_hash,
                                  &nsyms))
    {
        pr_error("Invalid or missing dynamic hash table(s)\n");
        goto err;
    }
    if (nsyms > UINT64_MAX / symentsize || nsyms > SIZE_MAX) {
        pr_error("Number of dynamic symbols too large (integer overflow)\n");
        goto err;
    }
    symtab_size = nsyms * symentsize;

    /* Validate that the table fits in a PT_LOAD segment,
     * both in the file and in memory. This also maps the virtual address
     * we got earlier into the actually useful file offset. */
    if (find_ptload_and_off_from_vaddr(symtab_vaddr, symtab_size, phdrs,
                                       &symtab_off, NULL))
    {
        pr_error("No PT_LOAD segment contains the dynamic symbol table\n");
        goto err;
    }

    /* Finally, read the actual table */
    if (read_dynamic_symbol_table(data, clazz, encoding, symtab_off, nsyms,
                                  strtab->size, shdrs->num,
                                  &sym_arr, &uses_symtab_shndx))
    {
        pr_error("Failed to read the dynamic symbol table\n");
        goto err;
    }

    /* Validate the hash tables by looking up every symbol in the symtab */
    if (validate_dynamic_hash_tables(data, strtab, out_hash, out_gnu_hash,
                                     sym_arr, nsyms, clazz))
    {
        pr_error("Failed to validate the DT(_GNU)_HASH table(s)\n");
        goto err;
    }

    /* Validate the ".dynsym" (`SHT_DYNSYM`) section header, if present */
    if (validate_sht_dynsym_if_exists(shdrs, sht_dynsym_idx,
                                      symtab_vaddr, symtab_off,
                                      sym_arr, symentsize, nsyms, strtab->shdr))
    {
        pr_error("Invalid dynsym section header\n");
        goto err;
    }

    /* Also parse the SYMTAB_SHNDX section, if required and/or present */
    if (parse_dyn_symtab_shndx_if_exists(entries, phdrs, shdrs, sht_dynsym_idx,
                                         data, clazz, encoding, sym_arr, nsyms,
                                         uses_symtab_shndx, out_symtab_shndx))
    {
        pr_error("Invalid DT/SHT_SYMTAB_SHNDX\n");
        goto err;
    }

    out->vaddr = symtab_vaddr;
    out->off = symtab_off;
    out->size = symtab_size;
    out->entsize = symentsize;
    out->dt_symtab = dt_symtab_idx;
    out->dt_syment = dt_syment_idx;
    out->shdr = sht_dynsym_idx;
    out->nsyms = nsyms;
    out->syms = sym_arr; sym_arr = NULL;
    return 0;

err:
    if (sym_arr != NULL) {
        free(sym_arr);
        sym_arr = NULL;
    }
    /* if (out->syms != NULL) can never be true
        free(out->syms); */
    *out = (struct elf_dyn_symtab) { 0 };
    out->dt_symtab = ELF_IDX_NULL;
    out->dt_syment = ELF_IDX_NULL;
    out->shdr = ELF_IDX_NULL;

    if (out_hash->buckets != NULL)
        free(out_hash->buckets);
    if (out_hash->chain != NULL)
        free(out_hash->chain);
    *out_hash = (struct elf_dt_hash) { 0 };
    out_hash->dyn_entry = ELF_IDX_NULL;
    out_hash->shdr = ELF_IDX_NULL;

    if (out_gnu_hash->bloom != NULL)
        free(out_gnu_hash->bloom);
    if (out_gnu_hash->buckets != NULL)
        free(out_gnu_hash->buckets);
    if (out_gnu_hash->chain != NULL)
        free(out_gnu_hash->chain);
    *out_gnu_hash = (struct elf_dt_gnu_hash) { 0 };
    out_gnu_hash->dyn_entry = ELF_IDX_NULL;
    out_gnu_hash->shdr = ELF_IDX_NULL;

    if (out_symtab_shndx->arr != NULL)
        free(out_symtab_shndx->arr);
    *out_symtab_shndx = (struct elf_dyn_symtab_shndx) { 0 };
    out_symtab_shndx->dyn_entry = ELF_IDX_NULL;
    out_symtab_shndx->shdr = ELF_IDX_NULL;

    return 1;
}

static int find_symtab(const struct elf_dyn_entries *entries, int clazz,
                       Elf64_Addr *out_vaddr, Elf64_Half *out_symentsize,
                       elf_idx_t *out_dt_symtab, elf_idx_t *out_dt_syment)
{
    elf_idx_t idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };
    if (find_unique_dyn_entries(entries, 2,
                                (const Elf64_Sxword[]) { DT_SYMTAB, DT_SYMENT },
                                idxs))
    {
        pr_error("Invalid or missing DT_SYMTAB and/or DT_SYMENT entries\n");
        return 1;
    }
    const Elf64_Addr symtab_vaddr = entries->arr[idxs[0]].d_un.d_ptr;
    const Elf64_Xword symentsize = entries->arr[idxs[1]].d_un.d_val;

    if (!((clazz == ELFCLASS32 && symentsize == sizeof(Elf32_Sym)) ||
          (clazz == ELFCLASS64 && symentsize == sizeof(Elf64_Sym))))
    {
        pr_error("Invalid value of DT_SYMENT for class %s: %" PRIu64 "\n",
                 clazz == ELFCLASS32 ? "ELFCLASS32" : "ELFCLASS64", symentsize);
        return 1;
    }

    *out_vaddr = symtab_vaddr;
    *out_symentsize = (Elf64_Half)symentsize;
    *out_dt_symtab = idxs[0];
    *out_dt_syment = idxs[1];
    return 0;
}

static int parse_dynamic_hash_tables(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_hash *out_hash, struct elf_dt_gnu_hash *out_gnu_hash,
        Elf64_Xword *out_dynsym_count
)
{
    /* Inspired by:
     *  https://lldb.llvm.org/cpp_reference/ObjectFileELF_8cpp_source.html
     * (line ~4315) */

    const int sysv_hash_ret =
        parse_dt_hash(data, clazz, encoding, phdrs, shdrs,
                          entries, sht_dynsym_idx, out_hash);
    const int gnu_hash_ret =
        parse_dt_gnu_hash(data, clazz, encoding, phdrs, shdrs,
                          entries, sht_dynsym_idx, out_gnu_hash);

    pr_debug("DT_HASH: %s, DT_GNU_HASH: %s\n",
            (sysv_hash_ret == 0 ? "OK" :
                (sysv_hash_ret < 0 ? "invalid" : "not present")),
            (gnu_hash_ret == 0 ? "OK" :
                (gnu_hash_ret < 0 ? "invalid" : "not present"))
    );

    if (sysv_hash_ret < 0 || gnu_hash_ret < 0) {
        pr_error("Malformed DT_HASH and/or DT_GNU_HASH table(s)\n");
        return 1;
    } else if (sysv_hash_ret != 0 && gnu_hash_ret != 0) {
        pr_error("Neither DT_HASH nor DT_GNU_HASH are present. "
                 "Cannot determine dynamic symbol count.\n");
        return 1;
    }

    Elf64_Xword nsyms_sysv_hash = 0, nsyms_gnu_hash = 0;
    if (sysv_hash_ret == 0)
        nsyms_sysv_hash = out_hash->hdr.nchain;

    if (gnu_hash_ret == 0)
        nsyms_gnu_hash = (Elf64_Xword)out_gnu_hash->hdr.symoffset +
                                out_gnu_hash->nchain;

    if (sysv_hash_ret == 0 && gnu_hash_ret == 0) {
        if (nsyms_sysv_hash != nsyms_gnu_hash) {
            pr_error("Symbol count from DT_HASH (%" PRIu64 ") "
                     "doesn't match that from DT_GNU_HASH (%" PRIu64 ")\n",
                     nsyms_sysv_hash, nsyms_gnu_hash);
            return 1;
        }
    }

    if (gnu_hash_ret == 0) *out_dynsym_count = nsyms_gnu_hash;
    else if (sysv_hash_ret == 0) *out_dynsym_count = nsyms_sysv_hash;
    else abort(); /* impossible outcome */

    return 0;
}

static int parse_dt_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_hash *out
)
{
    *out = (struct elf_dt_hash) { 0 };
    out->dyn_entry = ELF_IDX_NULL;
    out->shdr = ELF_IDX_NULL;

    int ret = 0;
    uint64_t off = 0, end = 0;
    ret = find_dt_hash(data, clazz, encoding, phdrs, entries, out);
    if (ret) /* ret < 0 means invalid, > 0 means absent */
        goto err; /* error already printed */
    off = out->off;

    /* From this point, any failure means that the structure
     * is malformed, not absent. */
    ret = -1;

    /* `find_dt_hash` already checks that
     * `dt_hash.off + dt_hash.total_size` doesn't overflow */
    end = off + out->total_size;
    if (read_dt_hash_contents(data, clazz, encoding, &off, &out->hdr, end,
                              &out->buckets, &out->chain))
    {
        pr_error("Failed to read the DT_HASH table contents\n");
        goto err;
    }

    if (validate_sht_hash_if_exists(shdrs, out, sht_dynsym_idx, clazz,
                                    &out->shdr))
    {
        pr_error("Invalid SHT_HASH section\n");
        goto err;
    }

    pr_debug("DT_HASH nbucket: %" PRIu32 ", nchain: %" PRIu32 "\n",
             out->hdr.nbucket, out->hdr.nchain);
    out->present = true;
    return 0;

err:
    if (out->buckets != NULL)
        free(out->buckets);
    if (out->chain != NULL)
        free(out->chain);

    *out = (struct elf_dt_hash) { 0 };
    out->dyn_entry = ELF_IDX_NULL;
    out->shdr = ELF_IDX_NULL;
    return ret;
}

static int find_dt_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_dyn_entries *entries,
        struct elf_dt_hash *out
)
{
    *out = (struct elf_dt_hash) { 0 };
    out->dyn_entry = ELF_IDX_NULL;
    out->shdr = ELF_IDX_NULL;

    /* Find the vaddr, file offset and containing PT_LOAD */
    elf_idx_t dt_hash_idx = ELF_IDX_NULL;
    const int r = find_unique_dyn_entries(entries, 1,
                (Elf64_Sxword[]) { DT_HASH }, &dt_hash_idx);
    if (r) {
        pr_debug("%s DT_HASH entry\n",
                 r < 0 ? "Duplicate" : "Missing");
        /* Duplicate (r == -1) means >invalid< (should return -1)
         * while Missing (r == 1) just >not found< (should return 1) */
        return r;
    }
    const Elf64_Addr dt_hash_vaddr = entries->arr[dt_hash_idx].d_un.d_ptr;

    Elf64_Off dt_hash_off = 0;
    elf_idx_t pt_load_idx = ELF_IDX_NULL;
    /* we will later validate that this segment contains the entire structure
     * and not just the header, but we must first read the header to determine
     * the total size of the table. */
    if (find_ptload_and_off_from_vaddr(dt_hash_vaddr, DT_HASH_HDR_SIZE, phdrs,
                                       &dt_hash_off, &pt_load_idx))
    {
        pr_error("No PT_LOAD segment properly contains the DT_HASH header\n");
        return -1;
    }

    /* Read the header */
    struct elf_dt_hash_hdr hdr = { 0 }; /* same across both classes */
    uint64_t off = dt_hash_off;
    if (read_Word(data, &off, clazz, encoding, &hdr.nbucket) ||
        read_Word(data, &off, clazz, encoding, &hdr.nchain) ||
        (off < dt_hash_off || off != dt_hash_off + DT_HASH_HDR_SIZE) ||
        (size_t)hdr.nbucket != hdr.nbucket || (size_t)hdr.nchain != hdr.nchain)
    {
        pr_error("Failed to read the DT_HASH table header\n");
        return -1;
    }
    /* `nchain` is the number of entries in the associated dynsym table,
     * which contains at least one reserved STN_UNDEF entry. */
    if (hdr.nchain == 0) {
        pr_error("DT_HASH table nchain must be greater than 0\n");
        return -1;
    }

    /* none of this can ever overflow a uint64_t */
    const Elf64_Xword buckets_total_size =
        (Elf64_Xword)hdr.nbucket * sizeof(Elf32_Word);
    const Elf64_Xword chain_total_size =
        (Elf64_Xword)hdr.nchain * sizeof(Elf32_Word);
    const Elf64_Xword dt_hash_total_size = (Elf64_Xword)
            DT_HASH_HDR_SIZE + buckets_total_size + chain_total_size;

    /* Now validate that the entire table is in the PT_LOAD,
     * not just the header */
    {
        Elf64_Off tmp_off = 0;
        elf_idx_t tmp_idx = ELF_IDX_NULL;
        if (find_ptload_and_off_from_vaddr(dt_hash_vaddr, dt_hash_total_size,
                                           phdrs, &tmp_off, &tmp_idx) ||
                tmp_off != dt_hash_off ||
                tmp_idx != pt_load_idx)
        {
            pr_error("The found PT_LOAD segment doesn't properly contain "
                    "the entire DT_HASH structure\n");
            return -1;
        }
    }

    out->hdr = hdr;
    out->vaddr = dt_hash_vaddr;
    out->off = dt_hash_off;
    out->dyn_entry = dt_hash_idx;
    out->total_size = dt_hash_total_size;
    return 0;
}

static int read_dt_hash_contents(
        const struct blob *data, int clazz, int encoding, uint64_t *off_p,
        const struct elf_dt_hash_hdr *hdr, Elf64_Off end,
        Elf32_Word **out_buckets, Elf32_Word **out_chain
)
{
    /* the above `find_dt_hash` already validates that both
     * `hdr->nbucket` and `hdr->nchain` are representable as size_t */
    int ret = 1;
    Elf32_Word *buckets = NULL, *chain = NULL;
    /* hdr->nbucket can be zero (in the case that there are no
     * _named_ symbols that the hash table would need to actually index). */
    if (hdr->nbucket > 0) {
        if ((buckets = calloc((size_t)hdr->nbucket, sizeof(Elf32_Word)))
                == NULL)
        {
            pr_error("Failed to allocate the DT_HASH bucket array\n");
            goto err;
        }
    }
    /* hdr->nchain must not be zero since it corresponds to
     * the number of entries in the associated symtab and every symtab
     * must have at least one `STN_UNDEF` entry at the beginning.
     * `hdr->nchain != 0` is checked by `find_dt_hash`. */
    if ((chain = calloc((size_t)hdr->nchain, sizeof(Elf32_Word))) == NULL) {
        pr_error("Failed to allocate the DT_HASH chain array\n");
        goto err;
    }

    /* `hdr` has already been read by `find_dt_hash` */
    *off_p += DT_HASH_HDR_SIZE;

    for (Elf32_Word i = 0; i < hdr->nbucket; i++) {
        if (read_Word(data, off_p, clazz, encoding, &buckets[i])) {
            pr_error("Failed to read DT_HASH bucket no %" PRIu32 "\n", i);
            goto err;
        }
        if (buckets[i] >= hdr->nchain) {
            pr_error("Invalid DT_HASH bucket no %" PRIu32 "\n", i);
            goto err;
        }
    }

    for (Elf32_Word i = 0; i < hdr->nchain; i++) {
        if (read_Word(data, off_p, clazz, encoding, &chain[i])) {
            pr_error("Failed to read DT_HASH chain no %" PRIu32 "\n", i);
            goto err;
        }
        if (chain[i] >= hdr->nchain) {
            pr_error("Invalid DT_HASH chain no %" PRIu32 "\n", i);
            goto err;
        }
    }

    if (*off_p != end) {
        pr_error("Invalid offset after reading the DT_HASH table "
                 "(expected 0x%" PRIx64 ", got 0x%" PRIx64 ")\n",
                 *off_p, end);
        goto err;
    }

    ret = 0;

err:
    if (!ret) {
        /* In the case where `hdr->nbucket` is 0, `buckets`
         * is not allocated and remains `NULL`.
         * `hdr->nchain` is always non-zero and therefore
         * `chain` is always non-NULL. */
        *out_buckets = buckets; buckets = NULL;
        *out_chain = chain; chain = NULL;
    } else {
        if (buckets != NULL) {
            free(buckets);
            buckets = NULL;
        }
        if (chain != NULL) {
            free(chain);
            chain = NULL;
        }
    }

    return ret;
}

static int validate_sht_hash_if_exists(const struct elf_shdrs *shdrs,
                                       const struct elf_dt_hash *dt_hash,
                                       elf_idx_t sht_dynsym_idx, int clazz,
                                       elf_idx_t *out)
{
    *out = ELF_IDX_NULL;

    const elf_idx_t sht_hash_idx =
        find_unique_shdr_by_type(shdrs, shdr_unique_SHT_HASH);
    if (sht_hash_idx == ELF_IDX_NULL && sht_dynsym_idx == ELF_IDX_NULL) {
        pr_debug("%s: No SHT_DYNSYM or SHT_HASH section headers\n",
                __func__);
        return 0;
    } else if (sht_hash_idx == ELF_IDX_NULL || sht_dynsym_idx == ELF_IDX_NULL) {
        pr_error("One of SHT_DYNSYM and SHT_HASH sections is present "
                 "while the other one is missing\n");
        return 1;
    }

    int ret = 0;
    const Elf64_Shdr *const sht_hash = &shdrs->arr[sht_hash_idx];
    const Elf64_Shdr *const sht_dynsym = &shdrs->arr[sht_dynsym_idx];

    if (sht_hash->sh_addr != dt_hash->vaddr) {
        pr_error("Invalid SHT_HASH vaddr\n");
        ret = 1;
    }
    if (sht_hash->sh_offset != dt_hash->off) {
        pr_error("Invalid SHT_HASH offset\n");
        ret = 1;
    }
    if (sht_hash->sh_size != dt_hash->total_size) {
        pr_error("Invalid SHT_HASH size\n");
        ret = 1;
    }

    const size_t symentsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Sym) : sizeof(Elf64_Sym);
    const Elf64_Xword total_symtab_size =
        (Elf64_Xword)dt_hash->hdr.nchain * symentsize;
    if (total_symtab_size != sht_dynsym->sh_size) {
        pr_error("%s: Calculated dynamic symbol table size (0x%" PRIx64 ") "
                 "doesn't match the dynsym section header (0x%" PRIx64 ")\n",
                 __func__, total_symtab_size, sht_dynsym->sh_size);
        ret = 1;
    }

    if (sht_dynsym_idx != ELF_IDX_NULL) {
        if (sht_hash->sh_link != sht_dynsym_idx) {
            pr_error("SHT_HASH sh_link doesn't point to SHT_DYNSYM\n");
            ret = 1;
        }
    } else {
        pr_error("SHT_HASH exists without any SHT_DYNSYM\n");
        ret = 1;
    }

    if (sht_hash->sh_info != 0)
        pr_error("WARNING: SHT_HASH sh_info non-zero\n");
    if (sht_hash->sh_entsize != sizeof(Elf32_Word))
        pr_error("WARNING: SHT_HASH sh_entsize != sizeof(Elf32_Word)\n");

    if (!ret)
        *out = sht_hash_idx;
    return ret;
}

static int parse_dt_gnu_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, elf_idx_t sht_dynsym_idx,
        struct elf_dt_gnu_hash *out
)
{
    *out = (struct elf_dt_gnu_hash) { 0 };

    elf_idx_t ptload = ELF_IDX_NULL;
    Elf32_Word max_bucket = 0;
    Elf64_Off chain_off = 0;

    int ret = find_dt_gnu_hash(data, clazz, encoding, phdrs, entries,
                               out, &ptload);
    if (ret != 0) {
        /* error already printed */
        goto err;
    }

    /* Any failure from this point means an >invalid< DT_GNU_HASH */
    ret = -1;

    if (read_bloom_and_buckets(data, clazz, encoding, phdrs,
                               out, ptload, &max_bucket, &chain_off))
    {
        pr_error("Failed to read the DT_GNU_HASH bloom filter and buckets\n");
        goto err;
    }

    if (find_gnu_hash_nchain(data, clazz, encoding, phdrs,
                             ptload, out, max_bucket, chain_off, &out->nchain))
    {
        pr_error("Couldn't find the number of entries in the GNU hash chain\n");
        goto err;
    }

    if (read_gnu_hash_chain(data, clazz, encoding, chain_off, out->nchain,
                            &out->chain))
    {
        pr_error("Failed to read the GNU hash chain\n");
        goto err;
    }

    /* max value: (16 + 8 + 4 + 4) * 2^32; doesn't overflow a uint64 */
    out->total_size = (Elf64_Xword)DT_GNU_HASH_HDR_SIZE +
                        ((Elf64_Xword)out->hdr.bloom_size * out->bloomentsize) +
                        ((Elf64_Xword)out->hdr.nbuckets * sizeof(Elf32_Word)) +
                        ((Elf64_Xword)out->nchain * sizeof(Elf32_Word));
    {
        Elf64_Off tmp_off = 0;
        elf_idx_t tmp_ptload = ELF_IDX_NULL;
        if (find_ptload_and_off_from_vaddr(out->vaddr, out->total_size, phdrs,
                    &tmp_off, &tmp_ptload) ||
                tmp_off != out->off || tmp_ptload != ptload)
        {
            pr_error("DT_GNU_HASH contents not contained in the found "
                     "PT_LOAD segment\n");
            goto err;
        }
    }

    if (validate_sht_gnu_hash_if_exists(out, shdrs, sht_dynsym_idx, clazz,
                                        &out->shdr))
    {
        pr_error("GNU hash section data mismatch\n");
        goto err;
    }

    pr_debug("DT_GNU_HASH nbuckets: %" PRIu32 ", nchain: %" PRIu32 ", "
             "symoffset: %" PRIu32 "\n",
             out->hdr.nbuckets, out->nchain, out->hdr.symoffset);
    out->present = true;
    return 0;

err:
    if (out->chain != NULL) {
        free(out->chain);
        out->chain = NULL;
    }
    if (out->buckets != NULL) {
        free(out->buckets);
        out->buckets = NULL;
    }
    if (out->bloom != NULL) {
        free(out->bloom);
        out->bloom = NULL;
    }
    return ret;
}

static int read_dt_gnu_hash_hdr(
        const struct blob *data, int clazz, int encoding, uint64_t *off_p,
        struct elf_dt_gnu_hash_hdr *out
)
{
    const uint64_t start_off = *off_p;
    if (start_off > UINT64_MAX - DT_GNU_HASH_HDR_SIZE)
        return -1;
    const uint64_t end = start_off + DT_GNU_HASH_HDR_SIZE;

    /* same across both classes */
    if (read_Word(data, off_p, clazz, encoding, &out->nbuckets) ||
        read_Word(data, off_p, clazz, encoding, &out->symoffset) ||
        read_Word(data, off_p, clazz, encoding, &out->bloom_size) ||
        read_Word(data, off_p, clazz, encoding, &out->bloom_shift))
    {
        pr_error("Failed to read the DT_GNU_HASH header words\n");
        return 1;
    }
    if (*off_p != end) {
        pr_error("Invalid offset after reading DT_GNU_HASH header\n");
        return 1;
    }

    int ret = 0;

    if (((size_t)out->nbuckets != out->nbuckets) ||
        ((size_t)out->bloom_size != out->bloom_size))
    {
        pr_error("DT_GNU_HASH nbuckets and/or bloom_size overflow size_t");
        ret = 1;
    }

    if (out->bloom_shift >= 32) {
        pr_error("Invalid DT_GNU_HASH bloom_shift\n");
        ret = 1;
    }

    /* glibc requires that `bloom_size` be a power of two */
    if (out->bloom_size == 0 ||
        (out->bloom_size & (out->bloom_size - 1)) != 0)
    {
        pr_error("DT_GNU_HASH bloom size not a power of two\n");
        ret = 1;
    }

    pr_debug("DT_GNU_HASH nbuckets: %" PRIu32 "\n", out->nbuckets);

    return ret;
}

static int find_dt_gnu_hash(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_dyn_entries *entries,
        struct elf_dt_gnu_hash *out, elf_idx_t *out_pt_load_idx
)
{
    *out = (struct elf_dt_gnu_hash) { 0 };
    out->shdr = ELF_IDX_NULL;
    out->dyn_entry = ELF_IDX_NULL;
    *out_pt_load_idx = ELF_IDX_NULL;

    /* Find the DT_GNU_HASH vaddr, file offset and containing PT_LOAD */
    elf_idx_t dt_gnu_hash_idx = ELF_IDX_NULL;
    const int r = find_unique_dyn_entries(entries, 1,
            (const Elf64_Sxword[]) { DT_GNU_HASH }, &dt_gnu_hash_idx);
    if (r) {
        pr_debug("%s DT_HASH entry\n",
                 r < 0 ? "Duplicate" : "Missing");
        /* Duplicate (r == -1) means >invalid< (should return -1)
         * while Missing (r == 1) just >not found< (should return 1) */
        return r;
    }
    const Elf64_Addr vaddr = entries->arr[dt_gnu_hash_idx].d_un.d_ptr;

    Elf64_Off dt_gnu_hash_off = 0;
    elf_idx_t pt_load_idx = ELF_IDX_NULL;
    /* as with DT_HASH, we must first read the header to determine the size
     * of the whole DT_GNU_HASH, which is validated later  */
    if (find_ptload_and_off_from_vaddr(vaddr, DT_GNU_HASH_HDR_SIZE, phdrs,
                                       &dt_gnu_hash_off, &pt_load_idx))
    {
        pr_error("No PT_LOAD segment properly contains "
                "the DT_GNU_HASH header\n");
        return -1;
    }

    /* Read the header */
    uint64_t off = dt_gnu_hash_off;
    struct elf_dt_gnu_hash_hdr hdr = { 0 };
    if (read_dt_gnu_hash_hdr(data, clazz, encoding, &off, &hdr)) {
        pr_error("Failed to read the DT_GNU_HASH header\n");
        return -1;
    }

    if (hdr.bloom_size == 0) {
        pr_error("Bloom filter size cannot be zero\n");
        return -1;
    }

    out->hdr = hdr;
    out->off = dt_gnu_hash_off;
    out->vaddr = vaddr;
    out->dyn_entry = dt_gnu_hash_idx;
    out->bloomentsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Word) : sizeof(Elf64_Xword);
    *out_pt_load_idx = pt_load_idx;

    return 0;
}

static int read_bloom_and_buckets(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, struct elf_dt_gnu_hash *ctx,
        elf_idx_t pt_load_idx, Elf32_Word *out_max_bucket,
        Elf64_Off *out_chain_off
)
{
    Elf64_Xword *bloom = NULL;
    Elf32_Word *buckets = NULL;

    uint64_t bloom_off = 0, bloom_total_size = 0;
    uint64_t buckets_off = 0, buckets_total_size = 0;
    uint64_t chain_off = 0;

    Elf32_Word max_bucket = 0;

    /* Overflow safety established by `read_dt_gnu_hash_hdr` */
    bloom_off = ctx->off + DT_GNU_HASH_HDR_SIZE;
    bloom_total_size = (uint64_t)ctx->hdr.bloom_size * ctx->bloomentsize;
    if (bloom_off > UINT64_MAX - bloom_total_size) {
        pr_error("Bloom filter size too large (integer overflow)\n");
        goto err;
    }

    buckets_off = bloom_off + bloom_total_size;
    buckets_total_size = (uint64_t)ctx->hdr.nbuckets * sizeof(Elf32_Word);
    if (buckets_off > UINT64_MAX - buckets_total_size) {
        pr_error("Buckets size too large (integer overflow)\n");
        goto err;
    }
    chain_off = buckets_off + buckets_total_size;

    /* Check that the bloom filter and buckets array are contained
     * in the same PT_LOAD segment as the header */
    {
        uint64_t tmp_off = 0;
        elf_idx_t tmp_pt_load_idx = ELF_IDX_NULL;
        /* 16 + 2^32 + 2^32 doesn't overflow a uint64_t */
        const uint64_t size =
            DT_GNU_HASH_HDR_SIZE + bloom_total_size + buckets_total_size;
        if (find_ptload_and_off_from_vaddr(ctx->vaddr, size, phdrs,
                                           &tmp_off, &tmp_pt_load_idx) ||
                tmp_off != ctx->off ||
                tmp_pt_load_idx != pt_load_idx)
        {
            pr_error("DT_GNU_HASH header, bloom filter and buckets "
                     "not file-backed by the found PT_LOAD segment\n");
            goto err;
        }
    }

    /* Read the bloom filter */
    /* bloom_size is guaranteed to be non-zero (and a power of two)
     * and to fit within size_t by `read_dt_gnu_hash_hdr` */
    bloom = calloc((size_t)ctx->hdr.bloom_size, sizeof(Elf64_Xword));
    if (bloom == NULL) {
        pr_error("Failed to allocate the bloom filter array\n");
        goto err;
    }
    {
        uint64_t off = bloom_off;
        for (Elf32_Word i = 0; i < ctx->hdr.bloom_size; i++) {
            /* glibc uses `ElfXX_Addr` for this too, lol */
            if (read_Addr(data, &off, clazz, encoding, &bloom[i])) {
                pr_error("Failed to read bloom filter entry no %" PRIu32 "\n",
                         i);
                goto err;
            }
        }
        if (off != buckets_off) {
            pr_error("Incorrect number of bytes read for the bloom filter\n");
            goto err;
        }
    }

    /* Read the buckets */
    if (ctx->hdr.nbuckets > 0) {
        /* size_t representability established by `read_dt_gnu_hash_hdr` */
        buckets = calloc((size_t)ctx->hdr.nbuckets, sizeof(Elf32_Word));
        if (buckets == NULL) {
            pr_error("Failed to allocate the buckets array\n");
            goto err;
        }
        uint64_t off = buckets_off;
        for (Elf32_Word i = 0; i < ctx->hdr.nbuckets; i++) {
            if (read_Word(data, &off, clazz, encoding, &buckets[i])) {
                pr_error("Failed to read bucket no %" PRIu32 "\n", i);
                goto err;
            }
            if (buckets[i] < ctx->hdr.symoffset && buckets[i] != 0) {
                pr_error("DT_GNU_HASH bucket %" PRIu32 " (%" PRIu32 ") "
                         "refers to symbol below symoffset\n", i, buckets[i]);
                goto err;
            }

            if (buckets[i] > max_bucket)
                max_bucket = buckets[i];
        }
        if (off != buckets_off + buckets_total_size) {
            pr_error("Incorrect number of bytes read for the buckets array\n");
            goto err;
        }
    } else {
        /* In the case where `hdr.nbuckets` is 0, there are no symbols indexed
         * by the hash table, that is, there are no _exported_ symbols.
         * That means that the total number of entries in the symtab becomes
         * just `hdr.symoffset`, and `NULL` is written into `out->buckets`. */
        buckets = NULL;
    }

    ctx->buckets = buckets; buckets = NULL;
    ctx->bloom = bloom; bloom = NULL;
    *out_max_bucket = max_bucket;
    *out_chain_off = chain_off;
    return 0;

err:
    if (buckets != NULL) {
        free(buckets);
        buckets = NULL;
    }
    if (bloom != NULL) {
        free(bloom);
        bloom = NULL;
    }
    return 1;
}

static int find_gnu_hash_nchain(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t containing_phdr_idx,
        const struct elf_dt_gnu_hash *ctx, Elf32_Word max_bucket,
        Elf64_Off chain_off, Elf32_Word *out
)
{
    if (max_bucket == 0) {
        pr_debug("%s: No hashed symbols\n", __func__);
        *out = 0;
        return 0;
    } else if (max_bucket < ctx->hdr.symoffset) {
        pr_error("Invalid max bucket value\n");
        return 1;
    }
    const Elf32_Word start_idx = max_bucket - ctx->hdr.symoffset;

    /* never overflows */
    const Elf64_Xword min_chain_size =
        ((Elf64_Xword)start_idx + 1) * sizeof(Elf32_Word);

    const Elf64_Phdr *const containing_phdr = &phdrs->arr[containing_phdr_idx];
    /* it's assumed that every entry in `phdrs` has already been validated */
    const Elf64_Off seg_end =
        containing_phdr->p_offset + containing_phdr->p_filesz;

    if (seg_end < sizeof(Elf32_Word) ||
        seg_end < chain_off ||
        min_chain_size > seg_end - chain_off)
    {
        pr_error("GNU hash chain doesn't fit in its PT_LOAD segment\n");
        return 1;
    }

    uint64_t idx = (uint64_t)start_idx;
    uint64_t off = chain_off + ((uint64_t)start_idx * sizeof(Elf32_Word));
    while (true) {
        if (off > seg_end - sizeof(Elf32_Word)) {
            pr_error("GNU hash chain doesn't fit in its PT_LOAD segment "
                     "(no terminator found)\n");
            return 1;
        }

        Elf32_Word c = 0;
        if (read_Word(data, &off, clazz, encoding, &c)) {
            pr_error("Failed to read chain entry no %" PRIu64 "\n", idx);
            return 1;
        }
        if (c & UINT32_C(1))
            break;

        if (idx == (uint64_t)UINT32_MAX) {
            pr_error("Chain entry index too large (integer overflow)\n");
            return 1;
        }
        idx++;
    }

    if (idx >= UINT32_MAX || idx > SIZE_MAX /* later passed to `calloc` */) {
        pr_error("Chain entry index too large (integer overflow)\n");
        return 1;
    }
    *out = (Elf32_Word)(idx + 1);
    return 0;
}

static int read_gnu_hash_chain(
        const struct blob *data, int clazz, int encoding,
        Elf64_Off chain_off, Elf32_Word nchain, Elf32_Word **out
)
{
    Elf32_Word *chain = NULL;

    if (nchain == 0) {
        pr_debug("%s: No chain entries\n", __func__);
        *out = NULL;
        return 0;
    }

    /* `nchain` is computed by `find_gnu_hash_nchain`,
     * which checks that it doesn't overflow SIZE_MAX */
    chain = calloc((size_t)nchain, sizeof(Elf32_Word));
    if (chain == NULL) {
        pr_error("Failed to allocate the hash chain array\n");
        goto err;
    }

    {
        uint64_t off = chain_off;
        for (Elf32_Word i = 0; i < nchain; i++) {
            if (read_Word(data, &off, clazz, encoding, &chain[i])) {
                pr_error("Failed to read hash chain entry no %" PRIu32 "\n", i);
                goto err;
            }
        }
    }

    *out = chain;
    return 0;

err:
    if (chain != NULL) {
        free(chain);
        chain = NULL;
    }
    *out = NULL;
    return 1;
}

static int validate_sht_gnu_hash_if_exists(const struct elf_dt_gnu_hash *ctx,
                                           const struct elf_shdrs *shdrs,
                                           elf_idx_t sht_dynsym_idx, int clazz,
                                           elf_idx_t *out_sht_gnu_hash_idx)
{
    *out_sht_gnu_hash_idx = ELF_IDX_NULL;
    const elf_idx_t sht_gnu_hash_idx =
        find_unique_shdr_by_type(shdrs, shdr_unique_SHT_GNU_HASH);
    if (sht_gnu_hash_idx == ELF_IDX_NULL && sht_dynsym_idx == ELF_IDX_NULL) {
        pr_debug("%s: No SHT_DYNSYM or SHT_GNU_HASH section headers\n",
                __func__);
        return 0;
    } else if (sht_gnu_hash_idx == ELF_IDX_NULL ||
               sht_dynsym_idx == ELF_IDX_NULL)
    {
        pr_error("One of SHT_DYNSYM and SHT_GNU_HASH sections is present "
                 "while the other one is missing\n");
        return 1;
    }
    const Elf64_Shdr *const sht_dynsym = &shdrs->arr[sht_dynsym_idx];
    const Elf64_Shdr *const sht_gnu_hash = &shdrs->arr[sht_gnu_hash_idx];

    int ret = 0;

    if (sht_gnu_hash->sh_addr != ctx->vaddr) {
        pr_error("Invalid SHT_GNU_HASH vaddr\n");
        ret = 1;
    }
    if (sht_gnu_hash->sh_offset != ctx->off) {
        pr_error("Invalid SHT_GNU_HASH offset\n");
        ret = 1;
    }
    if (ctx->total_size != sht_gnu_hash->sh_size) {
        pr_error("GNU hash calculated size (0x%" PRIx64 ") doesn't match "
                 "the section header (0x%" PRIx64 ")\n",
                 ctx->total_size, sht_gnu_hash->sh_size);
        ret = 1;
    }

    const size_t symentsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Sym) : sizeof(Elf64_Sym);
    const Elf64_Xword total_symtab_size =
        ((Elf64_Xword)ctx->hdr.symoffset + ctx->nchain) * symentsize;
    if (total_symtab_size != sht_dynsym->sh_size) {
        pr_error("Calculated dynamic symbol table size (0x%" PRIx64 ") "
                 "doesn't match the dynsym section header (0x%" PRIx64 ")\n",
                 total_symtab_size, sht_dynsym->sh_size);
        ret = 1;
    }

    if (sht_gnu_hash->sh_link != sht_dynsym_idx) {
        pr_error("SHT_GNU_HASH sh_link doesn't point to the dynsym section\n");
        ret = 1;
    }

    const Elf64_Xword gnu_hash_entsize = clazz == ELFCLASS32 ?
        4 /* 32-bit */ :
        0 /* 64-bit */;
    if (sht_gnu_hash->sh_entsize != gnu_hash_entsize) {
        pr_error("Invalid SHT_GNU_HASH entsize\n");
        ret = 1;
    }

    if (!ret)
        *out_sht_gnu_hash_idx = sht_gnu_hash_idx;
    return ret;
}

static int read_dynamic_symbol_table(
        const struct blob *data, int clazz, int encoding,
        Elf64_Off tbl_offset, Elf64_Xword nsyms,
        Elf64_Xword dynstr_size, Elf64_Xword n_shdrs,
        Elf64_Sym **out, bool *out_uses_symtab_shndx
)
{
    Elf64_Sym *arr = NULL;
    *out_uses_symtab_shndx = false;

    uint64_t off = tbl_offset;

    /* STB_LOCAL symbols must precede all other ones */
    bool saw_nonlocal = false;

    if (nsyms == 0) {
        pr_error("Dynamic symbol table has no first STN_UNDEF entry\n");
        goto err;
    }

    /* The first entry in the symbol table must be all zeroes */
    {
        Elf64_Sym tmp = { 0 };
        Elf64_Off tmp_off = tbl_offset;
        if (read_sym(data, &tmp_off, clazz, encoding, &tmp)) {
            pr_error("Failed to read the first dynamic symbol\n");
            goto err;
        }
        if (tmp.st_name != 0 || tmp.st_value != 0 || tmp.st_size != 0 ||
            tmp.st_info != 0 || tmp.st_other != 0 || tmp.st_shndx != SHN_UNDEF)
        {
            pr_error("The first entry is not zeroed out\n");
            goto err;
        }
    }

    /* `nsyms <= SIZE_MAX` checked in `parse_dynsym` */
    arr = calloc((size_t)nsyms, sizeof(Elf64_Sym));
    if (arr == NULL) {
        pr_error("Failed to allocate the dynamic symbols array\n");
        goto err;
    }

    for (Elf64_Xword i = 0; i < nsyms; i++) {
        if (read_sym(data, &off, clazz, encoding, &arr[i])) {
            pr_error("Failed to read dynamic symbol no %" PRIu64 "\n", i);
            goto err;
        }

        if (arr[i].st_name >= dynstr_size) {
            pr_error("Dynamic symbol entry no %" PRIu64 "'s st_name "
                     "overflows the dynamic string table\n", i);
            goto err;
        }

        const unsigned char binding = ELF64_ST_BIND(arr[i].st_info);
        switch (binding) {
            case STB_LOCAL:
                if (saw_nonlocal) {
                    pr_error("STB_LOCAL symbol (no %" PRIu64 ") appears after "
                             "a non-local symbol\n", i);
                    goto err;
                }
                break;
            case STB_GLOBAL:
            case STB_WEAK:
                break;
            default:
                if ((binding >= STB_LOOS && binding <= STB_HIOS) ||
                    (binding >= STB_LOPROC && binding <= STB_HIPROC))
                    break;

                pr_error("Dynamic symbol no %" PRIu64 " has invalid binding\n",
                         i);
                goto err;
        }

        const unsigned char type = ELF64_ST_TYPE(arr[i].st_info);
        switch (type) {
            case STT_NOTYPE: case STT_OBJECT: case STT_FUNC:
            case STT_SECTION: case STT_COMMON: case STT_TLS:
                break;
            case STT_FILE:
                if (binding != STB_LOCAL) {
                    pr_error("Invalid binding on STT_FILE symbol "
                             "(no %" PRIu64 ")\n", i);
                    goto err;
                }
                if (arr[i].st_shndx != SHN_ABS) {
                    pr_error("Invalid st_shndx value on STT_FILE symbol "
                             "(no %" PRIu64 ")\n", i);
                    goto err;
                }
                break;
            default:
                if ((type >= STT_LOOS && type <= STT_HIOS) ||
                    (type >= STT_LOPROC && type <= STT_HIPROC))
                    break;

                pr_error("Dynamic symbol no %" PRIu64 " has an invalid type\n",
                         i);
                goto err;
        }

        if (binding != STB_LOCAL)
            saw_nonlocal = true;

        if (arr[i].st_shndx != SHN_UNDEF &&
                arr[i].st_shndx < SHN_LORESERVE && arr[i].st_shndx >= n_shdrs)
        {
            /* Only accept invalid section indices if there are no
             * section headers at all (presumably they've been stripped out). */
            if (n_shdrs > 0) {
                pr_error("Dynamic symbol entry no %" PRIu64 "'s st_shndx "
                         "points to an invalid section\n", i);
                goto err;
            } else {
                pr_error("WARNING: symbol entry no %" PRIu64 " "
                         "references section %" PRIu32 ", "
                         "but no section headers are present\n",
                         i, arr[i].st_shndx);
            }
        } else if (arr[i].st_shndx == SHN_XINDEX) {
            /* The real index of the section referenced by this symbol
             * is located in a `SHT_SYMTAB_SHNDX` section,
             * which will be checked for and validated by later code. */
            *out_uses_symtab_shndx = true;
        } else if (arr[i].st_shndx == SHN_COMMON) {
            pr_error("Symbols with st_shndx == SHN_COMMON cannot appear "
                     " in ET_DYN ELFs\n");
            goto err;
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

static int validate_dynamic_hash_tables(
        const struct blob *data, const struct elf_dyn_strtab *strtab,
        const struct elf_dt_hash *hash, const struct elf_dt_gnu_hash *gnu_hash,
        const Elf64_Sym *symtab, Elf64_Xword nsyms, int clazz
)
{
    if (validate_sysv_hash(hash, symtab, nsyms, strtab, data)) {
        pr_error("Invalid SysV-style symbol name hash table (DT_HASH)\n");
        return 1;
    }

    if (validate_gnu_hash(gnu_hash, symtab, nsyms, strtab, data, clazz)) {
        pr_error("Invalid GNU-style symbol name hash table (DT_GNU_HASH)\n");
        return 1;
    }

    return 0;
}

static inline Elf32_Word sysv_hash(const uint8_t *name)
{
    Elf32_Word h = 0;
    while (*name != '\0') {
        h = (h << 4) + *name++;

        const Elf32_Word g = h & UINT32_C(0xf0000000);
        if (g != 0)
            h ^= g >> 24;

        h &= ~g;
    }

    return h;
}

static int validate_sysv_hash(const struct elf_dt_hash *hash,
                              const Elf64_Sym *symtab, Elf64_Xword nsyms,
                              const struct elf_dyn_strtab *strtab,
                              const struct blob *data)
{
    if (!hash->present)
        return 0;

    /* theoretically impossible case due to previous checks, but whatever */
    if (hash->hdr.nchain != nsyms) {
        pr_error("DT_HASH nchain does not equal "
                 "the number of dynamic symbols\n");
        return 1;
    } else if (hash->hdr.nchain == 0) {
        pr_error("DT_HASH nchain cannot be zero\n");
        return 1;
    }

    if (hash->hdr.nbucket == 0) {
        /* no buckets to validate */
        return 0;
    }

    /* use the "native" unsigned integer type */
    typedef size_t bitmap_word_t;
    enum { SEEN_WORD_BITS = sizeof(bitmap_word_t) * CHAR_BIT };

    /* basically: size = ceil(nsyms / 64) */
    /* `nsyms` is guaranteed to fit within `size_t` and be > 0;
     * this can never overflow */
    const size_t seen_bits_arrsize =
        1 + (((size_t)nsyms - 1) / SEEN_WORD_BITS);
    bitmap_word_t *seen_bits = calloc(seen_bits_arrsize, sizeof(bitmap_word_t));
    if (seen_bits == NULL) {
        pr_error("Failed to allocate the temporary seen bits array\n");
        return 1;
    }
    /* From this point on, no `return` without freeing `seen_bits` */
    int ret = 1;
    {
        /* `buckets[b]` is a starting index into `chain`,
         * and `chain[idx]` contains the next index into `chain`.
         * Every entry in `chain` cannot be referenced more than once, to not
         * create a circle. For a really nice visualisation of this,
         * see https://flapenguin.me/elf-dt-hash.
         *
         * What we are doing here is basically walking every chain,
         * which by the end should mean we've visited each entry in `chain`
         * at most once, and so, despite the nested loop,
         * the time complexity becomes O(n) (linear). */
        for (Elf64_Xword b = 0; b < hash->hdr.nbucket; b++) {
            Elf32_Word idx = hash->buckets[b];

            /* idx == 0 points at the first reserved STN_UNDEF entry,
             * which means the end of a chain */
            while (idx != STN_UNDEF) {
                if (idx >= nsyms) {
                    pr_error("Index in hash chain points outside the symtab\n");
                    goto err;
                }

                /* This detects both cycles within a chain and
                 * a symbol appearing in more than one bucket chain */

                /* idx < nsyms <= SIZE_MAX */
                const size_t wordidx = (size_t)idx / SEEN_WORD_BITS;

                const size_t bitidx = (size_t)idx % SEEN_WORD_BITS;
                const bitmap_word_t mask = (bitmap_word_t)1 << bitidx;

                if (seen_bits[wordidx] & mask) {
                    pr_error("DT_HASH symbol index seen more than once\n");
                    goto err;
                }
                seen_bits[wordidx] |= mask;

                /* Check if the current symbol's name hashes to the correct
                 * starting index (bucket) */
                const uint8_t *const name =
                    &data->data[strtab->off + symtab[idx].st_name];
                const Elf32_Word h = sysv_hash(name);

                if (h % hash->hdr.nbucket != b) {
                    pr_error("DT_HASH symbol no %" PRIu32 "'s name "
                             "hashes to the incorrect bucket\n", idx);
                    goto err;
                }

                idx = hash->chain[idx];
            }
        }
    }
    ret = 0;

err:
    free(seen_bits); seen_bits = NULL;
    return ret;
}

static int validate_gnu_hash(const struct elf_dt_gnu_hash *hash,
                             const Elf64_Sym *symtab, Elf64_Xword nsyms,
                             const struct elf_dyn_strtab *strtab,
                             const struct blob *data, int clazz)
{
    if (!hash->present)
        return 0;

    const struct elf_dt_gnu_hash_hdr *const hdr = &hash->hdr;
    const Elf32_Word nchain = hash->nchain;

    if (hdr->symoffset > nsyms || nchain != nsyms - hdr->symoffset) {
        pr_error("Invalid symoffset or nchain value\n");
        return 1;
    }

    if (hdr->nbuckets == 0) {
        if (nchain != 0) {
            pr_error("GNU hash has chains but no buckets\n");
            return 1;
        }

        /* no symbols are indexed by the table */
        return 0;
    }

    Elf32_Word chain_idx = 0;
    for (Elf32_Word b = 0; b < hdr->nbuckets; b++) {
        const Elf32_Word first_sym_idx = hash->buckets[b];
        if (first_sym_idx == STN_UNDEF) {
            /* empty bucket */
            continue;
        }

        /* this bucket should start right after where the previous one ended */
        if (chain_idx >= nchain ||
                (Elf64_Xword)first_sym_idx !=
                    (Elf64_Xword)hdr->symoffset + chain_idx)
        {
            pr_error("Invalid chain starting index (bucket value)\n");
            return 1;
        }

        /* Again, like in the case of DT_HASH, we are walking the `chain`
         * array and are visiting each entry exactly once, which means `O(n)`
         * complexity. This time, however, we don't need to keep track
         * of which entries we've visited already as the spec
         * requires the buckets to be ordered, one after the other. */
        while (true) {
            if (chain_idx >= nchain) {
                pr_error("Unterminated DT_GNU_HASH chain\n");
                return 1;
            }

            const Elf64_Xword sym_idx = (Elf64_Xword)hdr->symoffset + chain_idx;
            const Elf64_Sym *const sym = &symtab[sym_idx];

            const Elf32_Word h =
                gnu_hash(&data->data[strtab->off + sym->st_name]);

            const Elf32_Word curr_chain_entry = hash->chain[chain_idx];

            /* Do a "reverse lookup"; name -> hash instead of hash -> name,
             * to ensure that the symbol is correctly reachable via the table */

            /* 4) would be strcmp(sym->name, name),
             * which is where we're starting */

            /* 3) hash matches the current chain entry */
            if ((curr_chain_entry & ~UINT32_C(1)) != (h & ~UINT32_C(1))) {
                pr_error("Symbol name hash doesn't match its chain entry\n");
                return 1;
            }

            /* 2) name hashes to the correct bucket */
            if (h % hdr->nbuckets != b) {
                pr_error("Symbol name doesn't hash to its own bucket\n");
                return 1;
            }

            /* 1) hash passes the bloom filter test */
            const Elf32_Word class_bits = clazz == ELFCLASS32 ? 32u : 64u;
            const Elf32_Word bloom_idx = (h / class_bits) % hash->hdr.bloom_size;
            const Elf64_Xword bloom_word = hash->bloom[bloom_idx];

            const Elf64_Xword bit1 = UINT64_C(1) << (h % class_bits);
            const Elf64_Xword bit2 =
                UINT64_C(1) << ((h >> hdr->bloom_shift) % class_bits);
            if (!(bloom_word & bit1) || !(bloom_word & bit2)) {
                pr_error("Symbol name hash bits not set in bloom filter\n");
                return 1;
            }

            /* the `chain_idx < nchain` at the top guarantees
             * that this doesn't overflow */
            chain_idx++;
            if (curr_chain_entry & UINT32_C(1))
                /* a chain entry with the 0x1 bit marks the end of the bucket */
                break;
        }
    }
    if (chain_idx != nchain) {
        pr_error("Invalid number of chain entries traversed\n");
        return 1;
    }

    return 0;
}

static inline Elf32_Word gnu_hash(const uint8_t *name)
{
    Elf32_Word h = 5381;

    while (*name) {
        h = (h << 5) + h + *name;
        name++;
    }

    return h;
}

static int validate_sht_dynsym_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t sht_dynsym_idx,
        Elf64_Addr symtab_vaddr, Elf64_Off symtab_off,
        const Elf64_Sym *symtab, Elf64_Xword symentsize, Elf64_Xword nsyms,
        elf_idx_t dynstr_shdr_idx
)
{
    if (sht_dynsym_idx == ELF_IDX_NULL)
        return 0;

    const Elf64_Shdr *const sht_dynsym = &shdrs->arr[sht_dynsym_idx];
    int ret = 0;

    if (dynstr_shdr_idx == ELF_IDX_NULL) {
        pr_error("Dynsym section exists without a dynstr section\n");
        ret = 1;
    } else if (sht_dynsym->sh_link != dynstr_shdr_idx) {
        pr_error("SHT_DYNSYM sh_link doesn't point to the dynstr section\n");
        ret = 1;
    }

    if (sht_dynsym->sh_entsize != symentsize) {
        pr_error("Invalid sh_entsize in SHT_DYNSYM section header\n");
        ret = 1;
    }

    if (sht_dynsym->sh_size % symentsize != 0) {
        pr_error("Invalid SHT_DYNSYM section size\n");
        ret = 1;
    } else {
        const Elf64_Xword shdr_nsyms = sht_dynsym->sh_size / symentsize;
        if (shdr_nsyms != nsyms) {
            pr_error("SHT_DYNSYM shdr reports different dynamic symbol count "
                     "(%" PRIu64 ") than the DT_(GNU_)HASH (%" PRIu64 ")\n",
                     shdr_nsyms, nsyms);
            ret = 1;
        }
    }


    if (sht_dynsym->sh_addr != symtab_vaddr) {
        pr_error("Invalid SHT_DYNSYM vaddr\n");
        ret = 1;
    }
    if (sht_dynsym->sh_offset != symtab_off) {
        pr_error("Invalid SHT_DYNSYM offset\n");
        ret = 1;
    }

    /* SHT_DYNSYM's sh_info should hold:
     *  "One greater than the symbol table index of the last local symbol
     *  (binding STB_LOCAL)."
     */
    if (sht_dynsym->sh_info > nsyms || sht_dynsym->sh_info < 1) {
        pr_error("Invalid value of SHT_DYNSYM sh_info\n");
        ret = 1;
    }

    Elf64_Xword first_nonlocal = 0;
    while (first_nonlocal < nsyms &&
            ELF64_ST_BIND(symtab[first_nonlocal].st_info) == STB_LOCAL)
    {
        first_nonlocal++;
    }
    if (sht_dynsym->sh_info != first_nonlocal) {
        pr_error("SHT_DYNSYM's sh_info doesn't point "
                 "at the first non-local symbol\n");
        ret = 1;
    }

    return ret;
}

static int parse_dyn_symtab_shndx_if_exists(
        const struct elf_dyn_entries *entries, const struct elf_phdrs *phdrs,
        const struct elf_shdrs *shdrs, elf_idx_t sht_dynsym_idx,
        const struct blob *data, int clazz, int encoding,
        Elf64_Sym *symtab, Elf64_Xword nsyms, bool must_exist,

        struct elf_dyn_symtab_shndx *out
)
{
    *out = (struct elf_dyn_symtab_shndx) { 0 };
    out->dyn_entry = ELF_IDX_NULL;
    out->shdr = ELF_IDX_NULL;

    Elf64_Off off = 0;
    Elf64_Addr vaddr = 0;
    Elf64_Xword size = 0;
    elf_idx_t dt_symtab_shndx_idx = ELF_IDX_NULL;
    elf_idx_t sht_symtab_shndx_idx = ELF_IDX_NULL;
    Elf32_Word *arr = NULL;

    bool exists = false;
    const int r = find_unique_dyn_entries(entries, 1,
            (const Elf64_Sxword[]) { DT_SYMTAB_SHNDX }, &dt_symtab_shndx_idx);
    if (r < 0) {
        pr_error("Duplicate DT_SYMTAB_SHNDX entries\n");
        goto err;
    } else if (r > 0) {
        exists = false;
        pr_debug("No DT_SYMTAB_SHNDX entry\n");
    } else /* if (r == 0) */ {
        exists = true;
        vaddr = entries->arr[dt_symtab_shndx_idx].d_un.d_ptr;

        if (nsyms > UINT64_MAX / sizeof(Elf32_Word)) {
            pr_error("Number of symbols too large to calculate "
                     "DT_SYMTAB_SHNDX size (integer overflow)\n");
            goto err;
        }
        size = nsyms * sizeof(Elf32_Word);

        if (find_ptload_and_off_from_vaddr(vaddr, size, phdrs, &off, NULL)) {
            pr_error("No PT_LOAD segment contains the "
                     "DT_SYMTAB_SHNDX contents\n");
            goto err;
        }
    }

    if (!exists && must_exist) {
        pr_error("No DT_SYMTAB_SHNDX entry even though it's needed\n");
        goto err;
    }

    /* Read the SYMTAB_SHNDX contents */
    if (exists) {
        if (read_symtab_shndx_contents(data, clazz, encoding,
                                     symtab, nsyms, off, size, shdrs, &arr))
        {
            pr_error("Failed to parse the DT_SYMTAB_SHNDX contents\n");
            goto err;
        }
    }

    /* Also check for the SHT_SYMTAB_SHNDX shdr
     * (the one which references the SHT_DYNSYM section) */
    if (validate_dyn_sht_symtab_shndx_if_exists(
                shdrs, sht_dynsym_idx, nsyms, exists, vaddr, off,
                &sht_symtab_shndx_idx
        )
    ) {
        pr_error("Invalid state of the dynsym SHT_SYMTAB_SHNDX section\n");
        goto err;
    }

    out->dyn_entry = dt_symtab_shndx_idx;
    out->shdr = sht_symtab_shndx_idx;
    out->vaddr = vaddr;
    out->off = off;
    out->size = size;
    out->arr = arr;
    out->present = exists;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_symtab_shndx_contents(
        const struct blob *data, int clazz, int encoding,
        Elf64_Sym *symtab, Elf64_Xword nsyms, Elf64_Off start, Elf64_Xword size,
        const struct elf_shdrs *shdrs,
        Elf32_Word **out
)
{
    Elf32_Word *arr = NULL;

    uint64_t off = start;
    /* This range fits in a PT_LOAD segment
     * (`parse_dyn_symtab_shndx_if_exists`), so won't overflow */
    const Elf64_Off end = start + size;

    /* `nsyms` must fit within a `size_t` since it was previously validated
     * in `parse_dynsym` for the `symtab` array allocation  */
    arr = calloc((size_t)nsyms, sizeof(Elf32_Word));
    if (arr == NULL) {
        pr_error("Failed to allocate the SYMTAB_SHNDX entries array\n");
        goto err;
    }

    for (Elf64_Xword i = 0; i < nsyms; i++) {
        if (read_Word(data, &off, clazz, encoding, &arr[i])) {
            pr_error("Failed to read SHT_SYMTAB_SHNDX entry "
                     "no %" PRIu64 "\n", i);
            goto err;
        }

        if (symtab[i].st_shndx == SHN_XINDEX) {
            if (arr[i] == SHN_UNDEF) {
                pr_error("SHT_SYMTAB_SHNDX entry no %" PRIu64
                         " is SHN_UNDEF for a symbol using SHN_XINDEX\n", i);
                goto err;
            } else if (arr[i] >= shdrs->num) {
                /* Only accept invalid section indices if
                 * there are no section headers at all
                 * (presumably they've been stripped out). */
                if (shdrs->num > 0) {
                    pr_error("SHT_SYMTAB_SHNDX entry no %" PRIu64 " "
                             " references invalid section\n", i);
                    goto err;
                } else {
                    pr_error("WARNING: SHT_SYMTAB_SHNDX entry no %" PRIu64 " "
                             " references section %" PRIu32 ", but "
                             " no section headers are present\n", i, arr[i]);
                }
            }
        } else /* all other cases, even those >= SHN_LORESERVE */ {
            if (arr[i] != 0) {
                pr_error("SHT_SYMTAB_SHNDX entry no %" PRIu64 " "
                         "non-zero when the corresponding symbol "
                         "does not use SHN_XINDEX\n", i);
                goto err;
            }
        }
    }

    if (off != end) {
        pr_error("Invalid offset after reading "
                 "the SHT_SYMTAB_SHNDX section data\n");
        goto err;
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

static int validate_dyn_sht_symtab_shndx_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t sht_dynsym_idx,
        Elf64_Xword nsyms, bool dt_symtab_shndx_exists,
        Elf64_Addr vaddr, Elf64_Off off,
        elf_idx_t *out
)
{
    *out = ELF_IDX_NULL;

    if (sht_dynsym_idx == ELF_IDX_NULL) {
        pr_debug("No SHT_DYNSYM section; no SHT_SYMTAB_SHNDX section "
                 "referencing it can exist\n");
        return 0;
    }

    elf_idx_t idx = ELF_IDX_NULL;
    for (Elf64_Xword i = 0; i < shdrs->num; i++) {
        if (shdrs->arr[i].sh_type == SHT_SYMTAB_SHNDX &&
            shdrs->arr[i].sh_link == sht_dynsym_idx)
        {
            if (idx != ELF_IDX_NULL) {
                pr_error("Multiple SHT_SYMTAB_SHNDX sections referencing "
                         " the SHT_DYNSYM section\n");
                return 1;
            }
            idx = i;
        }
    }
    if (idx == ELF_IDX_NULL) {
        if (!dt_symtab_shndx_exists)
            pr_debug("No SHT_SYMTAB_SHNDX section referencing SHT_DYNSYM\n");
        else
            pr_debug("DT_SYMTAB_SHNDX exists without a corresponding "
                     "SHT_SYMTAB_SHNDX; no section header to validate.\n");

        return 0;
    } else if (idx != ELF_IDX_NULL && !dt_symtab_shndx_exists) {
        pr_error("SHT_SYMTAB_SHNDX exists without a "
                 "corresponding DT_SYMTAB_SHNDX entry\n");
        return 1;
    }
    const Elf64_Shdr *const shdr = &shdrs->arr[idx];

    int ret = 0;

    if (shdr->sh_addr != vaddr) {
        pr_error("SHT_SYMTAB_SHNDX vaddr invalid\n");
        ret = 1;
    }
    if (shdr->sh_offset != off) {
        pr_error("SHT_SYMTAB_SHNDX offset invalid\n");
        ret = 1;
    }

    if (shdr->sh_entsize != sizeof(Elf32_Word)) {
        pr_error("SHT_SYMTAB_SHNDX entsize invalid\n");
        ret = 1;
    }

    if (shdr->sh_size % sizeof(Elf32_Word) != 0) {
        pr_error("SHT_SYMTAB_SHNDX size not a multiple of entsize\n");
        ret = 1;
    } else {
        const Elf64_Xword n_ents = shdr->sh_size / sizeof(Elf32_Word);
        if (n_ents != nsyms) {
            pr_error("Number of entries in SHT_SYMTAB_SHNDX (%" PRIu64 ") "
                     "doesn't match the dynamic symbol count (%" PRIu64 ")\n",
                     n_ents, nsyms);
            ret = 1;
        }
    }

    if (shdr->sh_info != 0)
        pr_error("WARNING: SHT_SYMTAB_SHNDX sh_info non-zero\n");

    if (!ret)
        *out = idx;
    return ret;
}
