#ifndef ELF_DYN_SYM_PARSING_H_
#define ELF_DYN_SYM_PARSING_H_

/**
 * @file Module that parses the ".dynsym" dynamic symbol table.
 * Factored out of `elf-dyn-parsing` due to relative complexity.
 */

#include "elf.h"
#include "util.h"
#include <stdbool.h>

struct elf_phdrs;
struct elf_shdrs;
struct elf_dyn_strtab;
struct elf_dyn_entries;

/**
 * @struct In-memory representation of the legacy DT_HASH
 *  symbol lookup table. Usually not present on modern binaries,
 *  but supported for compatibility.
 */
struct elf_dt_hash {
    /**
     * A flag indicating that the `DT_HASH` table is present
     * and that this struct is valid.
     */
    bool present;

    /**
     * Virtual address of the hash table header and contents;
     * the value of the `DT_HASH` dynamic entry.
     */
    Elf64_Addr vaddr;

    /** File offset of the hash table header and contents. */
    Elf64_Off off;

    /** Total file size of the hash table header and contents. */
    Elf64_Xword total_size;

    /**
     * Index of the DT_HASH dynamic entry;
     * a reference into `entries`.
     */
    elf_idx_t dyn_entry;

    /** @define Size in bytes of the DT_HASH header */
#define DT_HASH_HDR_SIZE (2 * sizeof(Elf32_Word))
    /**
     * @struct Header of the DT_HASH table structure.
     *
     * Wire format:
     *  =========================
     *  | nbucket: u32          |
     *  | nchain: u32           |
     *  |-----------------------|
     *  | buckets: u32[nbucket] |
     *  /  ...                  /
     *  |                       |
     *  |-----------------------|
     *  | chain: u32[nchain]    |
     *  /  ...                  /
     *  |                       |
     *  =========================
     */
    struct elf_dt_hash_hdr {
        Elf32_Word nbucket; /**< Number of entries in `buckets`. */
        Elf32_Word nchain; /**< Number of entries in `chain`. */
    } hdr; /**< Header of the DT_HASH table structure. */

    /**
     * Array of dynamic symbol table indices, of size `hdr.nbucket`.
     *
     * During lookup, the initial symbol index is obtained as:
     *  `index = buckets[hash(symname) % nbucket]`.
     *
     * This array may be empty (set to `NULL`) when
     * there are no named symbols in the symtab.
     * In that case, `hdr.nbucket` is `0`.
     */
    Elf32_Word *buckets;

    /**
     * Array of symbol table indices forming the collision chains,
     * of size `hdr.nchain`.
     *
     * For a symbol index `i`, `chain[i]` gives the next symbol index
     * in the same hash bucket. A value of `STN_UNDEF`
     * terminates the chain.
     *
     * The length of this array equals the number of entries
     * in the associated dynamic symbol table, which must be non-zero
     * due to the requirement of the first reserved `STN_UNDEF` entry.
     * This means that, if `DT_HASH` is present at all, this array
     * must not be empty and `hdr.nchain > 0`.
     */
    Elf32_Word *chain;

    /**
     * Index of the ".hash" SHT_HASH section header, if present;
     * otherwise `ELF_IDX_NULL`.
     */
    elf_idx_t shdr;
};

/**
 * @struct In-memory representation of the new DT_GNU_HASH
 *  symbol lookup table. This is what's mostly used today
 *  in place of the legacy (and slow) DT_HASH.
 */
struct elf_dt_gnu_hash {
    /**
     * A flag indicating that the `DT_GNU_HASH` table is present
     * and that this struct is valid.
     */
    bool present;

    /**
     * A flag indicating that the table is the special case
     * "empty" table, that is, there are no hashed symbols.
     * Such a table has:
     *  `nbuckets == 1`,
     *  `symoffset` either set to 1 (GNU bfd ld)
     *      or the "correct" value - equal to the number
     *      of unhashed symbols (LLVM lld & GNU gold),
     *  `bloom_size == 1`, `bloom_shift == 0`,
     *  1 empty bloom filter word set to 0.
     *  1 empty bucket set to 0.
     */
    bool is_canonically_empty;

    /**
     * A flag indicating that the count of dynamic symbols
     * is ambiguous - the table `is_canonically_empty`
     * and `hdr.symoffset` is 1.
     *
     * This flag exists because some versions of GNU bfd ld
     * incorrectly always emit `symoffset == 1` when there are
     * no symbols to hash, i.e. there are no exported symbols.
     *
     * This is problematic because when there exist non-hashed
     * (e.g. imported) symbols, but no exported ones,
     * the total count of them can't be determined
     * from the GNU hash table alone.
     *
     * In some cases, this might make it literally impossible
     * to certainly determine the number of dynamic symbols.
     */
    bool sym_count_ambiguous;

    /**
     * Virtual address of the hash table header and contents;
     * the value of `DT_GNU_HASH`.
     */
    Elf64_Addr vaddr;

    /** File offset of the DT_GNU_HASH table header and contents. */
    Elf64_Off off;

    /**
     * Index of the DT_GNU_HASH dynamic entry;
     * a reference into `entries`.
     */
    elf_idx_t dyn_entry;

    /** @define Size in bytes of the DT_GNU_HASH header */
#define DT_GNU_HASH_HDR_SIZE (4 * sizeof(Elf32_Word))
    /**
     * @struct Header of the DT_GNU_HASH table structure.
     *
     * Wire format:
     *  ===============================
     *  | nbuckets: u32               |
     *  | symoffset: u32              |
     *  | bloom_size: u32             |
     *  | bloom_shift: u32            |
     *  |-----------------------------|
     *  | bloom: u(32|64)[bloom_size] |
     *  /  ...                        /
     *  |                             |
     *  |-----------------------------|
     *  | buckets: u32[nbuckets]      |
     *  /  ...                        /
     *  |                             |
     *  |-----------------------------|
     *  | chain: u32[??]              |
     *  /  ...                        /
     *  |  <terminator entry>         |
     *  ===============================
     */
    struct elf_dt_gnu_hash_hdr {
        Elf32_Word nbuckets; /**< Number of entries in `buckets`. */

        /**
         * The index (into `symtab`) of the first symbol
         * this hash table indexes.
         */
        Elf32_Word symoffset;

        /**
         * The number of class-sized words that
         * make up the bloom filter.
         */
        Elf32_Word bloom_size;

        /** Bit shift for the 2nd bloom filter test bit. */
        Elf32_Word bloom_shift;
    } hdr; /**< Header of the DT_GNU_HASH table structure. */

    /**
     * (file) size of an entry in the bloom filter
     * (`4` for `ELFCLASS32` and `8` for `ELFCLASS64`).
     */
    size_t bloomentsize;

    /**
     * The bloom filter array, of size `hdr.bloom_size`.
     *
     * Holds the GNU hash bloom filter, which is an optimization used
     * to reject (most) non-indexed symbol name hashes early.
     *
     * For `ELFCLASS32`, the values stored in the file are 32-bit,
     * so during parsing they are widened to 64-bit.
     */
    Elf64_Xword *bloom;

    /**
     * Array of dynamic symbol table indices, of size `hdr.nbuckets`.
     *
     * During lookup, the initial symbol index is obtained as:
     *  `index = buckets[hash(symname) % nbuckets]`.
     *
     * This array may be empty (set to `NULL`) when
     * there are no exported named symbols in the symtab.
     * In that case, `hdr.nbuckets` is `0`.
     */
    Elf32_Word *buckets;

    /**
     * Array of hashes to compare against (excluding the low 0x1 bits).
     *
     * The number of elements in this array equals the number
     * of symbols indexed by the GNU hash table, that is
     *  `nsyms = hdr.symoffset + nchain`.
     *
     * The only problem is that there's no way to know the length
     * of the array ahead of time; it's constructed like a C string
     * (terminated with a special value).
     * In this case, the array terminator is an element with the
     * lowermost bit 0x1 set.
     *
     * To use the table, obtain the index at which to start looking
     * from the appropriate bucket like this:
     *  `sym_idx = buckets[hash(name) % hdr.nbuckets]`, and then:
     *  `start_chain_index = sym_idx - hdr.symoffset`
     * Then, walk the chain array until
     *  `chain[i] & ~0x1 == hash(name) & ~0x1`,
     * or when you find the terminator entry (`chain[i] & 0x1`).
     *
     * If you find a match before reaching the end of the array,
     * the corresponding symbol is `index_in_chain + hdr.symoffset`.
     *
     * A visualisation of how this works:
     *  [symtab]
     *  <sym>   |              (symoffset = 3)
     *  <sym>   |
     *  <sym>   |  [chain]
     *  <sym_a> | 0x5ff0123e | <- no 0x1 bits
     *  <sym_b> | 0x6123234c #  <= initial idx from
     *  <sym_c> | 0x74413458 #        `buckets[hash(name) % nbuckets]`
     *  ....................~#
     *  <sym_x> | 0x01234564 # <- hash(name) == 0x1234564; match!;
     *  .....................|      found `sym_x`
     *  <sym_y> | 0x5274953f |
     *                     ^
     *                      \-- last entry with the 0x1 bit set
     */
    Elf32_Word *chain;

    /**
     * The number of entries in `chain`.
     *
     * Found at runtime by walking the `chain` array until
     * an entry with the lowest `0x1` bit set
     * (which marks the end of the array).
     */
    Elf32_Word nchain;

    /** Total file size of the whole DT_GNU_HASH structure. */
    Elf64_Xword total_size;

    /**
     * Index of the `SHT_GNU_HASH` ".gnu.hash" section header
     * (a reference into `shdr`), or `ELF_IDX_NULL` if not present.
     */
    elf_idx_t shdr;
};

/** @struct Data related to the dynamic symbol table (`.dynsym`). */
struct elf_dyn_symtab {
    /**
     * Virtual address of the dynamic symbol table;
     * the value of `DT_SYMTAB`.
     */
    Elf64_Addr vaddr;

    /** File offset of the dynamic symbol table. */
    Elf64_Off off;

    /** Total file size of the dynamic symbol table. */
    Elf64_Xword size;

    /**
     * `sizeof(Elf32_Sym)` for `ELFCLASS32` and
     * `sizeof(Elf64_Sym)` for `ELFCLASS64`;
     * the value of `DT_SYMENT`.
     */
    Elf64_Half entsize;

    /**
     * Index of the `DT_SYMTAB` entry (a reference into `entries`);
     * contains the virtual address of the dynamic symbol table.
     */
    elf_idx_t dt_symtab;

    /**
     * Index of the `DT_SYMENT` entry (a reference into `entries`);
     * contains the size of a dynamic symbol. This is goddamn useless.
     */
    elf_idx_t dt_syment;

    /**
     * Index of the `SHT_DYNSYM` section header
     * (a reference into `shdrs`), or `ELF_IDX_NULL` if not present.
     */
    elf_idx_t shdr;

    Elf64_Xword nsyms; /**< Number of dynamic symbols in the table. */
    /**
     * In-memory array of `nsyms` parsed dynamic symbols,
     * representing the dynamic symbol table.
     *
     * Note: If `shdrs->num == 0` (fully stripped out section headers),
     * invalid section references in the symbols' `st_shndx` fields
     * are permitted, which means that those values cannot be trusted
     * without additional checks.
     */
    Elf64_Sym *syms;

    bool dirty; /**< Dirty flag (see `serialize_elf`). */
};

/**
 * @struct Data related to the dynsym `SHT_SYMTAB_SHNDX` section.
 *
 * Every `ElfXX_Sym` has the `st_shndx` field, which holds a reference
 * to some section. However, this member is only a uint16_t,
 * so if there are more than `SHN_LORESERVE` sections, the field
 * holds the value `SHN_XINDEX` and the real section index
 * referenced by that symbol is stored in the corresponding word
 * in a `SHT_SYMTAB_SHNDX` section.
 *
 * The address of this section is determined by the `DT_SYMTAB_SHNDX`
 * entry, and the size is `symtab.nsyms * sizeof(Elf32_Word)`
 */
struct elf_dyn_symtab_shndx {
    /**
     * Flag indicating whether the SYMTAB_SHNDX array
     * corresponding to the dynamic symbol table is present.
     * Usually `false`, lol
     */
    bool present;

    /** Index of the `SHT_SYMTAB_SHNDX` section header, if present. */
    elf_idx_t shdr;

    /** Index of the `DT_SYMTAB_SHNDX` dynamic entry, if present. */
    elf_idx_t dyn_entry;

    /**
     * The virtual address of the SYMTAB_SHNDX section;
     * the value of the `DT_SYMTAB_SHNDX` entry.
     */
    Elf64_Addr vaddr;

    /** File offset of the SYMTAB_SHNDX section. */
    Elf64_Off off;

    /**
     * Total file size of the SYMTAB_SHNDX section
     * (`sizeof(Elf32_Word) * symtab.nsyms`).
     */
    Elf64_Xword size;

    /**
     * The in-memory array of `symtab.nsyms` elements
     * with the contents of the SYMTAB_SHNDX section.
     *
     * Note: If `shdrs->num == 0` (fully stripped out section headers),
     * invalid section references in this array are permitted
     * which means that the values here cannot be trusted without
     * additional checks.
     */
    Elf32_Word *arr;
};

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
    const ElfFileData *data,
    const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
    const struct elf_dyn_entries *entries, const struct elf_dyn_strtab *strtab,

    struct elf_dt_hash *out_hash, struct elf_dt_gnu_hash *out_gnu_hash,
    struct elf_dyn_symtab_shndx *out_symtab_shndx, struct elf_dyn_symtab *out
);

#endif /* ELF_DYN_SYM_PARSING_H_ */
