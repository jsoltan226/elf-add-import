#ifndef CTX_H_
#define CTX_H_

/**
 * @file Everything directly related to the ELF context struct.
 */

#include "elf.h"
#include "util.h"
#include <assert.h>

/**
 * @typedef Used to refer to entries in arrays of in-memory ELF structures,
 * such as the program and section headers and the dynamic entries.
 *
 * Note: Shrinking or inserting an element into an array invalidates
 * the corresponding `elf_idx_t` references. This is not an issue now as
 * currently any modifications done only append elements or
 * modify them in-place, but it is something worth keeping in mind.
 */
typedef Elf64_Xword elf_idx_t;

/**
 * @define
 * Sentinel value for `elf_idx_t` which indicates that an index is invalid.
 */
#define ELF_IDX_NULL ((Elf64_Xword)-1)

/**
 * @brief ELF file parsing & patching context.
 *
 * @struct elf
 * Container for all data required to parse, patch and re-serialize
 * an ELF file (any class, any data encoding).
 *
 * Populated by `parse_elf` and destroyed with `destroy_elf`.
 */
struct elf {

    /** CONSTANT METADATA, POPULATED BY `parse_elf` AND NEVER MODIFIED LATER **/

    /**
     * @struct The ELF ident bytes, organized into a struct.
     * See the ELF spec.
     * Always populated by `parse_elf`, but never re-serialized,
     * and therefore treated as immutable.
     */
    struct elf_ident {
        uint8_t magic[SELFMAG]; /**< `EI_MAG[0-3]`; 0x7f 'E' 'L' 'F' */
        uint8_t clazz;      /**< EI_CLASS; `ELFCLASS32` or `ELFCLASS64` */
        uint8_t data;       /**< EI_DATA; `ELFDATA2MSB` or `ELFDATA2LSB` */
        uint8_t version;    /**< EI_VERSION; `EV_CURRENT` i.e. `1` */
        uint8_t os_abi;     /**< EI_OSABI; OS ABI. Unused here. */
        uint8_t abi_version; /**< EI_OSABIVERSION; Unused here. */

        uint8_t pad_[7];    /**< `EI_PAD`; Padding bytes, set to 0 & ignored. */
    } ident; /**< ELF ident bytes. */
    static_assert(sizeof(struct elf_ident) == EI_NIDENT, "Invalid size");

    /**
     * @struct The original state of some ELF structures.
     * Must not be modifed after `parse_elf`.
     */
    struct elf_orig_data {
        Elf64_Ehdr ehdr; /**< The original ELF header. */

        Elf64_Xword phnum; /**< Original program header count. */
        Elf64_Xword phsize; /**< Original size of the phdr table. */

        Elf64_Xword shnum; /**< Original section header count. */
        Elf64_Xword shsize; /**< Original size of the shdr table. */

        Elf64_Word shstrndx; /**< Original index of the
                                  ".shstrtab" section header */

        /**
         * The original value of the DT_STRTAB entry;
         * contains the virtual addres of the .dynamic string table.
         */
        Elf64_Addr dyn_strtab_vaddr;

        /**
         * The original offset of the .dynamic string table within the ELF data.
         */
        Elf64_Off dyn_strtab_off;

        /**
         * The original value of the DT_STRSZ entry;
         * the size of the string table pointed to by DT_STRTAB.
         */
        Elf64_Xword dyn_strtab_sz;
    } orig; /**< Original state of the ELF data structures */

    /**
     * The value of `ehdr.e_phentsize` as well as `orig.ehdr.e_phentsize`
     * (so either `sizeof(Elf64_Phdr)` or `sizeof(Elf32_Phdr)`).
     * A little shortcut to not have to pick between `ehdr` and `orig.ehdr`,
     * since this value will always be constant after `parse_elf`.
     */
    Elf64_Half phentsize;

    /**
     * The value of `ehdr.e_shentsize` as well as `orig.ehdr.e_shentsize`
     * (so either `sizeof(Elf64_Shdr)` or `sizeof(Elf32_Shdr)`).
     * A little shortcut to not have to pick between `ehdr` and `orig.ehdr`,
     * since this value will always be constant.
     */
    Elf64_Half shentsize;

    /**
     * The size of a DT_* dynamic entry, depending on the ELF's class
     * (`sizeof(Elf32_Dyn)` for 32-bit or `sizeof(Elf64_Dyn)` for 64-bit).
     */
    Elf64_Half dynentsize;

    /**
     * The size of a dynamic symbol struct, depending on the ELF's class
     * (`sizeof(Elf32_Sym)` for 32-bit or `sizeof(Elf64_Sym)` for 64-bit).
     * Also the value of the `DT_SYMENT` entry. Equal to `dyn.symtab.entsize`.
     */
    Elf64_Half dynsymentsize;

    /** MUTABLE METADATA, INITIALLY POPULATED BY `parse_elf`,
     ** MODIFIED IN `main.c` BY VARIOUS HELPERS FROM `elf-patching.h`,
     ** AND LATER INTERPRETED & RE-SERIALIZED BY `serialize_elf`. **/

    /**
     * In-memory representation of the parsed ELF header.
     * Parsed by `read_validate_ehdr` and re-serialized by `write_ehdr`.
     * Always populated by `parse_elf`.
     */
    Elf64_Ehdr ehdr;
    bool ehdr_dirty; /**< Dirty flag for `ehdr`. See `serialize_elf`. */

    /**
     * If section headers are present, index into `shdrs.arr`
     * where the section-header-string-table (".shstrtab") section header is.
     * This special section contains the section name strings themselves.
     *
     * Note: this is the real index, including any `SHN_XINDEX` shenanigans.
     * Use `update_shstrndx` if you want to update this value.
     */
    Elf64_Word shstrndx;

    /**
     * Array of parsed program headers (in-memory representation).
     * Always populated by `parse_elf`.
     */
    struct elf_phdrs {
        /**
         * The real number of program headers,
         * taking into account support for values >= `PN_XNUM`.
         * Note: DO NOT MODIFY DIRECTLY; use `update_phnum` instead.
        */
        Elf64_Xword num;
        /**
         * Equal to `num` * `ehdr.e_phentsize`.
         *
         * Meant to provide a way to delegate integer overflow validation
         * exclusively to functions that mutate the `phdrs` struct,
         * saving on complexity in code which just needs to read this value.
         */
        Elf64_Xword size;

        /**
         * In-memory array of parsed program headers.
         * Note: DO NOT ACCESS DIRECTLY. See `get_phdr_rw`/`get_phdr_ro`.
         */
        Elf64_Phdr *arr;

        bool dirty; /**< Dirty flag (see `serialize_elf`). */
    } phdrs; /**< In-memory representation of the program headers. */

    /**
     * Array of parsed section headers (in-memory representation).
     * Since section headers are theoretically optional in `ET_DYN` ELFs,
     * `parse_elf` might write an empty array here.
     */
    struct elf_shdrs {
        /**
         * The real number of section headers,
         * taking into account support for values greater than `SHN_LORESERVE`.
         * Note: DO NOT MODIFY DIRECTLY; use `update_shnum` instead.
         */
        Elf64_Xword num;

        /**
         * Equal to `num` * `ehdr.e_shentsize`.
         *
         * Meant to provide a way to delegate integer overflow validation
         * exclusively to functions that mutate the `shdrs` struct,
         * saving on complexity in code which just needs to read this value.
         */
        Elf64_Xword size;

        /**
         * In-memory array of parsed section headers.
         * Note: DO NOT ACCESS DIRECTLY. See `get_shdr_rw`/`get_shdr_ro`.
         */
        Elf64_Shdr *arr;

        bool dirty; /**< Dirty flag (see `serialize_elf`). */
    } shdrs; /**< In-memory representation of the section headers. */

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
        } hash; /**< Data related to the legacy DT_HASH symbol lookup table. */

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
        } gnu_hash; /**< Data related to the new DT_GNU_HASH
                         symbol lookup table. */

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
        } symtab; /**< Data related to the dynamic symbol table (`.dynsym`). */

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
        } symtab_shndx; /**< Data related to the dynsym SYMTAB_SHNDX section. */
    } dyn; /**< Everything related to the dynamic section */

    /** The raw bytes of the ELF file **/
    struct blob data;
};

/**
 * Getter for a read-write reference to an entry in `elf->phdrs`.
 *
 * Use this instead of direct access to `elf->phdrs.arr` to avoid the risk
 * of a use-after-free potentially introduced by a future `realloc`.
 *
 * Note: The returned pointer should be used and discarded as soon as possible.
 * To refer to a given entry, store its index and use this API to retrieve it
 * whenever necessary.
 *
 * Remember to update the corresponding `dirty` flag, if applicable.
 *
 * @param elf The ELF context. Must not be NULL.
 *
 * @param idx The index of the entry to retrieve.
 *  Must be smaller than `elf->phdrs.num` and not equal `ELF_IDX_NULL`.
 *
 * @return Ephemeral pointer to an entry in `elf->phdrs.arr`
 *  or `NULL` if the index or ELF context are invalid.
 */
Elf64_Phdr * get_phdr_rw(struct elf *elf, elf_idx_t idx);

/**
 * Getter for a read-only reference to an entry in `elf->phdrs`.
 *
 * Use this instead of direct access to `elf->phdrs.arr` to avoid the risk
 * of a use-after-free potentially introduced by a future `realloc`.
 *
 * Note: The returned pointer should be used and discarded as soon as possible.
 * To refer to a given entry, store its index and use this API to retrieve it
 * whenever necessary.
 *
 * @param elf The ELF context. Must not be NULL.
 *
 * @param idx The index of the entry to retrieve.
 *  Must be smaller than `elf->phdrs.num` and not equal `ELF_IDX_NULL`.
 *
 * @return Ephemeral pointer to an entry in `elf->phdrs.arr`
 *  or `NULL` if the index or ELF context are invalid.
 */
const Elf64_Phdr * get_phdr_ro(const struct elf *elf, elf_idx_t idx);

/**
 * Getter for a read-write reference to an entry in `elf->shdrs`.
 *
 * Use this instead of direct access to `elf->shdrs.arr` to avoid the risk
 * of a use-after-free potentially introduced by a future `realloc`.
 *
 * Note: The returned pointer should be used and discarded as soon as possible.
 * To refer to a given entry, store its index and use this API to retrieve it
 * whenever necessary.
 *
 * Remember to update the corresponding `dirty` flag, if applicable.
 *
 * @param elf The ELF context. Must not be NULL.
 *
 * @param idx The index of the entry to retrieve.
 *  Must be smaller than `elf->shdrs.num` and not equal `ELF_IDX_NULL`.
 *
 * @return Ephemeral pointer to an entry in `elf->shdrs.arr`
 *  or `NULL` if the index or ELF context are invalid.
 */
Elf64_Shdr * get_shdr_rw(struct elf *elf, elf_idx_t idx);

/**
 * Getter for a read-only reference to an entry in `elf->shdrs`.
 *
 * Use this instead of direct access to `elf->shdrs.arr` to avoid the risk
 * of a use-after-free potentially introduced by a future `realloc`.
 *
 * Note: The returned pointer should be used and discarded as soon as possible.
 * To refer to a given entry, store its index and use this API to retrieve it
 * whenever necessary.
 *
 * @param elf The ELF context. Must not be NULL.
 *
 * @param idx The index of the entry to retrieve.
 *  Must be smaller than `elf->shdrs.num` and not equal `ELF_IDX_NULL`.
 *
 * @return Ephemeral pointer to an entry in `elf->shdrs.arr`
 *  or `NULL` if the index or ELF context are invalid.
 */
const Elf64_Shdr * get_shdr_ro(const struct elf *elf, elf_idx_t idx);

/**
 * Getter for a read-write reference to an entry in `elf->dyn.entries`.
 *
 * Use this instead of direct access to `elf->dyn.entries.arr` to avoid the risk
 * of a use-after-free potentially introduced by a future `realloc`.
 *
 * Note: The returned pointer should be used and discarded as soon as possible.
 * To refer to a given entry, store its index and use this API to retrieve it
 * whenever necessary.
 *
 * Remember to update the corresponding `dirty` flag, if applicable.
 *
 * @param elf The ELF context. Must not be NULL.
 *
 * @param idx The index of the entry to retrieve.
 *  Must be smaller than `elf->dyn.entries.num` and not equal `ELF_IDX_NULL`.
 *
 * @return Ephemeral pointer to an entry in `elf->dyn.entries.arr`
 *  or `NULL` if the index or ELF context are invalid.
 */
Elf64_Dyn * get_dyn_rw(struct elf *elf, elf_idx_t idx);

/**
 * Getter for a read-only reference to an entry in `elf->dyn.entries`.
 *
 * Use this instead of direct access to `elf->dyn.entries.arr` to avoid the risk
 * of a use-after-free potentially introduced by a future `realloc`.
 *
 * Note: The returned pointer should be used and discarded as soon as possible.
 * To refer to a given entry, store its index and use this API to retrieve it
 * whenever necessary.
 *
 * @param elf The ELF context. Must not be NULL.
 *
 * @param idx The index of the entry to retrieve.
 *  Must be smaller than `elf->dyn.entries.num` and not equal `ELF_IDX_NULL`.
 *
 * @return Ephemeral pointer to an entry in `elf->dyn.entries.arr`
 *  or `NULL` if the index or ELF context are invalid.
 */
const Elf64_Dyn * get_dyn_ro(const struct elf *elf, elf_idx_t idx);

/**
 * Destroys an ELF context, freeing any associated resources.
 *
 * @param[in,out] elf The ELF context to destroy.
 */
void destroy_elf(struct elf *elf);

#endif /* CTX_H_ */
