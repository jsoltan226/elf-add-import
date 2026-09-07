#ifndef CTX_H_
#define CTX_H_

/**
 * @file Everything directly related to the ELF context struct.
 */

#include "elf.h"
#include "util.h"
#include <assert.h>

/**
 * @type Used to refer to entries in arrays of in-memory ELF structures,
 * such as the program and section headers and the dynamic entries.
 */
typedef Elf64_Xword elf_idx_t;

/** Sentinel value for `elf_idx_t` which indicates that an index is invalid. */
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
        uint8_t clazz;      /**< `EI_CLASS`; `ELFCLASS32` or `ELFCLASS64` */
        uint8_t data;       /**< `EI_DATA`; `ELFDATA2MSB` or `ELFDATA2LSB` */
        uint8_t version;    /**< `EI_VERSION`; `EV_CURRENT` i.e. `1` */
        uint8_t os_abi;     /**< `EI_OSABI`; OS ABI. Unused here. */
        uint8_t abi_version; /**< `EI_OSABIVERSION`; Unused here. */

        uint8_t pad_[7];    /**< `EI_PAD`; Padding bytes, set to 0 & ignored. */
    } __attribute__((packed)) ident; /**< ELF ident bytes. */
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
     * (either `sizeof(Elf32_Dyn)` for 32-bit or `sizeof(Elf64_Dyn) for 64-bit).
     */
    Elf64_Half dynentsize;

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
     * Because we're working with `ET_DYN` files, this segment is mandatory
     * and this struct will therefore always be populated by `parse_elf`,
     * even if there are no section headers.
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

        /* The value of the DT_STRTAB entry;
         * contains the virtual addres of the .dynamic string table. */
        Elf64_Addr strtab_vaddr;

        /* The offset of the .dynamic string table within the ELF data */
        Elf64_Off strtab_off;

        /* The value of the DT_STRSZ entry;
         * the size of the string table pointed to by `strtab`. */
        Elf64_Xword strtab_sz;

        /* Index of the .dynstr section header (reference into `shdrs`).
         * Might be NULL if there's no .dynstr section. */
        elf_idx_t strtab_shdr;
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
