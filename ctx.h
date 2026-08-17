#ifndef CTX_H_
#define CTX_H_

/**
 * @file Everything directly related to the ELF context struct.
 */

#include "elf.h"
#include "util.h"
#include <assert.h>

/**
 * @brief ELF file parsing & patching context.
 *
 * @struct elf
 * Container for all data required to parse, patch and re-serialize
 * an ELF file (any class, any data encoding).
 *
 * Populated by `read_elf` and destroyed with `destroy_elf`.
 */
struct elf {
    /**
     * @struct The ELF ident bytes, organized into a struct.
     * See the ELF spec.
     * Always populated by `read_elf`, but never re-serialized.
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
     * In-memory representation of the parsed ELF header.
     * Parsed by `read_validate_ehdr` and re-serialized by `write_ehdr`.
     * Always populated by `read_elf`.
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
     * Always populated by `read_elf`.
     */
    struct elf_phdrs {
        /**
         * The real number of entries in the array, including any `PN_XNUM`
         * shenanigans.
         */
        Elf64_Xword num;
        Elf64_Phdr *arr; /**< In-memory array of parsed program headers. */
        bool dirty; /**< Dirty flag (see `serialize_elf`). */
    } phdrs; /**< In-memory representation of the program headers. */

    /**
     * Array of parsed section headers (in-memory representation).
     * Since section headers are theoretically optional in `ET_DYN` ELFs,
     * `read_elf` might write an empty array here.
     */
    struct elf_shdrs {
        Elf64_Xword num;
        Elf64_Shdr *arr; /**< In-memory array of parsed section headers. */
        bool dirty;
    } shdrs; /**< In-memory representation of the section headers. */

    /**
     * @brief Everything related to the dynamic section that's relevant here.
     * @struct PT_DYNAMIC segment / SHT_DYNAMIC ".dynamic" section.
     *
     * Because we're working with `ET_DYN` files, this segment is mandatory
     * and this struct will therefore always be populated by `read_elf`,
     * even if there are no section headers.
     */
    struct elf_dynamic {
        /**
         * Array of parsed DT_* dynamic entries (in-memory representation).
         * Always populated
         * */
        struct elf_dyn_entries {
            Elf64_Xword num;
            Elf64_Dyn *arr;
            bool dirty;
        } entries;

        /* Pointer to the PT_DYNAMIC program header (reference into `phdrs`).
         * On success, `read_validate_dynamic_section`
         * will always write a non-NULL value here. */
        Elf64_Phdr *phdr;

        /* Pointer to the SHT_DYNAMIC section header (reference into `shdrs`).
         * `read_validate_dynamic_section` might write NULL here. */
        Elf64_Shdr *shdr;

        /* The value of the DT_STRTAB entry;
         * contains the virtual addres of the .dynamic string table. */
        Elf64_Addr strtab_vaddr;

        /* The offset of the .dynamic string table within the ELF data */
        Elf64_Off strtab_off;

        /* The value of the DT_STRSZ entry;
         * the size of the string table pointed to by `strtab`. */
        Elf64_Xword strtab_sz;

        /* Pointer to the .dynstr section header (reference into `shdrs`).
         * Might be NULL if there's no .dynstr section. */
        Elf64_Shdr *strtab_shdr;
    } dyn; /**< Everything related to the dynamic section */

    /* The raw bytes of the ELF file */
    struct blob data;
};

/**
 * Destroys an ELF context, freeing any associated resources.
 *
 * @param[in,out] elf The ELF context to destroy.
 */
void destroy_elf(struct elf *elf);

#endif /* CTX_H_ */
