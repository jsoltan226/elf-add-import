#ifndef CTX_H_
#define CTX_H_

#include "elf.h"
#include "util.h"
#include <assert.h>

/* Container for all data required to parse, patch and re-serialize
 * an ELF file (any class, any data encoding).
 *
 * Populated by `read_elf` and destroyed with `destroy_elf`. */
struct elf {
    struct elf_ident {
        uint8_t magic[SELFMAG]; /* 0x7f 'E' 'L' 'F' */
        uint8_t clazz;
        uint8_t data; /* endianness */
        uint8_t version;
        uint8_t os_abi;
        uint8_t abi_version;

        uint8_t pad_[7];
    } __attribute__((packed)) ident;
    static_assert(sizeof(struct elf_ident) == EI_NIDENT, "Invalid size");

    /* Parsed ELF header */
    Elf64_Ehdr ehdr;
    bool ehdr_dirty;

    /* If section headers are present, index into `shdrs.arr`
     * where the section header string table is */
    Elf64_Word shstrndx;

    /* Array of parsed program headers */
    struct elf_phdrs {
        Elf64_Xword num;
        Elf64_Phdr *arr;
        bool dirty;
    } phdrs;

    /* Array of parsed section headers */
    struct elf_shdrs {
        Elf64_Xword num;
        Elf64_Shdr *arr;
        bool dirty;
    } shdrs;

    /* Everything related to the dynamic section
     * (PT_DYNAMIC segment / SHT_DYNAMIC ".dynamic" section) */
    struct elf_dynamic {
        /* Array of the parsed DT_* Elf64_Dyn entries */
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
    } dyn;

    /* The raw bytes of the ELF file */
    struct blob data;
};

void destroy_elf(struct elf *elf);

#endif /* CTX_H_ */
