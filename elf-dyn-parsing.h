#ifndef ELF_DYN_PARSING_H_
#define ELF_DYN_PARSING_H_

#include "ctx.h"
#include "elf.h"
#include "util.h"

/**
 * Parses the dynamic section of an ELF file.
 * The parsing is done using the PT_DYNAMIC program header,
 * without reliance on the section headers,
 * although if a SHT_DYNAMIC section is found, it will be validated
 * against the PT_DYNAMIC program header.
 *
 * @param data The ELF file data.
 *
 * @param clazz The ELF file class (ELFCLASS32 or ELFCLASS64).
 *
 * @param encoding The ELF file data encoding (ELFDATA2MSB or ELFDATA2LSB).
 *
 * @param phdrs Array of parsed and validated program headers. Must not be NULL.
 *
 * @param shdrs Array of parsed and validated section haeders. Must not be NULL.
 *
 * @param out_entries Output pointer.
 *  May be NULL, in which case it simply won't be written to
 *  and the resources will be freed automatically.
 *
 * @return 0 on success (valid PT_DYNAMIC phdr),
 *  non-zero on failure (invalid or non-existent PT_DYNAMIC phdr,
 *                       present but invalid SHT_DYNAMIC shdr).
 */
int read_validate_dynamic_section(
        const struct blob *data, int clazz, int encoding,
        struct elf_phdrs *phdrs, struct elf_shdrs *shdrs,

        struct elf_dynamic *out
);

/**
 * Validates a PT_DYNAMIC program header.
 * Part of `read_validate_dynamic_section`.
 *
 * @param pt_dynamic The PT_DYNAMIC program header. Must not be NULL.
 *
 * @param entsize Size of an ElfXX_Dyn entry (depends on the ELF's class).
 *
 * @return 0 on success, non-zero on failure.
 */
int validate_pt_dynamic(const Elf64_Phdr *pt_dynamic, size_t entsize);

/**
 * Validates a SHT_DYNAMIC section header.
 * Part of `read_validate_dynamic_section`.
 *
 * @param sht_dynamic The SHT_DYNAMIC section header to validate.
 *  Must not be NULL.
 *
 * @param pt_dynamic The previously checked PT_DYNAMIC program header,
 *  against which @sht_dynamic is to be validated. Must not be NULL.
 *
 * @param entsize Size of an ElfXX_Dyn entry (depends on the ELF's class).
 *
 * @return 0 on success, non-zero on failure.
 */
int validate_sht_dynamic(const Elf64_Shdr *sht_dynamic,
                         const Elf64_Phdr *pt_dynamic, size_t entsize);

/**
 * Parses and validates the array of dynamic entries
 * pointed to by a PT_DYNAMIC program header.
 * Part of `read_validate_dynamic_section`.
 *
 * @param data The ELF file's data. Must not be NULL.
 *
 * @param clazz The ELF file's class.
 *
 * @param encoding The ELF file's byte order.
 *
 * @param count Number of dynamic entries.
 *
 * @param pt_dynamic The previously validated PT_DYNAMIC program header.
 *  Must not be NULL.
 *
 * @param Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int parse_dyn_array(const struct blob *data, int clazz, int encoding,
                    Elf64_Xword count, const Elf64_Phdr *pt_dynamic,
                    Elf64_Dyn **out);

/**
 * Finds and validates a .dynstr section header
 * corresponding to data found in the program headers.
 *
 * @param shdrs The section header array.
 *  The array is not modified by this function.
 *
 * @param shnum The number of section headers.
 *
 * @param addr Virtual address of the dynamic string table
 *  (the value of DT_STRTAB).
 *
 * @param off Offset withing the ELF file of the dynamic string table.
 *
 * @param size Size of the dynamic string table (the value of DT_STRSZ).
 *
 * @param out Output pointer for the found valid .dynstr section header.
 *  On success it will either contain a reference into `shdrs`
 *  or NULL (if there's no .dynstr section).
 *
 * @return 0 on success, non-zero on failure.
 */
int find_validate_strtab_shdr(Elf64_Shdr *shdrs, Elf64_Xword shnum,
                              Elf64_Addr addr, Elf64_Off off,
                              Elf64_Xword size, Elf64_Shdr **out);

#endif /* ELF_DYN_PARSING_H_ */
