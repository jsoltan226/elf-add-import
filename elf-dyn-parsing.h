#ifndef ELF_DYN_PARSING_H_
#define ELF_DYN_PARSING_H_

/**
 * @file Dynamic section parsing module,
 *  separated from `elf-parsing` due to complexity.
 */

#include "ctx.h"
#include "elf.h"
#include "util.h"

/**
 * Parses the dynamic section of an ELF file.
 * The parsing is done using only the PT_DYNAMIC program header
 * (without relying on the section headers),
 * but if a SHT_DYNAMIC section is found it will be checked
 * against the data in the PT_DYNAMIC program header.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] clazz The ELF file class (ELFCLASS32 or ELFCLASS64).
 *
 * @param[in] encoding The ELF file data encoding (ELFDATA2MSB or ELFDATA2LSB).
 *
 * @param[in] phdrs Array of parsed and validated program headers.
 *  Must not be NULL.
 *
 * @param[in] shdrs Array of parsed and validated section haeders.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer.
 *  May be NULL, in which case it simply won't be written to
 *  and all allocated resources will be freed automatically.
 *
 * @param[out] out_dynentsize Output pointer for the size of a dynamic entry
 *  (`sizeof(Elf32_Dyn)` for 32-bit or `sizeof(Elf64_Dyn)` for 64-bit).
 *  May be NULL, in which case it simply won't be written to.
 *
 * @return 0 on success (valid PT_DYNAMIC phdr),
 *  non-zero on failure (invalid or non-existent PT_DYNAMIC phdr,
 *                       present but invalid SHT_DYNAMIC shdr).
 */
int read_validate_dynamic_section(
        const struct blob *data, int clazz, int encoding,
        struct elf_phdrs *phdrs, struct elf_shdrs *shdrs,

        struct elf_dynamic *out, Elf64_Half *out_dynentsize
);

/**
 * Validates a PT_DYNAMIC program header.
 * Part of `read_validate_dynamic_section`.
 *
 * @param[in] pt_dynamic The PT_DYNAMIC program header. Must not be NULL.
 *
 * @param[in] entsize Size of an ElfXX_Dyn entry (depends on the ELF's class).
 *
 * @return 0 on success, non-zero on failure.
 */
int validate_pt_dynamic(const Elf64_Phdr *pt_dynamic, size_t entsize);

/**
 * Validates a SHT_DYNAMIC section header.
 * Part of `read_validate_dynamic_section`.
 *
 * @param[in] sht_dynamic The SHT_DYNAMIC section header to validate.
 *  Must not be NULL.
 *
 * @param[in] pt_dynamic The previously checked PT_DYNAMIC program header,
 *  against which @sht_dynamic is to be validated. Must not be NULL.
 *
 * @param[in] entsize Size of an ElfXX_Dyn entry (depends on the ELF's class).
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
 * @param[in] data The ELF file's data. Must not be NULL.
 *
 * @param[in] clazz The ELF file's class.
 *
 * @param[in] encoding The ELF file's byte order.
 *
 * @param[in] count Number of dynamic entries.
 *
 * @param[in] pt_dynamic The previously validated PT_DYNAMIC program header.
 *  Must not be NULL.
 *
 * @param[out] out_arr Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int parse_dyn_array(const struct blob *data, int clazz, int encoding,
                    Elf64_Xword count, const Elf64_Phdr *pt_dynamic,
                    Elf64_Dyn **out_arr);

/**
 * Finds and validates a .dynstr section header
 * corresponding to data found in the program headers.
 *
 * @param[in] shdrs The section header array. Not modified by this function.
 *
 * @param[in] shnum The number of section headers.
 *
 * @param[in] addr Virtual address of the dynamic string table
 *  (the value of DT_STRTAB).
 *
 * @param[in] off Offset withing the ELF file of the dynamic string table.
 *
 * @param[in] size Size of the dynamic string table (the value of DT_STRSZ).
 *
 * @param[out] out Output pointer for the found valid .dynstr section header's
 *  index. On success it will either contain a reference into `shdrs`
 *  or `ELF_IDX_NULL` (if there's no .dynstr section).
 *
 * @return 0 on success, non-zero on failure.
 */
int find_validate_strtab_shdr(Elf64_Shdr *shdrs, Elf64_Xword shnum,
                              Elf64_Addr addr, Elf64_Off off,
                              Elf64_Xword size, elf_idx_t *out);

#endif /* ELF_DYN_PARSING_H_ */
