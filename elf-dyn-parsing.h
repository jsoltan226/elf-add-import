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
 * @brief Parses .dynamic and all related sections.
 *
 * The parsing is done using only the PT_DYNAMIC program headers
 * (without relying on the section headers),
 * but if section headers are present they will be checked
 * against the data in the phdrs.
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
 * @return 0 on success (valid dynamic linking data),
 *  non-zero on failure (invalid or non-existent dynamic linking data).
 */
int parse_dyn(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,

        struct elf_dynamic *out, Elf64_Half *out_dynentsize
);


int parse_dynsym(const struct blob *data, int clazz, int encoding,
                 const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
                 const struct elf_dyn_entries *entries);

#endif /* ELF_DYN_PARSING_H_ */
