#ifndef ELF_PARSING_H_
#define ELF_PARSING_H_

/**
 * @file Utitlies for parsing various ELF structs.
 * These functions read the raw bytes and convert them into the generic
 * in-memory representation (64-bit variant, host byte order).
 */

#include "elf.h"
#include "ctx.h"
#include "util.h"

/**
 * @brief Reads, parses and validates an ELF header (ehdr).
 *
 * @param[in] data The buffer to read from.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[in] out Output pointer.
 *  If NULL, only validation is performed without writing anything.
 *
 * @return 0 on success, non-zero on failure.
 */
int read_validate_ehdr(const struct blob *data, int clazz, int encoding,
                       Elf64_Ehdr *out);

/**
 * Reads, parses and validates the program header table (phdrs).
 *  Note: Since this code is used in the context of `ET_DYN` ELFs
 *  (dynamic exeutables/shared objects), the program header table must exist
 *  and it missing is considered an error.
 *
 * @param[in] data The buffer to read from. Must not be NULL.
 *
 * @param[out] out Output pointer.
 *  If NULL, only validation will be performed without writing anything.
 *
 * @param[in] ehdr The parsed ELF header which contains information
 *  about the offset and size of the program header table.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @return 0 on success, non-zero on failure.
 */
int read_validate_phdrs(const struct blob *data, struct elf_phdrs *out,
                        const Elf64_Ehdr *ehdr, int clazz, int encoding);

/**
 * @brief Reads, parses and validates the section header table (shdrs).
 *
 * Note: Since this code is used in the context of `ET_DYN` ELFs
 * (dynamic exeutables/shared objects), the section header table
 * is theoretically optional and might not exist at all
 * (though in practice that's very rare). In such situation,
 * a warning will be printed and `out` will contain
 * a NULL array of size 0.
 *
 * @param[in] data The buffer to read from. Must not be NULL.
 *
 * @param[out] out Output pointer.
 *  If NULL, only validation is performed without writing anything.
 *
 * @param[in]  ehdr The parsed ELF header which contains information
 *  about the offset and size of the section header table.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @return 0 on success, non-zero on failure.
 */
int read_validate_shdrs(const struct blob *data, struct elf_shdrs *out,
                        const Elf64_Ehdr *ehdr, int clazz, int encoding);

/**
 * @brief The main top-level ELF parsing function.
 *
 * Reads, parses and validates an ELF file located at `path`,
 * using the above functions as well as `read_validate_dynamic_section`.
 *
 * @param[in] path The path to the ELF file to load. Must not be NULL.
 *
 * @param out Output pointer.
 *  Can be NULL, in which case the ELF file is only validated,
 *  without any side effects.
 *  If non-NULL and the function succeeds, it is populated with a
 *  valid `struct elf` and should later be freed with `destroy_elf`.
 *
 * @return 0 on success, non-zero on failure.
 */
int read_elf(const char *path, struct elf *out);

#endif /* ELF_PARSING_H_ */
