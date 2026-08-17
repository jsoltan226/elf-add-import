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
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @param[in] ehdr The parsed ELF header which contains information
 *  about the offset and size of the program header table.
 *  Must not be NULL.
 *
 * @param[in] shdrs The parsed section headers,
 *  used when `e_phnum == PN_XNUM` (see the ELF spec).
 *  Must not be NULL, although the array inside may theoretically be empty.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @return 0 on success, non-zero on failure.
 */
int read_validate_phdrs(const struct blob *data, struct elf_phdrs *out,
                        const Elf64_Ehdr *ehdr, const struct elf_shdrs *shdrs,
                        int clazz, int encoding);

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
 * @param[out] out Output pointer for the parsed section header table.
 *  Must not be NULL.
 *
 * @param[out] out_shstrndx Output pointer for the real value of shstrndx.
 *  Must not be NULL.
 *
 * @param[in] ehdr The parsed ELF header which contains information
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
int read_validate_shdrs(const struct blob *data,
                        struct elf_shdrs *out, Elf64_Word *out_shstrndx,
                        const Elf64_Ehdr *ehdr, int clazz, int encoding);

/**
 * @brief The main top-level ELF parsing function.
 *
 * Parses and validates ELF file data using the above functions
 * as well as `read_validate_dynamic_section`.
 *
 * @param[in] data The ELF data to parse. Must not be NULL.
 *
 * @param[out] out Output pointer.
 *  Can be NULL, in which case the ELF file is only validated,
 *  without any side effects.
 *  If non-NULL and the function succeeds, it is populated with a
 *  valid `struct elf` and should later be freed with `destroy_elf`.
 *
 * @param[in] move Whether the new ELF context should take ownership of `data`.
 *  If true, `data->arr` must be a malloc'd array of size `data->size`
 *  and it must not be used after this function successfully returns.
 *  If false, a new buffer buffer is allocated for `out`
 *  and `data` is copied into it.
 *
 *  Note: On failure, `data` is NOT invalidated even if `move == true`
 *  and should still be freed manually.
 *
 * @return 0 on success, non-zero on failure.
 */
int parse_elf(struct blob *data, struct elf *out, bool move);

/**
 * Reads an ELF file and parses it using `parses_elf`.
 *
 * @param[in] path The path to the ELF file to load. Must not be NULL.
 *
 * @param out Output pointer.
 *  Can be NULL, in which case the ELF file is read and only validated,
 *  without any side effects.
 *  If non-NULL and the function succeeds, it is populated with a
 *  valid `struct elf` and should later be freed with `destroy_elf`.
 *
 * @return 0 on success, non-zero on failure.
 */
int read_elf(const char *path, struct elf *out);

#endif /* ELF_PARSING_H_ */
