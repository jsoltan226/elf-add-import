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
 * Note: Due to the requirement that `data->clazz` and `data->encoding` be set
 * one must first parse the ELF identification bytes to obtain their values.
 *
 * @param[in] data The ELF file data to read from,
 *  including the ELF class and data encoding.
 *
 * @param[in] out Output pointer.
 *  If NULL, only validation is performed without writing anything.
 *
 * @return 0 on success, non-zero on failure.
 */
int read_validate_ehdr(const ElfFileData *data, Elf64_Ehdr *out);

/**
 * Reads, parses and validates the program header table (phdrs).
 *  Note: Since this code is used in the context of `ET_DYN` ELFs
 *  (dynamic exeutables/shared objects), the program header table must exist
 *  and it missing is considered an error.
 *
 * @param[in] data The ELF file data to read from.
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
 * @return 0 on success, non-zero on failure.
 */
int read_validate_phdrs(const ElfFileData *data, struct elf_phdrs *out,
                        const Elf64_Ehdr *ehdr, const struct elf_shdrs *shdrs);

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
 * Another note: this function leaves out the check that confirms
 * that every section that exists in both the file and memory views,
 * is contained within some PT_LOAD segment and that they hold
 * to the same bytes both in memory and in the file,
 * as that check needs to be done after parsing the program headers.
 * That task is therefore delegated to `validate_shdr_mappings`.
 *
 * @param[in] data The ELF file data to read from.
 *
 * @param[out] out Output pointer for the parsed section header table.
 *  Must not be NULL.
 *
 * @param[in] ehdr The parsed ELF header which contains information
 *  about the offset and size of the section header table.
 *  Must not be NULL.
 *
 * @param[out] out_shstrndx Output pointer for the real value of shstrndx.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int read_validate_shdrs(const ElfFileData *data, struct elf_shdrs *out,
                        const Elf64_Ehdr *ehdr, Elf64_Word *out_shstrndx);

/**
 * Checks that every section that occupies space both in the file
 * and in memory (`sh_type != SHT_NOBITS && sh_flags & SHF_ALLOC`)
 * is contained within a PT_LOAD segment and that
 * both the file and memory views describe the same bytes
 * (`shdr->sh_addr - PT_LOAD->sh_addr == shdr->sh_offset - PT_LOAD->sh_offset`).
 *
 * This function is separate from `read_validate_shdrs` due to the dependency
 * on the program headers, which are parsed before the section headers.
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int validate_shdr_mappings(const struct elf_phdrs *phdrs,
                           const struct elf_shdrs *shdrs);

/**
 * @brief The main top-level ELF parsing function.
 *
 * Parses and validates ELF file data using the above functions
 * as well as `read_validate_dynamic_section`.
 *
 * @param[in] buf The data buffer to read from. Must not be NULL.
 *  Note: Despite the pointer being read-write, it is not written
 *  to at any point by this routine.
 *  If `move` is `true` and the function succeeds, `out` takes ownership
 *  of this pointer and it should not be used further.
 *
 * @param[in] size Size of `buf`.
 *
 * @param[out] out Output pointer.
 *  Can be NULL, in which case the ELF file is only validated,
 *  without any side effects.
 *  If non-NULL and the function succeeds, it is populated with a
 *  valid `struct elf` and should later be freed with `destroy_elf`.
 *
 * @param[in] move Whether the new ELF context should take ownership of `data`.
 *  If true, `buf` must be a malloc'd array of size `size`
 *  and it must not be used after this function successfully returns.
 *  If false, a new buffer buffer is allocated for `out`
 *  and `buf` is copied into it.
 *
 *  Note: On failure, `data` is NOT invalidated even if `move == true`
 *  and should still be freed manually.
 *
 * @return 0 on success, non-zero on failure.
 */
int parse_elf(uint8_t *buf, uint64_t size, struct elf *out, bool move);

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
