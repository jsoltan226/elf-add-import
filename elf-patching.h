#ifndef ELF_PATCHING_H_
#define ELF_PATCHING_H_

/**
 * @file Functions for updating/patching more complex ELF structures
 *  and everything that depends on them etc.
 */

#include "elf.h"
#include "ctx.h"

/**
 * Resizes the program header array to the desired size
 * and updates the appropriate metadata.
 *
 * @param phdrs A pointer to the program headers array to resize.
 *
 * @param new_size Desired new count of program headers.
 *  Must be greater than zero, because otherwise the program headers
 *  would have to be removed altogether, which would require
 *  `e_phoff` be set to `0` which is out of the scope of this function.
 *
 * @param out_ehdr_e_phnum_p Output pointer for the new value
 *  of an `Elf64_Ehdr`'s `e_phnum` field (this might be different
 *   than the real array size, see the ELF spec).
 *
 * @param shdrs Section headers array.
 *  Only relevant for `new_size` >= `PN_XNUM` (2^16 - 1 (0xffff)).
 *  In that case, the first section header's `sh_info` will contain the new size
 *  while the ELF header's `e_phnum` will be set to `PN_XNUM`.
 *  Otherwise it is ignored and can be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int update_phnum(struct elf_phdrs *phdrs, Elf64_Xword new_size,
                 Elf64_Half *out_ehdr_e_phnum_p, struct elf_shdrs *shdrs);

/**
 * Resizes the section header array to the desired size
 * and updates the appropriate metadata.
 *
 * @param shdrs A pointer to the section headers array to resize.
 *
 * @param new_size Desired new count of section headers.
 *  Must be greater than zero, because otherwise the section headers
 *  would have to be removed altogether, which would require
 *  `e_shoff` be set to `0` which is out of the scope of this function.
 *
 * @param out_ehdr_e_shnum_p Output pointer for the new value
 *  of an `Elf64_Ehdr`'s `e_shnum` field (this might be different
 *   than the real array size, see the ELF spec).
 *
 * @return 0 on success, non-zero on failure.
 */
int update_shnum(struct elf_shdrs *shdrs, Elf64_Xword new_size,
                 Elf64_Half *out_ehdr_e_shnum_p);

/**
 * Updates the section header string table index
 * as well as any additional metadata, if required.
 *
 * @param val The desired value of the index of the shdr strtab section.
 *  Note: the value `0` means that there's no shdr strtab section.
 *
 * @param out Output pointer. Will contain `val` on success.
 *
 * @param shdrs Section headers array.
 *  Only relevant for `val` >= `SHN_LORESERVE` (2^16 - 256 (0xff00)).
 *  In that case, the first section header's `sh_link` will contain the new size
 *  while the ELF header's `e_shstrndx` will be set to `SHN_XINDEX`.
 *  Otherwise ignored and can be set to `NULL`.
 *
 * @return 0 on success, non-zero on failure.
 *  Note: For `val` < `SHN_LORESERVE`, this function always succeeds.
 */
int update_shstrndx(Elf64_Word val, Elf64_Word *out,
                    Elf64_Half *out_ehdr_shstrndx_p, struct elf_shdrs *shdrs);

/**
 * @func
 * A function that serializes a data type, like ElfXX_Phdr, ElfXX_Dyn, etc.
 *
 * @param out Non-null The data to write into.
 *
 * @param off_p Non-null
 *  Pointer to the offset within `out` at which to start serializing.
 *  On success, the function should increment this offset
 *  to point past the written bytes.
 *
 * @param clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param data A pointer to an instance of the in-memory representation
 *  of the data type to serialize (e.g. `Elf64_Shdr`).
 *
 * @return 0 on success, non-zero on failure.
 */
typedef int (*serializer_proc_t)(struct blob *out, uint64_t *off_p,
                                 int clazz, int encoding, const void *data);

/**
 * @brief Serializes an array of entries (e.g. program headers, dynamic entries, etc)
 * using a serializer function.
 *
 * @param[in,out] data The buffer to write into.
 *  Must be large enough to acommodate the serialized data
 *  (`data->size >= off + (fileentsize * cnt)`).
 *  Must not be NULL.
 *
 * @param[in] serializer The function that performs the serialization
 *  of a single array member. See `serializer_proc_t`. Must not be NULL.
 *
 * @param[in] arr The array of in-memory entries to serialize.
 *  Must not be NULL if `cnt > 0`.
 *
 * @param[in] mementsize The size of each individual in-memory entry
 *  of `arr` i.e. the size of the type.
 *
 * @param[in] fileentsize The size of the serialized type
 *  (e.g. Elf32_Dyn, Elf64_Phdr, etc); depends on the ELF's class.
 *
 * @param[in] off The offset into `data` at which to start writing.
 *
 * @param[in] cnt The number of entries in `arr` (the array size).
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @return 0 on success, non-zero on failure.
 */
int serialize_arr(struct blob *data, serializer_proc_t serializer,
                  const void *arr, size_t mementsize, Elf64_Half fileentsize,
                  uint64_t off, Elf64_Xword cnt, int clazz, int encoding);

/**
 * @brief Re-serializes all relevant potentially modified ELF structures.
 *
 * Uses the above `serialize_arr` to serialize any of the following:
 *  - Program headers (phdrs),
 *  - Section headers (shdrs),
 *  - Dynamic entries (dyn.entries)
 *
 * as well as `write_ehdr` to serialize the ELF header.
 *
 * Serialization is only done if the corresponding `dirty` flags are set.
 *
 * @param[in,out] elf The ELF context which contains the data to serialize
 *  as well as the buffer to write into.
 *
 * @return 0 on success, non-zero on failure.
 */
int serialize_elf(struct elf *elf);

#endif /* ELF_PATCHING_H_ */
