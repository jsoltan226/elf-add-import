#ifndef ELF_PATCHING_H_
#define ELF_PATCHING_H_

/**
 * @file Functions for updating/patching more complex ELF structures
 *  and everything that depends on them.
 */

#include "elf.h"
#include "ctx.h"

/**
 * Resizes the program header array to the desired size
 * and updates the appropriate metadata.
 * Does **NOT** copy, move, erase or otherwise modify any data in `elf->data`.
 *
 * If growing, the new phdr entries are zeroed out.
 * Resizing to 0 is not supported.
 *
 * @param[in,out] elf The ELF context to update. Must not be NULL.
 *
 * @param[in] new_phnum Desired new count of program headers.
 *  Must be greater than zero, because otherwise the program headers
 *  would have to be removed altogether which we don't support.
 *
 * @return 0 on success, non-zero on failure.
 */
int update_phnum(struct elf *elf, Elf64_Xword new_phnum);

/**
 * Updates the program header table offset in the ELF header,
 * as well as all other relevant metadata.
 * Does **NOT** copy, move, erase or otherwise modify any data in `elf->data`.
 *
 * Note: If also resizing the table, be sure to call `update_phnum` **BEFORE**
 *  `update_phoff` as the bounds checks in this function rely on the
 *  current size of `elf->phdrs`.
 *
 * @param[in,out] elf The ELF context to update. Must not be NULL.
 *
 * @param[in] new_off The desired new offset of the program header table.
 *  Must reside within an existing PT_LOAD segment.
 *
 * @return 0 on success, non-zero on failure.
 */
int update_phoff(struct elf *elf, Elf64_Off new_off);

/**
 * Resizes the section header array to the desired size
 * and updates the appropriate metadata.
 * Does **NOT** copy, move, erase or otherwise modify any data in `elf->data`.
 *
 * If growing, the new shdr entries are zeroed out.
 * Resizing to 0 is not supported.
 *
 * @param[in,out] elf The ELF context to update. Must not be NULL.
 *
 * @param[in] new_shnum Desired new count of section headers.
 *  Must be greater than zero, because otherwise the section headers
 *  would have to be removed altogether which we don't support.
 *
 * @return 0 on success, non-zero on failure.
 */
int update_shnum(struct elf *elf, Elf64_Xword new_shnum);

/**
 * Updates the section header table offset in the ELF header,
 * as well as all other relevant metadata.
 * Does **NOT** copy, move, erase or otherwise modify any data in `elf->data`.
 *
 * Note: If also resizing the table, be sure to call `update_shnum` **BEFORE**
 *  `update_shoff` as the bounds checks in this function rely on the
 *  current size of `elf->shdrs`.
 *
 * @param[in,out] elf The ELF context to update. Must not be NULL.
 *
 * @param[in] new_off The desired new offset of the section header table.
 *  Must reside within an existing PT_LOAD segment.
 *
 * @return 0 on success, non-zero on failure.
 */
int update_shoff(struct elf *elf, Elf64_Off new_off);

/**
 * Updates the section header string table index
 * as well as any additional metadata, if required.
 * Does **NOT** copy, move, erase or otherwise modify any data in `elf->data`.
 *
 * @param[in,out] elf The ELF context to update. Must not be NULL.
 *
 * @param[in] new_shstrndx The desired value of
 *  the index of the shdr strtab section.
 *  Note: the value `0` means that there is no shdr strtab section.
 *
 * @return 0 on success, non-zero on failure.
 *  Note: For `val` < `SHN_LORESERVE`, this function always succeeds.
 */
int update_shstrndx(struct elf *elf, Elf64_Word new_shstrndx);

/**
 * Updates the DT_STRTAB and DT_STRSZ entries which hold the values
 * for the .dynstr dynamic string table virtual address and size, respectively.
 * Does **NOT** copy, move, erase or otherwise modify any data in `elf->data`.
 *
 * This function also handles the automatic updating of the ".dynstr" section
 * in the section headers, if one is found.
 * All other relevant metadata in `elf` is also handled.
 *
 * Note: The provided range must be contained in a PT_LOAD segment
 *  already present in `elf`.
 *
 * @param[in,out] elf The ELF context to update. Must not be NULL.
 *
 * @param[in] new_addr The new value of DT_STRTAB
 *  (virtual address of the .dynstr dynamic string table).
 *
 * @param[in] new_size The new value of DT_STRSZ
 *  (size of the .dynstr dynamic string table).
 *
 * @return 0 on success, non-zero on failure.
 */
int update_dynstr_range(struct elf *elf,
                        Elf64_Addr new_addr, Elf64_Xword new_size);

/**
 * Updates the number of dynamic entries (resizes the array).
 * If growing, the new entries are zeroed out, making their type `DT_NULL`.
 * Does **NOT** copy, move, erase or otherwise modify any data in `elf->data`.
 *
 * Note: If also moving the table, be sure to call `update_dyn_tbl_off`
 *  **BEFORE** `update_dyn_tbl_num` as the bounds checks in this function
 *  rely on the current offset & vaddr of the _DYNAMIC table.
 *
 * @param[in,out] elf The ELF context to update. Must not be NULL.
 *
 * @param[in] new_dynnum The desired new number of DT_* dynamic entries.
 *
 * @return 0 on success, non-zero on failure.
 */
int update_dyn_tbl_num(struct elf *elf, Elf64_Xword new_dynnum);

/**
 * Updates the offset (location) of the dynamic entries array.
 * Does **NOT** copy, move, erase or otherwise modify any data in `elf->data`.
 *
 * @param[in,out] elf The ELF context to update. Must not be NULL.
 *
 * @param[in] new_off The desired new file offset of the DYNAMIC table.
 *  The offset must account for the fact that the dynamic table
 *  must wholly reside within an existing PT_LOAD segment.
 *
 * @return 0 on success, non-zero on failure.
 */
int update_dyn_tbl_off(struct elf *elf, Elf64_Off new_off);

/**
 * @func
 * A function that serializes an ELF structure, like ElfXX_Phdr, ElfXX_Dyn, etc,
 *  from the generic in-memory representation
 *  to the desired class (32/64bit) and encoding (little/big endian).
 *
 * @param[out] out The data to write into.
 *
 * @param[in,out] off_p Non-null
 *  Pointer to the offset within `out` at which to start serializing.
 *  On success, the function should increment this offset
 *  to point past the written bytes.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[in] data A pointer to an instance of the in-memory representation
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
 * @param[in] reset_dirty_flags Whether to reset all the previously set `dirty`
 *  flags to `false` after serialization.
 *
 * @return 0 on success, non-zero on failure.
 */
int serialize_elf(struct elf *elf, bool reset_dirty_flags);

#endif /* ELF_PATCHING_H_ */
