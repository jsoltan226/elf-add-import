#ifndef ELF_TYPES_H_
#define ELF_TYPES_H_

/**
 * @file Utilities for serializing and de-serialializing
 * ELF primitive types and structures.
 */

#include "elf.h"
#include "util.h"
#include <stdint.h>

/** PRIMITIVE TYPES **/

/* Whether the type only has an ELF64 variant
 * (e.g. Elf64_Xword; Elf32_Xword doesn't exist) */
#define exclusive_64bit
#define no_exclusive_64bit

/* Whether the underlying type for both the ELF32 and ELF64 variants
 * is the same (e.g. Elf64_Half and Elf32_Half are both uint16_t) */
#define same_size
#define different_size

#define ELF_PRIMITIVE_FN_LIST                                           \
    DECL_ELF_PRIMITIVE_FN(Half, 16, 16, uint, UINT16, UINT16,           \
                          no_exclusive_64bit, same_size)                \
    DECL_ELF_PRIMITIVE_FN(Word, 32, 32, uint, UINT32, UINT16,           \
                          no_exclusive_64bit, same_size)                \
    DECL_ELF_PRIMITIVE_FN(Off, 32, 64, uint, UINT32, UINT64,            \
                          no_exclusive_64bit, different_size)           \
    DECL_ELF_PRIMITIVE_FN(Addr, 32, 64, uint, UINT32, UINT64,           \
                          no_exclusive_64bit, different_size)           \
    DECL_ELF_PRIMITIVE_FN(Xword, 64, 64, uint, UINT64, UINT64,          \
                          exclusive_64bit, same_size)                   \
                                                                        \
    /** WARNING: for signed types there's no automatic checking         \
     ** for underflow of the Elf32 version of the type **/              \
                                                                        \
    DECL_ELF_PRIMITIVE_FN(Sword, 32, 32, int, INT32, INT32,             \
                          no_exclusive_64bit, same_size)                \
    DECL_ELF_PRIMITIVE_FN(Sxword, 64, 64, int, INT64, INT64,            \
                          exclusive_64bit, same_size)                   \


#define DECL_ELF_PRIMITIVE_FN(elf_type, bits32, bits64,                 \
                              t_prefix, prefix32, prefix64,             \
                              exclusive_64__, same_size__)              \
                                                                        \
/**                                                                            \
 * Parses an ELF primitive type to the generic in-memory representation.       \
 *                                                                             \
 * @param[in] data The data to read from. Must not be NULL.                    \
 *                                                                             \
 * @param[in,out] off_p A pointer to the offset at which to read.              \
 *  This value will be incremented to point past the read data.                \
 *  Must not be NULL.                                                          \
 *                                                                             \
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).  \
 *                                                                             \
 * @param[in] encoding The data encoding (endianness) of the ELF file          \
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).                                          \
 *                                                                             \
 * @param[out] out Output pointer. Must not be NULL.                           \
 *                                                                             \
 * @return 0 on success, non-zero if the data is outside of buffer bounds.     \
 */                                                                            \
int read_##elf_type(const struct blob *data, uint64_t *off_p,           \
                    int clazz, int encoding,                            \
                    Elf64_##elf_type *out);                             \
                                                                        \
/**                                                                            \
 * Serializes an ELF primitive type to the given class and data encoding.      \
 *                                                                             \
 * @param[out] data The data to write into. Must not be NULL.                  \
 *                                                                             \
 * @param[in,out] off_p A pointer to the offset at which to write.             \
 *  This value will be incremented to point past the newly written data.       \
 *  Must not be NULL.                                                          \
 *                                                                             \
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).  \
 *                                                                             \
 * @param[in] encoding The data encoding (endianness) of the ELF file          \
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).                                          \
 *                                                                             \
 * @param[in] val The in-memory primitive value to serialize.                  \
 *                                                                             \
 * @return 0 on success, non-zero if the serialized `val` can't fit in `data`  \
 *  or `clazz` is `ELFCLASS32` and `val` overflows the Elf32 equivalent type.  \
 */                                                                            \
int write_##elf_type(struct blob *data, uint64_t *off_p,                \
                     int clazz, int endianness,                         \
                     Elf64_##elf_type val);                             \

ELF_PRIMITIVE_FN_LIST

#undef DECL_ELF_PRIMITIVE_FN
#undef exclusive_64bit
#undef no_exclusive_64bit
#undef same_size
#undef different_size

/** ELF STRUCTURES **/

/* The `read_ehdr` function is directly a part of `read_validate_ehdr` */

/**
 * Serializes an ELF header structure to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[in] ehdr The in-memory ELF header to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `ehdr` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_ehdr(struct blob *data, uint64_t *off_p,
               int clazz, int encoding, const Elf64_Ehdr *ehdr);

/**
 * Parses a program header structure to the generic in-memory representation.
 * The fields' values are not validated to be sensible and spec-compliant.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_phdr(const struct blob *data, uint64_t *off_p,
              int clazz, int encoding, Elf64_Phdr *out);

/**
 * Serializes a program header structure to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[in] phdr The in-memory program header to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `phdr` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_phdr(struct blob *data, uint64_t *off_p,
               int clazz, int encoding, const Elf64_Phdr *phdr);

/**
 * Parses a section header structure to the generic in-memory representation.
 * The fields' values are not validated to be sensible and spec-compliant.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_shdr(const struct blob *data, uint64_t *off_p,
              int clazz, int encoding, Elf64_Shdr *out);

/**
 * Serializes a section header structure to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[in] shdr The in-memory section header to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `shdr` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_shdr(struct blob *data, uint64_t *off_p,
              int clazz, int encoding, const Elf64_Shdr *shdr);

/**
 * Parses a dynamic entry structure to the generic in-memory representation.
 * The fields' values are not validated to be sensible and spec-compliant.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_dyn(const struct blob *data, uint64_t *off_p,
             int clazz, int encoding, Elf64_Dyn *out);

/**
 * Serializes a dynamic entry structure to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] clazz The class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] encoding The data encoding (endianness) of the ELF file
 *  (`ELFDATA2MSB` or `ELFDATA2LSB`).
 *
 * @param[in] dyn The in-memory dynamic entry to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `dyn` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_dyn(struct blob *data, uint64_t *off_p,
              int clazz, int encoding, const Elf64_Dyn *dyn);

/**
 * Returns a string with the name of the ET_* ELF type
 * corresponding to the integer value `et` or "(unknown)" if one isn't found.
 * Never returns NULL.
 */
const char * elf_type_toString(Elf64_Half et);

/**
 * Returns a string with the name of the SHT_* section header type
 * corresponding to the integer value `sht` or "(unknown)" if one isn't found.
 * Never returns NULL.
 */
const char * section_type_toString(Elf64_Word sht);

/**
 * Returns a string with the name of the DT_* dynamic entry type
 * corresponding to the integer value `dt` or "(unknown)" if one isn't found.
 * Never returns NULL.
 */
const char * dynamic_tag_to_string(Elf64_Sxword dt);

#endif /* ELF_TYPES_H_ */
