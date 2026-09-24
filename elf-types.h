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

/**
 * Whether the type only has an ELF64 variant
 * (e.g. Elf64_Xword; Elf32_Xword doesn't exist)
 */
/* #define elf_64BIT_EXCLUSIVE */
/* #define elf_BOTH_CLASSES */

/** Whether the underlying type is signed (e.g. Elf64_Sword) */
/* #define elf_SIGNED */
/* #define elf_UNSIGNED */

/**
 * Whether the underlying types have the same size
 * (e.g. (Elf32_Half == Elf64_Half but Elf32_Addr != Elf64_Addr)
 */
/* #define elf_SAME_SIZE */
/* #define elf_DIFFERENT_SIZE */

#define ELF_PRIMITIVE_LIST \
    /* (name, bits32, bits64, exclusive64, signed, same_size */                \
    DECL_ELF_PRIMITIVE(Half, 16, 16,                                           \
                       elf_BOTH_CLASSES, elf_UNSIGNED, elf_SAME_SIZE)          \
    DECL_ELF_PRIMITIVE(Section, 16, 16,                                        \
                       elf_BOTH_CLASSES, elf_UNSIGNED, elf_SAME_SIZE)          \
    DECL_ELF_PRIMITIVE(Word, 32, 32,                                           \
                       elf_BOTH_CLASSES, elf_UNSIGNED, elf_SAME_SIZE)          \
    DECL_ELF_PRIMITIVE(Off, 32, 64,                                            \
                       elf_BOTH_CLASSES, elf_UNSIGNED, elf_DIFFERENT_SIZE)     \
    DECL_ELF_PRIMITIVE(Addr, 32, 64,                                           \
                       elf_BOTH_CLASSES, elf_UNSIGNED, elf_DIFFERENT_SIZE)     \
                                                                               \
    DECL_ELF_PRIMITIVE(Xword, 64, 64,                                          \
                       elf_64BIT_EXCLUSIVE, elf_UNSIGNED, elf_SAME_SIZE)       \
                                                                               \
    DECL_ELF_PRIMITIVE(Sword, 32, 32,                                          \
                       elf_BOTH_CLASSES, elf_SIGNED, elf_SAME_SIZE)            \
    DECL_ELF_PRIMITIVE(Sxword, 64, 64,                                         \
                       elf_64BIT_EXCLUSIVE, elf_SIGNED, elf_SAME_SIZE)         \


#define DECL_ELF_PRIMITIVE(name, bits32, bits64,                               \
                           exclusive64, signedness, same_size)                 \
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
int read_##name(const struct blob *data, uint64_t *off_p,                      \
                int clazz, int encoding,                                       \
                Elf64_##name *out);                                            \
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
int write_##name(struct blob *data, uint64_t *off_p,                           \
                 int clazz, int encoding,                                      \
                 Elf64_##name val);                                            \

ELF_PRIMITIVE_LIST

#undef DECL_ELF_PRIMITIVE


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
 * The fields' values are not validated to be sensible or spec-compliant.
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
 * The fields' values are not validated to be sensible or spec-compliant.
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
 * The fields' values are not validated to be sensible or spec-compliant.
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
 * Parses a symbol table entry to the generic in-memory representation.
 * The fields' values are not validated to be sensible or spec-compliant.
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
int read_sym(const struct blob *data, uint64_t *off_p,
             int clazz, int encoding, Elf64_Sym *out);

/**
 * Serializes a symbol table entry to the given class and data encoding.
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
 * @param[in] sym The in-memory symbol struct to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `sym` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_sym(struct blob *data, uint64_t *off_p,
              int clazz, int encoding, const Elf64_Sym *sym);


/**
 * Returns a string with the name of the ET_* ELF type
 * corresponding to the integer value `et` or "(unknown)" if one isn't found.
 * Never returns NULL.
 */
const char * elf_type_toString(Elf64_Half et);

/**
 * Returns a string with the name of the PT_* program header type
 * corresponding to the integer valu `pt` or "(unknown)" if one isn't found.
 * Never returns NULL.
 */
const char * program_header_type_toString(Elf64_Word pt);

/**
 * Returns a string with the name of the SHT_* section header type
 * corresponding to the integer value `sht` or "(unknown)" if one isn't found.
 * Never returns NULL.
 */
const char * section_header_type_toString(Elf64_Word sht);

/**
 * Returns a string with the name of the DT_* dynamic entry type
 * corresponding to the integer value `dt` or "(unknown)" if one isn't found.
 * Never returns NULL.
 */
const char * dynamic_tag_to_string(Elf64_Sxword dt);

#endif /* ELF_TYPES_H_ */
