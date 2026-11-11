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
int read_##name(const ElfFileData *data, Elf64_Off *off_p, Elf64_##name *out); \
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
int write_##name(ElfFileData *data, Elf64_Off *off_p, Elf64_##name val);       \

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
 * @param[in] ehdr The in-memory ELF header to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `ehdr` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_ehdr(ElfFileData *data, Elf64_Off *off_p, const Elf64_Ehdr *ehdr);

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
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_phdr(const ElfFileData *data, Elf64_Off *off_p, Elf64_Phdr *out);

/**
 * Serializes a program header structure to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] phdr The in-memory program header to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `phdr` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_phdr(ElfFileData *data, Elf64_Off *off_p, const Elf64_Phdr *phdr);

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
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_shdr(const ElfFileData *data, Elf64_Off *off_p, Elf64_Shdr *out);

/**
 * Serializes a section header structure to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] shdr The in-memory section header to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `shdr` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_shdr(ElfFileData *data, Elf64_Off *off_p, const Elf64_Shdr *shdr);

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
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_dyn(const ElfFileData *data, Elf64_Off *off_p, Elf64_Dyn *out);

/**
 * Serializes a dynamic entry structure to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] d The in-memory dynamic entry to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `dyn` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_dyn(ElfFileData *data, Elf64_Off *off_p, const Elf64_Dyn *d);

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
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_sym(const ElfFileData *data, Elf64_Off *off_p, Elf64_Sym *out);

/**
 * Serializes a symbol table entry to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] s The in-memory symbol struct to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `sym` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_sym(ElfFileData *data, Elf64_Off *off_p, const Elf64_Sym *s);

/**
 * Parses a symbol version definition struct to the generic
 * in-memory representation. The fields' values are not validated
 * to be sensible or spec-compliant.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_verdef(const ElfFileData *data, Elf64_Off *off_p, Elf64_Verdef *out);

/**
 * Serializes a symbol version definition struct
 * to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] vd The in-memory symbol version definition struct to serialize.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `vd` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_verdef(ElfFileData *data, Elf64_Off *off_p, const Elf64_Verdef *vd);

/**
 * Parses a symbol version definition auxiliary information struct
 * to the generic in-memory representation. The fields' values
 * are not validated to be sensible or spec-compliant.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_verdaux(const ElfFileData *data, Elf64_Off *off_p, Elf64_Verdaux *out);

/**
 * Serializes a symbol version definition auxiliary information struct
 * to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] vda The in-memory symbol version definition auxiliary information
 *  struct to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `vda` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_verdaux(ElfFileData *data, Elf64_Off *off_p,
                  const Elf64_Verdaux *vda);

/**
 * Parses a symbol version dependency struct to the generic
 * in-memory representation. The fields' values are not validated
 * to be sensible or spec-compliant.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_verneed(const ElfFileData *data, Elf64_Off *off_p, Elf64_Verneed *out);

/**
 * Serializes a symbol version dependency struct
 * to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] vn The in-memory symbol version dependency struct to serialize.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `vn` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_verneed(ElfFileData *data, Elf64_Off *off_p, const Elf64_Verneed *vn);

/**
 * Parses a symbol version dependency auxiliary information struct
 * to the generic in-memory representation. The fields' values
 * are not validated to be sensible or spec-compliant.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_vernaux(const ElfFileData *data, Elf64_Off *off_p, Elf64_Vernaux *out);

/**
 * Serializes a symbol version dependency auxiliary information struct
 * to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] vna The in-memory symbol version dependency auxiliary information
 *  struct to serialize. Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `vna` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_vernaux(ElfFileData *data, Elf64_Off *off_p,
                  const Elf64_Vernaux *vna);

/**
 * Parses a relocation (without addend) struct to the generic
 * in-memory representation. The fields' values are not validated
 * to be sensible or spec-compliant.
 *
 * NOTE: When `data->clazz` is `ELFCLASS32`,
 * the `r_info` field is automatically converted to the 64-bit representation,
 * so even when dealing with a 32-bit ELF, always use the 64-bit macros
 * (`ELF64_R_SYM`, `ELF64_R_TYPE` and `ELF64_R_INFO`) to read/write the value.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_rel(const ElfFileData *data, Elf64_Off *off_p, Elf64_Rel *out);

/**
 * Serializes a relocation (without addend) struct
 * to the given class and data encoding.
 *
 * NOTE: When `data->clazz` is `ELFCLASS32`,
 * the `r_info` field is automatically converted to the 32-bit representation,
 * so even when dealing with a 32-bit ELF, always use the 64-bit macros
 * (`ELF64_R_SYM`, `ELF64_R_TYPE` and `ELF64_R_INFO`) to read/write the value.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] rel The in-memory relocation (without addend) struct to serialize.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `rel` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_rel(ElfFileData *data, Elf64_Off *off_p, const Elf64_Rel *rel);

/**
 * Parses a relocation (with addend) struct to the generic
 * in-memory representation. The fields' values are not validated
 * to be sensible or spec-compliant.
 *
 * NOTE: When `data->clazz` is `ELFCLASS32`,
 * the `r_info` field is automatically converted to the 64-bit representation,
 * so even when dealing with a 32-bit ELF, always use the 64-bit macros
 * (`ELF64_R_SYM`, `ELF64_R_TYPE` and `ELF64_R_INFO`) to read/write the value.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_rela(const ElfFileData *data, Elf64_Off *off_p, Elf64_Rela *out);

/**
 * Serializes a relocation (with addend) struct
 * to the given class and data encoding.
 *
 * NOTE: When `data->clazz` is `ELFCLASS32`,
 * the `r_info` field is automatically converted to the 32-bit representation,
 * so even when dealing with a 32-bit ELF, always use the 64-bit macros
 * (`ELF64_R_SYM`, `ELF64_R_TYPE` and `ELF64_R_INFO`) to read/write the value.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] rela The in-memory relocation (with addend) struct to serialize.
 *  Must not be NULL.
 *
 * @return 0 on success, non-zero if the serialized `rela` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and a value overflows the Elf32 equivalent type.
 */
int write_rela(ElfFileData *data, Elf64_Off *off_p, const Elf64_Rela *rela);

/**
 * Parses a relative relocation (RELR) entry to the generic
 * in-memory representation. The value is not validated
 * to be sensible or spec-compliant.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to read.
 *  This value will be incremented to point past the read data.
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero if the data is outside of buffer bounds.
 */
int read_relr(const ElfFileData *data, Elf64_Off *off_p, Elf64_Relr *out);

/**
 * Serializes a relative relocation (RELR) entry
 * to the given class and data encoding.
 *
 * @param[out] data The data to write into. Must not be NULL.
 *
 * @param[in,out] off_p A pointer to the offset at which to write.
 *  This value will be incremented to point past the newly written data.
 *  Must not be NULL.
 *
 * @param[in] relr The in-memory RELR entry value to serialize.
 *
 * @return 0 on success, non-zero if the serialized `relr` can't fit in `data`
 *  or `clazz` is `ELFCLASS32` and `relr` overflows the equivalent Elf32 type.
 */
int write_relr(ElfFileData *data, Elf64_Off *off_p, Elf64_Relr relr);

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
