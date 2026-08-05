#ifndef ELF_TYPES_H_
#define ELF_TYPES_H_

#include "elf.h"
#include "util.h"
#include <stdint.h>

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
int read_##elf_type(const struct blob *data, uint64_t *off_p,           \
                    int clazz, int endianness,                          \
                    Elf64_##elf_type *out);                             \
                                                                        \
int write_##elf_type(struct blob *data, uint64_t *off_p,                \
                     int clazz, int endianness,                         \
                     Elf64_##elf_type val);                             \

ELF_PRIMITIVE_FN_LIST

#undef DECL_ELF_PRIMITIVE_FN
#undef exclusive_64bit
#undef no_exclusive_64bit
#undef same_size
#undef different_size

int write_ehdr(struct blob *data, uint64_t *off_p,
               int clazz, int encoding, const Elf64_Ehdr *ehdr);


int read_phdr(const struct blob *data, uint64_t *off_p,
              int clazz, int encoding, Elf64_Phdr *out);

int write_phdr(struct blob *data, uint64_t *off_p,
               int clazz, int encoding, const Elf64_Phdr *phdr);

int read_shdr(const struct blob *data, uint64_t *off_p,
              int clazz, int encoding, Elf64_Shdr *out);

int write_shdr(struct blob *data, uint64_t *off_p,
              int clazz, int encoding, const Elf64_Shdr *shdr);

int read_dyn(const struct blob *data, uint64_t *off_p,
             int clazz, int encoding, Elf64_Dyn *out);

int write_dyn(struct blob *data, uint64_t *off_p,
              int clazz, int encoding, const Elf64_Dyn *dyn);

const char * elf_type_toString(Elf64_Half et);

const char * section_type_toString(Elf64_Word sht);

const char * dynamic_tag_to_string(Elf64_Sxword dt);

#endif /* ELF_TYPES_H_ */
