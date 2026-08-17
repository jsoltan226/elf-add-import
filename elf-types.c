#include "elf-types.h"
#include "elf.h"
#include "util.h"
#include "portable-endian.h"
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdalign.h>

/**
 * Before you start reading this monstrosity,
 * here is the roughly equivalent C++ pseudocode:
 *
 * template<typename Elf_type,
 *          typename UnderlyingType32, typename UnderlyingType64,
 *          bool SameSize, bool ExclusiveTo64>
 * int read(const struct blob *data, uint64_t *off_p,
 *          int clazz, int endianness, Elf_type *out)
 * {
 *     if constexpr (SameSize) {
 *         //// `same_size_read__` ////
 *         (void) clazz;
 *         goto /constexpr/ whatever_read64__;
 *     } else {
 *         //// `different_size_read__` ////
 *         if (clazz == ELFCLASS32) {
 *             if constexpr (ExclusiveTo64) {
 *                 //// `exclusive_64bit_read32__` ////
 *                 // Error: This type is not valid for ELF32
 *                 return 1;
 *             } else {
 *                 //// `no_exclusive_64bit_read32__` ////
 *                 if (overflow_safe_cmp(*off_p + sizeof(Elf_type) >
 *                                       data->size))
 *                 {
 *                     // Error: Not enough data
 *                     return 1;
 *                 }
 *
 *                 UnderlyingType32 tmp =
 *                     *(const UnderlyingType32 *)(data->data + *off_p);
 *                 if (endianness == ELFDATA2MSB) {
 *                     *out = (Elf_type)from_be(tmp);
 *                 } else // if (endianness == ELFDATA2MSB) // {
 *                     *out = (Elf_type)from_le(tmp);
 *                 }
 *             }
 *
 *         } else // if (clazz == ELFCLASS64) // {
 * whatever_read64__:
 *             //// `whatever_read64__` ////
 *             if (overflow_safe_cmp(*off_p + sizeof(Elf_type) > data->size)) {
 *                 // Error: Not enough data
 *                 return 1;
 *             }
 *
 *             UnderlyingType64 tmp =
 *                 *(const UnderlyingType64 *)(data->data + *off_p);
 *             if (endianness == ELFDATA2MSB) {
 *                 *out = (Elf_type)from_be(tmp);
 *             } else // if (endianness == ELFDATA2MSB) // {
 *                 *out = (Elf_type)from_le(tmp);
 *             }
 *         }
 *     }
 * }
 *
 * This structure also applies to the later `write` variants.
 */

/* Below lies the reason why C++ was created */

#define exclusive_64bit_read32__(elf_type, bits32, bits64,                     \
                                 t_prefix, prefix32, prefix64)                 \
        pr_error("%s: This type is not valid for ELF32\n", __func__);          \
        return -1;                                                             \

#define no_exclusive_64bit_read32__(elf_type, bits32, bits64,                  \
                                    t_prefix, prefix32, prefix64)              \
                                                                               \
        if (data->size < sizeof(Elf32_##elf_type) ||                           \
                data->size - sizeof(Elf32_##elf_type) < *off_p)                \
        {                                                                      \
            pr_error("%s: ([0x%" PRIx64 "]) Not enough data\n",                \
                     __func__, *off_p);                                        \
            return 1;                                                          \
        }                                                                      \
                                                                               \
        Elf32_##elf_type tmp;                                                  \
        memcpy(&tmp, data->data + *off_p, sizeof(Elf32_##elf_type));           \
        *off_p += sizeof(Elf32_##elf_type);                                    \
                                                                               \
        if (endianness == ELFDATA2MSB) {                                       \
            *out = (Elf32_##elf_type) be##bits32##toh(tmp);                    \
        } else /* if (endianness == ELFDATA2LSB) */ {                          \
            *out = (Elf32_##elf_type) le##bits32##toh(tmp);                    \
        }                                                                      \

#define whatever_read64__(elf_type, bits32, bits64,                            \
                          t_prefix, prefix32, prefix64)                        \
        if (data->size < sizeof(Elf64_##elf_type) ||                           \
                data->size - sizeof(Elf64_##elf_type) < *off_p)                \
        {                                                                      \
            pr_error("%s: ([0x%" PRIx64 "]) Not enough data\n",                \
                    __func__, *off_p);                                         \
            return 1;                                                          \
        }                                                                      \
                                                                               \
        Elf64_##elf_type tmp;                                                  \
        memcpy(&tmp, data->data + *off_p, sizeof(Elf64_##elf_type));           \
        *off_p += sizeof(Elf64_##elf_type);                                    \
                                                                               \
        if (endianness == ELFDATA2MSB) {                                       \
            *out = (Elf64_##elf_type) be##bits64##toh(tmp);                    \
        } else /* if (endianness == ELFDATA2LSB) */ {                          \
            *out = (Elf64_##elf_type) le##bits64##toh(tmp);                    \
        }                                                                      \

#define different_size_read__(elf_type, bits32, bits64, t_prefix,              \
                              prefix32, prefix64, disable_if_exclusive_64)     \
    if (clazz == ELFCLASS32) {                                                 \
        disable_if_exclusive_64##_read32__(elf_type, bits32, bits64,           \
                                           t_prefix, prefix32, prefix64);      \
    } else /* if (clazz == ELFCLASS64) */ {                                    \
        whatever_read64__(elf_type, bits32, bits64,                            \
                          t_prefix, prefix32, prefix64);                       \
    }                                                                          \

#define same_size_read__(elf_type, bits32, bits64, t_prefix,                   \
                         prefix32, prefix64, disable_if_exclusive_64)          \
    (void) clazz;                                                              \
    /* Reuse the 64-bit case for the generic variant */                        \
    whatever_read64__(elf_type, bits32, bits64, t_prefix, prefix32, prefix64); \


#define DECL_ELF_PRIMITIVE_FN(elf_type, bits32, bits64,                        \
                              t_prefix, prefix32, prefix64,                    \
                              disable_if_exclusive_64, is_same_size)           \
                                                                               \
int read_##elf_type(const struct blob *data, uint64_t *off_p,                  \
                    int clazz, int endianness,                                 \
                    Elf64_##elf_type *out)                                     \
{                                                                              \
    is_same_size##_read__(elf_type, bits32, bits64, t_prefix,                  \
                          prefix32, prefix64, disable_if_exclusive_64);        \
    return 0;                                                                  \
}                                                                              \

ELF_PRIMITIVE_FN_LIST

#undef DECL_ELF_PRIMITIVE_FN
#undef same_size_read__
#undef different_size_read__
#undef whatever_read64__
#undef no_exclusive_64bit_read32__
#undef exclusive_64bit_read32__


/**
 * See the comments above the `read` macros for an explanation of this... thing
 */

#define exclusive_64bit_write32__(elf_type, bits32, bits64,                    \
                                  t_prefix, prefix32, prefix64)                \
        pr_error("%s: This type is not valid for ELF32\n", __func__);          \
        return -1;                                                             \

#define no_exclusive_64bit_write32__(elf_type, bits32, bits64,                 \
                                     t_prefix, prefix32, prefix64)             \
        if (data->size < sizeof(Elf32_##elf_type) ||                           \
                data->size - sizeof(Elf32_##elf_type) < *off_p)                \
        {                                                                      \
            pr_error("%s: ([0x%" PRIx64 "]) Not enough space in data buffer\n",\
                    __func__, *off_p);                                         \
            return 1;                                                          \
        }                                                                      \
                                                                               \
        if (val > prefix32##_MAX) {                                            \
            pr_error("%s: ([0x%" PRIx64 "]) Value 0x%" PRIx##bits64            \
                    " too large for the ELF32 version of the type\n",          \
                    __func__, *off_p, val);                                    \
            return 1;                                                          \
        }                                                                      \
                                                                               \
        if (endianness == ELFDATA2MSB) {                                       \
            memcpy(data->data + *off_p,                                        \
                   &(t_prefix##bits32##_t){ htobe##bits32(val) },              \
                   sizeof(t_prefix##bits32##_t)                                \
            );                                                                 \
        } else /* if (endianness == ELFDATA2LSB) */ {                          \
            memcpy(data->data + *off_p,                                        \
                   &(t_prefix##bits32##_t){ htole##bits32(val) },              \
                   sizeof(t_prefix##bits32##_t)                                \
            );                                                                 \
        }                                                                      \
                                                                               \
        *off_p += sizeof(Elf32_##elf_type);                                    \

#define whatever_write64__(elf_type, bits32, bits64,                           \
                           t_prefix, prefix32, prefix64)                       \
        if (data->size < sizeof(Elf64_##elf_type) ||                           \
                data->size - sizeof(Elf64_##elf_type) < *off_p)                \
        {                                                                      \
            pr_error("%s: ([0x%" PRIx64 "]) Not enough space in data buffer\n",\
                    __func__, *off_p);                                         \
            return 1;                                                          \
        }                                                                      \
                                                                               \
        if (endianness == ELFDATA2MSB) {                                       \
            memcpy(data->data + *off_p,                                        \
                   &(t_prefix##bits64##_t){ htobe##bits64(val) },              \
                   sizeof(t_prefix##bits64##_t)                                \
            );                                                                 \
        } else /* if (endianness == ELFDATA2LSB) */ {                          \
            memcpy(data->data + *off_p,                                        \
                   &(t_prefix##bits64##_t){ htole##bits64(val) },              \
                   sizeof(t_prefix##bits64##_t)                                \
            );                                                                 \
        }                                                                      \
                                                                               \
        *off_p += sizeof(Elf64_##elf_type);                                    \

#define same_size_write__(elf_type, bits32, bits64, t_prefix,                  \
                          prefix32, prefix64, disable_if_exclusive_64)         \
    (void) clazz;                                                              \
    /* Reuse the 64-bit case for the generic variant */                        \
    whatever_write64__(elf_type, bits32, bits64, t_prefix, prefix32, prefix64);\

#define different_size_write__(elf_type, bits32, bits64, t_prefix,             \
                               prefix32, prefix64, disable_if_exclusive_64)    \
    if (clazz == ELFCLASS32) {                                                 \
                                                                               \
        disable_if_exclusive_64##_write32__(elf_type, bits32, bits64,          \
                                            t_prefix, prefix32, prefix64);     \
                                                                               \
    } else /* if (clazz == ELFCLASS64) */ {                                    \
        whatever_write64__(elf_type, bits32, bits64,                           \
                           t_prefix, prefix32, prefix64);                      \
    }                                                                          \

#define DECL_ELF_PRIMITIVE_FN(elf_type, bits32, bits64,                        \
                              t_prefix, prefix32, prefix64,                    \
                              disable_if_exclusive_64, is_same_size)           \
int write_##elf_type(struct blob *data, uint64_t *off_p,                       \
                    int clazz, int endianness,                                 \
                    Elf64_##elf_type val)                                      \
{                                                                              \
                                                                               \
    is_same_size##_write__(elf_type, bits32, bits64, t_prefix,                 \
                           prefix32, prefix64, disable_if_exclusive_64);       \
    return 0;                                                                  \
}                                                                              \

ELF_PRIMITIVE_FN_LIST

#undef DECL_ELF_PRIMITIVE_FN
#undef same_size_write__
#undef different_size_write__
#undef whatever_write64__
#undef no_exclusive_64bit_write32__
#undef exclusive_64bit_write32__

int write_ehdr(struct blob *data, uint64_t *off_p,
               int clazz, int encoding, const Elf64_Ehdr *ehdr)
{
    const size_t size = clazz == ELFCLASS32 ?
        sizeof(Elf32_Ehdr) : sizeof(Elf64_Ehdr);

    if (data->size < size) {
        pr_error("%s: ([0x%" PRIx64 "]) "
                "Not enough space in data buffer\n", __func__, *off_p);
        return 1;
    }

    memcpy(data->data + *off_p, &ehdr->e_ident, EI_NIDENT);
    *off_p += EI_NIDENT;

    if (write_Half(data, off_p, clazz, encoding, ehdr->e_type) ||
        write_Half(data, off_p, clazz, encoding, ehdr->e_machine) ||
        write_Word(data, off_p, clazz, encoding, ehdr->e_version) ||
        write_Addr(data, off_p, clazz, encoding, ehdr->e_entry) ||
        write_Off(data, off_p, clazz, encoding, ehdr->e_phoff) ||
        write_Off(data, off_p, clazz, encoding, ehdr->e_shoff) ||
        write_Word(data, off_p, clazz, encoding, ehdr->e_flags) ||
        write_Half(data, off_p, clazz, encoding, ehdr->e_ehsize) ||
        write_Half(data, off_p, clazz, encoding, ehdr->e_phentsize) ||
        write_Half(data, off_p, clazz, encoding, ehdr->e_phnum) ||
        write_Half(data, off_p, clazz, encoding, ehdr->e_shentsize) ||
        write_Half(data, off_p, clazz, encoding, ehdr->e_shnum) ||
        write_Half(data, off_p, clazz, encoding, ehdr->e_shstrndx))
    {
        return 1;
    }

    return 0;
}

int read_phdr(const struct blob *data, uint64_t *off_p,
              int clazz, int encoding, Elf64_Phdr *out)
{
    if (read_Word(data, off_p, clazz, encoding, &out->p_type))
        return 1;

    /* In ELF32 `p_flags` is in a different place than in ELF64 */
    if (clazz == ELFCLASS64)
        if (read_Word(data, off_p, clazz, encoding, &out->p_flags))
            return 1;

    if (read_Off(data, off_p, clazz, encoding, &out->p_offset) ||
        read_Addr(data, off_p, clazz, encoding, &out->p_vaddr) ||
        read_Addr(data, off_p, clazz, encoding, &out->p_paddr))
    {
        return 1;
    }

    /* they really messed up the program header spec, didn't they? */
    if (clazz == ELFCLASS64) {
        if (read_Xword(data, off_p, clazz, encoding, &out->p_filesz) ||
            read_Xword(data, off_p, clazz, encoding, &out->p_memsz) ||
            read_Xword(data, off_p, clazz, encoding, &out->p_align))
        {
            return 1;
        }

    } else /* if (clazz == ELFCLASS32) */ {
        Elf64_Word tmp_filesz = 0, tmp_memsz = 0, tmp_align = 0;
        if (read_Word(data, off_p, clazz, encoding, &tmp_filesz) ||
            read_Word(data, off_p, clazz, encoding, &tmp_memsz) ||
            read_Word(data, off_p, clazz, encoding, &out->p_flags) ||
            read_Word(data, off_p, clazz, encoding, &tmp_align))
        {
                return 1;
        }

        out->p_filesz = tmp_filesz | UINT64_C(0);
        out->p_memsz = tmp_memsz | UINT64_C(0);
        out->p_align = tmp_align | UINT64_C(0);
    }

    pr_debug("\n%s: *off_p: 0x%" PRIx64 "\n", __func__, *off_p);
    pr_debug("%s: out->p_type: 0x%" PRIx32 " (%" PRIu32 ")\n", __func__,
             out->p_type, out->p_type);
    pr_debug("%s: out->p_flags: 0x%" PRIx32 " (%" PRIu32 ")\n", __func__,
             out->p_flags, out->p_flags);
    pr_debug("%s: out->p_offset: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             out->p_offset, out->p_offset);
    pr_debug("%s: out->p_vaddr: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             out->p_vaddr, out->p_vaddr);
    pr_debug("%s: out->p_paddr: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             out->p_paddr, out->p_paddr);
    pr_debug("%s: out->p_filesz: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             out->p_filesz, out->p_filesz);
    pr_debug("%s: out->p_memsz: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             out->p_memsz, out->p_memsz);
    pr_debug("%s: out->p_align: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             out->p_align, out->p_align);
    return 0;
}

int write_phdr(struct blob *data, uint64_t *off_p,
               int clazz, int encoding, const Elf64_Phdr *phdr)
{
    pr_debug("\n%s: *off_p: 0x%" PRIx64 "\n", __func__, *off_p);
    pr_debug("%s: phdr->p_type: 0x%" PRIx32 " (%" PRIu32 ")\n", __func__,
             phdr->p_type, phdr->p_type);
    pr_debug("%s: phdr->p_flags: 0x%" PRIx32 " (%" PRIu32 ")\n", __func__,
             phdr->p_flags, phdr->p_flags);
    pr_debug("%s: phdr->p_offset: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             phdr->p_offset, phdr->p_offset);
    pr_debug("%s: phdr->p_vaddr: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             phdr->p_vaddr, phdr->p_vaddr);
    pr_debug("%s: phdr->p_paddr: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             phdr->p_paddr, phdr->p_paddr);
    pr_debug("%s: phdr->p_filesz: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             phdr->p_filesz, phdr->p_filesz);
    pr_debug("%s: phdr->p_memsz: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             phdr->p_memsz, phdr->p_memsz);
    pr_debug("%s: phdr->p_align: 0x%" PRIx64 " (%" PRIu64 ")\n", __func__,
             phdr->p_align, phdr->p_align);

    if (write_Word(data, off_p, clazz, encoding, phdr->p_type))
        return 1;

    /* In ELF32 `p_flags` is in a different place than in ELF64 */
    if (clazz == ELFCLASS64)
        if (write_Word(data, off_p, clazz, encoding, phdr->p_flags))
            return 1;

    if (write_Off(data, off_p, clazz, encoding, phdr->p_offset) ||
        write_Addr(data, off_p, clazz, encoding, phdr->p_vaddr) ||
        write_Addr(data, off_p, clazz, encoding, phdr->p_paddr))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (write_Xword(data, off_p, clazz, encoding, phdr->p_filesz) ||
            write_Xword(data, off_p, clazz, encoding, phdr->p_memsz) ||
            write_Xword(data, off_p, clazz, encoding, phdr->p_align))
        {
            return 1;
        }
    } else /* if (clazz == ELFCLASS32) */ {
        if (write_Word(data, off_p, clazz, encoding, phdr->p_filesz) ||
            write_Word(data, off_p, clazz, encoding, phdr->p_memsz) ||
            write_Word(data, off_p, clazz, encoding, phdr->p_flags) ||
            write_Word(data, off_p, clazz, encoding, phdr->p_align))
        {
                return 1;
        }
    }

    return 0;
}

int read_shdr(const struct blob *data, uint64_t *off_p,
              int clazz, int encoding, Elf64_Shdr *out)
{
    if (read_Word(data, off_p, clazz, encoding, &out->sh_name) ||
        read_Word(data, off_p, clazz, encoding, &out->sh_type))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (read_Xword(data, off_p, clazz, encoding, &out->sh_flags))
            return 1;
    } else /* if (clazz == ELFCLASS32) */ {
        Elf64_Word tmp = 0;
        if (read_Word(data, off_p, clazz, encoding, &tmp))
            return 1;

        out->sh_flags = UINT64_C(0) | tmp;
    }

    if (read_Addr(data, off_p, clazz, encoding, &out->sh_addr) ||
        read_Off(data, off_p, clazz, encoding, &out->sh_offset))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (read_Xword(data, off_p, clazz, encoding, &out->sh_size))
            return 1;
    } else /* if (clazz == ELFCLASS32) */ {
        Elf64_Word tmp = 0;
        if (read_Word(data, off_p, clazz, encoding, &tmp))
            return 1;

        out->sh_size = UINT64_C(0) | tmp;
    }

    if (read_Word(data, off_p, clazz, encoding, &out->sh_link) ||
        read_Word(data, off_p, clazz, encoding, &out->sh_info))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (read_Xword(data, off_p, clazz, encoding, &out->sh_addralign) ||
            read_Xword(data, off_p, clazz, encoding, &out->sh_entsize))
        {
            return 1;
        }
    } else /* if (clazz == ELFCLASS32) */ {
        Elf64_Word tmp_addralign = 0, tmp_entsize = 0;
        if (read_Word(data, off_p, clazz, encoding, &tmp_addralign) ||
            read_Word(data, off_p, clazz, encoding, &tmp_entsize))
            return 1;

        out->sh_addralign = UINT64_C(0) | tmp_addralign;
        out->sh_entsize = UINT64_C(0) | tmp_entsize;
    }

    return 0;
}

int write_shdr(struct blob *data, uint64_t *off_p,
              int clazz, int encoding, const Elf64_Shdr *shdr)
{
    if (write_Word(data, off_p, clazz, encoding, shdr->sh_name) ||
        write_Word(data, off_p, clazz, encoding, shdr->sh_type))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (write_Xword(data, off_p, clazz, encoding, shdr->sh_flags))
            return 1;
    } else /* if (clazz == ELFCLASS32) */ {
        if (write_Word(data, off_p, clazz, encoding, shdr->sh_flags))
            return 1;
    }

    if (write_Addr(data, off_p, clazz, encoding, shdr->sh_addr) ||
        write_Off(data, off_p, clazz, encoding, shdr->sh_offset))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (write_Xword(data, off_p, clazz, encoding, shdr->sh_size))
            return 1;
    } else /* if (clazz == ELFCLASS32) */ {
        if (write_Word(data, off_p, clazz, encoding, shdr->sh_size))
            return 1;
    }

    if (write_Word(data, off_p, clazz, encoding, shdr->sh_link) ||
        write_Word(data, off_p, clazz, encoding, shdr->sh_info))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (write_Xword(data, off_p, clazz, encoding, shdr->sh_addralign) ||
            write_Xword(data, off_p, clazz, encoding, shdr->sh_entsize))
        {
            return 1;
        }
    } else /* if (clazz == ELFCLASS32) */ {
        if (write_Word(data, off_p, clazz, encoding, shdr->sh_addralign) ||
            write_Word(data, off_p, clazz, encoding, shdr->sh_entsize))
        {
            return 1;
        }
    }

    return 0;
}

static_assert(sizeof(Elf32_Word) == sizeof(Elf32_Addr),
        "Elf32_Dyn: d_val and d_ptr have different sizes");
static_assert(alignof(Elf32_Word) == alignof(Elf32_Addr),
        "Elf32_Dyn: d_val and d_ptr have different alignments");
static_assert(offsetof(Elf32_Dyn, d_un.d_val) ==
                offsetof(Elf32_Dyn, d_un.d_ptr),
        "Elf32_Dyn: d_val and d_ptr are at different offsets");
static_assert(sizeof(Elf64_Xword) == sizeof(Elf64_Addr),
        "Elf64_Dyn: d_val and d_ptr have different sizes");
static_assert(alignof(Elf64_Xword) == alignof(Elf64_Addr),
        "Elf64_Dyn: d_val and d_ptr have different alignments");
static_assert(offsetof(Elf64_Dyn, d_un.d_val) ==
                offsetof(Elf64_Dyn, d_un.d_ptr),
        "Elf64_Dyn: d_val and d_ptr are at different offsets");

int read_dyn(const struct blob *data, uint64_t *off_p,
             int clazz, int encoding, Elf64_Dyn *out)
{
    if (clazz == ELFCLASS32) {
        Elf64_Sword d_tag = 0;
        if (read_Sword(data, off_p, clazz, encoding, &d_tag))
            return 1;
        out->d_tag = (Elf32_Sword)d_tag;

        /* Elf32_Dyn.d_un is a union of Elf32_Word and Elf32_Addr
         * which are both `uint32_t`s,
         * so it's safe to unconditionally just read a 32-bit Word */
        Elf64_Word d_un_val = 0;
        if (read_Word(data, off_p, clazz, encoding, &d_un_val))
            return 1;

        out->d_un.d_val = d_un_val;

    } else /* if (clazz == ELFCLASS64) */ {
        if (read_Sxword(data, off_p, clazz, encoding, &out->d_tag))
            return 1;

        /* Elf64_Dyn.d_un is a union of Elf64_Xword and Elf64_Addr
         * which are both `uint64_t`s,
         * so it's safe to unconditionally just read a 64-bit Xword */
        if (read_Xword(data, off_p, clazz, encoding, &out->d_un.d_val))
            return 1;
    }

    return 0;
}

int write_dyn(struct blob *data, uint64_t *off_p,
              int clazz, int encoding, const Elf64_Dyn *dyn)
{

    if (clazz == ELFCLASS32) {
        if (dyn->d_tag > INT32_MAX || dyn->d_tag < INT32_MIN) {
            pr_error("%s: d_tag value outside of 32-bit integer limits\n",
                    __func__);
            return 1;
        }
        if (write_Sword(data, off_p, clazz, encoding, dyn->d_tag))
            return 1;

        /* See the above `read_dyn` */
        if (dyn->d_un.d_val > UINT32_MAX) {
            pr_error("%s: d_un value outside of 32-bit integer limits\n",
                    __func__);
            return 1;
        }
        if (write_Word(data, off_p, clazz, encoding, dyn->d_un.d_val))
            return 1;
    } else /* if (clazz == ELFCLASS64) */ {
        if (write_Sxword(data, off_p, clazz, encoding, dyn->d_tag))
            return 1;

        /* See the above `read_dyn` */
        if (write_Xword(data, off_p, clazz, encoding, dyn->d_un.d_val))
            return 1;
    }

    return 0;
}

const char * elf_type_toString(Elf64_Half et)
{
    switch (et) {
        case ET_NONE: return "ET_NONE";
        case ET_REL: return "ET_REL";
        case ET_EXEC: return "ET_EXEC";
        case ET_DYN: return "ET_DYN";
        case ET_CORE: return "ET_CORE";
        default:
            if (et >= ET_LOOS && et <= ET_HIOS)
                return "unknown OS-specific ELF";

            if (et >= ET_LOPROC /* && et <= ET_HIPROC (always true) */)
                return "unknown processor-specific ELF";

            return "(unknown)";
    }
}

const char * program_header_type_toString(Elf64_Word pt)
{
    switch (pt) {
        case PT_NULL: return "PT_NULL";
        case PT_LOAD: return "PT_LOAD";
        case PT_DYNAMIC: return "PT_DYNAMIC";
        case PT_INTERP: return "PT_INTERP";
        case PT_NOTE: return "PT_NOTE";
        case PT_SHLIB: return "PT_SHLIB";
        case PT_PHDR: return "PT_PHDR";
        case PT_TLS: return "PT_TLS";
        case PT_NUM: return "PT_NUM";

        case PT_GNU_EH_FRAME: return "PT_GNU_EH_FRAME";
        case PT_GNU_STACK: return "PT_GNU_STACK";
        case PT_GNU_RELRO: return "PT_GNU_RELRO";
        case PT_GNU_PROPERTY: return "PT_GNU_PROPERTY";
        case PT_GNU_SFRAME: return "PT_GNU_SFRAME";

        case PT_SUNWBSS: return "PT_SUNWBSS";
        case PT_SUNWSTACK: return "PT_SUNWSTACK";

        default:
           if (pt >= PT_LOSUNW && pt <= PT_HISUNW)
               return "unknown SUN-specific program header";
           else if (pt >= PT_LOOS && pt < PT_HIOS)
               return "unknown OS-specific program header";


           if (pt >= PT_HIPROC && pt <= PT_LOPROC)
               return "unknown processor-specific program header";

           return "(unknown)";
    }
}

const char * section_header_type_toString(Elf64_Word sht)
{
    switch (sht) {
        case SHT_NULL: return "SHT_NULL";
        case SHT_PROGBITS: return "SHT_PROGBITS";
        case SHT_SYMTAB: return "SHT_SYMTAB";
        case SHT_STRTAB: return "SHT_STRTAB";
        case SHT_RELA: return "SHT_RELA";
        case SHT_HASH: return "SHT_HASH";
        case SHT_DYNAMIC: return "SHT_DYNAMIC";
        case SHT_NOTE: return "SHT_NOTE";
        case SHT_NOBITS: return "SHT_NOBITS";
        case SHT_REL: return "SHT_REL";
        case SHT_SHLIB: return "SHT_SHLIB";
        case SHT_DYNSYM: return "SHT_DYNSYM";
        case SHT_INIT_ARRAY: return "SHT_INIT_ARRAY";
        case SHT_FINI_ARRAY: return "SHT_FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "SHT_PREINIT_ARRAY";
        case SHT_GROUP: return "SHT_GROUP";
        case SHT_SYMTAB_SHNDX: return "SHT_SYMTAB_SHNDX";
        case SHT_RELR: return "SHT_RELR";
        case SHT_NUM: return "SHT_NUM";
        case SHT_LOOS: return "SHT_LOOS";

        case SHT_GNU_ATTRIBUTES: return "SHT_GNU_ATTRIBUTES";
        case SHT_GNU_HASH: return "SHT_GNU_HASH";
        case SHT_GNU_LIBLIST: return "SHT_GNU_LIBLIST";
        case SHT_CHECKSUM: return "SHT_CHECKSUM";
        case SHT_GNU_verdef: return "SHT_GNU_verdef";
        case SHT_GNU_verneed: return "SHT_GNU_verneed";
        case SHT_GNU_versym: return "SHT_GNU_versym";

        case SHT_SUNW_move: return "SHT_SUNW_move";
        case SHT_SUNW_COMDAT: return "SHT_SUNW_COMDAT";
        case SHT_SUNW_syminfo: return "SHT_SUNW_syminfo";


        default:
            if (sht >= SHT_LOSUNW && sht <= SHT_HISUNW)
                return "unknown SUN-specific section header";
            else if (sht >= SHT_LOOS && sht <= SHT_HIOS)
                return "unknown OS-specific section header";

            if (sht >= SHT_LOPROC && sht <= SHT_HIPROC)
                return "unknown processor-specific section header";

            if (sht >= SHT_LOUSER && sht <= SHT_HIUSER)
                return "unknown application-specific section header";

            return "(unknown)";
    }
}

const char * dynamic_tag_to_string(Elf64_Sxword dt)
{
    switch (dt) {
        case DT_NULL: return "DT_NULL";
        case DT_NEEDED: return "DT_NEEDED";
        case DT_PLTRELSZ: return "DT_PLTRELSZ";
        case DT_PLTGOT: return "DT_PLTGOT";
        case DT_HASH: return "DT_HASH";
        case DT_STRTAB: return "DT_STRTAB";
        case DT_SYMTAB: return "DT_SYMTAB";
        case DT_RELA: return "DT_RELA";
        case DT_RELASZ: return "DT_RELASZ";
        case DT_RELAENT: return "DT_RELAENT";
        case DT_STRSZ: return "DT_STRSZ";
        case DT_SYMENT: return "DT_SYMENT";
        case DT_INIT: return "DT_INIT";
        case DT_FINI: return "DT_FINI";
        case DT_SONAME: return "DT_SONAME";
        case DT_RPATH: return "DT_RPATH";
        case DT_SYMBOLIC: return "DT_SYMBOLIC";
        case DT_REL: return "DT_REL";
        case DT_RELSZ: return "DT_RELSZ";
        case DT_RELENT: return "DT_RELENT";
        case DT_PLTREL: return "DT_PLTREL";
        case DT_DEBUG: return "DT_DEBUG";
        case DT_TEXTREL: return "DT_TEXTREL";
        case DT_JMPREL: return "DT_JMPREL";
        case DT_BIND_NOW: return "DT_BIND_NOW";
        case DT_INIT_ARRAY: return "DT_INIT_ARRAY";
        case DT_FINI_ARRAY: return "DT_FINI_ARRAY";
        case DT_INIT_ARRAYSZ: return "DT_INIT_ARRAYSZ";
        case DT_FINI_ARRAYSZ: return "DT_FINI_ARRAYSZ";
        case DT_RUNPATH: return "DT_RUNPATH";
        case DT_FLAGS: return "DT_FLAGS";
        case DT_PREINIT_ARRAY: return "DT_PREINIT_ARRAY";
        case DT_PREINIT_ARRAYSZ: return "DT_PREINIT_ARRAYSZ";
        case DT_SYMTAB_SHNDX: return "DT_SYMTAB_SHNDX";
        case DT_RELRSZ: return "DT_RELRSZ";
        case DT_RELR: return "DT_RELR";
        case DT_RELRENT: return "DT_RELRENT";

        case DT_GNU_PRELINKED: return "DT_GNU_PRELINKED";
        case DT_GNU_CONFLICTSZ: return "DT_GNU_CONFLICTSZ";
        case DT_GNU_LIBLISTSZ: return "DT_GNU_LIBLISTSZ";
        case DT_CHECKSUM: return "DT_CHECKSUM";
        case DT_PLTPADSZ: return "DT_PLTPADSZ";
        case DT_MOVEENT: return "DT_MOVEENT";
        case DT_MOVESZ: return "DT_MOVESZ";
        case DT_FEATURE_1: return "DT_FEATURE_1";
        case DT_POSFLAG_1: return "DT_POSFLAG_1";
        case DT_SYMINSZ: return "DT_SYMINSZ";
        case DT_SYMINENT: return "DT_SYMINENT";

        case DT_GNU_HASH: return "DT_GNU_HASH";
        case DT_TLSDESC_PLT: return "DT_TLSDESC_PLT";
        case DT_TLSDESC_GOT: return "DT_TLSDESC_GOT";
        case DT_GNU_CONFLICT: return "DT_GNU_CONFLICT";
        case DT_GNU_LIBLIST: return "DT_GNU_LIBLIST";
        case DT_CONFIG: return "DT_CONFIG";
        case DT_DEPAUDIT: return "DT_DEPAUDIT";
        case DT_AUDIT: return "DT_AUDIT";
        case DT_PLTPAD: return "DT_PLTPAD";
        case DT_MOVETAB: return "DT_MOVETAB";
        case DT_SYMINFO: return "DT_SYMINFO";

        case DT_VERSYM: return "DT_VERSYM";
        case DT_RELACOUNT: return "DT_RELACOUNT";
        case DT_RELCOUNT: return "DT_RELCOUNT";

        case DT_FLAGS_1: return "DT_FLAGS_1";
        case DT_VERDEF: return "DT_VERDEF";
        case DT_VERDEFNUM: return "DT_VERDEFNUM";
        case DT_VERNEED: return "DT_VERNEED";
        case DT_VERNEEDNUM: return "DT_VERNEEDNUM";

        case DT_AUXILIARY: return "DT_AUXILIARY";
        case DT_FILTER: return "DT_FILTER";

        default:
            if (dt >= DT_LOOS && dt <= DT_HIOS)
                return "unknown OS-specific dynamic tag";

            if (dt >= DT_LOPROC && dt <= DT_HIPROC)
                return "unknown processor-specific dynamic tag";

            return "(unknown)";
    }
}
