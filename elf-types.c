#include "elf-types.h"
#include "elf.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdalign.h>

/**
 * Reads a byte from a blob while ensuring that the offset is within bounds.
 *
 * @param[in] data The data to read from. Must not be NULL.
 *
 * @param[in,out] off_p The offset at which to read. Will be incremented
 *  to point past the read byte on success. Must not be NULL.
 *
 * @param[out] out Output pointer for the read value. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure (out of bounds).
 */
static int read_byte(const struct blob *data, uint64_t *off_p, uint8_t *out);

/**
 * Writes a byte to a blob while ensuring that the offset is within bounds.
 *
 * @param[in,out] data The data to write to. Must not be NULL.
 *
 * @param[in,out] off_p The offset at which to write. Will be incremented
 *  to point past the written byte on success. Must not be NULL.
 *
 * @param[in] val The value to write.
 *
 * @return 0 on success, non-zero on failure (out of bounds).
 */
static int write_byte(struct blob *data, uint64_t *off_p, uint8_t val);

static inline bool host_is_little_endian(void)
{
    const uint16_t x = UINT16_C(1);
    return *(const uint8_t *)&x == UINT8_C(1);
}

static int read_generic(const struct blob *data, uint64_t *off_p,
                        uint64_t n, uint8_t *out /* [n] */,
                        int encoding, const char *fnname)
{
#ifndef pr_error
    (void) fnname;
#endif /* pr_error */

    if (n > data->size || *off_p > data->size - n) {
        pr_error("%s: ([0x%" PRIx64 "]) Read of size %" PRIu64 " "
                 "would overflow data buffer (%" PRIu64 ")\n",
                 fnname, *off_p, n, data->size);
        return 1;
    } else if (*off_p > UINT64_MAX - n) {
        pr_error("%s: ([0x%" PRIx64 "]) Read of size %" PRIu64 " "
                 "would overflow the 64-bit integer limit\n",
                 fnname, *off_p, n);
        return 1;
    }

    const bool swap_needed =
        host_is_little_endian() != (encoding == ELFDATA2LSB);
    if (swap_needed) {
        for (uint64_t i = 0; i < n; i++)
            out[i] = data->data[*off_p + n - i - 1];
    } else {
        memcpy(out, data->data + *off_p, n);
    }

    *off_p += n;
    return 0;
}

static int write_generic(struct blob *data, uint64_t *off_p,
                         uint64_t n, const uint8_t *val /* [n] */,
                         int encoding, const char *fnname)
{
#ifndef pr_error
    (void) fnname;
#endif /* pr_error */

    if (n > data->size || *off_p > data->size - n) {
        pr_error("%s: ([0x%" PRIx64 "]) Write of size %" PRIu64 " "
                 "would overflow data buffer (%" PRIu64 ")\n",
                 fnname, *off_p, n, data->size);
        return 1;
    } else if (*off_p > UINT64_MAX - n) {
        pr_error("%s: ([0x%" PRIx64 "]) Write of size %" PRIu64 " "
                 "would overflow the 64-bit integer limit\n",
                 fnname, *off_p, n);
        return 1;
    }

    const bool swap_needed =
        host_is_little_endian() != (encoding == ELFDATA2LSB);
    if (swap_needed) {
        for (uint64_t i = 0; i < n; i++)
            data->data[*off_p + n - i - 1] = val[i];
    } else {
        memcpy(data->data + *off_p, val, n);
    }

    *off_p += n;
    return 0;
}

static inline int64_t decode_s64(uint64_t u)
{
    if (u <= INT64_MAX)
        return (int64_t)u;

    uint64_t magnitude = UINT64_MAX - u + UINT64_C(1);

    if (magnitude == UINT64_C(1) << 63)
        return INT64_MIN;

    return -(int64_t)magnitude;
}

static inline int32_t decode_s32(uint32_t u)
{
    if (u <= INT32_MAX)
        return (int32_t)u;

    uint32_t magnitude = UINT32_MAX - u + UINT32_C(1);

    if (magnitude == UINT32_C(1) << 31)
        return INT32_MIN;

    return -(int32_t)magnitude;
}

#define elf_64BIT_EXCLUSIVE_32bit_check do {                                \
    pr_error("%s: This type is not supported for ELFCLASS32\n", __func__);  \
    return 1;                                                               \
} while (0)

#define elf_BOTH_CLASSES_32bit_check (void)0

#define elf_SIGNED_read_conv(bits) decode_s##bits(tmp)
#define elf_UNSIGNED_read_conv(bits) tmp

#define DECL_ELF_PRIMITIVE(name, bits32, bits64,                               \
                           exclusive64, signedness, same_size)                 \
                                                                               \
int read_##name(const struct blob *data, uint64_t *off_p,                      \
                int clazz, int encoding,                                       \
                Elf64_##name *out)                                             \
{                                                                              \
    if (clazz == ELFCLASS32) {                                                 \
        { exclusive64##_32bit_check; }                                         \
                                                                               \
        uint##bits32##_t tmp;                                                  \
        if (read_generic(data, off_p, bits32 / 8, (uint8_t *)&tmp, encoding,   \
                         __func__))                                            \
            return 1;                                                          \
                                                                               \
        *out = (Elf64_##name) signedness##_read_conv(bits32);                  \
        return 0;                                                              \
    } else /* if (clazz == ELFCLASS64) */ {                                    \
        uint##bits64##_t tmp;                                                  \
        if (read_generic(data, off_p, bits64 / 8, (uint8_t *)&tmp, encoding,   \
                         __func__))                                            \
            return 1;                                                          \
                                                                               \
        *out = signedness##_read_conv(bits64);                                 \
        return 0;                                                              \
    }                                                                          \
}                                                                              \

ELF_PRIMITIVE_LIST

#undef DECL_ELF_PRIMITIVE
#undef elf_SIGNED_read_conv
#undef elf_UNSIGNED_read_conv


#define elf_SIGNED_32bit_write_limit_check(bits32, bits64, is_same_size) do {  \
    if (val < INT##bits32##_MIN || val > INT##bits32##_MAX) {                  \
        pr_error("%s: Value %" PRIi##bits64 " not within limits "              \
                 "of the 32-bit type\n", __func__, val);                       \
        return 1;                                                              \
    }                                                                          \
} while (0)


/* For same-size types (e.g. ElfXX_Half, ElfXX_Word), skip the
 * integer overflow check as it's never true */
#define elf_SAME_SIZE_32bit_unsigned_overflow_check(bits32, bits64) (void) 0

#define elf_DIFFERENT_SIZE_32bit_unsigned_overflow_check(bits32, bits64) do {  \
    if (val > UINT##bits32##_MAX) {                                            \
        pr_error("%s: Value %" PRIu##bits64 " overflows the 32-bit type\n",    \
                 __func__, val);                                               \
        return 1;                                                              \
    }                                                                          \
} while (0)

#define elf_UNSIGNED_32bit_write_limit_check(bits32, bits64, same_size)        \
                                                                               \
    same_size##_32bit_unsigned_overflow_check(bits32, bits64)                  \



#define DECL_ELF_PRIMITIVE(name, bits32, bits64,                               \
                           exclusive64, signedness, same_size)                 \
                                                                               \
int write_##name(struct blob *data, uint64_t *off_p,                           \
                 int clazz, int encoding,                                      \
                 Elf64_##name val)                                             \
{                                                                              \
    if (clazz == ELFCLASS32) {                                                 \
        { exclusive64##_32bit_check; }                                         \
                                                                               \
        { signedness##_32bit_write_limit_check(bits32, bits64, same_size); }   \
                                                                               \
        const uint##bits32##_t tmp = (uint##bits32##_t)val;                    \
        return write_generic(data, off_p, bits32 / 8, (const uint8_t *)&tmp,   \
                             encoding, __func__);                              \
    } else /* if (clazz == ELFCLASS64) */ {                                    \
        const uint##bits64##_t tmp = (uint##bits64##_t)val;                    \
        return write_generic(data, off_p, bits64 / 8, (const uint8_t *)&tmp,   \
                             encoding, __func__);                              \
    }                                                                          \
}                                                                              \

ELF_PRIMITIVE_LIST

#undef DECL_ELF_PRIMITIVE

#undef elf_SIGNED_32bit_write_limit_check
#undef elf_UNSIGNED_32bit_write_limit_check

#undef elf_64BIT_EXCLUSIVE_32bit_check
#undef elf_BOTH_CLASSES_32bit_check

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

#if 0
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
#endif /* 0 */
    return 0;
}

int write_phdr(struct blob *data, uint64_t *off_p,
               int clazz, int encoding, const Elf64_Phdr *phdr)
{
#if 0
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
#endif /* 0 */

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
        if (phdr->p_filesz > UINT32_MAX) {
            pr_error("p_filesz too large for Elf32_Word\n");
            return 1;
        }
        const Elf32_Word filesz = (Elf32_Word)phdr->p_filesz;
        if (phdr->p_memsz > UINT32_MAX) {
            pr_error("p_memsz too large for Elf32_Word\n");
            return 1;
        }
        const Elf32_Word memsz = (Elf32_Word)phdr->p_memsz;
        if (phdr->p_align > UINT32_MAX) {
            pr_error("p_align too large for Elf32_Word\n");
            return 1;
        }
        const Elf32_Word align = (Elf32_Word)phdr->p_align;
        if (write_Word(data, off_p, clazz, encoding, filesz) ||
            write_Word(data, off_p, clazz, encoding, memsz) ||
            write_Word(data, off_p, clazz, encoding, phdr->p_flags) ||
            write_Word(data, off_p, clazz, encoding, align))
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

    /* will write 8 bytes for ELFCLASS64 and 4 bytes for ELFCLASS32 */
    if (write_Addr(data, off_p, clazz, encoding, shdr->sh_flags))
        return 1;

    if (write_Addr(data, off_p, clazz, encoding, shdr->sh_addr) ||
        write_Off(data, off_p, clazz, encoding, shdr->sh_offset))
    {
        return 1;
    }

    /* will write 8 bytes for ELFCLASS64 and 4 bytes for ELFCLASS32 */
    if (write_Addr(data, off_p, clazz, encoding, shdr->sh_size))
        return 1;

    if (write_Word(data, off_p, clazz, encoding, shdr->sh_link) ||
        write_Word(data, off_p, clazz, encoding, shdr->sh_info))
    {
        return 1;
    }

    /* will write 8 bytes for ELFCLASS64 and 4 bytes for ELFCLASS32 */
    if (write_Addr(data, off_p, clazz, encoding, shdr->sh_addralign) ||
        write_Addr(data, off_p, clazz, encoding, shdr->sh_entsize))
        return 1;

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
    pr_debug("%s: tag: %s: writing 0x%" PRIx64 "\n", __func__,
            dynamic_tag_to_string(dyn->d_tag), dyn->d_un.d_val);
    if (clazz == ELFCLASS32) {
        if (dyn->d_tag > INT32_MAX || dyn->d_tag < INT32_MIN) {
            pr_error("%s: d_tag value outside of 32-bit integer limits\n",
                    __func__);
            return 1;
        }

        if (write_Sword(data, off_p, clazz, encoding, (Elf32_Sword)dyn->d_tag))
            return 1;

        /* See the above `read_dyn` */
        if (dyn->d_un.d_val > UINT32_MAX) {
            pr_error("%s: d_un value outside of 32-bit integer limits\n",
                    __func__);
            return 1;
        }
        if (write_Word(data, off_p, clazz, encoding,
                       (Elf32_Word)dyn->d_un.d_val))
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

int read_sym(const struct blob *data, uint64_t *off_p,
             int clazz, int encoding, Elf64_Sym *out)
{

    /* if you're wondering what's going on here, just look at the definitions
     * of `Elf32_Sym` and `Elf64_Sym` */

    if (read_Word(data, off_p, clazz, encoding, &out->st_name))
        return 1;

    if (clazz == ELFCLASS32) {
        if (read_Addr(data, off_p, clazz, encoding, &out->st_value))
            return 1;

        Elf32_Word tmp_size;
        if (read_Word(data, off_p, clazz, encoding, &tmp_size))
            return 1;
        out->st_size = (Elf64_Xword)tmp_size;

    }

    if (read_byte(data, off_p, &out->st_info) ||
        read_byte(data, off_p, &out->st_other) ||
        read_Section(data, off_p, clazz, encoding, &out->st_shndx))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (read_Addr(data, off_p, clazz, encoding, &out->st_value) ||
            read_Xword(data, off_p, clazz, encoding, &out->st_size))
        {
            return 1;
        }
    }

    return 0;
}

int write_sym(struct blob *data, uint64_t *off_p,
              int clazz, int encoding, const Elf64_Sym *sym)
{
    /* if you're wondering what's going on here, just look at the definitions
     * of `Elf32_Sym` and `Elf64_Sym` */

    if (write_Word(data, off_p, clazz, encoding, sym->st_name))
        return 1;

    if (clazz == ELFCLASS32) {
        if (sym->st_size > UINT32_MAX) {
            pr_error("%s: st_size value outside of 32-bit integer limit\n",
                    __func__);
            return 1;
        }

        if (write_Addr(data, off_p, clazz, encoding, sym->st_value) ||
            write_Word(data, off_p, clazz, encoding, (Elf32_Word)sym->st_size))
        {
            return 1;
        }
    }

    if (write_byte(data, off_p, sym->st_info) ||
        write_byte(data, off_p, sym->st_other) ||
        write_Section(data, off_p, clazz, encoding, sym->st_shndx))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (write_Addr(data, off_p, clazz, encoding, sym->st_value) ||
            write_Xword(data, off_p, clazz, encoding, sym->st_size))
        {
            return 1;
        }
    }

    return 0;
}

int write_verdef(struct blob *data, uint64_t *off_p,
                 int clazz, int encoding, const Elf64_Verdef *vd)
{
    return 0
        || write_Half(data, off_p, clazz, encoding, vd->vd_version)
        || write_Half(data, off_p, clazz, encoding, vd->vd_flags)
        || write_Half(data, off_p, clazz, encoding, vd->vd_ndx)
        || write_Half(data, off_p, clazz, encoding, vd->vd_cnt)
        || write_Word(data, off_p, clazz, encoding, vd->vd_hash)
        || write_Word(data, off_p, clazz, encoding, vd->vd_aux)
        || write_Word(data, off_p, clazz, encoding, vd->vd_next);
}

int read_verdef(const struct blob *data, uint64_t *off_p,
                int clazz, int encoding, Elf64_Verdef *out)
{
    return 0
        || read_Half(data, off_p, clazz, encoding, &out->vd_version)
        || read_Half(data, off_p, clazz, encoding, &out->vd_flags)
        || read_Half(data, off_p, clazz, encoding, &out->vd_ndx)
        || read_Half(data, off_p, clazz, encoding, &out->vd_cnt)
        || read_Word(data, off_p, clazz, encoding, &out->vd_hash)
        || read_Word(data, off_p, clazz, encoding, &out->vd_aux)
        || read_Word(data, off_p, clazz, encoding, &out->vd_next);
}

int write_verdaux(struct blob *data, uint64_t *off_p,
                  int clazz, int encoding, const Elf64_Verdaux *vda)
{
    return write_Word(data, off_p, clazz, encoding, vda->vda_name) ||
           write_Word(data, off_p, clazz, encoding, vda->vda_next);
}

int read_verdaux(const struct blob *data, uint64_t *off_p,
                 int clazz, int encoding, Elf64_Verdaux *out)
{
    return read_Word(data, off_p, clazz, encoding, &out->vda_name) ||
           read_Word(data, off_p, clazz, encoding, &out->vda_next);
}

int write_verneed(struct blob *data, uint64_t *off_p,
                  int clazz, int encoding, const Elf64_Verneed *vn)
{
    return 0
        || write_Half(data, off_p, clazz, encoding, vn->vn_version)
        || write_Half(data, off_p, clazz, encoding, vn->vn_cnt)
        || write_Word(data, off_p, clazz, encoding, vn->vn_file)
        || write_Word(data, off_p, clazz, encoding, vn->vn_aux)
        || write_Word(data, off_p, clazz, encoding, vn->vn_next);
}

int read_verneed(const struct blob *data, uint64_t *off_p,
                 int clazz, int encoding, Elf64_Verneed *out)
{
    return 0
        || read_Half(data, off_p, clazz, encoding, &out->vn_version)
        || read_Half(data, off_p, clazz, encoding, &out->vn_cnt)
        || read_Word(data, off_p, clazz, encoding, &out->vn_file)
        || read_Word(data, off_p, clazz, encoding, &out->vn_aux)
        || read_Word(data, off_p, clazz, encoding, &out->vn_next);
}

int write_vernaux(struct blob *data, uint64_t *off_p,
                  int clazz, int encoding, const Elf64_Vernaux *vna)
{
    return 0
        || write_Word(data, off_p, clazz, encoding, vna->vna_hash)
        || write_Half(data, off_p, clazz, encoding, vna->vna_flags)
        || write_Half(data, off_p, clazz, encoding, vna->vna_other)
        || write_Word(data, off_p, clazz, encoding, vna->vna_name)
        || write_Word(data, off_p, clazz, encoding, vna->vna_next);
}

int read_vernaux(const struct blob *data, uint64_t *off_p,
                 int clazz, int encoding, Elf64_Vernaux *out)
{
    return 0
        || read_Word(data, off_p, clazz, encoding, &out->vna_hash)
        || read_Half(data, off_p, clazz, encoding, &out->vna_flags)
        || read_Half(data, off_p, clazz, encoding, &out->vna_other)
        || read_Word(data, off_p, clazz, encoding, &out->vna_name)
        || read_Word(data, off_p, clazz, encoding, &out->vna_next);
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


           if (pt >= PT_LOPROC && pt <= PT_HIPROC)
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

static int read_byte(const struct blob *data, uint64_t *off_p, uint8_t *out)
{
    if (*off_p >= data->size) {
        pr_error("%s: ([0x%" PRIx64 "]) Not enough data\n", __func__, *off_p);
        return 1;
    }

    *out = data->data[(*off_p)++];
    return 0;
}

static int write_byte(struct blob *data, uint64_t *off_p, uint8_t val)
{
    if (*off_p >= data->size) {
        pr_error("%s: ([0x%" PRIx64 "]) Not enough data\n", __func__, *off_p);
        return 1;
    }

    data->data[(*off_p)++] = val;
    return 0;
}
