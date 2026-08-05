#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdalign.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>
#include <sys/stat.h>
#include <elf.h>

#define pr_error(...) fprintf(stderr, __VA_ARGS__)

#if 1
#define pr_debug printf
#else
static void __attribute__((format(printf, 1, 2)))
dummy_pr_debug__(const char *fmt, ...) { (void) fmt; }
#define pr_debug(...) dummy_pr_debug__(__VA_ARGS__)
#endif /* 0 */

/* Container for an array of bytes */
struct blob {
    uint64_t size;
    uint8_t *data;
};

/* Container for all data required to parse, patch and re-serialize
 * an ELF file (any class, any data encoding).
 *
 * Populated by `read_elf` and destroyed with `destroy_elf`. */
struct elf {
    struct elf_ident {
        uint8_t magic[SELFMAG]; /* 0x7f 'E' 'L' 'F' */
        uint8_t clazz;
        uint8_t data; /* endianness */
        uint8_t version;
        uint8_t os_abi;
        uint8_t abi_version;

        uint8_t pad_[7];
    } __attribute__((packed)) ident;
    static_assert(sizeof(struct elf_ident) == EI_NIDENT, "Invalid size");

    /* Parsed ELF header */
    Elf64_Ehdr ehdr;
    bool ehdr_dirty;

    /* If section headers are present, index into `shdrs.arr`
     * where the section header string table is */
    Elf64_Word shstrndx;

    /* Array of parsed program headers */
    struct elf_phdrs {
        Elf64_Xword num;
        Elf64_Phdr *arr;
        bool dirty;
    } phdrs;

    /* Array of parsed section headers */
    struct elf_shdrs {
        Elf64_Xword num;
        Elf64_Shdr *arr;
        bool dirty;
    } shdrs;

    /* Everything related to the dynamic section
     * (PT_DYNAMIC segment / SHT_DYNAMIC ".dynamic" section) */
    struct elf_dynamic {
        /* Array of the parsed DT_* Elf64_Dyn entries */
        struct elf_dyn_entries {
            Elf64_Xword num;
            Elf64_Dyn *arr;
            bool dirty;
        } entries;

        /* Pointer to the PT_DYNAMIC program header (reference into `phdrs`).
         * On success, `read_validate_dynamic_section`
         * will always write a non-NULL value here. */
        Elf64_Phdr *phdr;

        /* Pointer to the SHT_DYNAMIC section header (reference into `shdrs`).
         * `read_validate_dynamic_section` might write NULL here. */
        Elf64_Shdr *shdr;

        /* The value of the DT_STRTAB entry;
         * contains the virtual addres of the .dynamic string table. */
        Elf64_Addr strtab_vaddr;

        /* The offset of the .dynamic string table within the ELF data */
        Elf64_Off strtab_off;

        /* The value of the DT_STRSZ entry;
         * the size of the string table pointed to by `strtab`. */
        Elf64_Xword strtab_sz;

        /* Pointer to the .dynstr section header (reference into `shdrs`).
         * Might be NULL if there's no .dynstr section. */
        Elf64_Shdr *strtab_shdr;
    } dyn;

    /* The raw bytes of the ELF file */
    struct blob data;
};

static inline int popcnt(uint64_t x) {
    int ret = 0;
    for (int i = 0; i < 64; i++) {
        if (x & (UINT64_C(1) << i))
            ret++;
    }
    return ret;
}
static inline uint64_t align_pow2(uint64_t x, uint64_t n) {
    if (popcnt(n) != 1) {
        pr_error("%s: Not a power of two\n", __func__);
        fflush(stderr);
        abort();
    }

    if (x > UINT64_MAX - (n - 1)) {
        pr_error("%s: Integer overflow\n", __func__);
        fflush(stderr);
        abort();
    }

    return (x + (n - 1)) & ~(n - 1);
}

static inline bool ranges_overlap(uint64_t start1, uint64_t size1,
                                  uint64_t start2, uint64_t size2)
{
    if (start1 > UINT64_MAX - size1 ||
        start2 > UINT64_MAX - size2)
    {
        pr_error("%s: Invalid ranges (integer overflow)\n", __func__);
        return false;
    }

    const uint64_t end1 = start1 + size1;
    const uint64_t end2 = start2 + size2;

    return start1 < end2 && start2 < end1;
}

static int read_file(const char *path, struct blob *out);

static const char * elf_type_toString(Elf64_Half et);
static int read_validate_ident(const struct blob *data, struct elf_ident *out);
static int read_validate_ehdr(const struct blob *data, int clazz, int encoding,
                              Elf64_Ehdr *out);
static int write_ehdr(struct blob *data, uint64_t *off_p,
                      int clazz, int encoding, const Elf64_Ehdr *ehdr);

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
static int update_phnum(struct elf_phdrs *phdrs, Elf64_Xword new_size,
                        Elf64_Half *out_ehdr_e_phnum_p,
                        struct elf_shdrs *shdrs);

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
static int update_shnum(struct elf_shdrs *shdrs, Elf64_Xword new_size,
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
static int update_shstrndx(Elf64_Word val,
                           Elf64_Word *out, Elf64_Half *out_ehdr_shstrndx_p,
                           struct elf_shdrs *shdrs);

static int read_phdr(const struct blob *data, uint64_t *off_p,
                     int clazz, int encoding, Elf64_Phdr *out);
static int read_validate_phdrs(const struct blob *data, struct elf_phdrs *out,
                               const Elf64_Ehdr *ehdr, int clazz, int encoding);
static int write_phdr(struct blob *data, uint64_t *off_p,
                      int clazz, int encoding, const Elf64_Phdr *phdr);

static const Elf64_Phdr * get_load_segment_containing_range(
        const Elf64_Phdr *phdrs, Elf64_Xword nphdrs,
        Elf64_Xword start, Elf64_Xword size
);

static int read_shdr(const struct blob *data, uint64_t *off_p,
                     int clazz, int encoding, Elf64_Shdr *out);
static int read_validate_shdrs(const struct blob *data, struct elf_shdrs *out,
                               const Elf64_Ehdr *ehdr, int clazz, int encoding);
static int write_shdr(struct blob *data, uint64_t *off_p,
                      int clazz, int encoding, const Elf64_Shdr *shdr);

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
    DECL_ELF_PRIMITIVE_FN(Sword, 32, 32, int, INT32, INT32,             \
                          no_exclusive_64bit, same_size)                \
    DECL_ELF_PRIMITIVE_FN(Sxword, 64, 64, int, INT64, INT64,            \
                          exclusive_64bit, same_size)                   \


#define DECL_ELF_PRIMITIVE_FN(elf_type, bits32, bits64,                 \
                              t_prefix, prefix32, prefix64,             \
                              exclusive_64__, same_size__)              \
                                                                        \
static int read_##elf_type(const struct blob *data, uint64_t *off_p,    \
                           int clazz, int endianness,                   \
                           Elf64_##elf_type *out);                      \
                                                                        \
static int write_##elf_type(struct blob *data, uint64_t *off_p,         \
                            int clazz, int endianness,                  \
                            Elf64_##elf_type val);                      \

ELF_PRIMITIVE_FN_LIST

#undef DECL_ELF_PRIMITIVE_FN
#undef exclusive_64bit
#undef no_exclusive_64bit
#undef same_size
#undef different_size

/**
 * Reads, parses and validates an ELF file located at `path`.
 *
 * @param path The path to the ELF file to load.
 *
 * @param out Output pointer.
 *  Can be NULL, in which case the ELF file is only validated,
 *  without any side effects.
 *  If non-NULL and the function succeeds, it is populated with a
 *  valid `struct elf` and should later be freed with `destroy_elf`.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_elf(const char *path, struct elf *out);

static const char * section_name_strptr(const struct elf *elf,
                                        Elf64_Addr sh_name);

static __attribute__((unused))
const char * section_type_toString(Elf64_Word sht);
static void list_sections(const struct elf *elf);

static void find_load_segment_limits(const struct elf *elf,
                                     uint64_t *out_vaddr, uint64_t *out_align);
#define SUS_REPLACEMENT_STRING "TEST"
static int modify_and_move_program_headers(struct elf *elf);

/**
 * Parses the dynamic section from `elf`.
 * The parsing is done using the PT_DYNAMIC program header,
 * without reliance on the section headers.
 * However, if a SHT_DYNAMIC section is found, it will be validated
 * against the PT_DYNAMIC program header.
 *
 * @param data The ELF file data.
 *
 * @param clazz The ELF file class (ELFCLASS32 or ELFCLASS64).
 *
 * @param encoding The ELF file data encoding (ELFDATA2MSB or ELFDATA2LSB).
 *
 * @param phdrs Array of parsed and validated program headers. Must not be NULL.
 *
 * @param shdrs Array of parsed and validated section haeders. Must not be NULL.
 *
 * @param out_entries Output pointer.
 *  May be NULL, in which case it simply won't be written to
 *  and the resources will be freed automatically.
 *
 * @return 0 on success (valid PT_DYNAMIC phdr),
 *  non-zero on failure (invalid or non-existent PT_DYNAMIC phdr,
 *                       present but invalid SHT_DYNAMIC shdr).
 */
static int read_validate_dynamic_section(
        const struct blob *data, int clazz, int encoding,
        struct elf_phdrs *phdrs, struct elf_shdrs *shdrs,

        struct elf_dynamic *out
);

/**
 * Validates a PT_DYNAMIC program header.
 * Part of `read_validate_dynamic_section`.
 *
 * @param pt_dynamic The PT_DYNAMIC program header. Must not be NULL.
 *
 * @param entsize Size of an ElfXX_Dyn entry (depends on the ELF's class).
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_pt_dynamic(const Elf64_Phdr *pt_dynamic, size_t entsize);

/**
 * Validates a SHT_DYNAMIC section header.
 * Part of `read_validate_dynamic_section`.
 *
 * @param sht_dynamic The SHT_DYNAMIC section header to validate.
 *  Must not be NULL.
 *
 * @param pt_dynamic The previously checked PT_DYNAMIC program header,
 *  against which @sht_dynamic is to be validated. Must not be NULL.
 *
 * @param entsize Size of an ElfXX_Dyn entry (depends on the ELF's class).
 *
 * @return 0 on success, non-zero on failure.
 */
static int validate_sht_dynamic(const Elf64_Shdr *sht_dynamic,
                                const Elf64_Phdr *pt_dynamic, size_t entsize);

/**
 * Parses and validates the array of dynamic entries
 * pointed to by a PT_DYNAMIC program header.
 * Part of `read_validate_dynamic_section`.
 *
 * @param data The ELF file's data. Must not be NULL.
 *
 * @param clazz The ELF file's class.
 *
 * @param encoding The ELF file's byte order.
 *
 * @param count Number of dynamic entries.
 *
 * @param pt_dynamic The previously validated PT_DYNAMIC program header.
 *  Must not be NULL.
 *
 * @param Output pointer. Must not be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
static int parse_dyn_array(
        const struct blob *data, int clazz, int encoding,
        Elf64_Xword count, const Elf64_Phdr *pt_dynamic,

        Elf64_Dyn **out
);

/**
 * Finds and validates a .dynstr section header
 * corresponding to data found in the program headers.
 *
 * @param shdrs The section header array.
 *  The array is not modified by this function.
 *
 * @param shnum The number of section headers.
 *
 * @param addr Virtual address of the dynamic string table
 *  (the value of DT_STRTAB).
 *
 * @param off Offset withing the ELF file of the dynamic string table.
 *
 * @param size Size of the dynamic string table (the value of DT_STRSZ).
 *
 * @param out Output pointer for the found valid .dynstr section header.
 *  On success it will either contain a reference into `shdrs`
 *  or NULL (if there's no .dynstr section).
 *
 * @return 0 on success, non-zero on failure.
 */
static int find_validate_strtab_shdr(Elf64_Shdr *shdrs, Elf64_Xword shnum,
                                     Elf64_Addr addr, Elf64_Off off,
                                     Elf64_Xword size, Elf64_Shdr **out);

static int read_dyn(const struct blob *data, uint64_t *off_p,
                     int clazz, int encoding, Elf64_Dyn *out);
static int write_dyn(struct blob *data, uint64_t *off_p,
                      int clazz, int encoding, const Elf64_Dyn *dyn);

static void print_dynamic_section(const struct elf *elf);

static int modify_and_move_dynamic_section(struct elf *elf, uint64_t *off_p);

typedef int (*serializer_proc_t)(struct blob *out, uint64_t *off_p,
                                 int clazz, int encoding, const void *data);

static int serialize_arr(struct blob *data, serializer_proc_t serializer,
                         const void *arr, size_t mementsize,
                         uint64_t off, Elf64_Half fileentsize, Elf64_Xword size,
                         int clazz, int endianness);

static int serialize_elf(struct elf *elf);
static int write_elf(const struct elf *elf, const char *path);
static void destroy_elf(struct elf *elf);

int main(int argc, char **argv)
{
    struct elf elf = { 0 };

    if (argc <= 2) {
        pr_error("Not enough args\n"
                        "Usage: %s <in ELF file> <out ELF file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (read_elf(argv[1], &elf)) goto err;

    list_sections(&elf);

    if (elf.dyn.shdr != NULL) {
        printf("Dynamic section name: \"%s\"\n",
                section_name_strptr(&elf, elf.dyn.shdr->sh_name));
    }
    if (elf.dyn.strtab_shdr != NULL) {
        printf("Dynamic string table section name: \"%s\"\n",
                section_name_strptr(&elf, elf.dyn.strtab_shdr->sh_name));
    }

    if (modify_and_move_program_headers(&elf))
        goto err;

    if (serialize_elf(&elf))
        goto err;
    if (write_elf(&elf, argv[2]))
        goto err;

    destroy_elf(&elf);
    return EXIT_SUCCESS;

err:
    destroy_elf(&elf);
    return EXIT_FAILURE;
}

static int read_file(const char *path, struct blob *out)
{
    int fd = -1;
    uint8_t *buf = NULL;
    struct stat st = { 0 };

    out->data = NULL;
    out->size = 0;

    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1) {
        pr_error("Failed to open input file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    }
    if (fstat(fd, &st)) {
        pr_error("Failed to stat input file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    } else if (st.st_size < 0 ||
            (uint64_t)st.st_size > UINT64_MAX ||
            (uint64_t)st.st_size > SIZE_MAX)
    {
        pr_error("Invalid input file size\n");
        goto err;
    }

    if ((buf = malloc(st.st_size)) == NULL) {
        pr_error("Failed to allocate ELF file data buffer\n");
        goto err;
    }

    if (read(fd, buf, st.st_size) == -1) {
        pr_error("Failed to read %zu bytes from input file "
                        "\"%s\": %d (%s)\n",
                (size_t)st.st_size, path, errno, strerror(errno)
        );
        goto err;
    }

    if (close(fd)) {
        pr_error("Failed to close the input file fd: %d (%s)\n",
                errno, strerror(errno));
        fd = -1;
        goto err;
    }
    fd = -1;

    out->data = buf; buf = NULL;
    out->size = st.st_size;

    return 0;

err:
    if (buf != NULL) {
        free(buf);
        buf = NULL;
    }

    if (fd != -1) {
        if (close(fd)) {
            pr_error("Failed to close the input file fd: %d (%s)\n",
                    errno, strerror(errno));
        }
        fd = -1;
    }

    return 1;
}

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
        Elf32_##elf_type tmp = (Elf32_##elf_type)                              \
            *(const t_prefix##bits32##_t *)(data->data + *off_p);              \
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
        Elf64_##elf_type tmp = (Elf64_##elf_type)                              \
            *(const t_prefix##bits64##_t *)(data->data + *off_p);              \
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
static int read_##elf_type(const struct blob *data, uint64_t *off_p,           \
                           int clazz, int endianness,                          \
                           Elf64_##elf_type *out)                              \
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
            *(t_prefix##bits32##_t *)(data->data + *off_p) =                   \
                htobe##bits32((t_prefix##bits32##_t)val);                      \
        } else /* if (endianness == ELFDATA2LSB) */ {                          \
            *(t_prefix##bits32##_t *)(data->data + *off_p) =                   \
                htole##bits32((t_prefix##bits32##_t)val);                      \
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
            *(t_prefix##bits64##_t *)(data->data + *off_p) =                   \
                htobe##bits64((t_prefix##bits64##_t)val);                      \
        } else /* if (endianness == ELFDATA2LSB) */ {                          \
            *(t_prefix##bits64##_t *)(data->data + *off_p) =                   \
                htole##bits64((t_prefix##bits64##_t)val);                      \
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
static int write_##elf_type(struct blob *data, uint64_t *off_p,                \
                            int clazz, int endianness,                         \
                            Elf64_##elf_type val)                              \
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

static const char * elf_type_toString(Elf64_Half et)
{
    switch (et) {
        case ET_NONE: return "ET_NONE";
        case ET_REL: return "ET_REL";
        case ET_EXEC: return "ET_EXEC";
        case ET_DYN: return "ET_DYN";
        case ET_CORE: return "ET_CORE";
        default: return "(unknown)";
    }
}

static int read_validate_ident(const struct blob *data, struct elf_ident *out)
{
    if (data->size < EI_NIDENT) {
        pr_error("File too small to be an ELF file\n");
        return -1;
    }
    memcpy(out, data->data, EI_NIDENT);

    int ret = 0;

    if (memcmp(&out->magic, ELFMAG, SELFMAG)) {
        pr_error("Invalid ELF magic!\n");
        ret = 1;
    }

    if (out->version != EV_CURRENT) {
        pr_error("Invalid version: 0x%" PRIx8 "\n",
                out->version);
        ret = 1;
    }

    if (out->clazz != ELFCLASS32 &&
        out->clazz != ELFCLASS64)
    {
        pr_error("Invalid class: 0x%" PRIx8 "\n",
                out->clazz);
        ret = 1;
    } else {
        pr_debug("Class: %s\n",
                out->clazz == ELFCLASS32 ? "ELFCLASS32": "ELFCLASS64");
    }

    if (out->data != ELFDATA2LSB &&
        out->data != ELFDATA2MSB)
    {
        pr_error("Invalid data: 0x%" PRIx8 "\n",
                out->data);
        ret = 1;
    } else {
        pr_debug("Data: 2's complement, %s endian\n",
                out->data == ELFDATA2MSB ? "big": "little");
    }

    /* We don't care about ABIs */
    (void) out->os_abi;
    (void) out->abi_version;

    return ret;
}

static int read_validate_ehdr(const struct blob *data, int clazz, int encoding,
                              Elf64_Ehdr *out)
{
    if ((clazz == ELFCLASS32 && data->size < sizeof(Elf32_Ehdr)) ||
        (clazz == ELFCLASS64 && data->size < sizeof(Elf64_Ehdr)))
    {
        pr_error("File too small to be an ELF file\n");
        return 1;
    }

    uint64_t off = UINT64_C(0);
    memcpy(&out->e_ident, data->data, EI_NIDENT);
    off += EI_NIDENT;

    if (read_Half(data, &off, clazz, encoding, &out->e_type) ||
        read_Half(data, &off, clazz, encoding, &out->e_machine) ||
        read_Word(data, &off, clazz, encoding, &out->e_version) ||
        read_Addr(data, &off, clazz, encoding, &out->e_entry) ||
        read_Off(data, &off, clazz, encoding, &out->e_phoff) ||
        read_Off(data, &off, clazz, encoding, &out->e_shoff) ||
        read_Word(data, &off, clazz, encoding, &out->e_flags) ||
        read_Half(data, &off, clazz, encoding, &out->e_ehsize) ||
        read_Half(data, &off, clazz, encoding, &out->e_phentsize) ||
        read_Half(data, &off, clazz, encoding, &out->e_phnum) ||
        read_Half(data, &off, clazz, encoding, &out->e_shentsize) ||
        read_Half(data, &off, clazz, encoding, &out->e_shnum) ||
        read_Half(data, &off, clazz, encoding, &out->e_shstrndx))
    {
        return 1;
    }

    int ret = 0;

    pr_debug("ELF type: 0x%" PRIx16 " (%s)\n",
            out->e_type, elf_type_toString(out->e_type));
    if (out->e_type != ET_DYN) {
        pr_error("Unsupported ELF type 0x%" PRIx16 " (%s); must be ET_DYN "
                "(Dynamic executable or shared library)\n",
                out->e_type, elf_type_toString(out->e_type));
        ret = 1;
    }

    pr_debug("ELF version: 0x%" PRIx32 "\n", out->e_version);
    if (out->e_version != EV_CURRENT) {
        pr_error("Invalid ELF version (must be 1)\n");
        ret = 1;
    }

    pr_debug("Entry point: 0x%" PRIx64 "\n", out->e_entry);
    pr_debug("Program headers offset: 0x%" PRIx64 "\n", out->e_phoff);
    if (out->e_phoff == 0) {
        pr_error("No program headers!\n");
        ret = 1;
    }
    pr_debug("Section headers offset: 0x%" PRIx64 "\n", out->e_shoff);
    pr_debug("Flags: 0x%" PRIx32 "\n", out->e_flags);

    pr_debug("ELF header size: 0x%" PRIx16 "\n", out->e_ehsize);
    if ((clazz == ELFCLASS32 && out->e_ehsize != sizeof(Elf32_Ehdr)) ||
        (clazz == ELFCLASS64 && out->e_ehsize != sizeof(Elf64_Ehdr)))
    {
        pr_error("Invalid ELF header size\n");
        ret = 1;
    }

    pr_debug("Program header size: 0x%" PRIx16 "\n", out->e_phentsize);
    if ((clazz == ELFCLASS32 && out->e_phentsize != sizeof(Elf32_Phdr)) ||
        (clazz == ELFCLASS64 && out->e_phentsize != sizeof(Elf64_Phdr)))
    {
        pr_error("Invalid program header size\n");
        ret = 1;
    }

    pr_debug("Number of program headers: %" PRIu16 "\n", out->e_phnum);
    if (out->e_phnum >= PN_XNUM) {
        if (out->e_shoff == 0 || out->e_shnum < 1) {
            pr_error("Section headers required for PN_XNUM (2^16 - 1) "
                    "or more program headers\n");
            ret = 1;
        }
    }

    pr_debug("Section header size: 0x%" PRIx16 "\n", out->e_shentsize);
    if ((clazz == ELFCLASS32 && out->e_shentsize != sizeof(Elf32_Shdr)) ||
        (clazz == ELFCLASS64 && out->e_shentsize != sizeof(Elf64_Shdr)))
    {
        pr_error("Invalid section header size\n");
        ret = 1;
    }

    pr_debug("Number of section headers: %" PRIu16 "\n", out->e_shnum);
    if (out->e_shnum >= SHN_LORESERVE) {
        /*
        pr_error("Section header count >= SHN_LORESERVE unsupported\n");
        ret = 1;
        */
    }

    pr_debug("Section header string table index: 0x%" PRIx16 "\n",
            out->e_shstrndx);
    if (out->e_shnum != 0 && out->e_shstrndx >= out->e_shnum) {
        pr_error("Section header string table index out of bounds\n");
        ret = 1;
    } else if ((out->e_shnum == 0 || out->e_shoff == 0) && out->e_shstrndx != 0) {
        pr_error("Section header string table index non-zero "
                "when section headers aren't present\n");
        ret = 1;
    }
    if (out->e_shstrndx >= SHN_LORESERVE) {
        pr_error("Section string table index "
                ">= SHN_LORESERVE is not supported\n");
        ret = 1;
    }

    return ret;
}

static int write_ehdr(struct blob *data, uint64_t *off_p,
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

static int update_phnum(struct elf_phdrs *phdrs, Elf64_Xword new_size,
                        Elf64_Half *out_ehdr_e_phnum_p,
                        struct elf_shdrs *shdrs)
{
    /* see `update_shnum`, does almost the same thing
     * but is a more pleasant to read */

    if (new_size == 0) {
        pr_error("%s: Resizing to 0 means the program headers "
                "would have to be deleted entirely, "
                "which is not supported here.\n",
                __func__);
        goto err;
    }

    /** Resize the phdrs array **/

    if (phdrs->num > SIZE_MAX / sizeof(Elf64_Phdr)) {
        pr_error("%s: Old size too large (integer overflow)\n",
                __func__);
        goto err;
    }
    if (new_size > SIZE_MAX / sizeof(Elf64_Phdr)) {
        pr_error("%s: New size too large (integer overflow)\n",
                __func__);
        goto err;
    }
    const size_t prevsz = phdrs->num * sizeof(Elf64_Phdr);
    const size_t newsz = new_size * sizeof(Elf64_Phdr);

    {
        /* `realloc(NULL, sz)` is equivalent to `malloc(sz)` */
        void *tmp = realloc(phdrs->arr, newsz);
        if (tmp == NULL) {
            pr_error("Failed to resize (realloc) the program headers array\n");
            goto err;
        }
        phdrs->arr = tmp;
    }
    /* append zeroized entries if growing */
    if (newsz > prevsz)
        memset((uint8_t *)phdrs->arr + prevsz, 0, newsz - prevsz);

    /** Update the headers' fields */

    if (new_size < PN_XNUM) {
        /* "normal" case */
        *out_ehdr_e_phnum_p = (Elf64_Half)new_size;
    } else /* if (val >= PN_XNUM) */ {
        if (shdrs == NULL || shdrs->arr == NULL || shdrs->num < 1) {
            pr_error("%s: No section headers; can't resize past PN_XNUM\n",
                     __func__);
            goto err;
        }

        /**
         * The spec says that if the phnum is >= PN_XNUM,
         * `e_phnum` should contain `PN_XNUM` while the real number of phdrs
         * should be stored in the `sh_info` field of the first section header.
         */
        *out_ehdr_e_phnum_p = PN_XNUM;
        shdrs->arr[0].sh_info = new_size;
        shdrs->dirty = true;
    }

    phdrs->num = new_size;
    phdrs->dirty = true;
    return 0;

err:
    if (phdrs->arr != NULL) {
        free(phdrs->arr);
        phdrs->arr = NULL;
    }
    phdrs->num = 0;
    phdrs->dirty = false;
    return 1;
}

static __attribute__((unused))
int update_shnum(struct elf_shdrs *shdrs, Elf64_Xword new_size,
                 Elf64_Half *out_ehdr_e_shnum_p)
{
    if (new_size == 0) {
        pr_error("%s: Resizing to 0 means the section headers "
                "would have to be deleted entirely, "
                "which is not supported here.\n",
                __func__);
        goto err;
    }

    /** Resize the `shdrs` array **/
    if (shdrs->num > SIZE_MAX / sizeof(Elf64_Shdr)) {
        pr_error("%s: Old size too large (integer overflow)\n", __func__);
        goto err;
    }
    if (new_size > SIZE_MAX / sizeof(Elf64_Shdr)) {
        pr_error("%s: New size too large (integer overflow)\n", __func__);
        goto err;
    }
    const size_t prevsz = shdrs->num * sizeof(Elf64_Shdr);
    const size_t newsz = new_size * sizeof(Elf64_Shdr);

    {
        /* `realloc(NULL, sz)` is equivalent to `malloc(sz)` */
        void *tmp = realloc(shdrs->arr, newsz);
        if (tmp == NULL) {
            pr_error("Failed to resize (realloc) the section headers array\n");
            goto err;
        }
        shdrs->arr = tmp;
    }
     /* append zeroized entries if growing */
    if (newsz > prevsz)
        memset((uint8_t *)shdrs->arr + prevsz, 0, newsz - prevsz);

    /** Update the headers' fields **/
    if (new_size < SHN_LORESERVE) {
        /* "normal" case */
        *out_ehdr_e_shnum_p = (Elf64_Half)new_size;
    } else /* if (new_size >= SHN_LORESERVE) */ {
        /**
         * The spec says that if the shnum is >= SHN_LORESERVE,
         * `e_shnum` should contain the value `0` while the real number of shdrs
         * should be stored in the `sh_size` field of the first section header.
         */
        *out_ehdr_e_shnum_p = 0;
        shdrs->arr[0].sh_size = new_size;
    }

    shdrs->num = new_size;
    shdrs->dirty = true;
    return 0;

err:
    if (shdrs->arr != NULL) {
        free(shdrs->arr);
        shdrs->arr = NULL;
    }
    shdrs->num = 0;
    shdrs->dirty = false;
    return 1;
}

static __attribute__((unused))
int update_shstrndx(Elf64_Word val,
                    Elf64_Word *out, Elf64_Half *out_ehdr_shstrndx_p,
                    struct elf_shdrs *shdrs)
{
    if (val == 0) {
        /* just for good measure */
        if (shdrs != NULL && shdrs->num > 0 && shdrs->arr != NULL)
            shdrs->arr[0].sh_link = 0;

        *out = 0;
        *out_ehdr_shstrndx_p = SHN_UNDEF;
        return 0;
    } else if (val < SHN_LORESERVE) {
        if (shdrs != NULL && shdrs->num > 0 && shdrs->arr != NULL)
            shdrs->arr[0].sh_link = 0;

        *out = val;
        *out_ehdr_shstrndx_p = (Elf64_Half)val;
        return 0;
    } else /* if (val >= SHN_LORESERVE) */ {
        if (shdrs == NULL || shdrs->num < 1 || shdrs->arr == NULL) {
            pr_error("%s: No section headers; "
                    "can't set index past `SHN_LORESERVE`\n",
                    __func__);
            return -1;
        }

        shdrs->arr[0].sh_link = val;
        shdrs->dirty = true;
        *out_ehdr_shstrndx_p = SHN_XINDEX;
        *out = val;
        return 0;
    }
}

static int read_phdr(const struct blob *data, uint64_t *off_p,
                     int clazz, int endianness, Elf64_Phdr *out)
{
    if (read_Word(data, off_p, clazz, endianness, &out->p_type))
        return 1;

    /* In ELF32 `p_flags` is in a different place than in ELF64 */
    if (clazz == ELFCLASS64)
        if (read_Word(data, off_p, clazz, endianness, &out->p_flags))
            return 1;

    if (read_Off(data, off_p, clazz, endianness, &out->p_offset) ||
        read_Addr(data, off_p, clazz, endianness, &out->p_vaddr) ||
        read_Addr(data, off_p, clazz, endianness, &out->p_paddr))
    {
        return 1;
    }

    /* they really messed up the program header spec, didn't they? */
    if (clazz == ELFCLASS64) {
        if (read_Xword(data, off_p, clazz, endianness, &out->p_filesz) ||
            read_Xword(data, off_p, clazz, endianness, &out->p_memsz) ||
            read_Xword(data, off_p, clazz, endianness, &out->p_align))
        {
            return 1;
        }

    } else /* if (clazz == ELFCLASS32) */ {
        Elf64_Word tmp_filesz = 0, tmp_memsz = 0, tmp_align = 0;
        if (read_Word(data, off_p, clazz, endianness, &tmp_filesz) ||
            read_Word(data, off_p, clazz, endianness, &tmp_memsz) ||
            read_Word(data, off_p, clazz, endianness, &out->p_flags) ||
            read_Word(data, off_p, clazz, endianness, &tmp_align))
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

static int read_validate_phdrs(const struct blob *data, struct elf_phdrs *out,
                               const Elf64_Ehdr *ehdr, int clazz, int encoding)
{
    out->arr = NULL;
    out->num = 0;
    out->dirty = false;

    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phentsize == 0) {
no_headers:
        pr_error("No program headers!\n");
        return -1;
    }

    /* Get the real value of `phnum` */
    Elf64_Xword phnum = 0;
    if (ehdr->e_phnum == PN_XNUM) {
        Elf64_Shdr first_shdr = { 0 };
        uint64_t sh_off = ehdr->e_shoff;
        if (read_shdr(data, &sh_off, clazz, encoding, &first_shdr)) {
            pr_error("Failed to read first section header\n");
            return 1;
        }
        if (first_shdr.sh_info == 0)
            goto no_headers;

        phnum = first_shdr.sh_info;
    } else {
        phnum = ehdr->e_phnum;
    }
    if (phnum >= SIZE_MAX / ehdr->e_phentsize ||
        phnum >= UINT64_MAX / ehdr->e_phentsize)
    {
        pr_error("Number of program headers too large "
                "(integer overflow)\n");
        return -1;
    }

    const uint64_t phsize = phnum * ehdr->e_phentsize;
    if (phsize > data->size || data->size - phsize < ehdr->e_phoff) {
        pr_error("Program headers overflow data buffer\n");
        return 1;
    }

    Elf64_Phdr *arr = calloc(phnum, sizeof(Elf64_Phdr));
    if (arr == NULL) {
        pr_error("Failed to allocate program header array\n");
        return 1;
    }
    /* from this point onward, no `return` without freeing `arr` first */
    int ret = 0;

    uint64_t off = ehdr->e_phoff;
    Elf64_Phdr phdr = { 0 };
    uint64_t prev_vaddr = 0;
    bool found_pt_load = false, found_pt_interp = false,
         found_pt_phdr = false, found_pt_dynamic = false;
    Elf64_Phdr pt_phdr = { 0 }, pt_dynamic = { 0 };
    for (Elf64_Xword i = 0; i < phnum; i++) {
        if (read_phdr(data, &off, clazz, encoding, &phdr)) {
            pr_error("Couldn't read program header no %" PRIu64
                     " (offset 0x%" PRIx64 ")\n", i, off);
            ret = 1;
            break;
        }
        /* `(i + 1) * ehdr->e_phentsize` can be at most `phsize`
         * which by previous logic is validated to not overflow `data->size`
         * and in consequence, the uint64 limit. */
        if (off != ehdr->e_phoff + (((uint64_t)i + 1) * ehdr->e_phentsize)) {
            pr_error("Invalid offset 0x%" PRIx64
                     " after reading program header no %" PRIu64
                     " (impossible outcome)\n",
                     off, i);
            fflush(stderr);
            abort();
        }

        if (phdr.p_offset >= data->size ||
            data->size - phdr.p_offset < phdr.p_filesz)
        {
            pr_error("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                     "Segment overflows data buffer\n", i, off);
            ret = 1;
        }

        if (phdr.p_vaddr > UINT64_MAX - phdr.p_memsz) {
            pr_error("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                     "Segment overflows address space\n", i, off);
            ret = 1;
        }

        switch (phdr.p_type) {
        case PT_NULL:
            pr_debug("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type: PT_NULL\n", i, off);
            break;

        case PT_LOAD:
            found_pt_load = true;
            pr_debug("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type: PT_LOAD\n", i, off);

            /* PT_LOAD segments must appear in ascending order,
             * sorted by `p_vaddr` */
            if (phdr.p_vaddr < prev_vaddr) {
                pr_error("[Program header no %" PRIu64
                         " (offset 0x%" PRIx64 ")]: "
                         "PT_LOAD vaddr (0x%" PRIx64 ") "
                         "smaller than previous (0x%" PRIx64 ")\n",
                         i, off, phdr.p_vaddr, prev_vaddr);
                ret = 1;
            }

            /* Memory size cannot be smaller than file size */
            if (phdr.p_memsz < phdr.p_filesz) {
                pr_error("[Program header no %" PRIu64
                         " (offset 0x%" PRIx64 ")]: "
                         "PT_LOAD memsz (0x%" PRIx64 ") "
                         "cannot be smaller than filesz (0x%" PRIx64 ")\n",
                         i, off, phdr.p_memsz, phdr.p_filesz);
                ret = 1;
            }

            /* Alignment must be 0, 1, or a power of two */
            if (phdr.p_align > 1) {
                if ((phdr.p_align & (phdr.p_align - 1)) != 0) {
                    pr_error("[Program header no %" PRIu64
                             " (offset 0x%" PRIx64 ")]: "
                             "PT_LOAD alignment (0x%" PRIx64 ") "
                             "must be a 0, 1, or power of two\n",
                             i, off, phdr.p_align);
                    ret = 1;
                }

                /* vaddr and file offset must be congruent modulo p_align */
                const uint64_t d = phdr.p_vaddr > phdr.p_offset ?
                    phdr.p_vaddr - phdr.p_offset :
                    phdr.p_offset - phdr.p_vaddr;
                if (d % phdr.p_align != 0) {
                    pr_error("[Program header no %" PRIu64
                             " (offset 0x%" PRIx64 ")]: "
                             "PT_LOAD p_vaddr (0x%" PRIx64 ") "
                             "and p_offset (0x%" PRIx64 ") are not congruent "
                             "modulo alignment (0x%" PRIx64 ")\n",
                             i, off, phdr.p_vaddr, phdr.p_offset, phdr.p_align);
                    ret = 1;
                }
            }

            prev_vaddr = phdr.p_vaddr;
            break;

        case PT_DYNAMIC:
            pr_debug("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type: PT_DYNAMIC\n", i, off);
            if (found_pt_dynamic) {
                pr_error(
                    "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                    "Multiple PT_DYNAMIC segments are not supported\n", i, off
                );
                ret = 1;
            }
            found_pt_dynamic = true;
            pt_dynamic = phdr;
            break;

        case PT_INTERP:
            pr_debug("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type: PT_INTERP\n", i, off);
            if (found_pt_interp) {
                pr_error(
                    "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                    "More than one PT_INTERP header\n", i, off
                );
                ret = 1;
            }
            if (found_pt_load) {
                pr_error(
                    "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                    "PT_INTERP header found after a PT_LOAD\n", i, off
                );
                ret = 1;
            }
            found_pt_interp = true;

            if (!ret) {
                if (data->data[phdr.p_offset + phdr.p_filesz - 1] != '\0') {
                    pr_error(
                        "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                        "PT_INTERP string is not NULL-terminated\n", i, off
                    );
                    ret = 1;
                } else {
                    pr_debug("Program interpreter: %s\n",
                             (const char *)&data->data[phdr.p_offset]);
                }
            }
            break;

        case PT_NOTE:
            pr_debug("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type: PT_NOTE\n", i, off);
            break;
        case PT_SHLIB:
            pr_error("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type: PT_SHLIB (reserved/unsupported)\n", i, off);
            ret = 1;
            break;
        case PT_PHDR:
            pr_debug("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type: PT_PHDR\n", i, off);
            if (found_pt_phdr) {
                pr_error(
                    "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                    "More than one PT_PHDR header\n", i, off
                );
                ret = 1;
            }
            if (found_pt_load) {
                pr_error(
                    "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                    "PT_PHDR header found after a PT_LOAD\n", i, off
                );
                ret = 1;
            }
            found_pt_phdr = true;
            pt_phdr = phdr;

            if (phdr.p_offset != ehdr->e_phoff || phdr.p_filesz != phsize) {
                pr_error(
                    "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                        "Invalid PT_PHDR header extents "
                        "(offset: 0x%" PRIx64 ", size: 0x%" PRIx64 "\n",
                        i, off, phdr.p_offset, phdr.p_filesz
                );
                ret = 1;
            }

            break;
        case PT_TLS:
            pr_debug("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                     " Header type: PT_TLS\n", i, off);
            break;

        default:
            if (phdr.p_type >= PT_LOOS && phdr.p_type <= PT_HIPROC) {
                pr_debug(
                    "[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]:"
                    " OS-specific header type: 0x%" PRIx32 "\n", i, off,
                    phdr.p_type
                );
                break;
            }

            pr_error("[Program header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                     "Invalid program header type: 0x%" PRIx32 "\n", i, off,
                     phdr.p_type);
            ret = 1;
            continue;
        }

        if (!ret)
            memcpy(&arr[i], &phdr, sizeof(Elf64_Phdr));
    }

    /* Validate that any `PT_PHDR` and `PT_DYNAMIC` segments
     * are inside another `PT_LOAD` segment */
    if (!ret) {
        if (found_pt_phdr &&
                get_load_segment_containing_range(arr, phnum,
                    pt_phdr.p_vaddr, pt_phdr.p_memsz) == NULL)
        {
            pr_error("PT_PHDR is not contained within any PT_LOAD segment\n");
            ret = 1;
        }
        if (found_pt_dynamic &&
                get_load_segment_containing_range(arr, phnum,
                    pt_dynamic.p_vaddr, pt_dynamic.p_memsz) == NULL)
        {
            pr_error("PT_DYNAMIC is not contained within any PT_LOAD segment\n");
            ret = 1;
        }
    }

    if (ret) {
        if (arr != NULL) {
            free(arr);
            arr = NULL;
        }
    } else {
        out->arr = arr; arr = NULL;
        out->num = phnum;
        out->dirty = false;
    }

    return ret;
}

static int write_phdr(struct blob *data, uint64_t *off_p,
                     int clazz, int endianness, const Elf64_Phdr *phdr)
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

    if (write_Word(data, off_p, clazz, endianness, phdr->p_type))
        return 1;

    /* In ELF32 `p_flags` is in a different place than in ELF64 */
    if (clazz == ELFCLASS64)
        if (write_Word(data, off_p, clazz, endianness, phdr->p_flags))
            return 1;

    if (write_Off(data, off_p, clazz, endianness, phdr->p_offset) ||
        write_Addr(data, off_p, clazz, endianness, phdr->p_vaddr) ||
        write_Addr(data, off_p, clazz, endianness, phdr->p_paddr))
    {
        return 1;
    }

    if (clazz == ELFCLASS64) {
        if (write_Xword(data, off_p, clazz, endianness, phdr->p_filesz) ||
            write_Xword(data, off_p, clazz, endianness, phdr->p_memsz) ||
            write_Xword(data, off_p, clazz, endianness, phdr->p_align))
        {
            return 1;
        }
    } else /* if (clazz == ELFCLASS32) */ {
        if (write_Word(data, off_p, clazz, endianness, phdr->p_filesz) ||
            write_Word(data, off_p, clazz, endianness, phdr->p_memsz) ||
            write_Word(data, off_p, clazz, endianness, phdr->p_flags) ||
            write_Word(data, off_p, clazz, endianness, phdr->p_align))
        {
                return 1;
        }
    }

    return 0;
}

static const Elf64_Phdr * get_load_segment_containing_range(
        const Elf64_Phdr *phdrs, Elf64_Xword nphdrs,
        Elf64_Xword start, Elf64_Xword size
)
{
    if (start > UINT64_MAX - size) {
        pr_error("%s: Span too large (integer overflow)\n", __func__);
        return NULL;
    }

    for (Elf64_Xword i = 0; i < nphdrs; i++) {
        const Elf64_Phdr *const curr = &phdrs[i];

        /* anything `curr` is assumed to be bounds-checked and validated
         * earlier by `read_validate_phdrs` */
        if (curr->p_type == PT_LOAD &&
            start >= curr->p_vaddr &&
            start + size <= curr->p_vaddr + curr->p_memsz)
        {
            return curr;
        }
    }

    return NULL;
}

static int read_shdr(const struct blob *data, uint64_t *off_p,
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

static int read_validate_shdrs(const struct blob *data, struct elf_shdrs *out,
                               const Elf64_Ehdr *ehdr, int clazz, int encoding)
{
    out->arr = NULL;
    out->num = 0;
    out->dirty = false;

    if (ehdr->e_shnum == 0 || ehdr->e_shoff == 0 || ehdr->e_shentsize == 0) {
no_headers:
        pr_error("WARNING: The ELF has no section headers!\n");
        return 0;
    }

    Elf64_Xword shnum = 0;
    if (ehdr->e_shnum >= SHN_LORESERVE) {
        Elf64_Shdr first_shdr = { 0 };
        uint64_t off = ehdr->e_shoff;
        if (read_shdr(data, &off, clazz, encoding, &first_shdr)) {
            pr_error("Couldn't read the first section header\n");
            return 1;
        }
        if (first_shdr.sh_size == 0)
            goto no_headers;

        shnum = first_shdr.sh_size;
    } else {
        shnum = ehdr->e_shnum;
    }

    if (shnum >= SIZE_MAX / ehdr->e_shentsize ||
        shnum >= UINT64_MAX / ehdr->e_shentsize)
    {
        pr_error("Number of section headers too large "
                "(integer overflow)\n");
        return 1;
    }

    const uint64_t shsize = (uint64_t)ehdr->e_shentsize * shnum;
    if (shsize > data->size || data->size - shsize < ehdr->e_shoff) {
        pr_error("Section headers overflow data buffer\n");
        return 1;
    }

    Elf64_Shdr shstrtab = { 0 };
    if (ehdr->e_shstrndx != SHN_UNDEF) {
        uint64_t shstrtaboff =
            ehdr->e_shoff + (ehdr->e_shstrndx * ehdr->e_shentsize);
        if (read_shdr(data, &shstrtaboff, clazz, encoding, &shstrtab)) {
            pr_error("Couldn't read the shstrtab section header\n");
            return 1;
        }

        if (shstrtab.sh_type != SHT_STRTAB) {
            pr_error("Invalid section type for .shstrtab\n");
            return 1;
        }

        if (data->data[shstrtab.sh_offset] != '\0') {
            pr_error("Section .shstrtab doesn't start with a NULL character\n");
            return 1;
        }
        if (data->data[shstrtab.sh_offset + shstrtab.sh_size - 1] != '\0') {
            pr_error("Section .shstrtab is not NULL-terminated\n");
            return 1;
        }
    }

    Elf64_Shdr *arr = calloc(shnum, sizeof(Elf64_Shdr));
    if (arr == NULL) {
        pr_error("Failed to allocate program section array\n");
        return 1;
    }
    /* from this point onward, no `return` without freeing `arr` first */
    int ret = 0;

    uint64_t off = ehdr->e_shoff;
    Elf64_Shdr shdr = { 0 };

    for (Elf64_Xword i = 0; i < shnum; i++) {
        if (read_shdr(data, &off, clazz, encoding, &shdr)) {
            pr_error("Couldn't read section header no %" PRIu64
                     " (offset 0x%" PRIx64 ")\n", i, off);
            ret = 1;
            break;
        }
        /* `(i + 1) * ehdr->e_shentsize` can be at most `shsize`
         * which by previous logic is validated to not overflow `data->size`
         * and in consequence, the uint64 limit. */
        if (off != ehdr->e_shoff + (((uint64_t)i + 1) * ehdr->e_shentsize)) {
            pr_error("Invalid offset 0x%" PRIx64
                     " after reading section header no %" PRIu64
                     " (impossible outcome)\n",
                     off, i);
            fflush(stderr);
            abort();
        }

        if (shdr.sh_type != SHT_NOBITS &&
                (shdr.sh_offset >= data->size ||
                 data->size - shdr.sh_offset < shdr.sh_size))
        {
            pr_error("[Section header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                     "Section overflows data buffer\n", i, off);
            ret = 1;
        }

        if (shdr.sh_name >= shstrtab.sh_size) {
            pr_error("[Section header no %" PRIu64 " (offset 0x%" PRIx64 ")]: "
                     "Section name outside of the .shstrtab section bounds\n",
                     i, off);
            ret = 1;
        }

        if (!ret)
            memcpy(&arr[i], &shdr, sizeof(Elf64_Shdr));
    }

    if (ret) {
        if (arr != NULL) {
            free(arr);
            arr = NULL;
        }
    } else {
        out->arr = arr; arr = NULL;
        out->num = shnum;
        out->dirty = false;
    }

    return ret;
}

static int write_shdr(struct blob *data, uint64_t *off_p,
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

static int read_elf(const char *path, struct elf *out)
{
    struct elf e = { 0 };
    memset(&e, 0, sizeof(struct elf));

    if (read_file(path, &e.data)) {
        pr_error("Couldn't read input file \"%s\"\n", path);
        goto err;
    }

    if (read_validate_ident(&e.data, &e.ident)) {
        pr_error("File \"%s\" is not an ELF file!\n", path);
        goto err;
    }
    const int c = e.ident.clazz;
    const int d = e.ident.data;

    if (read_validate_ehdr(&e.data, c, d, &e.ehdr)) {
        pr_error("Invalid ELF header in file \"%s\"\n", path);
        goto err;
    }

    if (read_validate_phdrs(&e.data, &e.phdrs, &e.ehdr, c, d)) {
        pr_error("Invalid program headers in file \"%s\"\n", path);
        goto err;
    }

    if (read_validate_shdrs(&e.data, &e.shdrs, &e.ehdr, c, d)) {
        pr_error("Invalid section headers in file \"%s\"\n", path);
        goto err;
    }

    if (read_validate_dynamic_section(&e.data, c, d, &e.phdrs, &e.shdrs, &e.dyn)) {
        pr_error("Invalid or missing dynamic section in file \"%s\"\n", path);
        goto err;
    }

    if (out != NULL)
        memcpy(out, &e, sizeof(struct elf));
    else
        destroy_elf(&e);

    printf("Successfully read and parsed ELF%s-%s file \"%s\"\n",
           (c == ELFCLASS32 ? "32" : "64"),
           (d == ELFDATA2MSB ? "BE" : "LE"),
           path
    );
    return 0;

err:
    destroy_elf(&e);
    return 1;
}

static const char * section_name_strptr(const struct elf *elf,
                                        Elf64_Addr sh_name)
{
    if (elf == NULL || elf->shdrs.arr == NULL ||
        elf->shstrndx >= elf->shdrs.num)
    {
        return "N/A (missing or invalid shstrtab section)";
    }

    const Elf64_Shdr *shstrtab = &elf->shdrs.arr[elf->ehdr.e_shstrndx];
    if (shstrtab->sh_offset >= elf->data.size ||
        shstrtab->sh_size >= elf->data.size - shstrtab->sh_offset ||
        elf->data.data == NULL)
    {
        return "N/A (shstrtab section overflows ELF file)";
    }

    if (shstrtab->sh_size < 1)
        return "N/A (shstrtab section size is 0)";

    if (sh_name >= shstrtab->sh_size)
        return "N/A (section name offset overflows shstrtab section)";

    if (elf->data.data[shstrtab->sh_offset + shstrtab->sh_size - 1] != '\0')
        return "N/A (shstrtab not NULL-terminated)";

    return (const char *)&elf->data.data[shstrtab->sh_offset + sh_name];
}

static const char * __attribute__((unused)) section_type_toString(Elf64_Word sht)
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
    case SHT_SUNW_move: return "SHT_SUNW_move";
    case SHT_SUNW_COMDAT: return "SHT_SUNW_COMDAT";
    case SHT_SUNW_syminfo: return "SHT_SUNW_syminfo";
    case SHT_GNU_verdef: return "SHT_GNU_verdef";
    case SHT_GNU_verneed: return "SHT_GNU_verneed";
    case SHT_GNU_versym: return "SHT_GNU_versym";
    default: return "(unknown)";
    }
}

static void list_sections(const struct elf *elf)
{
    for (Elf64_Xword i = 0; i < elf->shdrs.num; i++) {
        const Elf64_Shdr *shdr = &elf->shdrs.arr[i];

        pr_debug("Section: %-20s \"%s\"\n",
                 section_type_toString(shdr->sh_type),
                 section_name_strptr(elf, shdr->sh_name)
        );
    }
}

static void find_load_segment_limits(const struct elf *elf,
                                     uint64_t *out_vaddr, uint64_t *out_align)
{
    uint64_t max_vaddr = 0;
    /* fall back to the standard 4k page size if nothing is found */
    uint64_t max_align = 4096;

    for (Elf64_Xword i = 0; i < elf->phdrs.num; i++) {
        const Elf64_Phdr *const phdr = &elf->phdrs.arr[i];
        if (phdr->p_type != PT_LOAD)
            continue;

        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr)
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        if (phdr->p_align > max_align)
            max_align = phdr->p_align;
    }

    *out_vaddr = max_vaddr;
    *out_align = max_align;
}

static int modify_and_move_program_headers(struct elf *elf)
{
    if (elf->phdrs.num >= UINT64_MAX ||
        elf->phdrs.num + 1 > UINT64_MAX / elf->ehdr.e_phentsize ||
        elf->phdrs.num + 1 > SIZE_MAX / sizeof(Elf64_Phdr))
    {
        pr_error("Too many program headers (integer overflow)\n");
        return -1;
    }

    const Elf64_Xword old_phnum = elf->phdrs.num;
    const uint64_t old_phsize = old_phnum * elf->ehdr.e_phentsize;
    const Elf64_Off old_phoff = elf->ehdr.e_phoff;

    printf("Old program header table offset: 0x%" PRIx64 "\n", old_phoff);
    printf("Old program header count: %" PRIu64 "\n", old_phnum);

    /* Calculate new *file* size of the phdrs */
    const Elf64_Xword new_phnum = elf->phdrs.num + 1;
    const uint64_t new_phsize = new_phnum * elf->ehdr.e_phentsize;

    /* Calculate size of the new PT_LOAD *memory* segment
     * that will contain the moved phdrs */
    uint64_t new_ptload_vaddr = 0, new_ptload_size = 0;

    uint64_t new_align = 0;
    uint64_t vaddr = 0;
    /* `read_validate_phdrs` validates that every PT_LOAD's
     * `align` value is a power of two */
    find_load_segment_limits(elf, &vaddr, &new_align);

    new_ptload_vaddr = align_pow2(vaddr, new_align);
    new_ptload_size = align_pow2(new_phsize, new_align);

    /* new *file* offset */
    const Elf64_Off new_phoff = align_pow2(elf->data.size, new_align);

    /* Update the "self-reference" PT_PHDR if it exists */
    for (Elf64_Xword i = 0; i < elf->phdrs.num; i++) {
        Elf64_Phdr *const phdr = &elf->phdrs.arr[i];
        if (phdr->p_type != PT_PHDR)
            continue;

        phdr->p_offset = new_phoff;
        phdr->p_filesz = new_phsize;
        phdr->p_memsz = new_phsize;
        /* In memory, the program headers will be
         * at the start of the new segment */
        phdr->p_vaddr = new_ptload_vaddr;
        phdr->p_paddr = new_ptload_vaddr;
    }

    /* Add a PT_LOAD segment for our moved phdrs.
     * Since we are placing it at the end of the address space,
     * we don't have to do any further sorting
     * (`PT_LOAD` segments must be ordered by their `p_vaddr` ascending) */
    elf->ehdr.e_phoff = new_phoff;
    if (update_phnum(&elf->phdrs, new_phnum, &elf->ehdr.e_phnum, &elf->shdrs)) {
        pr_error("Failed to grow the program headers array\n");
        return 1;
    }

    elf->phdrs.arr[new_phnum - 1] = (Elf64_Phdr) {
        .p_type = PT_LOAD,
        .p_flags = PF_R,
        .p_offset = new_phoff,
        .p_vaddr = new_ptload_vaddr,
        .p_paddr = new_ptload_vaddr,
        .p_filesz = new_phsize,
        .p_memsz = new_ptload_size,
        .p_align = new_align
    };

    /* Make some space for our new data */
    if (new_phsize > SIZE_MAX || elf->data.size > SIZE_MAX - new_phsize) {
        pr_error("New file size would overflow size_t, can't realloc\n");
        return 1;
    }
    const size_t new_data_size = new_phoff + new_phsize;

    {
        void *tmp = realloc(elf->data.data, new_data_size);
        if (tmp == NULL) {
            pr_error("Failed to grow (realloc) the ELF file data\n");
            return 1;
        }
        elf->data.data = tmp;
    }
    memset(elf->data.data + elf->data.size, 0, new_data_size - elf->data.size);
    elf->data.size = new_data_size;

    /* Clean up the old phdrs */
    size_t i = 0;
    while (i < old_phsize) {
        size_t n = (old_phsize - i) < (sizeof(SUS_REPLACEMENT_STRING) - 1) ?
            (old_phsize - i) : (sizeof(SUS_REPLACEMENT_STRING) - 1);
        memcpy(elf->data.data + old_phoff + i, SUS_REPLACEMENT_STRING, n);
        i += n;
    }

    elf->ehdr_dirty = true;
    elf->phdrs.dirty = true;
    printf("New program header table offset: 0x%" PRIx64 "\n", new_phoff);
    printf("New program header count: %" PRIu64 "\n", new_phnum);
    return 0;
}

static int read_validate_dynamic_section(
        const struct blob *data, int clazz, int encoding,
        struct elf_phdrs *phdrs, struct elf_shdrs *shdrs,

        struct elf_dynamic *out
)
{
    if (data == NULL || phdrs == NULL || shdrs == NULL) {
        pr_error("%s: Invalid parameters!\n", __func__);
        return -1;
    }

    if (out != NULL)
        memset(out, 0, sizeof(struct elf_dynamic));

    const size_t entsize = clazz == ELFCLASS32 ?
        sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);

    /** Find and validate the PT_DYNAMIC program header **/
    Elf64_Phdr *pt_dynamic = NULL;
    {
        for (Elf64_Xword i = 0; i < phdrs->num; i++) {
            if (phdrs->arr[i].p_type == PT_DYNAMIC) {
                pt_dynamic = &phdrs->arr[i];
                break;
            }
        }
        if (pt_dynamic == NULL) {
            pr_error("No PT_DYNAMIC header; "
                     "the ELF is probably not dynamically linked\n");
            return 1;
        } else if (validate_pt_dynamic(pt_dynamic, entsize)) {
            pr_error("Invalid PT_DYNAMIC segment header\n");
            return 1;
        }
    }
    const Elf64_Xword dynnum = pt_dynamic->p_filesz / entsize;

    /** If present, validate the .dynamic section header against PT_DYNAMIC **/
    Elf64_Shdr *sht_dynamic = NULL;
    {
        for (Elf64_Xword i = 0; i < shdrs->num; i++) {
            if (shdrs->arr[i].sh_type == SHT_DYNAMIC) {
                if (sht_dynamic != NULL) {
                    pr_error("Multiple SHT_DYNAMIC section headers\n");
                    return 1;
                }
                sht_dynamic = &shdrs->arr[i];
            }
        }
        if (sht_dynamic) {
            if (validate_sht_dynamic(sht_dynamic, pt_dynamic, entsize)) {
                pr_error("Invalid SHT_DYNAMIC section header\n");
                return 1;
            }
        }
    }

    /** Parse the ElfXX_Dyn entries **/
    Elf64_Dyn *arr = NULL;
    if (parse_dyn_array(data, clazz, encoding, dynnum, pt_dynamic, &arr)) {
        pr_error("Failed to parse the dynamic entry array\n");
        return 1;
    }
    printf("Number of dynamic entries: %" PRIu64 "\n", dynnum);

    /** Locate the dynstr string table **/
    Elf64_Addr strtab_addr = 0;
    Elf64_Xword strtab_size = 0;
    {
        Elf64_Dyn *dt_strtab = NULL, *dt_strsz = NULL;
        for (Elf64_Xword i = 0; i < dynnum; i++) {
            if (arr[i].d_tag == DT_STRTAB) {
                if (dt_strtab != NULL) {
                    pr_error("Multiple DT_STRTAB entries\n");
                    goto err;
                }
                dt_strtab = &arr[i];
            } else if (arr[i].d_tag == DT_STRSZ) {
                if (dt_strsz != NULL) {
                    pr_error("Multiple DT_STRSZ entries\n");
                    goto err;
                }
                dt_strsz = &arr[i];
            }
        }
        if (dt_strtab == NULL || dt_strsz == NULL) {
            pr_error("Couldn't find DT_STRTAB and/or DT_STRSZ\n");
            goto err;
        }
        strtab_addr = dt_strtab->d_un.d_ptr;
        strtab_size = dt_strsz->d_un.d_val;
    }

    /** Ensure that the string table is within a PT_LOAD segment **/
    const Elf64_Phdr *strtab_load_seg =
        get_load_segment_containing_range(phdrs->arr, phdrs->num,
                                          strtab_addr, strtab_size);
    if (strtab_load_seg == NULL) {
        pr_error("Dynamic string table not within any PT_LOAD segment\n");
        goto err;
    }

    /* Deduce the strtab's file offset from the PT_LOAD segment header */
    const Elf64_Off off_in_load_seg = strtab_addr - strtab_load_seg->p_vaddr;
    const Elf64_Off strtab_off = strtab_load_seg->p_offset + off_in_load_seg;

    /** If there's any .dynstr section header, validate it **/
    Elf64_Shdr *strtab_shdr = NULL;
    if (find_validate_strtab_shdr(shdrs->arr, shdrs->num,
                                  strtab_addr, strtab_off, strtab_size,
                                  &strtab_shdr))
    {
        pr_error("Invalid .dynstr section header\n");
        goto err;
    }

    if (out != NULL) {
        out->entries.arr = arr; arr = NULL;
        out->entries.num = dynnum;
        out->entries.dirty = false;

        out->phdr = pt_dynamic;
        out->shdr = sht_dynamic;

        out->strtab_vaddr = strtab_addr;
        out->strtab_sz = strtab_size;
        out->strtab_off = strtab_off;
        out->strtab_shdr = strtab_shdr;
    } else {
        free(arr);
        arr = NULL;
    }
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int validate_pt_dynamic(const Elf64_Phdr *pt_dynamic, size_t entsize)
{
    if (pt_dynamic == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }
    if (pt_dynamic->p_type != PT_DYNAMIC) {
        pr_error("Program header is not PT_DYNAMIC\n");
        return -1;
    }

    /* Segment bounds already checked in `read_validate_phdrs` */

    if (pt_dynamic->p_filesz % entsize != 0) {
        pr_error("PT_DYNAMIC segment size (%" PRIu64 ") "
                 "is not a multiple of ElfXX_Dyn (%" PRIu64 ")\n",
                 pt_dynamic->p_filesz, entsize);
        return 1;
    } else if (pt_dynamic->p_filesz != pt_dynamic->p_memsz) {
        pr_error("PT_DYNAMIC filesz != memsz\n");
        return 1;
    }

    const Elf64_Xword dynnum = pt_dynamic->p_filesz / entsize;
    if (dynnum > SIZE_MAX) {
        pr_error("Number of dynamic entries overflows size_t");
        return 1;
    }

    return 0;
}

static int validate_sht_dynamic(const Elf64_Shdr *sht_dynamic,
                                const Elf64_Phdr *pt_dynamic, size_t entsize)
{
    if (sht_dynamic == NULL) {
        pr_error("%s: Invalid parameters\n", __func__);
        return -1;
    }

#define sht_pt_val_cmp(sht_field, shtpri, pt_field, ptpri)              \
do {                                                                    \
    static_assert(sizeof(sht_dynamic->sh_##sht_field) ==                \
                    sizeof(pt_dynamic->p_##pt_field),                   \
                  "Comparing fields of different sizes");               \
                                                                        \
    if (sht_dynamic->sh_##sht_field != pt_dynamic->p_##pt_field) {      \
        pr_error("SHT_DYNAMIC " #sht_field " (0x%" shtpri ") "          \
            "does not match PT_DYNAMIC " #pt_field "(0x%" ptpri ")\n",  \
            sht_dynamic->sh_##sht_field, pt_dynamic->p_##pt_field);     \
        return 1;                                                       \
    }                                                                   \
} while (0)

    sht_pt_val_cmp(offset, PRIx64,      offset, PRIx64);
    sht_pt_val_cmp(size, PRIx64,        filesz, PRIx64);
    sht_pt_val_cmp(addr, PRIx64,        vaddr, PRIx64);
    sht_pt_val_cmp(addralign, PRIu64,   align, PRIu64);

#undef sht_pt_val_cmp

    if (sht_dynamic->sh_entsize != entsize) {
        pr_error("Unexpected value of SHT_DYNAMIC sh_entsize\n");
        return 1;
    }

    return 0;
}

static int parse_dyn_array(
        const struct blob *data, int clazz, int encoding,
        Elf64_Xword count, const Elf64_Phdr *pt_dynamic,

        Elf64_Dyn **out
)
{
    Elf64_Dyn *arr = NULL;
    *out = NULL;

    if (count == 0) {
        pr_error("Number of dynamic entries is 0!\n");
        goto err;
    }

    arr = calloc(count, sizeof(Elf64_Dyn));
    if (arr == NULL) {
        pr_error("Failed to allocate the dynamic entries array\n");
        goto err;
    }

    Elf64_Xword off = pt_dynamic->p_offset;

    bool terminated = false;
    for (Elf64_Xword i = 0; i < count; i++) {
        if (read_dyn(data, &off, clazz, encoding, &arr[i])) {
            pr_error("Failed to parse dynamic entry "
                     "no %" PRIu64 " at offset 0x%" PRIx64 "\n", i, off);
            goto err;
        }

        if (arr[i].d_tag == DT_NULL && !terminated) {
            terminated = true;
        } else if (terminated && arr[i].d_tag != DT_NULL) {
            pr_error("Entries after DT_NULL terminator\n");
            goto err;
        }
    }
    if (!terminated) {
        pr_error("Dynamic entry array not terminated\n");
        goto err;
    }

    if (off != pt_dynamic->p_offset + pt_dynamic->p_filesz) {
        pr_error("Invalid offset (0x%" PRIx64 ") after parsing "
                "dynamic table (expected 0x%" PRIx64 ")\n",
                off, pt_dynamic->p_offset + pt_dynamic->p_filesz);
        goto err;
    }

    *out = arr; arr = NULL;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int find_validate_strtab_shdr(Elf64_Shdr *shdrs, Elf64_Xword shnum,
                                     Elf64_Addr addr, Elf64_Off off,
                                     Elf64_Xword size, Elf64_Shdr **out)
{
    Elf64_Shdr *shdr = NULL;
    for (Elf64_Xword i = 0; i < shnum; i++) {
        Elf64_Shdr *const curr = &shdrs[i];

        if (ranges_overlap(curr->sh_addr, curr->sh_size, addr, size) ||
            ranges_overlap(curr->sh_offset, curr->sh_size, off, size))
        {
            if (shdr != NULL) {
                pr_error("Multiple sections contain "
                         "the .dynamic string table\n");
                return 1;
            }
            shdr = curr;
        }
    }
    if (shdr == NULL) {
        /* no .dynstr section was found */
        if (out != NULL) *out = NULL;
        return 0;
    }

    int ret = 0;
    if (shdr->sh_type != SHT_STRTAB) {
        pr_error("Invalid .dynstr section type\n");
        ret = 1;
    }
    if (shdr->sh_offset != off) {
        pr_error("Invalid .dynstr section file offset\n");
        ret = 1;
    }
    if (shdr->sh_addr != addr) {
        pr_error("Invalid .dynstr section virtual address\n");
        ret = 1;
    }
    if (shdr->sh_size != size) {
        pr_error("Invalid .dynstr sectoin size\n");
        ret = 1;
    }

    if (!ret && out != NULL)
        *out = shdr;

    return ret;
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

static int read_dyn(const struct blob *data, uint64_t *off_p,
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

static int write_dyn(struct blob *data, uint64_t *off_p,
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

static __attribute__((unused))
const char *  dynamic_tag_to_string(Elf64_Sxword dt)
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
    default: return "(unknown)";
    }
}

static __attribute__((unused))
void print_dynamic_section(const struct elf *elf)
{
    (void) elf;
}

static __attribute__((unused))
int modify_and_move_dynamic_section(struct elf *elf, uint64_t *off_p)
{
    (void) elf;
    (void) off_p;
    return -1;
}

static int serialize_arr(struct blob *data, serializer_proc_t serializer,
                         const void *arr, size_t mementsize,
                         uint64_t off, Elf64_Half fileentsize, Elf64_Xword size,
                         int clazz, int endianness)
{
    if (mementsize == 0 || fileentsize == 0) {
        pr_error("Element size is 0\n");
        return -1;
    }
    if (arr == NULL) {
        pr_error("Unexpected NULL pointer (arr)\n");
        return -1;
    }
    if (size > UINT64_MAX / fileentsize ||
        size > UINT64_MAX / mementsize)
    {
        fprintf(stderr,
                "Invalid element count (integer overflow)\n");
        return -1;
    }
    const uint64_t filesize = size * fileentsize;

    const uint64_t start = off;
    if (filesize > UINT64_MAX - start) {
        fprintf(stderr,
                "Invalid offset (integer overflow)\n");
        return -1;
    }

    if (filesize > data->size ||
        start > data->size - filesize)
    {
        pr_error("Not enough space in data buffer\n");
        return 1;
    }

    for (Elf64_Xword i = 0; i < size; i++) {
        const void *ptr = (const uint8_t *)arr + (i * mementsize);
        if (serializer(data, &off, clazz, endianness, ptr)) {
            fprintf(stderr,
                    "Failed to serialize element no %" PRIu64 "\n", i);
            return 1;
        }
    }

    if (off != start + filesize) {
        pr_error("Invalid offset after serialization "
                "(0x%" PRIx64 ", expected 0x%" PRIx64 ")\n",
                off, start + filesize);
        return 1;
    }

    return 0;
}

static int serialize_elf(struct elf *elf)
{
    const int c = elf->ident.clazz, d = elf->ident.data;

    pr_debug("ELF header dirty: %d\n", !!elf->ehdr_dirty);
    if (elf->ehdr_dirty) {
        uint64_t off = 0;
        if (write_ehdr(&elf->data, &off, c, d, &elf->ehdr)) {
            pr_error("Failed to rewrite the ELF header\n");
            return 1;
        }
        printf("Successfully rewrote ELF header\n");
    }

    pr_debug("Program headers dirty: %d\n", !!elf->phdrs.dirty);
    if (elf->phdrs.dirty) {
        if (serialize_arr(&elf->data, (serializer_proc_t)write_phdr,
                           elf->phdrs.arr, sizeof(Elf64_Phdr),
                           elf->ehdr.e_phoff, elf->ehdr.e_phentsize,
                           elf->phdrs.num, c, d))
        {
            pr_error("Failed to rewrite the program headers\n");
            return 1;
        }
        printf("Successfully rewrote program headers\n");
    }

    pr_debug("Section headers dirty: %d\n", !!elf->shdrs.dirty);
    if (elf->shdrs.dirty) {
        if (serialize_arr(&elf->data, (serializer_proc_t)write_shdr,
                           elf->shdrs.arr, sizeof(Elf64_Shdr),
                           elf->ehdr.e_shoff, elf->ehdr.e_shentsize,
                           elf->shdrs.num, c, d))
        {
            pr_error("Failed to rewrite the section headers\n");
            return 1;
        }
        printf("Successfully rewrote section headers\n");
    }

    pr_debug("Dynamic entries dirty: %d\n", !!elf->dyn.entries.dirty);
    if (elf->dyn.entries.dirty) {
        const Elf64_Xword fileentsize =
            c == ELFCLASS32 ? sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);
        if (serialize_arr(&elf->data, (serializer_proc_t)write_dyn,
                           elf->dyn.entries.arr, sizeof(Elf64_Dyn),
                           elf->dyn.phdr->p_offset, fileentsize,
                           elf->dyn.entries.num, c, d))
        {
            pr_error("Failed to serialize the dynamic section\n");
            return 1;
        }
    }

    return 0;
}

static int write_elf(const struct elf *elf, const char *path)
{
    int fd = -1;


    if ((fd = open(path, O_RDWR | O_CLOEXEC | O_TRUNC | O_CREAT, 0644)) == -1) {
        pr_error("Failed to open output file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    }

    if (elf->data.size > SIZE_MAX || elf->data.size == 0 ||
        elf->data.data == NULL)
    {
        pr_error("ELF data invalid\n");
        goto err;
    }

    if (write(fd, elf->data.data, elf->data.size) == -1) {
        fprintf(stderr,
                "Failed to write to output file \"%s\": %d (%s)\n",
                path, errno, strerror(errno));
        goto err;
    }

    if (close(fd)) {
        pr_error("Failed to close the output fd: %d (%s)\n",
                errno, strerror(errno));
        fd = -1;
        goto err;
    }

    printf("Successfully wrote file \"%s\"\n", path);
    return 0;

err:
    if (fd != -1) {
        if (close(fd)) {
            pr_error("Failed to close the output fd: %d (%s)\n",
                    errno, strerror(errno));
        }
        fd = -1;
    }

    return 1;
}

static void destroy_elf(struct elf *elf)
{
    if (elf->data.data != NULL)
        free(elf->data.data);

    if (elf->phdrs.arr != NULL)
        free(elf->phdrs.arr);

    if (elf->shdrs.arr != NULL)
        free(elf->shdrs.arr);

    if (elf->dyn.entries.arr != NULL)
        free(elf->dyn.entries.arr);

    memset(elf, 0, sizeof(struct elf));
}
