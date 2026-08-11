#include "elf-parsing.h"
#include "elf.h"
#include "ctx.h"
#include "util.h"
#include "elf-types.h"
#include "elf-dyn-parsing.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static int read_validate_ident(const struct blob *data, struct elf_ident *out);

int read_validate_ehdr(const struct blob *data, int clazz, int encoding,
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

int read_validate_phdrs(const struct blob *data, struct elf_phdrs *out,
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

int read_validate_shdrs(const struct blob *data, struct elf_shdrs *out,
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

int parse_elf(struct blob *data, struct elf *out, bool move)
{
    if (data == NULL || data->data == NULL) {
        pr_error("`data` is NULL\n");
        return -1;
    }

    struct elf e = { 0 };
    memset(&e, 0, sizeof(struct elf));

    if (read_validate_ident(data, &e.ident)) {
        pr_error("Not an ELF file (invalid magic)\n");
        goto err;
    }
    const int c = e.ident.clazz;
    const int d = e.ident.data;

    if (read_validate_ehdr(data, c, d, &e.ehdr)) {
        pr_error("Invalid ELF header\n");
        goto err;
    }

    if (read_validate_phdrs(data, &e.phdrs, &e.ehdr, c, d)) {
        pr_error("Invalid program headers\n");
        goto err;
    }

    if (read_validate_shdrs(data, &e.shdrs, &e.ehdr, c, d)) {
        pr_error("Invalid section headers\n");
        goto err;
    }

    if (read_validate_dynamic_section(data, c, d, &e.phdrs, &e.shdrs, &e.dyn)) {
        pr_error("Invalid or missing dynamic segment\n");
        goto err;
    }

    if (move) {
        e.data = *data;
        *data = (struct blob) { .data = NULL, .size =0 };
    } else {
        e.data.size = data->size;
        e.data.data = malloc(data->size);
        if (e.data.data == NULL) {
            pr_error("Failed to allocate a copy of the data\n");
            goto err;
        }
        memcpy(e.data.data, data->data, data->size);
    }

    if (out != NULL)
        memcpy(out, &e, sizeof(struct elf));
    else
        destroy_elf(&e);

    printf("Successfully parsed ELF%s-%s data\n",
           (c == ELFCLASS32 ? "32" : "64"),
           (d == ELFDATA2MSB ? "BE" : "LE")
    );
    return 0;

err:
    destroy_elf(&e);
    return 1;
}

int read_elf(const char *path, struct elf *out)
{
    struct blob data = { 0 };
    if (read_file(path, &data)) {
        pr_error("Couldn't read input file \"%s\"\n", path);
        return 1;
    }

    if (parse_elf(&data, out, true)) {
        pr_error("Couldn't parse ELF file \"%s\"\n", path);
        free(data.data);
        data = (struct blob) { 0 };
        return 1;
    }

    data = (struct blob) { 0 };
    return 0;
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
