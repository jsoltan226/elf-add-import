#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include "elf-parsing.h"
#include "elf-patching.h"
#include <string.h>
#include <inttypes.h>

#ifndef SUS_REPLACEMENT_STRING
#define SUS_REPLACEMENT_STRING "TEST"
#endif /* SUS_REPLACEMENT_STRING */
static int modify_and_move_program_headers(struct elf *elf);

static void list_sections(const struct elf *elf);

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

    if (serialize_elf(&elf, true))
        goto err;

    /* validate the newly serialized ELF */
    printf("Validating patched data... ");
    if (parse_elf(&elf.data, NULL, false)) {
        printf("Sanity check failed\n");
        goto err;
    }

    if (write_file(argv[2], &elf.data))
        goto err;

    destroy_elf(&elf);
    return EXIT_SUCCESS;

err:
    destroy_elf(&elf);
    return EXIT_FAILURE;
}

static void list_sections(const struct elf *elf)
{
    for (Elf64_Xword i = 0; i < elf->shdrs.num; i++) {
        const Elf64_Shdr *const shdr = &elf->shdrs.arr[i];

        pr_debug("Section: %-20s \"%s\"\n",
                 section_header_type_toString(shdr->sh_type),
                 section_name_strptr(elf, shdr->sh_name)
        );
    }
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

    if ((elf->data.data = safe_realloc((void **)&elf->data.data,
                                       new_data_size, 1)) == NULL)
    {
        pr_error("Failed to grow (realloc) the ELF file data\n");
        return 1;
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
