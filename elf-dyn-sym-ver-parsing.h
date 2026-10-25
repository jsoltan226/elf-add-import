#ifndef ELF_DYN_SYM_VER_PARSING_H_
#define ELF_DYN_SYM_VER_PARSING_H_

#include "ctx.h"
#include "util.h"

struct elf_dyn_sym_ver {
    struct elf_dyn_sym_ver_def {
        Elf64_Xword num;
        struct elf_dyn_sym_ver_def_ent {
            Elf64_Verdef vd;
            Elf64_Verdaux *aux_list;
        } *arr;

        elf_idx_t base_idx;

        Elf64_Addr vaddr;
        Elf64_Off off;
        elf_idx_t dt_verdef_idx;
        elf_idx_t dt_verdefnum_idx;

        elf_idx_t shdr;
    } def;

    struct elf_dyn_sym_ver_need {
        Elf64_Xword num;
        struct elf_dyn_sym_ver_need_ent {
            Elf64_Verneed vn;
            Elf64_Vernaux *aux_list;
        } *arr;

        Elf64_Addr vaddr;
        Elf64_Off off;
        elf_idx_t dt_verneed_idx;
        elf_idx_t dt_verneednum_idx;

        elf_idx_t shdr;
    } need;
};

int parse_ver(const struct elf_phdrs *phdrs,
              const struct elf_shdrs *shdrs,
              const struct elf_dyn_strtab *strtab,
              const struct elf_dyn_entries *entries,
              const ElfFileData *data,
              struct elf_dyn_sym_ver *out);

#endif /* ELF_DYN_SYM_VER_PARSING_H_ */
