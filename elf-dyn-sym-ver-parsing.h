#ifndef ELF_DYN_SYM_VER_PARSING_H_
#define ELF_DYN_SYM_VER_PARSING_H_

#include "ctx.h"
#include "util.h"

int parse_ver(const struct elf_phdrs *phdrs,
              const struct elf_shdrs *shdrs,
              const struct elf_dyn_strtab *strtab,
              const struct elf_dyn_entries *entries,
              const struct blob *data, int clazz, int encoding);

#endif /* ELF_DYN_SYM_VER_PARSING_H_ */
