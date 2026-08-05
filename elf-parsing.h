#ifndef ELF_PARSING_H_
#define ELF_PARSING_H_

#include "elf.h"
#include "ctx.h"
#include "util.h"

int read_validate_ehdr(const struct blob *data, int clazz, int encoding,
                       Elf64_Ehdr *out);

int read_validate_phdrs(const struct blob *data, struct elf_phdrs *out,
                        const Elf64_Ehdr *ehdr, int clazz, int encoding);

int read_validate_shdrs(const struct blob *data, struct elf_shdrs *out,
                        const Elf64_Ehdr *ehdr, int clazz, int encoding);

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
int read_elf(const char *path, struct elf *out);

#endif /* ELF_PARSING_H_ */
