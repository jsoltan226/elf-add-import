#include "ctx.h"
#include <stdlib.h>
#include <string.h>

void destroy_elf(struct elf *elf)
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
