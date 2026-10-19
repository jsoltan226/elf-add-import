#include "elf-dyn-sym-ver-parsing.h"
#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

static int validate_sht_gnu_verdef_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword min_size, Elf64_Xword num,
        elf_idx_t *out
)
{
    *out = ELF_IDX_NULL;

    const elf_idx_t shdr_idx =
        find_unique_shdr_by_type(shdrs, shdr_unique_SHT_GNU_verdef);
    if (shdr_idx == ELF_IDX_NULL) {
        pr_debug("No SHT_GNU_verdef section\n");
        return 0;
    }
    const Elf64_Shdr *const shdr = &shdrs->arr[shdr_idx];

    if (dynstr_idx == ELF_IDX_NULL) {
        pr_error("SHT_GNU_verdef exists without a dynstr section\n");
        return 1;
    }

    int ret = 0;

    if (shdr->sh_addr != vaddr) {
        pr_error("Invalid SHT_GNU_verdef virtual address\n");
        ret = 1;
    }

    if (shdr->sh_offset != off) {
        pr_error("Invalid SHT_GNU_verdef offset\n");
        ret = 1;
    }

    if (shdr->sh_size < min_size) {
        pr_error("Invalid SHT_GNU_verdef size\n");
        ret = 1;
    }

    if (shdr->sh_info != num) {
        pr_error("Invalid value of SHT_GNU_verdef sh_info\n");
        ret = 1;
    }

    if (shdr->sh_link != dynstr_idx) {
        pr_error("SHT_GNU_verdef sh_link doesn't point "
                 "to the dynstr section\n");
        ret = 1;
    }

    if (shdr->sh_entsize != 0) {
        pr_error("Invalid SHT_GNU_verdef entsize\n");
        ret = 1;
    }

    if (!ret)
        *out = shdr_idx;
    return ret;
}

static_assert(sizeof(Elf64_Verdef) == sizeof(Elf32_Verdef),
              "sizeof(ElfXX_Verdef) must be the same for both classes");
#define VERDEF_ENTSIZE (sizeof(Elf64_Verdef))

static_assert(sizeof(Elf64_Verdaux) == sizeof(Elf32_Verdaux),
              "sizeof(ElfXX_Verdaux) must be the same for both classes");
#define VERDAUX_ENTSIZE (sizeof(Elf64_Verdaux))

static __attribute__((unused)) int read_verdaux_list(
        const struct blob *data, int clazz, int encoding,
        const struct elf_dyn_strtab *strtab, Elf64_Word vd_hash,
        Elf64_Off seg_end, Elf64_Off start_off, Elf64_Half cnt,
        Elf64_Verdaux **out, Elf64_Off *max_end
)
{
    Elf64_Verdaux *arr = NULL;
    *out = NULL;
    Elf64_Off off = 0;

    /* `cnt` guaranteed to be > 0 */
    assert(cnt > 0);

    /* `size_t` is guaranteed to be at least 16 bits wide */
    arr = calloc((size_t)cnt, sizeof(Elf64_Verdaux));
    if (arr == NULL) {
        pr_error("Failed to allocate verdef auxiliary info entries list\n");
        return 1;
    }

    off = start_off;
    for (Elf64_Half i = 0; i < cnt; i++) {
        if (off > seg_end - VERDAUX_ENTSIZE) {
            pr_error("Verdaux entry no %" PRIu16 " "
                     "would overflow segment bounds\n", i);
            goto err;
        }
        Elf64_Verdaux *const curr = &arr[i];
        {
            Elf64_Off tmp = off;
            if (read_verdaux(data, &tmp, clazz, encoding, curr)) {
                pr_error("Failed to read verdaux entry no %" PRIu16 "\n", i);
                goto err;
            }
            if (tmp > *max_end)
                *max_end = tmp;
        }

        if (curr->vda_name >= strtab->size) {
            pr_error("Invalid vda_name field of verdaux entry "
                     "no %" PRIu16 "\n", i);
            goto err;
        }

        if (i == 0) {
            /* Parent verdef's `vd_hash` should match
             * `sysv_hash(first_aux->vda_name)` */
            const uint8_t *name_str =
                &data->data[strtab->off + curr->vda_name];
            if (sysv_hash(name_str) != vd_hash) {
                pr_error("Hash mismatch in name referenced by "
                         "verdaux entry no %" PRIu16 "\n", i);
                goto err;
            }
        }

        if (curr->vda_next != 0 && curr->vda_next < VERDAUX_ENTSIZE) {
            pr_error("Invalid vda_next value in "
                    "verdaux entry no %" PRIu16 "\n", i);
            goto err;
        }

        if (i == cnt - 1) {
            if (curr->vda_next != 0) {
                pr_error("Unterminated of verdaux entry list\n");
                goto err;
            }
        } else {
            if (curr->vda_next == 0) {
                pr_error("Early termination of verdaux entry list\n");
                goto err;
            }

            if (curr->vda_next > seg_end - off) {
                pr_error("Next verdaux entry offset overflows load segment\n");
                goto err;
            }
            off += curr->vda_next;
        }
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

static __attribute__((unused)) int read_verdef_entries(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        const struct elf_dyn_strtab *strtab, Elf64_Off start_off, size_t num,
        Elf64_Verdef **out, Elf64_Verdaux ***out_aux_lists,
        elf_idx_t *out_base_idx, Elf64_Half *out_max_vd_ndx,
        Elf64_Off *out_max_end
)
{
    *out = NULL;
    *out_aux_lists = NULL;
    *out_base_idx = ELF_IDX_NULL;
    *out_max_vd_ndx = 0;
    *out_max_end = 0;
    Elf64_Verdef *defs = NULL;
    Elf64_Verdaux **aux_lists = NULL;
    Elf64_Off max_end = 0;
    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];
    const Elf64_Off ptload_end = ptload->p_offset + ptload->p_filesz;

    elf_idx_t vd_base_idx = ELF_IDX_NULL;
    Elf64_Half max_vd_ndx = 0;
    Elf64_Off off;

    defs = calloc(num, VERDEF_ENTSIZE);
    if (defs == NULL) {
        pr_error("Failed to allocate the verdef entries array\n");
        goto err;
    }
    aux_lists = calloc(num, sizeof(Elf64_Verdaux *));
    if (aux_lists == NULL) {
        pr_error("Failed to allocate the verdef auxiliary entry lists array\n");
        goto err;
    }

    off = start_off;
    for (Elf64_Xword i = 0; i < num; i++) {
        if (off > ptload_end - VERDEF_ENTSIZE) {
            pr_error("Next verdef entry would overflow segment bounds\n");
            goto err;
        }
        Elf64_Verdef *const curr = &defs[i];
        {
            Elf64_Off tmp = off;
            if (read_verdef(data, &tmp, clazz, encoding, curr)) {
                pr_error("Failed to read version definition entry "
                         "no %" PRIu64 "\n", i);
                goto err;
            }
            if (tmp > max_end)
                max_end = tmp;
        }

        if (curr->vd_version != VER_DEF_CURRENT) {
            pr_error("Invalid struct version of "
                     "verdef entry no %" PRIu64 "\n", i);
            goto err;
        }

        const Elf64_Half allowed = VER_FLG_BASE | VER_FLG_WEAK | VER_FLG_INFO;
        if (curr->vd_flags & (Elf64_Half)~allowed) {
            pr_error("Invalid flags field of "
                     "verdef entry no %" PRIu64 "\n", i);
            goto err;
        }
        if (curr->vd_flags & VER_FLG_BASE) {
            if (vd_base_idx != ELF_IDX_NULL) {
                pr_error("More than one verdef entry with BASE flag\n");
                goto err;
            }
            vd_base_idx = i;
        }

        if (curr->vd_ndx > max_vd_ndx)
            max_vd_ndx = curr->vd_ndx;

        if (curr->vd_cnt == 0) {
            pr_error("Number of auxiliary entries of "
                     "verdef entry no %" PRIu64 " is 0\n", i);
            goto err;
        }

        if (curr->vd_aux > ptload_end - off) {
            pr_error("Auxiliary array offset of verdef entry no %" PRIu64 " "
                     "overflows load segment\n", i);
            goto err;
        }
        const Elf64_Off aux_off = off + curr->vd_aux;

        /* also validates `vd_hash` */
        if (read_verdaux_list(data, clazz, encoding, strtab, curr->vd_hash,
                              ptload_end, aux_off, curr->vd_cnt,
                              &aux_lists[i], &max_end))
        {
            pr_error("Failed to read auxiliary information entry list of "
                     "verdef entry no %" PRIu64 "\n", i);
            goto err;
        }

        if (curr->vd_next != 0 && curr->vd_next < VERDEF_ENTSIZE) {
            pr_error("Invalid value of vd_next in "
                    "verdef entry no %" PRIu64 "\n", i);
            goto err;
        }

        if (i == num - 1) {
            if (curr->vd_next != 0) {
                pr_error("Unterminated verdef entries list\n");
                goto err;
            }
        } else {
            if (curr->vd_next == 0) {
                pr_error("Early termination of verdef entries list\n");
                goto err;
            }

            if (curr->vd_next > ptload_end - off) {
                pr_error("Next verdef entry offset overflows load segment\n");
                goto err;
            }
            off += curr->vd_next;
        }
    }

    *out = defs;
    *out_aux_lists = aux_lists;
    *out_base_idx = vd_base_idx;
    *out_max_vd_ndx = max_vd_ndx;
    *out_max_end = max_end;
    return 0;

err:
    if (defs != NULL) {
        free(defs);
        defs = NULL;
    }
    if (aux_lists != NULL) {
        for (size_t i = 0; i < num; i++) {
            if (aux_lists[i] != NULL) {
                free(aux_lists[i]);
                aux_lists[i] = NULL;
            }
        }
        free(aux_lists);
        aux_lists = NULL;
    }

    return 1;
}

static int parse_verdef(const struct elf_phdrs *phdrs,
                        const struct elf_shdrs *shdrs,
                        const struct elf_dyn_strtab *strtab,
                        const struct elf_dyn_entries *entries,
                        elf_idx_t dt_verdef_idx, elf_idx_t dt_verdefnum_idx,
                        const struct blob *data, int clazz, int encoding)
{
    const Elf64_Addr vaddr = entries->arr[dt_verdef_idx].d_un.d_ptr;
    const Elf64_Xword num = entries->arr[dt_verdefnum_idx].d_un.d_val;

    if (num == 0) {
        pr_error("WARNING: Empty DT_VERDEF list\n");
        return 0;
    }

    Elf64_Xword min_tbl_size = 0;
    elf_idx_t ptload_idx = ELF_IDX_NULL;
    Elf64_Off tbl_off = 0;
    Elf64_Verdef *arr = NULL;
    Elf64_Verdaux **aux_arrs = NULL;
    Elf64_Off max_end = 0;
    elf_idx_t vd_base_idx = ELF_IDX_NULL;
    Elf64_Half max_vd_ndx = 0;
    elf_idx_t sht_gnu_verdef_idx = ELF_IDX_NULL;

    if (num > UINT64_MAX / VERDEF_ENTSIZE || num > SIZE_MAX) {
        pr_error("Number of verdef entries too large (integer overflow)\n");
        goto err;
    }
    min_tbl_size = num * VERDEF_ENTSIZE;

    if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                       &tbl_off, &ptload_idx))
    {
        pr_error("Verdef table not contained in any PT_LOAD segment\n");
        goto err;
    }

    if (read_verdef_entries(data, clazz, encoding, phdrs, ptload_idx, strtab,
                            tbl_off, num, &arr, &aux_arrs,
                            &vd_base_idx, &max_vd_ndx, &max_end))
    {
        pr_error("Failed to parse the version definition list\n");
        goto err;
    }
    if (max_end < tbl_off || max_end - tbl_off < min_tbl_size) {
        pr_error("Read an incorrect number of bytes "
                 "(something has gone seriously wrong)\n");
        goto err;
    }
    min_tbl_size = max_end - tbl_off;

    if (validate_sht_gnu_verdef_if_exists(shdrs, strtab->shdr, vaddr, tbl_off,
                                          min_tbl_size, num,
                                          &sht_gnu_verdef_idx))
    {
        pr_error("Invalid SHT_GNU_verdef section\n");
        goto err;
    }

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    if (aux_arrs != NULL) {
        for (Elf64_Xword i = 0; i < num; i++) {
            if (aux_arrs[i] != NULL) {
                free(aux_arrs[i]);
                aux_arrs[i] = NULL;
            }
        }
        free(aux_arrs);
        aux_arrs = NULL;
    }

    return 1;
}

int parse_ver(const struct elf_phdrs *phdrs,
              const struct elf_shdrs *shdrs,
              const struct elf_dyn_strtab *strtab,
              const struct elf_dyn_entries *entries,
              const struct blob *data, int clazz, int encoding)
{
    int r = 0;
    elf_idx_t dt_versym_idx = ELF_IDX_NULL;
    enum { DT_VERDEF_IDX = 0, DT_VERDEFNUM_IDX = 1 };
    elf_idx_t verdef_idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };
    enum { DT_VERNEED_IDX = 0, DT_VERNEEDNUM_IDX = 1 };
    elf_idx_t verneed_idxs[2] = { ELF_IDX_NULL, ELF_IDX_NULL };

    bool __attribute__((unused)) versym_present = false,
         verdef_present = false,
         verneed_present = false;

    r = find_unique_dyn_entry(entries, DT_VERSYM, &dt_versym_idx);
    if (r < 0) {
        pr_error("Duplicate DT_VERSYM entry\n");
        goto err;
    }
    versym_present = r == 0;

    r = find_unique_dyn_entries(entries, 2,
            (Elf64_Sxword[]) { DT_VERDEF, DT_VERDEFNUM }, verdef_idxs);
    if (r < 0) {
        pr_error("Duplicate and/or missing DT_VERDEF and/or DT_VERDEFNUM "
                 "entries");
        goto err;
    }
    verdef_present = r == 0;

    r = find_unique_dyn_entries(entries, 2,
            (Elf64_Sxword[]) { DT_VERNEED, DT_VERNEEDNUM }, verneed_idxs);
    if (r < 0) {
        pr_error("Duplicate and/or missing DT_VERNEED and/or DT_VERNEEDNUM "
                 "entries");
        goto err;
    }
    verneed_present = r == 0;

    if ((verdef_present || verneed_present) && !versym_present) {
        pr_error("DT_VERDEF and/or DT_VERNEED present without DT_VERSYM\n");
        goto err;
    }

    if (verdef_present) {
        if (parse_verdef(phdrs, shdrs, strtab, entries,
                    verdef_idxs[DT_VERDEF_IDX], verdef_idxs[DT_VERDEFNUM_IDX],
                    data, clazz, encoding))
        {
            pr_error("Failed to parse symbol version definition information\n");
            goto err;
        }
    }

    if (verneed_present) {
        return -1;
    }

err:
    return 1;
}
