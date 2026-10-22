#include "elf-dyn-sym-ver-parsing.h"
#include "ctx.h"
#include "elf.h"
#include "util.h"
#include "elf-types.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>

static_assert(sizeof(Elf64_Verdef) == sizeof(Elf32_Verdef),
              "sizeof(ElfXX_Verdef) must be the same for both classes");
#define VERDEF_ENTSIZE (sizeof(Elf64_Verdef))

static_assert(sizeof(Elf64_Verdaux) == sizeof(Elf32_Verdaux),
              "sizeof(ElfXX_Verdaux) must be the same for both classes");
#define VERDAUX_ENTSIZE (sizeof(Elf64_Verdaux))

static_assert(sizeof(Elf64_Verneed) == sizeof(Elf32_Verneed),
              "sizeof(ElfXX_Verneed) must be the same for both classes");
#define VERNEED_ENTSIZE (sizeof(Elf64_Verneed))

static_assert(sizeof(Elf64_Vernaux) == sizeof(Elf32_Vernaux),
              "sizeof(ElfXX_Vernaux) must be the same for both classes");
#define VERNAUX_ENTSIZE (sizeof(Elf64_Vernaux))

/* (2^16 / 2), because the highest bit in version indices is reserved.
 * Technically, the values `0` and `1` are in some cases reserved too,
 * but two wasted bits are not worth the added complexity. */
#define VERNDX_BITS (0x8000)
#define WORD_BITS (sizeof(size_t) * CHAR_BIT)

/* ceil(VERNDX_BITS / 64), on 64-bit systems */
#define VERNDX_BITMAP_WORDS ((VERNDX_BITS + WORD_BITS - 1) / WORD_BITS)

typedef size_t verndx_bitmap_t[VERNDX_BITMAP_WORDS];

static bool claim_version_index(verndx_bitmap_t seen_bits, Elf64_Half vndx_val)
{
    /* The highest bit is a "hidden" flag */
    const Elf64_Half real_vndx = vndx_val & UINT16_C(0x7fff);

    const size_t wordidx = real_vndx / WORD_BITS;
    const size_t bitidx = real_vndx % WORD_BITS;
    const size_t mask = (size_t)1 << bitidx;

    if (seen_bits[wordidx] & mask)
        return true;

    seen_bits[wordidx] |= mask;
    return false;
}

static int parse_verdef(const struct elf_phdrs *phdrs,
                        const struct elf_shdrs *shdrs,
                        const struct elf_dyn_strtab *strtab,
                        const struct elf_dyn_entries *entries,
                        elf_idx_t dt_verdef_idx, elf_idx_t dt_verdefnum_idx,
                        verndx_bitmap_t seen_vndx_bitmap,
                        const struct blob *data, int clazz, int encoding);

static int read_verdef_entries(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        const struct elf_dyn_strtab *strtab, Elf64_Off start_off, size_t num,
        Elf64_Verdef **out, Elf64_Verdaux ***out_aux_lists,
        elf_idx_t *out_base_idx, Elf64_Off *out_max_end,
        verndx_bitmap_t verndx_bitmap
);

static int read_verdaux_list(
        const struct blob *data, int clazz, int encoding,
        const struct elf_dyn_strtab *strtab, Elf64_Word vd_hash,
        Elf64_Off seg_end, Elf64_Off start_off, Elf64_Half cnt,
        Elf64_Off *max_end_p, Elf64_Verdaux **out, Elf64_Off *out_list_end
);

static int validate_sht_gnu_verXXX_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword min_size, Elf64_Xword num,
        elf_idx_t *out, bool is_verdef
);

static int parse_verneed(const struct elf_phdrs *phdrs,
                         const struct elf_shdrs *shdrs,
                         const struct elf_dyn_strtab *strtab,
                         const struct elf_dyn_entries *entries,
                         elf_idx_t dt_verneed_idx, elf_idx_t dt_verneednum_idx,
                         verndx_bitmap_t seen_vndx_bitmap,
                         const struct blob *data, int clazz, int encoding);


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

    verndx_bitmap_t seen_vndx_bitmap = { 0 };

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
                seen_vndx_bitmap, data, clazz, encoding))
        {
            pr_error("Failed to parse symbol version definition information\n");
            goto err;
        }
    }

    if (verneed_present) {
        if (parse_verneed(phdrs, shdrs, strtab, entries,
                verneed_idxs[DT_VERNEED_IDX], verneed_idxs[DT_VERNEEDNUM_IDX],
                seen_vndx_bitmap, data, clazz, encoding))
        {
            pr_error("Failed to parse symbol version dependency information\n");
            goto err;
        }
    }

    if (verneed_present) {
        return -1;
    }

err:
    return 1;
}

struct verdef_name_ref {
    Elf64_Word vd_hash;
    const char *name;
    size_t self_idx;
};

static int verdef_name_ref_cmp(const void *a_, const void *b_)
{
    const struct verdef_name_ref *const a = a_;
    const struct verdef_name_ref *const b = b_;

    /* Sort the verdef entries by their first aux entries' `vda_name`
     * while using the `vd_hash` to our advantage */

    if (a->vd_hash < b->vd_hash) return -1;
    if (a->vd_hash > b->vd_hash) return 1;

    return strcmp(a->name, b->name);
}

static int validate_verdef_names(
        const Elf64_Verdef *arr, const Elf64_Verdaux *const *aux_lists,
        size_t num, const struct elf_dyn_strtab *strtab, const struct blob *data
)
{
    int ret = 0;
    struct verdef_name_ref *refs = NULL;
    const uint8_t *const strtab_bytes = data->data + strtab->off;

    refs = calloc(num, sizeof(*refs));
    if (refs == NULL) {
        pr_error("Failed to allocate verdef name ref structs array\n");
        ret = -1;
        goto out;
    }
    for (size_t i = 0; i < num; i++) {
        const Elf64_Word vd_hash = arr[i].vd_hash;
        const Elf64_Verdaux *const first_aux = &aux_lists[i][0];

        refs[i] = (struct verdef_name_ref) {
            .vd_hash = vd_hash,
            .name = (const char *)&strtab_bytes[first_aux->vda_name],
            .self_idx = i
        };
    }

    qsort(refs, num, sizeof(*refs), verdef_name_ref_cmp);

    /* Check for duplicates */
    for (size_t i = 1; i < num; i++) {
        const struct verdef_name_ref *const curr = &refs[i];
        const struct verdef_name_ref *const prev = &refs[i - 1];

        if (prev->vd_hash == curr->vd_hash &&
            !strcmp(prev->name, curr->name))
        {
            pr_error("Duplicate verdef name \"%s\"\n", curr->name);
            ret = 1;
        }
    }

    /* Resolve every verdef's verdaux[1..n] vda_names
     * against some other verdef's verdaux[0]'s vda_name.
     *
     * This is easy because we conveniently have exactly what we need:
     * a (sorted!) array of verdefs with their verdaux[0] entries. */
    for (size_t i = 0; i < num; i++) {
        const struct verdef_name_ref *const curr = &refs[i];

        for (Elf64_Half j = 1; j < arr[curr->self_idx].vd_cnt; j++) {

            const Elf64_Verdaux *const curr_1_n_aux =
                &aux_lists[curr->self_idx][j];

            const char *const vda_name = (const char *)
                &strtab_bytes[curr_1_n_aux->vda_name];

            const struct verdef_name_ref key = {
                .vd_hash = sysv_hash((const uint8_t *)vda_name),
                .name = vda_name
            };
            const struct verdef_name_ref *const res =
                bsearch(&key, refs, num, sizeof(*refs), verdef_name_ref_cmp);

            if (res == NULL) {
                pr_error("Additional verdaux entry \"%s\" doesn't resolve "
                         "to any verdef's first verdaux entry\n", vda_name);
                ret = 1;
            } else if (res->self_idx == curr->self_idx) {
                pr_error("Verdef \"%s\" depends on itself\n", curr->name);
                ret = 1;
            }
        }
    }

out:
    if (refs != NULL) {
        free(refs);
        refs = NULL;
    }
    return ret;
}

static int parse_verdef(const struct elf_phdrs *phdrs,
                        const struct elf_shdrs *shdrs,
                        const struct elf_dyn_strtab *strtab,
                        const struct elf_dyn_entries *entries,
                        elf_idx_t dt_verdef_idx, elf_idx_t dt_verdefnum_idx,
                        verndx_bitmap_t seen_vndx_bitmap,
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
    elf_idx_t sht_gnu_verdef_idx = ELF_IDX_NULL;

    if (num > UINT64_MAX / VERDEF_ENTSIZE || num > SIZE_MAX) {
        pr_error("Number of verdef entries too large (integer overflow)\n");
        goto err;
    }
    /**
     * Since `VERDEF_ENTSIZE` > `VERDAUX_ENTSIZE`,
     * this guarantees that whatever segment we find can contain
     * at least one ElfXX_Verdef or ElfXX_Verdaux, which means that
     * `seg_end - VERDEF_ENTSIZE` as well as `seg_end - VERDAUX_ENTSIZE`
     * never underflow.
     */
    min_tbl_size = num * VERDEF_ENTSIZE;

    if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                       &tbl_off, &ptload_idx))
    {
        pr_error("Verdef table not contained in any PT_LOAD segment\n");
        goto err;
    }

    if (read_verdef_entries(data, clazz, encoding, phdrs, ptload_idx, strtab,
                            tbl_off, (size_t)num, &arr, &aux_arrs,
                            &vd_base_idx, &max_end, seen_vndx_bitmap))
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
    /* Sanity check */
    {
        elf_idx_t tmp = ELF_IDX_NULL;
        if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                           NULL, &tmp) || tmp != ptload_idx)
        {
            pr_error("Full verdef table not backed by the "
                     "correct PT_LOAD segment\n");
            goto err;
        }
    }

    if (validate_verdef_names(arr, (const Elf64_Verdaux *const *)aux_arrs, num,
                              strtab, data))
    {
        pr_error("Invalid verdef names/dependencies\n");
        goto err;
    }

    if (validate_sht_gnu_verXXX_if_exists(shdrs, strtab->shdr, vaddr, tbl_off,
                                          min_tbl_size, num,
                                          &sht_gnu_verdef_idx, true))
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

static int read_validate_verdef_entry(
        const struct blob *data, int clazz, int encoding,
        Elf64_Off seg_end, const struct elf_dyn_strtab *strtab,
        bool is_last_entry, Elf64_Off *max_end_p,
        verndx_bitmap_t seen_vndx_bitmap, Elf64_Off *off_p,

        Elf64_Verdef *out, Elf64_Verdaux **out_aux_list,
        bool *out_is_base
)
{
    if (*off_p > seg_end - VERDEF_ENTSIZE) {
        pr_error("Next verdef entry would overflow segment bounds\n");
        return 1;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verdef(data, &tmp, clazz, encoding, out)) {
            pr_error("Failed to read verdef entry from file data\n");
            return 1;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    if (out->vd_version != VER_DEF_CURRENT) {
        pr_error("Invalid struct version\n");
        return 1;
    }

    const Elf64_Half allowed = VER_FLG_BASE | VER_FLG_WEAK;
    if (out->vd_flags & (Elf64_Half)~allowed) {
        pr_error("Invalid vd_flags\n");
        return 1;
    }
    if (out->vd_flags & VER_FLG_BASE)
        *out_is_base = true;

    /* The 15th bit in VERSYM entries is reserved as a "hidden" flag,
     * so if any `vd_ndx` has it set it can't be referenced at all.
     *
     * Also, the values `0` and `1` are reserved for the values
     * `VER_NDX_LOCAL` and `VER_NDX_GLOBAL`, respectively,
     * with `VER_NDX_LOCAL` always being invalid,
     * while `VER_NDX_GLOBAL` being assigned to the base symbol. */
    if (out->vd_ndx & UINT16_C(0x8000)) {
        pr_error("Highest bit set in vd_ndx making the verdef entry "
                 "unreferenceable from VERSYM\n");
        return 1;
    } else if (out->vd_ndx == VER_NDX_LOCAL ||
        ((out->vd_flags & VER_FLG_BASE) != (out->vd_ndx == VER_NDX_GLOBAL)))
    {
        pr_error("vd_ndx set to a reserved or invalid value\n");
        return 1;
    } else if (claim_version_index(seen_vndx_bitmap, out->vd_ndx)) {
        pr_error("Duplicate version index in vd_ndx\n");
        return 1;
    }

    if (out->vd_cnt == 0) {
        pr_error("Number of auxiliary entries is 0\n");
        return 1;
    }

    if (out->vd_aux < VERDEF_ENTSIZE) {
        pr_error("Start of auxiliary array inside of verdef entry\n");
        return 1;
    } else if (out->vd_aux > seg_end - *off_p) {
        pr_error("Auxiliary array offset overflows load segment\n");
        return 1;
    }
    const Elf64_Off aux_off = *off_p + out->vd_aux;

    Elf64_Off aux_end = 0;
    /* also validates `vd_hash` */
    if (read_verdaux_list(data, clazz, encoding, strtab, out->vd_hash,
                          seg_end, aux_off, out->vd_cnt, max_end_p,
                          out_aux_list, &aux_end))
    {
        pr_error("Failed to read auxiliary information entry list\n");
        return 1;
    }

    if (out->vd_next != 0 && out->vd_next < VERDEF_ENTSIZE) {
        pr_error("Invalid value of vd_next\n");
        return 1;
    }

    if (is_last_entry) {
        if (out->vd_next != 0) {
            pr_error("Unterminated verdef entries list\n");
            return 1;
        }
    } else /* if (!is_last_entry) */ {
        if (out->vd_next == 0) {
            pr_error("Early termination of verdef entries list\n");
            return 1;
        }

        if (out->vd_next > seg_end - *off_p) {
            pr_error("Next verdef entry offset overflows load segment\n");
            return 1;
        }
        const Elf64_Off next_off = *off_p + out->vd_next;
        if (next_off < aux_end) {
            pr_error("Next verdaux entry overlaps current one's aux list\n");
            return 1;
        }

        *off_p += out->vd_next;
    }
    return 0;
}

static int read_verdef_entries(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        const struct elf_dyn_strtab *strtab, Elf64_Off start_off, size_t num,
        Elf64_Verdef **out, Elf64_Verdaux ***out_aux_lists,
        elf_idx_t *out_base_idx, Elf64_Off *out_max_end,
        verndx_bitmap_t seen_vndx_bitmap
)
{
    *out = NULL;
    *out_aux_lists = NULL;
    *out_base_idx = ELF_IDX_NULL;
    *out_max_end = 0;
    Elf64_Verdef *arr = NULL;
    Elf64_Verdaux **aux_lists = NULL;
    Elf64_Off max_end = 0;

    elf_idx_t vd_base_idx = ELF_IDX_NULL;
    Elf64_Off off;

    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];
    const Elf64_Off ptload_end = ptload->p_offset + ptload->p_filesz;

    assert(ptload_end >= VERDEF_ENTSIZE && ptload_end >= VERDAUX_ENTSIZE);
    assert(num > 0);

    arr = calloc(num, VERDEF_ENTSIZE);
    if (arr == NULL) {
        pr_error("Failed to allocate the verdef entries array\n");
        goto err;
    }
    aux_lists = calloc(num, sizeof(Elf64_Verdaux *));
    if (aux_lists == NULL) {
        pr_error("Failed to allocate the verdef auxiliary entry lists array\n");
        goto err;
    }
    for (size_t i = 0; i < num; i++) aux_lists[i] = NULL;

    off = start_off;
    for (size_t i = 0; i < num; i++) {
        const bool is_last = (i == num - 1);
        bool is_base = false;
        if (read_validate_verdef_entry(data, clazz, encoding, ptload_end,
                                       strtab, is_last, &max_end, seen_vndx_bitmap,
                                       &off, &arr[i], &aux_lists[i], &is_base))
        {
            pr_error("Failed to parse version definition entry no %zu\n", i);
            goto err;
        }

        if (is_base) {
            if (vd_base_idx != ELF_IDX_NULL) {
                pr_error("More than one verdef entry has the BASE flag set\n");
                goto err;
            }
            vd_base_idx = i;
        }
    }

    if (vd_base_idx == ELF_IDX_NULL) {
        pr_error("No BASE verdef entry\n");
        goto err;
    } else {
        pr_debug("BASE Verdef entry: \"%s\"\n",
                 (const char *)data->data + strtab->off +
                                aux_lists[vd_base_idx][0].vda_name);
    }

    *out = arr;
    *out_aux_lists = aux_lists;
    *out_base_idx = vd_base_idx;
    *out_max_end = max_end;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
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

static int read_validate_verdaux_entry(
        const struct blob *data, int clazz, int encoding,
        const struct elf_dyn_strtab *strtab, Elf64_Word vd_hash,
        Elf64_Off seg_end, bool is_first_entry, bool is_last_entry,
        Elf64_Off *max_end_p, Elf64_Off *off_p, Elf64_Verdaux *out
)
{
    assert(seg_end >= VERDAUX_ENTSIZE);
    if (*off_p > seg_end - VERDAUX_ENTSIZE) {
        pr_error("Verdaux entry would overflow segment bounds\n");
        return 1;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verdaux(data, &tmp, clazz, encoding, out)) {
            pr_error("Failed to read verdaux entry from file data\n");
            return 1;
        }
        if (tmp < *off_p || tmp - *off_p != VERDAUX_ENTSIZE) {
            pr_error("Incorrect number of bytes read (impossible outcome)\n");
            return -1;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    if (out->vda_name >= strtab->size) {
        pr_error("vda_name outside string table bounds\n");
        return 1;
    }

    /* Parent verdef's `vd_hash` should match
     * `sysv_hash(first_aux->vda_name)` */
    if (is_first_entry) {
        const uint8_t *str_ptr = data->data + strtab->off + out->vda_name;
        if (sysv_hash(str_ptr) != vd_hash) {
            pr_error("Hash of vda_name doesn't match parent verdef vd_hash\n");
            return 1;
        }
    }

    if (out->vda_next != 0 && out->vda_next < VERDAUX_ENTSIZE) {
        pr_error("The value of vda_next places the next entry "
                 "inside the current one\n");
        return 1;
    }
    if (is_last_entry) {
        if (out->vda_next != 0) {
            pr_error("Unterminated verdaux entry list\n");
            return 1;
        }
    } else /* if (!is_last_entry) */ {
        if (out->vda_next == 0) {
            pr_error("Early termination of verdaux entry list\n");
            return 1;
        }

        if (out->vda_next > seg_end - *off_p) {
            pr_error("Next verdaux entry offset overflows load segment\n");
            return 1;
        }
        *off_p += out->vda_next;
    }
    return 0;
}

static int read_verdaux_list(
        const struct blob *data, int clazz, int encoding,
        const struct elf_dyn_strtab *strtab, Elf64_Word vd_hash,
        Elf64_Off seg_end, Elf64_Off start_off, Elf64_Half cnt,
        Elf64_Off *max_end_p, Elf64_Verdaux **out, Elf64_Off *out_list_end
)
{
    *out = NULL;
    *out_list_end = 0;
    Elf64_Off off = 0;
    Elf64_Verdaux *arr = NULL;
    Elf64_Off list_end = 0;

    assert(seg_end >= VERDAUX_ENTSIZE);
    assert(cnt > 0);

    /* `size_t` is guaranteed to be at least 16 bits wide */
    arr = calloc((size_t)cnt, sizeof(Elf64_Verdaux));
    if (arr == NULL) {
        pr_error("Failed to allocate verdef auxiliary info entries list\n");
        goto err;
    }

    off = start_off;
    for (Elf64_Half i = 0; i < cnt; i++) {
        const bool is_first = (i == 0);
        const bool is_last = (i == cnt - 1);
        if (read_validate_verdaux_entry(data, clazz, encoding, strtab,
                                        vd_hash, seg_end, is_first, is_last,
                                        max_end_p, &off, &arr[i]))
        {
            pr_error("Failed to parse verdef auxiliary info entry "
                     "no %" PRIu16 "\n", i);
            goto err;
        }
        if (is_first) {
            pr_debug("Verdef entry aux[0]: \"%s\"\n",
                 (const char *)data->data + strtab->off + arr[i].vda_name);
        } else {
            pr_debug("    -> aux[%" PRIu16 "]: \"%s\"\n", i,
                     (const char *)data->data + strtab->off + arr[i].vda_name);
        }

        if (is_last)
            /* `read_validate_verdaux_entry` safely computes this value */
            list_end = off + VERDAUX_ENTSIZE;
    }

    *out = arr; arr = NULL;
    *out_list_end = list_end;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int validate_sht_gnu_verXXX_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword min_size, Elf64_Xword num,
        elf_idx_t *out, bool is_verdef
)
{
    *out = ELF_IDX_NULL;

    const enum shdr_unique_type type = is_verdef ? shdr_unique_SHT_GNU_verdef :
                                                   shdr_unique_SHT_GNU_verneed;
    const char *const name = is_verdef ? "SHT_GNU_verdef" : "SHT_GNU_verneed";

    const elf_idx_t shdr_idx = find_unique_shdr_by_type(shdrs, type);
    if (shdr_idx == ELF_IDX_NULL) {
        pr_debug("No %s section\n", name);
        return 0;
    }
    const Elf64_Shdr *const shdr = &shdrs->arr[shdr_idx];

    if (dynstr_idx == ELF_IDX_NULL) {
        pr_error("%s exists without a dynstr section\n", name);
        return 1;
    }

    int ret = 0;

    if (shdr->sh_addr != vaddr) {
        pr_error("Invalid %s virtual address\n", name);
        ret = 1;
    }

    if (shdr->sh_offset != off) {
        pr_error("Invalid %s offset\n", name);
        ret = 1;
    }

    if (shdr->sh_size < min_size) {
        pr_error("Invalid %s size\n", name);
        ret = 1;
    }

    if (shdr->sh_info != num) {
        pr_error("Invalid value of %s sh_info\n", name);
        ret = 1;
    }

    if (shdr->sh_link != dynstr_idx) {
        pr_error("%s sh_link doesn't point to the dynstr section\n", name);
        ret = 1;
    }

    if (shdr->sh_entsize != 0) {
        pr_error("Invalid %s entsize\n", name);
        ret = 1;
    }

    if (!ret)
        *out = shdr_idx;
    return ret;
}


struct dt_needed_name {
    Elf64_Xword entry_val;
    Elf32_Word hash;
};

static int dt_needed_name_cmp(const void *a_, const void *b_)
{
    const struct dt_needed_name *const a = a_;
    const struct dt_needed_name *const b = b_;

    if (a->entry_val < b->entry_val) return -1;
    else if (a->entry_val == b->entry_val) return 0;
    else /* if (a->entry_val > b->entry_val) */ return 1;
}

static int init_dt_needed_name_table(
        const struct elf_dyn_entries *entries,
        const struct elf_dyn_strtab *strtab, const struct blob *data,
        struct dt_needed_name **out, size_t *out_num
)
{
    *out = NULL;
    *out_num = 0;

    struct dt_needed_name *new_tbl = NULL;
    Elf64_Xword n_dt_needed = 0;

    for (Elf64_Xword i = 0; i < entries->num; i++) {
        if (entries->arr[i].d_tag == DT_NEEDED) {
            n_dt_needed++;
        }
    }
    if (n_dt_needed == 0) {
        pr_error("Number of DT_NEEDED entries cannot be 0 "
                 "with version dependency information present\n");
        goto err;
    } else if (n_dt_needed > SIZE_MAX) {
        pr_error("Number of DT_NEEDED entries too large (integer overflow)\n");
        goto err;
    }


    new_tbl = calloc((size_t)n_dt_needed, sizeof(*new_tbl));
    if (new_tbl == NULL) {
        pr_error("Failed to allocate the DT_NEEDED name hash table\n");
        goto err;
    }
    {
        Elf64_Xword all_entries_idx = 0;
        Elf64_Xword dt_needed_idx = 0;
        do {
            const Elf64_Dyn *const curr_entry = &entries->arr[all_entries_idx];
            if (curr_entry->d_tag != DT_NEEDED)
                continue;

            assert(dt_needed_idx < n_dt_needed);

            new_tbl[dt_needed_idx].entry_val = curr_entry->d_un.d_val;

            if (curr_entry->d_un.d_val >= strtab->size) {
                pr_error("DT_NEEDED entry value overflows string table\n");
                goto err;
            }
            const uint8_t *str_ptr = data->data +
                                     strtab->off + curr_entry->d_un.d_val;
            new_tbl[dt_needed_idx].hash = gnu_hash(str_ptr);

            dt_needed_idx++;
        } while (++all_entries_idx < entries->num);
    }
    qsort(new_tbl, (size_t)n_dt_needed, sizeof(*new_tbl), dt_needed_name_cmp);

    *out = new_tbl; new_tbl = NULL;
    *out_num = (size_t)n_dt_needed;
    return 0;

err:
    if (new_tbl != NULL) {
        free(new_tbl);
        new_tbl = NULL;
    }
    return 1;
}

static bool name_is_dt_needed(
        const struct dt_needed_name *dt_needed_tbl, size_t n_dt_needed,
        const struct blob *data, const struct elf_dyn_strtab *strtab,
        Elf64_Word vn_file
)
{
    /* `vn_file` guaranteed to not overflow `strtab` */
    assert(vn_file < strtab->size);

    /**
     * First, try to check for a DT_NEEDED entry whose value (dynstr offset)
     * is the exact same as `curr->vn_file`, in which case we definetly know
     * that the names match.
     *
     * The `dt_needed_tbl` is sorted by the `entry_val` members,
     * which represent the values of DT_NEEDED entries.
     */
    bool found = false;
    const struct dt_needed_name tmp = { .entry_val = vn_file };
    const struct dt_needed_name *const res =
        bsearch(&tmp, dt_needed_tbl, n_dt_needed, sizeof(*res),
                dt_needed_name_cmp);
    if (res != NULL) {
        pr_debug("Verneed \"%s\": matching DT_NEEDED found "
                 "using pointer equality\n",
                 (const char *)(data->data + strtab->off + vn_file));
        found = true;
    } else {
        /* If we don't find a matching name by exact "pointer equality",
         * just loop through the table and compare hashes. */
        const uint8_t *str_ptr = data->data + strtab->off + vn_file;
        const Elf32_Word hash = gnu_hash(str_ptr);
        for (size_t j = 0; j < n_dt_needed; j++) {
            if (dt_needed_tbl[j].hash == hash) {
                /* Do a strcmp in case of a hash collision */
                const char *dt_needed_strptr = (const char *)
                    (data->data + strtab->off + dt_needed_tbl[j].entry_val);
                if (!strcmp((const char *)str_ptr, dt_needed_strptr)) {
                    found = true;
                    pr_debug("Verneed \"%s\": matching DT_NEEDED found "
                             "using hash comparison\n", (const char *)str_ptr);
                    break;
                }
            }
        }
    }
    return found;
}

static int read_validate_vernaux_entry(
        const struct blob *data, int clazz, int encoding,
        const struct elf_dyn_strtab *strtab, Elf64_Off seg_end,
        bool is_last_entry, Elf64_Off *max_end_p,
        verndx_bitmap_t seen_vndx_bitmap, Elf64_Off *off_p,
        Elf64_Vernaux *out
)
{
    assert(seg_end >= VERNAUX_ENTSIZE);
    if (*off_p > seg_end - VERNAUX_ENTSIZE) {
        pr_error("Vernaux entry overflows segment bounds\n");
        return 1;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_vernaux(data, &tmp, clazz, encoding, out)) {
            pr_error("Failed to read vernaux entry from file data\n");
            return 1;
        }
        if (tmp < *off_p || tmp - *off_p != VERNAUX_ENTSIZE) {
            pr_error("Incorrect number of bytes read (impossible outcome)\n");
            return -1;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    if (out->vna_name >= strtab->size) {
        pr_error("vna_name points outside of string table bounds\n");
        return 1;
    }

    const uint8_t *str_ptr = data->data + strtab->off + out->vna_name;
    if (sysv_hash(str_ptr) != out->vna_hash) {
        pr_error("vna_hash doesn't match the hash of the string "
                 "referenced by vna_name\n");
        return 1;
    }

    const Elf64_Half allowed = VER_FLG_WEAK | VER_FLG_INFO;
    if (out->vna_flags & (Elf64_Half)~allowed) {
        pr_error("Invalid vna_flags\n");
        return 1;
    }

    /* The values `0` and `1` are reserved for the values
     * `VER_NDX_LOCAL` and `VER_NDX_GLOBAL`, respectively.
     * However, on some solaris systems the value `0` was historically used
     * as a placeholder because the linker didn't assign any value then,
     * so treat that case only as a warning.
     *
     * As for the "hidden" flag (bit 15),
     * there's a difference between how GNU and Solaris systems treat it,
     * so just let `claim_version_index` ignore it. */
    const Elf64_Half raw_vndx = out->vna_other;
    const Elf64_Half real_vndx = out->vna_other & UINT16_C(0x7fff);
    if (raw_vndx == VER_NDX_LOCAL) {
        pr_error("WARNING: vna_other is set to the reserved value 0\n");
    } else if (real_vndx == VER_NDX_LOCAL || real_vndx == VER_NDX_GLOBAL) {
        pr_error("vna_other is set to a reserved value\n");
        return 1;
    } else if (claim_version_index(seen_vndx_bitmap, raw_vndx)) {
        pr_error("Duplicate version index in the vna_other field\n");
        return 1;
    }

    if (out->vna_next != 0 && out->vna_next < VERNAUX_ENTSIZE) {
        pr_error("The value of vna_next places the next entry "
                 "inside the current one\n");
        return 1;
    }
    if (is_last_entry) {
        if (out->vna_next != 0) {
            pr_error("Unterminated of vernaux entry list\n");
            return 1;
        }
    } else {
        if (out->vna_next == 0) {
            pr_error("Early termination of vernaux entry list\n");
            return 1;
        }

        if (out->vna_next > seg_end - *off_p) {
            pr_error("Next vernaux entry offset overflows load segment\n");
            return 1;
        }
        *off_p += out->vna_next;
    }
    return 0;
}

static int read_vernaux_list(
        const struct blob *data, int clazz, int encoding,
        const struct elf_dyn_strtab *strtab,
        Elf64_Off seg_end, Elf64_Off start_off, Elf64_Half cnt,
        Elf64_Off *max_end_p, verndx_bitmap_t seen_vndx_bitmap,
        Elf64_Vernaux **out, Elf64_Off *out_list_end
)
{
    Elf64_Off off = 0;
    Elf64_Vernaux *arr = NULL;
    Elf64_Off list_end = 0;
    *out = NULL;
    *out_list_end = 0;

    assert(seg_end >= VERNAUX_ENTSIZE);
    assert(cnt > 0);

    /* `size_t` is guaranteed to be at least 16 bits wide */
    arr = calloc((size_t)cnt, sizeof(Elf64_Vernaux));
    if (arr == NULL) {
        pr_error("Failed to allocate verneed auxiliary info entries list\n");
        goto err;
    }

    off = start_off;
    for (Elf64_Half i = 0; i < cnt; i++) {
        const bool is_last = (i == cnt - 1);
        if (read_validate_vernaux_entry(data, clazz, encoding, strtab, seg_end,
                                        is_last, max_end_p, seen_vndx_bitmap,
                                        &off, &arr[i]))
        {
            pr_error("Failed to read verneed auxiliary info entry "
                     "no %" PRIu16 "\n", i);
            goto err;
        }

        pr_debug("    -> aux[%" PRIu16 "]: \"%s\"\n", i,
                 (const char *)data->data + strtab->off + arr[i].vna_name);
        if (is_last)
            /* `read_validate_vernaux_entry` safely computes this value */
            list_end = off + VERNAUX_ENTSIZE;
    }

    *out = arr; arr = NULL;
    *out_list_end = list_end;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_validate_verneed_entry(
        const struct blob *data, int clazz, int encoding,
        const struct dt_needed_name *dt_needed_tbl, size_t n_dt_needed,
        Elf64_Off seg_end, const struct elf_dyn_strtab *strtab,
        bool is_last_entry,  Elf64_Off *max_end_p,
        verndx_bitmap_t seen_vndx_bitmap, Elf64_Off *off_p,

        Elf64_Verneed *out, Elf64_Vernaux **out_aux_list
)
{
    if (*off_p > seg_end - VERNEED_ENTSIZE) {
        pr_error("Next verneed entry would overflow segment bounds\n");
        return 1;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verneed(data, &tmp, clazz, encoding, out)) {
            pr_error("Failed to read version dependency entry "
                     "from file data\n");
            return 1;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    if (out->vn_version != VER_NEED_CURRENT) {
        pr_error("Invalid struct version\n");
        return 1;
    }

    if (out->vn_file >= strtab->size) {
        pr_error("vn_file outside of string table bounds\n");
        return 1;
    }
    if (!name_is_dt_needed(dt_needed_tbl, n_dt_needed, data, strtab,
                           out->vn_file))
    {
        pr_error("vn_file not referenced by any DT_NEEDED entry\n");
        return 1;
    }

    if (out->vn_aux < VERNEED_ENTSIZE) {
        pr_error("Start of auxiliary list inside verneed entry\n");
        return 1;
    } else if (out->vn_aux > seg_end - *off_p) {
        pr_error("Start of auxiliary list outside of load segment bounds\n");
        return 1;
    }
    const Elf64_Off aux_off = *off_p + out->vn_aux;

    if (out->vn_cnt == 0) {
        pr_error("Number of auxiliary entries is 0\n");
        return 1;
    }

    Elf64_Off aux_end = 0;
    if (read_vernaux_list(data, clazz, encoding, strtab, seg_end,
                          aux_off, out->vn_cnt, max_end_p, seen_vndx_bitmap,
                          out_aux_list, &aux_end))
    {
        pr_error("Failed to read the auxiliary information entries list\n");
        return 1;
    }

    if (out->vn_next != 0 && out->vn_next < VERNEED_ENTSIZE) {
        pr_error("Invalid value of vn_next\n");
        return 1;
    }
    if (is_last_entry) {
        if (out->vn_next != 0) {
            pr_error("Unterminated verneed array\n");
            return 1;
        }
    } else /* if (!is_last_entry) */ {
        if (out->vn_next == 0) {
            pr_error("Early termination of verneed array\n");
            return 1;
        }

        if (out->vn_next > seg_end - *off_p) {
            pr_error("Next vernaux entry offset overflows load segment\n");
            return 1;
        }
        const Elf64_Off next_off = *off_p + out->vn_next;
        if (next_off < aux_end) {
            pr_error("Next vernaux entry overlaps current one's aux list\n");
            return 1;
        }

        *off_p = next_off;
    }
    return 0;
}

static int read_verneed_entries(
        const struct blob *data, int clazz, int encoding,
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        const struct elf_dyn_entries *entries,
        const struct elf_dyn_strtab *strtab,
        Elf64_Off tbl_off, size_t num,

        Elf64_Verneed **out, Elf64_Vernaux ***out_aux_lists,
        Elf64_Off *out_max_end, verndx_bitmap_t seen_vndx_bitmap
)
{
    *out = NULL;
    *out_aux_lists = NULL;
    *out_max_end = 0;
    Elf64_Verneed *arr = NULL;
    Elf64_Vernaux **aux_lists = NULL;
    Elf64_Off off = 0;
    struct dt_needed_name *dt_needed_tbl = NULL;
    size_t n_dt_needed = 0;
    Elf64_Off max_end = 0;

    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];
    const Elf64_Off ptload_end = ptload->p_offset + ptload->p_filesz;

    assert(num > 0);
    assert(ptload_end >= VERNEED_ENTSIZE && ptload_end >= VERNAUX_ENTSIZE);

    if (init_dt_needed_name_table(entries, strtab, data,
                                  &dt_needed_tbl, &n_dt_needed))
    {
        pr_error("Failed to initialize the DT_NEEDED names hash table\n");
        goto err;
    }

    arr = calloc(num, sizeof(Elf64_Verneed));
    if (arr == NULL) {
        pr_error("Failed to allocate the version dependency entries array\n");
        goto err;
    }
    aux_lists = calloc(num, sizeof(Elf64_Vernaux *));
    if (aux_lists == NULL) {
        pr_error("Failed to allocate the verneed auxiliary lists array\n");
        goto err;
    }
    for (size_t i = 0; i < num; i++) aux_lists[i] = NULL;

    off = tbl_off;
    for (size_t i = 0; i < num; i++) {
        const bool is_last = (i == num - 1);
        if (read_validate_verneed_entry(data, clazz, encoding,
                    dt_needed_tbl, n_dt_needed, ptload_end, strtab,
                    is_last, &max_end, seen_vndx_bitmap,
                    &off, &arr[i], &aux_lists[i]))
        {
            pr_error("Failed to parse version dependency information entry "
                     "no %zu\n", i);
            goto err;
        }
    }

    free(dt_needed_tbl); dt_needed_tbl = NULL;
    *out = arr; arr = NULL;
    *out_aux_lists = aux_lists; aux_lists = NULL;
    *out_max_end = max_end;
    return 0;

err:
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
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    if (dt_needed_tbl != NULL) {
        free(dt_needed_tbl);
        dt_needed_tbl = NULL;
    }
    return 1;
}

struct verneed_name_ref {
    const char *vn_file;
    const char *vna_name;
    Elf64_Word vna_hash;
};

static int verneed_name_ref_cmp(const void *a_, const void *b_)
{
    const struct verneed_name_ref *const a = a_;
    const struct verneed_name_ref *const b = b_;

    /* Sort the vernaux entries by (parent vn_file, vna_version)
     * while using the `vna_hash` to our advantage */

    /* Different parent `vn_file` */
    int r = strcmp(a->vn_file, b->vn_file);
    if (r != 0)
        return r;

    /* Different `vna_hash` */
    if (a->vna_hash < b->vna_hash) return -1;
    if (a->vna_hash > b->vna_hash) return 1;

    /* Same `vna_hash`, different `vna_name` */
    return strcmp(a->vna_name, b->vna_name);
}

static int validate_verneed_names_uniqueness(
        const Elf64_Verneed *arr, const Elf64_Vernaux *const *aux_lists,
        size_t num, const struct elf_dyn_strtab *strtab, const struct blob *data
)
{
    struct verneed_name_ref *refs = NULL;
    int ret = 0;

    size_t total_aux = 0;
    for (size_t i = 0; i < num; i++) {
        /* 16-bit values never overflow size_t */
        if ((size_t)arr[i].vn_cnt > SIZE_MAX - total_aux) {
            pr_error("Too many vernaux entries (integer overflow)\n");
            ret = -1;
            goto out;
        }

        total_aux += (size_t)arr[i].vn_cnt;
    }

    refs = calloc(total_aux, sizeof(*refs));
    if (refs == NULL) {
        pr_error("Failed to allocate the verneed name ref structs array\n");
        ret = -1;
        goto out;
    }
    {
        size_t refs_idx = 0;
        for (size_t i = 0; i < num; i++) {
            const uint8_t *const vn_file_strptr =
                data->data + strtab->off + arr[i].vn_file;

            for (Elf64_Half j = 0; j < arr[i].vn_cnt; j++) {
                const Elf64_Vernaux *const curr_aux = &aux_lists[i][j];

                const uint8_t *const vna_name_strptr =
                    data->data + strtab->off + curr_aux->vna_name;

                assert(refs_idx < total_aux);
                refs[refs_idx] = (struct verneed_name_ref) {
                    .vn_file = (const char *)vn_file_strptr,
                    .vna_name = (const char *)vna_name_strptr,
                    .vna_hash = curr_aux->vna_hash,
                };
                refs_idx++;
            }
        }
        assert(refs_idx == total_aux);
    }

    qsort(refs, total_aux, sizeof(*refs), verneed_name_ref_cmp);

    for (size_t i = 1; i < total_aux; i++) {
        const struct verneed_name_ref *const prev = &refs[i - 1];
        const struct verneed_name_ref *const curr = &refs[i];

        if (!strcmp(prev->vn_file, curr->vn_file) &&
            prev->vna_hash == curr->vna_hash &&
            !strcmp(prev->vna_name, curr->vna_name))
        {
            pr_error("Duplicate version dependency: \"%s\" -> \"%s\"\n",
                     curr->vn_file, curr->vna_name);
            ret = 1;
        }
    }

out:
    if (refs != NULL) {
        free(refs);
        refs = NULL;
    }
    return ret;
}

static int parse_verneed(const struct elf_phdrs *phdrs,
                         const struct elf_shdrs *shdrs,
                         const struct elf_dyn_strtab *strtab,
                         const struct elf_dyn_entries *entries,
                         elf_idx_t dt_verneed_idx, elf_idx_t dt_verneednum_idx,
                         verndx_bitmap_t seen_vndx_bitmap,
                         const struct blob *data, int clazz, int encoding)
{
    const Elf64_Addr vaddr = entries->arr[dt_verneed_idx].d_un.d_ptr;
    const Elf64_Xword num = entries->arr[dt_verneednum_idx].d_un.d_val;

    if (num == 0) {
        pr_error("WARNING: Empty DT_VERNEED list\n");
        return 0;
    }

    Elf64_Xword min_tbl_size = 0;
    elf_idx_t ptload_idx = ELF_IDX_NULL;
    Elf64_Off tbl_off = 0;
    Elf64_Verneed *arr = NULL;
    Elf64_Vernaux **aux_arrs = NULL;
    Elf64_Off max_end = 0;
    elf_idx_t sht_gnu_verneed_idx = ELF_IDX_NULL;

    if (num > UINT64_MAX / VERNEED_ENTSIZE || num > SIZE_MAX) {
        pr_error("Number of verneed entries too large (integer overflow)\n");
        goto err;
    }
    /**
     * Since `VERNEED_ENTSIZE` is the same as `VERNAUX_ENTSIZE`,
     * this guarantees that whatever segment we find can contain
     * at least one ElfXX_Verneed or ElfXX_Vernaux, which means that
     * `seg_end - VERNEED_ENTSIZE` as well as `seg_end - VERNAUX_ENTSIZE`
     * never underflow.
     */
    min_tbl_size = num * VERNEED_ENTSIZE;

    if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                       &tbl_off, &ptload_idx))
    {
        pr_error("Verneed table not contained in any PT_LOAD segment\n");
        goto err;
    }

    if (read_verneed_entries(data, clazz, encoding, phdrs, ptload_idx,
                             entries, strtab, tbl_off, (size_t)num,
                             &arr, &aux_arrs, &max_end, seen_vndx_bitmap))
    {
        pr_error("Failed to parse the version dependency list\n");
        goto err;
    }
    if (max_end < tbl_off || max_end - tbl_off < min_tbl_size) {
        pr_error("Read an incorrect number of bytes "
                 "(something has gone seriously wrong)\n");
        goto err;
    }
    min_tbl_size = max_end - tbl_off;
    /* Sanity check */
    {
        elf_idx_t tmp = ELF_IDX_NULL;
        if (find_ptload_and_off_from_vaddr(vaddr, min_tbl_size, phdrs,
                                           NULL, &tmp) || tmp != ptload_idx)
        {
            pr_error("Full verneed table not backed by the "
                     "correct PT_LOAD segment\n");
            goto err;
        }
    }

    if (validate_verneed_names_uniqueness(arr,
                (const Elf64_Vernaux *const *)aux_arrs, (size_t)num, strtab, data))
    {
        pr_error("Duplicate verneed names\n");
        goto err;
    }

    if (validate_sht_gnu_verXXX_if_exists(shdrs, strtab->shdr, vaddr, tbl_off,
                                          min_tbl_size, num,
                                          &sht_gnu_verneed_idx, false))
    {
        pr_error("Invalid SHT_GNU_verneed section\n");
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
