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

struct ver_parsing_ctx {
    const ElfFileData *data;
    const struct elf_dyn_strtab *strtab;
    verndx_bitmap_t seen_vndx_bitmap;
};

static inline const uint8_t *
strtab_strptr(const struct ver_parsing_ctx *ctx, Elf64_Off off)
{
    if (off >= ctx->strtab->size) {
        pr_error("Offset outside of string table bounds\n");
        return NULL;
    }

    return ctx->data->buf + ctx->strtab->off + off;
}

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
                        const struct elf_dyn_entries *entries,
                        elf_idx_t dt_verdef_idx, elf_idx_t dt_verdefnum_idx,
                        struct ver_parsing_ctx *ctx,
                        struct elf_dyn_sym_ver_def *out);

static int read_verdef_entries(
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        Elf64_Off start_off, size_t num, struct ver_parsing_ctx *ctx,

        struct elf_dyn_sym_ver_def_ent **out, Elf64_Off *out_max_end,
        elf_idx_t *out_base_idx
);

static int read_verdaux_list(
        const struct ver_parsing_ctx *ctx, Elf64_Word vd_hash,
        Elf64_Off seg_end, Elf64_Off start_off, Elf64_Half cnt,
        Elf64_Off *max_end_p, Elf64_Verdaux **out, Elf64_Off *out_list_end
);

static int validate_sht_gnu_verXXX_if_exists(
        const struct elf_shdrs *shdrs, elf_idx_t dynstr_idx,
        Elf64_Addr vaddr, Elf64_Off off, Elf64_Xword min_size, Elf64_Xword num,
        elf_idx_t *out, bool is_verdef
);

static int parse_verneed(
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries,
        elf_idx_t dt_verneed_idx, elf_idx_t dt_verneednum_idx,
        struct ver_parsing_ctx *ctx,

        struct elf_dyn_sym_ver_need *out
);

static const struct elf_dyn_sym_ver_def empty_verdef_ctx = {
    .num = 0, .arr = NULL,
    .base_idx = ELF_IDX_NULL,
    .vaddr = 0, .off = 0,
    .dt_verdef_idx = ELF_IDX_NULL, .dt_verdefnum_idx = ELF_IDX_NULL,
    .shdr = ELF_IDX_NULL
};

static const struct elf_dyn_sym_ver_need empty_verneed_ctx = {
    .num = 0, .arr = NULL,
    .vaddr = 0, .off = 0,
    .dt_verneed_idx = ELF_IDX_NULL, .dt_verneednum_idx = ELF_IDX_NULL,
    .shdr = ELF_IDX_NULL
};

static const struct elf_dyn_sym_ver empty_ver_ctx = {
    .def = empty_verdef_ctx,
    .need = empty_verneed_ctx
};

int parse_ver(const struct elf_phdrs *phdrs,
              const struct elf_shdrs *shdrs,
              const struct elf_dyn_strtab *strtab,
              const struct elf_dyn_entries *entries,
              const ElfFileData *data,
              struct elf_dyn_sym_ver *out)
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

    struct elf_dyn_sym_ver ver = empty_ver_ctx;

    struct ver_parsing_ctx ver_parsing_ctx = {
        .data = data,
        .strtab = strtab,
        .seen_vndx_bitmap = { 0 }
    };

    if (out != NULL)
        *out = empty_ver_ctx;

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
        if (parse_verdef(phdrs, shdrs, entries,
                verdef_idxs[DT_VERDEF_IDX], verdef_idxs[DT_VERDEFNUM_IDX],
                &ver_parsing_ctx, &ver.def))
        {
            pr_error("Failed to parse symbol version definition information\n");
            goto err;
        }
    }

    if (verneed_present) {
        if (parse_verneed(phdrs, shdrs, entries,
                verneed_idxs[DT_VERNEED_IDX], verneed_idxs[DT_VERNEEDNUM_IDX],
                &ver_parsing_ctx, &ver.need))
        {
            pr_error("Failed to parse symbol version dependency information\n");
            goto err;
        }
    }

err:
    if (ver.def.arr != NULL) {
        for (Elf64_Xword i = 0; i < ver.def.num; i++) {
            if (ver.def.arr[i].aux_list != NULL) {
                free(ver.def.arr[i].aux_list);
                ver.def.arr[i].aux_list = NULL;
            }
        }
        free(ver.def.arr);
        ver.def.arr = NULL;
    }
    if (ver.need.arr != NULL) {
        for (Elf64_Xword i = 0; i < ver.need.num; i++) {
            if (ver.need.arr[i].aux_list != NULL) {
                free(ver.need.arr[i].aux_list);
                ver.need.arr[i].aux_list = NULL;
            }
        }
        free(ver.need.arr);
        ver.need.arr = NULL;
    }
    ver = empty_ver_ctx;
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
        const struct elf_dyn_sym_ver_def_ent *arr, size_t num,
        const struct ver_parsing_ctx *ctx
)
{
    int ret = 0;
    struct verdef_name_ref *refs = NULL;

    refs = calloc(num, sizeof(*refs));
    if (refs == NULL) {
        pr_error("Failed to allocate verdef name ref structs array\n");
        ret = -1;
        goto out;
    }
    for (size_t i = 0; i < num; i++) {
        const Elf64_Word vd_hash = arr[i].vd.vd_hash;
        const Elf64_Verdaux *const first_aux = &arr[i].aux_list[0];

        refs[i] = (struct verdef_name_ref) {
            .vd_hash = vd_hash,
            .name = (const char *)strtab_strptr(ctx, first_aux->vda_name),
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
        const struct verdef_name_ref *const curr_ref = &refs[i];

        const struct elf_dyn_sym_ver_def_ent *const curr_vd =
            &arr[curr_ref->self_idx];

        for (Elf64_Half j = 1; j < curr_vd->vd.vd_cnt; j++) {

            const Elf64_Verdaux *const curr_1_n_aux = &curr_vd->aux_list[j];

            const char *const vda_name = (const char *)
                strtab_strptr(ctx, curr_1_n_aux->vda_name);
            assert(vda_name != NULL);

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
            } else if (res->self_idx == curr_ref->self_idx) {
                pr_error("Verdef \"%s\" depends on itself\n", curr_ref->name);
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
                        const struct elf_dyn_entries *entries,
                        elf_idx_t dt_verdef_idx, elf_idx_t dt_verdefnum_idx,
                        struct ver_parsing_ctx *ctx,
                        struct elf_dyn_sym_ver_def *out)
{
    *out = empty_verdef_ctx;

    const Elf64_Addr vaddr = entries->arr[dt_verdef_idx].d_un.d_ptr;
    const Elf64_Xword num = entries->arr[dt_verdefnum_idx].d_un.d_val;

    if (num == 0)
        pr_error("WARNING: Empty DT_VERDEF list\n");

    Elf64_Xword min_tbl_size = 0;
    elf_idx_t ptload_idx = ELF_IDX_NULL;
    Elf64_Off tbl_off = 0;
    struct elf_dyn_sym_ver_def_ent *arr = NULL;
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

    if (num > 0) {
        if (read_verdef_entries(phdrs, ptload_idx, tbl_off, (size_t)num, ctx,
                                &arr, &max_end, &vd_base_idx))
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

        if (validate_verdef_names(arr, num, ctx)) {
            pr_error("Invalid verdef names/dependencies\n");
            goto err;
        }
    }

    if (validate_sht_gnu_verXXX_if_exists(shdrs, ctx->strtab->shdr,
                                          vaddr, tbl_off, min_tbl_size, num,
                                          &sht_gnu_verdef_idx, true))
    {
        pr_error("Invalid SHT_GNU_verdef section\n");
        goto err;
    }

    out->num = num;
    out->arr = arr; arr = NULL;
    out->base_idx = vd_base_idx;
    out->vaddr = vaddr;
    out->off = tbl_off;
    out->dt_verdef_idx = dt_verdef_idx;
    out->dt_verdefnum_idx = dt_verdefnum_idx;
    out->shdr = sht_gnu_verdef_idx;
    return 0;

err:
    if (arr != NULL) {
        for (Elf64_Xword i = 0; i < num; i++) {
            if (arr[i].aux_list != NULL) {
                free(arr[i].aux_list);
                arr[i].aux_list = NULL;
            }
        }
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_validate_verdef_entry(
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p,

        struct elf_dyn_sym_ver_def_ent *out, bool *out_is_base
)
{
    Elf64_Verdef vd = { 0 };
    Elf64_Verdaux *aux_list = NULL;
    Elf64_Off aux_list_end = 0;

    *out = (struct elf_dyn_sym_ver_def_ent) { 0 };

    if (*off_p > seg_end - VERDEF_ENTSIZE) {
        pr_error("Next verdef entry would overflow segment bounds\n");
        goto err;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verdef(ctx->data, &tmp, &vd)) {
            pr_error("Failed to read verdef entry from file data\n");
            goto err;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    /* `vd.vd_version` */
    if (vd.vd_version != VER_DEF_CURRENT) {
        pr_error("Invalid struct version\n");
        goto err;
    }

    /* `vd.vd_flags` */
    {
        const Elf64_Half allowed = VER_FLG_BASE | VER_FLG_WEAK;
        if (vd.vd_flags & (Elf64_Half)~allowed) {
            pr_error("Invalid vd_flags\n");
            goto err;
        }
        if (vd.vd_flags & VER_FLG_BASE)
            *out_is_base = true;
    }

    /* `vd.vd_ndx` */
    {
        /* The 15th bit in VERSYM entries is reserved as a "hidden" flag,
         * so if any `vd_ndx` has it set it can't be referenced at all.
         *
         * Also, the values `0` and `1` are reserved for the values
         * `VER_NDX_LOCAL` and `VER_NDX_GLOBAL`, respectively,
         * with `VER_NDX_LOCAL` always being invalid,
         * while `VER_NDX_GLOBAL` being assigned to the base symbol. */
        if (vd.vd_ndx & UINT16_C(0x8000)) {
            pr_error("Highest bit set in vd_ndx making the verdef entry "
                     "unreferenceable from VERSYM\n");
            goto err;
        } else if (vd.vd_ndx == VER_NDX_LOCAL ||
                ((vd.vd_flags & VER_FLG_BASE) != (vd.vd_ndx == VER_NDX_GLOBAL)))
        {
            pr_error("vd_ndx set to a reserved or invalid value\n");
            goto err;
        } else if (claim_version_index(ctx->seen_vndx_bitmap, vd.vd_ndx)) {
            pr_error("Duplicate version index in vd_ndx\n");
            goto err;
        }
    }

    /* `vd.vd_aux`, `vd.vd_cnt`, `vd.vd_hash` */
    aux_list = NULL;
    aux_list_end = 0;
    {
        if (vd.vd_cnt == 0) {
            pr_error("Number of auxiliary entries is 0\n");
            goto err;
        }

        if (vd.vd_aux < VERDEF_ENTSIZE) {
            pr_error("Start of auxiliary array inside of verdef entry\n");
            goto err;
        } else if (vd.vd_aux > seg_end - *off_p) {
            pr_error("Auxiliary array offset overflows load segment\n");
            goto err;
        }
        const Elf64_Off aux_off = *off_p + vd.vd_aux;

        /* also validates `vd_hash` */
        if (read_verdaux_list(ctx, vd.vd_hash, seg_end, aux_off,
                              vd.vd_cnt, max_end_p, &aux_list, &aux_list_end))
        {
            pr_error("Failed to read auxiliary information entry list\n");
            goto err;
        }
    }

    /* `vd.vd_next` */
    {
        if (vd.vd_next != 0 && vd.vd_next < VERDEF_ENTSIZE) {
            pr_error("Invalid value of vd_next\n");
            goto err;
        }

        if (is_last_entry) {
            if (vd.vd_next != 0) {
                pr_error("Unterminated verdef entries list\n");
                goto err;
            }
        } else /* if (!is_last_entry) */ {
            if (vd.vd_next == 0) {
                pr_error("Early termination of verdef entries list\n");
                goto err;
            }

            if (vd.vd_next > seg_end - *off_p) {
                pr_error("Next verdef entry offset overflows load segment\n");
                goto err;
            }
            const Elf64_Off next_off = *off_p + vd.vd_next;
            if (next_off < aux_list_end) {
                pr_error("Next verdef entry overlaps current one's aux list\n");
                goto err;
            }

            *off_p += vd.vd_next;
        }
    }

    out->vd = vd;
    out->aux_list = aux_list; aux_list = NULL;
    return 0;

err:
    if (aux_list != NULL) {
        free(aux_list);
        aux_list = NULL;
    }
    return 1;
}

static int read_verdef_entries(
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        Elf64_Off start_off, size_t num, struct ver_parsing_ctx *ctx,

        struct elf_dyn_sym_ver_def_ent **out, Elf64_Off *out_max_end,
        elf_idx_t *out_base_idx
)
{
    *out = NULL;
    *out_base_idx = ELF_IDX_NULL;
    *out_max_end = 0;
    struct elf_dyn_sym_ver_def_ent *arr = NULL;
    Elf64_Off max_end = 0;

    elf_idx_t vd_base_idx = ELF_IDX_NULL;
    Elf64_Off off;

    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];
    const Elf64_Off ptload_end = ptload->p_offset + ptload->p_filesz;

    assert(ptload_end >= VERDEF_ENTSIZE && ptload_end >= VERDAUX_ENTSIZE);
    assert(num > 0);

    arr = calloc(num, sizeof(struct elf_dyn_sym_ver_def_ent));
    if (arr == NULL) {
        pr_error("Failed to allocate the verdef entries array\n");
        goto err;
    }
    for (size_t i = 0; i < num; i++) arr[i].aux_list = NULL;

    off = start_off;
    for (size_t i = 0; i < num; i++) {
        const bool is_last = (i == num - 1);
        bool is_base = false;
        if (read_validate_verdef_entry(ptload_end, is_last, ctx, &max_end, &off,
                                       &arr[i], &is_base))
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
        pr_debug("BASE Verdef entry: \"%s\"\n", (const char *)
                 strtab_strptr(ctx, arr[vd_base_idx].aux_list[0].vda_name));
    }

    *out = arr; arr = NULL;
    *out_base_idx = vd_base_idx;
    *out_max_end = max_end;
    return 0;

err:
    if (arr != NULL) {
        for (size_t i = 0; i < num; i++) {
            if (arr[i].aux_list != NULL) {
                free(arr[i].aux_list);
                arr[i].aux_list = NULL;
            }
        }
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int read_validate_verdaux_entry(
        const struct ver_parsing_ctx *ctx, Elf64_Word vd_hash,
        Elf64_Off seg_end, bool is_first_entry, bool is_last_entry,
        Elf64_Off *max_end_p, Elf64_Off *off_p, Elf64_Verdaux *out
)
{
    *out = (Elf64_Verdaux) { 0 };

    assert(seg_end >= VERDAUX_ENTSIZE);
    if (*off_p > seg_end - VERDAUX_ENTSIZE) {
        pr_error("Verdaux entry would overflow segment bounds\n");
        return 1;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verdaux(ctx->data, &tmp, out)) {
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

    /* `vda_name` */
    {
        const uint8_t *const vda_name_str = strtab_strptr(ctx, out->vda_name);
        if (vda_name_str == NULL) {
            pr_error("vda_name outside string table bounds\n");
            return 1;
        }

        /* Parent verdef's `vd_hash` should match
         * `sysv_hash(first_aux->vda_name)` */
        if (is_first_entry) {
            if (sysv_hash(vda_name_str) != vd_hash) {
                pr_error("Hash of vda_name doesn't match "
                         "parent verdef vd_hash\n");
                return 1;
            }
        }
    }

    /* `vda_next` */
    {
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
    }
    return 0;
}

static int read_verdaux_list(
        const struct ver_parsing_ctx *ctx, Elf64_Word vd_hash,
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

        if (read_validate_verdaux_entry(ctx, vd_hash, seg_end,
                                        is_first, is_last, max_end_p,
                                        &off, &arr[i]))
        {
            pr_error("Failed to parse verdef auxiliary info entry "
                     "no %" PRIu16 "\n", i);
            goto err;
        }
        if (is_first) {
            pr_debug("Verdef entry aux[0]: \"%s\"\n", (const char *)
                     strtab_strptr(ctx, arr[i].vda_name));
        } else {
            pr_debug("    -> aux[%" PRIu16 "]: \"%s\"\n", i,
                     (const char *)strtab_strptr(ctx, arr[i].vda_name));
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
        const struct elf_dyn_strtab *strtab, const ElfFileData *data,
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
            const uint8_t *str_ptr = data->buf +
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
        const struct ver_parsing_ctx *ctx, Elf64_Word vn_file
)
{
    /* `vn_file` guaranteed to not overflow `strtab` */
    assert(vn_file < ctx->strtab->size);

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
                 (const char *)strtab_strptr(ctx, vn_file));
        found = true;
    } else {
        /* If we don't find a matching name by exact "pointer equality",
         * just loop through the table and compare hashes. */
        const uint8_t *const vn_file_str = strtab_strptr(ctx, vn_file);
        const Elf32_Word vn_file_hash = gnu_hash(vn_file_str);

        for (size_t j = 0; j < n_dt_needed; j++) {
            if (dt_needed_tbl[j].hash == vn_file_hash) {
                /* Do a strcmp in case of a hash collision */
                const char *const dt_needed_str = (const char *)
                    strtab_strptr(ctx, dt_needed_tbl[j].entry_val);

                if (!strcmp((const char *)vn_file_str, dt_needed_str)) {
                    pr_debug("Verneed \"%s\": matching DT_NEEDED found "
                             "using hash comparison\n",
                             (const char *)vn_file_str);
                    found = true;
                    break;
                }
            }
        }
    }
    return found;
}

static int read_validate_vernaux_entry(
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p, Elf64_Vernaux *out
)
{
    *out = (Elf64_Vernaux) { 0 };

    assert(seg_end >= VERNAUX_ENTSIZE);
    if (*off_p > seg_end - VERNAUX_ENTSIZE) {
        pr_error("Vernaux entry overflows segment bounds\n");
        return 1;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_vernaux(ctx->data, &tmp, out)) {
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

    /* `vna_name`, `vna_hash` */
    {
        const uint8_t *const vna_name_str = strtab_strptr(ctx, out->vna_name);
        if (vna_name_str == NULL) {
            pr_error("vna_name points outside of string table bounds\n");
            return 1;
        }
        if (sysv_hash(vna_name_str) != out->vna_hash) {
            pr_error("vna_hash doesn't match the hash of the string "
                     "referenced by vna_name\n");
            return 1;
        }
    }

    /* `vna_flags` */
    {
        const Elf64_Half allowed = VER_FLG_WEAK | VER_FLG_INFO;
        if (out->vna_flags & (Elf64_Half)~allowed) {
            pr_error("Invalid vna_flags\n");
            return 1;
        }
    }

    /* `vna_other` */
    {
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
        } else if (claim_version_index(ctx->seen_vndx_bitmap, raw_vndx)) {
            pr_error("Duplicate version index in the vna_other field\n");
            return 1;
        }
    }

    /* `vna_next` */
    {
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
    }

    return 0;
}

static int read_vernaux_list(
        struct ver_parsing_ctx *ctx, Elf64_Off seg_end,
        Elf64_Off start_off, Elf64_Half cnt, Elf64_Off *max_end_p,
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
        if (read_validate_vernaux_entry(seg_end, is_last, ctx, max_end_p,
                                        &off, &arr[i]))
        {
            pr_error("Failed to read verneed auxiliary info entry "
                     "no %" PRIu16 "\n", i);
            goto err;
        }

        pr_debug("    -> aux[%" PRIu16 "]: \"%s\"\n", i,
                 (const char *)strtab_strptr(ctx, arr[i].vna_name));
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
        const struct dt_needed_name *dt_needed_tbl, size_t n_dt_needed,
        Elf64_Off seg_end, bool is_last_entry, struct ver_parsing_ctx *ctx,
        Elf64_Off *max_end_p, Elf64_Off *off_p,

        struct elf_dyn_sym_ver_need_ent *out
)
{
    Elf64_Verneed vn = { 0 };
    Elf64_Vernaux *aux_list = NULL;
    Elf64_Off aux_list_end = 0;

    *out = (struct elf_dyn_sym_ver_need_ent) { 0 };

    if (*off_p > seg_end - VERNEED_ENTSIZE) {
        pr_error("Next verneed entry would overflow segment bounds\n");
        goto err;
    }
    {
        Elf64_Off tmp = *off_p;
        if (read_verneed(ctx->data, &tmp, &vn)) {
            pr_error("Failed to read version dependency entry "
                     "from file data\n");
            goto err;
        }
        if (tmp > *max_end_p)
            *max_end_p = tmp;
    }

    /* `vn.vn_version` */
    if (vn.vn_version != VER_NEED_CURRENT) {
        pr_error("Invalid struct version\n");
        goto err;
    }

    /* `vn.vn_file` */
    {
        if (vn.vn_file >= ctx->strtab->size) {
            pr_error("vn_file outside of string table bounds\n");
            goto err;
        }
        if (!name_is_dt_needed(dt_needed_tbl, n_dt_needed, ctx, vn.vn_file)) {
            pr_error("vn_file not referenced by any DT_NEEDED entry\n");
            goto err;
        }
    }

    /* `vn.vn_aux`, `vn.vn_cnt` */
    aux_list = NULL;
    aux_list_end = 0;
    {
        if (vn.vn_aux < VERNEED_ENTSIZE) {
            pr_error("Start of auxiliary list inside verneed entry\n");
            goto err;
        } else if (vn.vn_aux > seg_end - *off_p) {
            pr_error("Start of auxiliary list outside of load segment bounds\n");
            goto err;
        }
        const Elf64_Off aux_off = *off_p + vn.vn_aux;

        if (vn.vn_cnt == 0) {
            pr_error("Number of auxiliary entries is 0\n");
            goto err;
        }

        if (read_vernaux_list(ctx, seg_end, aux_off, vn.vn_cnt, max_end_p,
                              &aux_list, &aux_list_end))
        {
            pr_error("Failed to read the auxiliary information entries list\n");
            goto err;
        }
    }

    /* `vn.vn_next` */
    {
        if (vn.vn_next != 0 && vn.vn_next < VERNEED_ENTSIZE) {
            pr_error("Invalid value of vn_next\n");
            goto err;
        }
        if (is_last_entry) {
            if (vn.vn_next != 0) {
                pr_error("Unterminated verneed array\n");
                goto err;
            }
        } else /* if (!is_last_entry) */ {
            if (vn.vn_next == 0) {
                pr_error("Early termination of verneed array\n");
                goto err;
            }

            if (vn.vn_next > seg_end - *off_p) {
                pr_error("Next vernaux entry offset overflows load segment\n");
                goto err;
            }
            const Elf64_Off next_off = *off_p + vn.vn_next;
            if (next_off < aux_list_end) {
                pr_error("Next verneed entry overlaps current one's "
                         "aux list\n");
                goto err;
            }

            *off_p = next_off;
        }
    }

    out->vn = vn;
    out->aux_list = aux_list; aux_list = NULL;
    return 0;

err:
    if (aux_list != NULL) {
        free(aux_list);
        aux_list = NULL;
    }
    return 1;
}

static int read_verneed_entries(
        struct ver_parsing_ctx *ctx,
        const struct elf_phdrs *phdrs, elf_idx_t ptload_idx,
        const struct elf_dyn_entries *entries,
        Elf64_Off tbl_off, size_t num,

        struct elf_dyn_sym_ver_need_ent **out, Elf64_Off *out_max_end
)
{
    *out = NULL;
    *out_max_end = 0;
    struct elf_dyn_sym_ver_need_ent *arr = NULL;
    Elf64_Off max_end = 0;
    Elf64_Off off = 0;
    struct dt_needed_name *dt_needed_tbl = NULL;
    size_t n_dt_needed = 0;

    const Elf64_Phdr *const ptload = &phdrs->arr[ptload_idx];
    const Elf64_Off ptload_end = ptload->p_offset + ptload->p_filesz;

    assert(num > 0);
    assert(ptload_end >= VERNEED_ENTSIZE && ptload_end >= VERNAUX_ENTSIZE);

    if (init_dt_needed_name_table(entries, ctx->strtab, ctx->data,
                                  &dt_needed_tbl, &n_dt_needed))
    {
        pr_error("Failed to initialize the DT_NEEDED names hash table\n");
        goto err;
    }

    arr = calloc(num, sizeof(struct elf_dyn_sym_ver_need_ent));
    if (arr == NULL) {
        pr_error("Failed to allocate the version dependency entries array\n");
        goto err;
    }
    for (size_t i = 0; i < num; i++) arr[i].aux_list = NULL;

    off = tbl_off;
    for (size_t i = 0; i < num; i++) {
        const bool is_last = (i == num - 1);
        if (read_validate_verneed_entry(dt_needed_tbl, n_dt_needed,
                                        ptload_end, is_last, ctx, &max_end,
                                        &off, &arr[i]))
        {
            pr_error("Failed to parse version dependency information entry "
                     "no %zu\n", i);
            goto err;
        }
    }

    free(dt_needed_tbl); dt_needed_tbl = NULL;
    *out = arr; arr = NULL;
    *out_max_end = max_end;
    return 0;

err:
    if (arr != NULL) {
        for (size_t i = 0; i < num; i++) {
            if (arr[i].aux_list != NULL) {
                free(arr[i].aux_list);
                arr[i].aux_list = NULL;
            }
        }
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
        const struct elf_dyn_sym_ver_need_ent *arr, size_t num,
        const struct ver_parsing_ctx *ctx
)
{
    struct verneed_name_ref *refs = NULL;
    int ret = 0;

    size_t total_aux = 0;
    for (size_t i = 0; i < num; i++) {
        const Elf64_Half vn_cnt = arr[i].vn.vn_cnt;

        /* 16-bit values never overflow size_t */
        if ((size_t)vn_cnt > SIZE_MAX - total_aux) {
            pr_error("Too many vernaux entries (integer overflow)\n");
            ret = -1;
            goto out;
        }

        total_aux += (size_t)vn_cnt;
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
                strtab_strptr(ctx, arr[i].vn.vn_file);

            for (Elf64_Half j = 0; j < arr[i].vn.vn_cnt; j++) {
                const Elf64_Vernaux *const curr_aux = &arr[i].aux_list[j];

                const uint8_t *const vna_name_strptr =
                    strtab_strptr(ctx, curr_aux->vna_name);

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

static int parse_verneed(
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries,
        elf_idx_t dt_verneed_idx, elf_idx_t dt_verneednum_idx,
        struct ver_parsing_ctx *ctx,

        struct elf_dyn_sym_ver_need *out
)
{
    *out = empty_verneed_ctx;

    const Elf64_Addr vaddr = entries->arr[dt_verneed_idx].d_un.d_ptr;
    const Elf64_Xword num = entries->arr[dt_verneednum_idx].d_un.d_val;

    if (num == 0)
        pr_error("WARNING: Empty DT_VERNEED list\n");

    Elf64_Xword min_tbl_size = 0;
    elf_idx_t ptload_idx = ELF_IDX_NULL;
    Elf64_Off tbl_off = 0;
    struct elf_dyn_sym_ver_need_ent *arr = NULL;
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

    if (num > 0) {
        if (read_verneed_entries(ctx, phdrs, ptload_idx, entries,
                                 tbl_off, (size_t)num, &arr, &max_end))
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

        if (validate_verneed_names_uniqueness(arr, (size_t)num, ctx)) {
            pr_error("Duplicate verneed names\n");
            goto err;
        }
    }

    if (validate_sht_gnu_verXXX_if_exists(shdrs, ctx->strtab->shdr,
                                          vaddr, tbl_off, min_tbl_size, num,
                                          &sht_gnu_verneed_idx, false))
    {
        pr_error("Invalid SHT_GNU_verneed section\n");
        goto err;
    }

    out->num = num;
    out->arr = arr; arr = NULL;
    out->vaddr = vaddr;
    out->off = tbl_off;
    out->dt_verneed_idx = dt_verneed_idx;
    out->dt_verneednum_idx = dt_verneednum_idx;
    out->shdr = sht_gnu_verneed_idx;
    return 0;

err:
    if (arr != NULL) {
        for (Elf64_Xword i = 0; i < num; i++) {
            if (arr[i].aux_list != NULL) {
                free(arr[i].aux_list);
                arr[i].aux_list = NULL;
            }
        }
        free(arr);
        arr = NULL;
    }
    return 1;
}
