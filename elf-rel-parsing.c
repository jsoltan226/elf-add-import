#include "elf-rel-parsing.h"
#include "elf-types.h"
#include "elf.h"
#include "ctx.h"
#include "util.h"
#include "elf-dyn-parsing.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/**
 * Reads a table of ElfXX_Rel or ElfXX_Rela entries.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] num The number of relocation entries to read;
 *  the value of `DT_REL(A)SZ / DT_REL(A)ENT`. Must be greater than 0.
 *  Note: `num * struct_size` must not overflow `size_t`.
 *
 * @param[out] out_arr Output pointer for the newly allocated array
 *  of `num` parsed ElfXX_Rel or ElfXX_Rela entries. Must not be NULL.
 *  Will contain a value only on success; `NULL` otherwise.
 *
 * @param[in,out] max_symidx_p Pointer to a variable storing the highest-seen
 *  dynamic symbol index referenced by a relocation entry. Must not be NULL.
 *
 * @param[in] struct_size `sizeof(Elf64_Rel)` or `sizeof(Elf64_Rela)`;
 *  the size of each (normalized) entry in `*out_arr`.
 *
 * @param[in] r_info_offset The offset of the `r_info` field in the respective
 *  `Elf64_Rel(a)` struct.
 *
 * @param[in] read_proc The `read_rel(a)` function from `elf-types.h`
 *  corresponding to the given struct.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_relX_table(
        const ElfFileData *data, Elf64_Off tbl_off, size_t num, void **out_arr,
        Elf64_Word *max_symidx_p, size_t struct_size, size_t r_info_offset,
        int (*read_proc)(const ElfFileData *data, Elf64_Off *off_p, void *out)
);

/**
 * Looks for any `SHT_REL*` section headers overlapping
 * the corresponding `DT_REL*` table range and validates them.
 *
 * @param[in] shdrs The parased section headers array. Must not be NULL.
 *
 * @param[in] tbl_vaddr The virtual address of the corresponding REL* table;
 *  the value of `DT_REL*`.
 *
 * @param[in] tbl_off File offset of the corresponding REL* table.
 *
 * @param[in] tbl_size Size of the corresponding REL* table;
 *  the value of `DT_REL*SZ`.
 *
 * @param[in] sht_dynsym_idx Index (into `shdrs`) of the `SHT_DYNSYM`
 *  section header, or `ELF_IDX_NULL` if it doesn't exist.
 *  Used only when `sh_type == SHT_REL || sh_type == SHT_RELA`;
 *  ignored for `sh_type == SHT_RELR`.
 *
 * @param[in] entsize The size of each entry in the corresponding REL* table;
 *  the value of `DT_REL*ENT`.
 *
 * @param[out] out_arr Output pointer for the newly allocated array
 *  of `*out_num` section header indices (into `shdrs`),
 *  or `NULL` if no `SHT_REL*` section headers overlapping the REL* table
 *  are found or some other error occurs. Must not be NULL.
 *
 * @param[out] out_num Output pointer for the number of found `SHT_REL*`
 *  section headers which overlap the respective REL* table;
 *  the size of `*out_arr`. Must not be NULL.
 *
 * @param[in] sh_type The type of the section header corresponding to
 *  the relevant type of relocation entries; one of:
 *   `SHT_REL`, `SHT_RELA`, `SHT_RELR`
 *
 * @return 0 on success,
 *  positive (>0) value if no shdrs that meet the requirements are found,
 *  negative (<0) if an invalid shdr is found or some other error occurs.
 */
static int find_validate_sht_relX_shdrs(
    const struct elf_shdrs *shdrs, Elf64_Addr tbl_vaddr, Elf64_Off tbl_off,
    Elf64_Xword tbl_size, elf_idx_t sht_dynsym_idx, Elf64_Half entsize,
    elf_idx_t **out_arr, size_t *out_num, Elf64_Word sh_type
);

/**
 * Validates a single `SHT_REL*` section header overlapping
 * the corresponding REL* table.
 *
 * Checks that:
 *  - The section is fully contained in the REL* table's file & memory range,
 *  - The section doesn't overlap any other `SHT_REL*` sections associated
 *      with the REL* table,
 *  - The `sh_size` and `sh_entsize` values match those of the dynamic entries,
 *  - For SHT_REL and SHT_RELA (`is_relr == false`):
 *      - The `sh_link` value references the `SHT_DYNSYM` section,
 *      - The `sh_info` value is either 0 or a valid index into `shdrs`.
 *  - For SHT_RELR (`is_relr == true`):
 *      - The `sh_link` and `sh_info` fields are 0.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] shdr_idx Index (into `shdrs`) of the `SHT_REL*` section header
 *  to be validated.
 *
 * @param[in] tbl_addr The virtual address of the corresponding REL* table;
 *  the value of `DT_REL*`.
 *
 * @param[in] tbl_off File offset of the corresponding REL* table.
 *
 * @param[in] tbl_size Size of the corresponding REL* table;
 *  the value of `DT_REL*SZ`.
 *
 * @param[in] found_shdrs The array of `curr_num_found_shdrs`
 *  indices of other `SHT_REL*` section headers which have been found
 *  to overlap the corresponding REL* table.
 *
 * @param[in] entsize The size of each entry in the corresponding REL* table;
 *  the value of `DT_REL*ENT`.
 *
 * @param[in] sht_dynsym_idx Index (into `shdrs`) of the `SHT_DYNSYM`
 *  section header, or `ELF_IDX_NULL` if it doesn't exist.
 *  Used only for `SHT_REL` and `SHT_RELA`; ignored if `is_relr == true`.
 *
 * @param[in] is_relr Whether the type of the section is `SHT_RELR`.
 *
 * @return 0 on success, non-zero if the shdr is invalid.
 */
static int validate_sht_relX_shdr(
        const struct elf_shdrs *shdrs, elf_idx_t shdr_idx,
        Elf64_Addr tbl_addr, Elf64_Off tbl_off, Elf64_Xword tbl_size,
        const elf_idx_t *found_shdrs, size_t curr_num_found_shdrs,
        Elf64_Half entsize, elf_idx_t sht_dynsym_idx, bool is_relr
);

/**
 * Finds and, if present, parses the table of relocations
 * that is associated with the dynamic symbol table.
 * Part of `parse_reloc`.
 *
 * Uses the `find_rel` function and the generic wrappers to:
 *  - Check for and parse the DT_REL entries and other metadata; (`find_rel`)
 *  - Read the DT_REL table (`read_relX_table`);
 *  - Find and validate any section headers which overlap the DT_REL table
 *      (`find_validate_sht_relX_shdrs`)
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in,out] max_symidx_p Pointer to a variable storing the highest-seen
 *  dynamic symbol index referenced by a relocation entry. Must not be NULL.
 *
 * @param[out] out Output pointer, populated with actual values on success
 *  and initialized to `empty_reloc_rel_st` otherwise. Must not be NULL.
 *
 * @return 0 if the DT_REL table was found and parsed successfully,
 *  positive (>0) value if no DT_REL table exists,
 *  negative (<0) if the DT_REL table is invalid or some other error occurred.
 */
static int parse_rel(
        const ElfFileData *data,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, Elf64_Word *max_symidx_p,
        struct elf_reloc_rel *out
);

/**
 * Locates and parses the DT_REL table metadata,
 * initializing the relevant fields in the `elf_reloc_rel` struct.
 * Part of `parse_rel`.
 *
 * The following fields are populated with the parsed values:
 *      vaddr, off, size, entsize;
 *      num,
 *      dt_rel_idx, dt_relsz_idx, dt_relent_idx;
 *      dt_relcount_idx, relcount; (if DT_RELCOUNT exists)
 * The following fields are initialized to NULL/empty values:
 *      arr;
 *      n_shdrs, shdrs;
 *      dt_relcount_idx, relcount; (if DT_RELCOUNT does not exist)
 *      present; (meant to be set in the top-level `parse_rel`
 *                only after full successful parsing)
 *
 * See the definition of `struct elf_reloc_rel` for the details
 * regarding the values with which the above fields are initialized.
 *
 * In case of failure or if no DT_REL metadata is found,
 * `out` is initialized to `empty_reloc_rel_st`.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 if valid DT_REL metadata was found,
 *         positive (>0) value if the DT_REL table is absent,
 *         negative (<0) value if the found DT_REL metadata is invalid.
 */
static int find_rel(const struct elf_dyn_entries *entries, int clazz,
                    const struct elf_phdrs *phdrs, struct elf_reloc_rel *out);


/** A `void *` wrapper for the `read_rel` function from `elf-types.h`. */
static inline int
read_rel_wrapper(const ElfFileData *data, Elf64_Off *off_p, void *out)
{
    return read_rel(data, off_p, (Elf64_Rel *)out);
}

/** A REL wrapper for the `read_relX_table` function. Part of `parse_rel`. */
static inline int
read_rel_table(const ElfFileData *data, Elf64_Off tbl_off, size_t num,
               Elf64_Rel **out_arr, Elf64_Word *max_symidx_p)
{
    *out_arr = NULL;
    void *tmp_arr = NULL;

    const int ret =
        read_relX_table(data, tbl_off, num, &tmp_arr, max_symidx_p,
                        sizeof(Elf64_Rel), offsetof(Elf64_Rel, r_info),
                        read_rel_wrapper);
    if (ret == 0) {
        *out_arr = tmp_arr;
        tmp_arr = NULL;
    }
    return ret;
}

/**
 * Finds and, if present, parses the table of relocations with explicit addends
 * that is associated with the dynamic symbol table.
 * Part of `parse_reloc`.
 *
 * Uses the `find_rela` function and the generic wrappers to:
 *  - Check for and parse the DT_RELA entries and other metadata; (`find_rela`)
 *  - Read the DT_RELA table (`read_relX_table`);
 *  - Find and validate any section headers which overlap the DT_RELA table
 *      (`find_validate_sht_relX_shdrs`)
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in,out] max_symidx_p Pointer to a variable storing the highest-seen
 *  dynamic symbol index referenced by a relocation entry. Must not be NULL.
 *
 * @param[out] out Output pointer, populated with actual values on success
 *  and initialized to `empty_reloc_rela_st` otherwise. Must not be NULL.
 *
 * @return 0 if the DT_RELA table was found and parsed successfully,
 *  positive (>0) value if no DT_RELA table exists,
 *  negative (<0) if the DT_RELA table is invalid or some other error occurred.
 */
static int parse_rela(
        const ElfFileData *data,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, Elf64_Word *max_symidx_p,
        struct elf_reloc_rela *out
);

/**
 * Locates and parses the DT_RELA table metadata,
 * initializing the relevant fields in the `elf_reloc_rela` struct.
 * Part of `parse_rela`.
 *
 * The following fields are populated with the parsed values:
 *      vaddr, off, size, entsize;
 *      num,
 *      dt_rela_idx, dt_relasz_idx, dt_relaent_idx;
 *      dt_relacount_idx, relacount; (if DT_RELACOUNT exists)
 * The following fields are initialized to NULL/empty values:
 *      arr;
 *      n_shdrs, shdrs;
 *      dt_relacount_idx, relacount; (if DT_RELACOUNT does not exist)
 *      present; (meant to be set in the top-level `parse_rela`
 *                only after full successful parsing)
 *
 * See the definition of `struct elf_reloc_rela` for the details
 * regarding the values with which the above fields are initialized.
 *
 * In case of failure or if no DT_RELA metadata is found,
 * `out` is initialized to `empty_reloc_rela_st`.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 if valid DT_RELA metadata was found,
 *         positive (>0) value if the DT_RELA table is absent,
 *         negative (<0) value if the found DT_RELA metadata is invalid.
 */
static int find_rela(const struct elf_dyn_entries *entries, int clazz,
                     const struct elf_phdrs *phdrs, struct elf_reloc_rela *out);

/** A `void *` wrapper for the `read_rela` function from `elf-types.h`. */
static inline int
read_rela_wrapper(const ElfFileData *data, Elf64_Off *off_p, void *out)
{
    return read_rela(data, off_p, (Elf64_Rela *)out);
}

/** A RELA wrapper for the `read_relX_table` function. Part of `parse_rela`. */
static inline int
read_rela_table(const ElfFileData *data, Elf64_Off tbl_off, size_t num,
                Elf64_Rela **out_arr, Elf64_Word *max_symidx_p)
{
    *out_arr = NULL;
    void *tmp_arr = NULL;

    const int ret =
        read_relX_table(data, tbl_off, num, &tmp_arr, max_symidx_p,
                        sizeof(Elf64_Rela), offsetof(Elf64_Rela, r_info),
                        read_rela_wrapper);
    if (ret == 0) {
        *out_arr = tmp_arr;
        tmp_arr = NULL;
    }
    return ret;
}

/**
 * Finds, and if present, parses the table of relocations associated with
 * the Procedure Linkage Table (PLT). Part of `parse_reloc`.
 *
 * Parses the metadata, and based on it, determines the type of relocations
 * stored in the table (either ElfXX_Rel or ElfXX_Rela) and then calls
 * the wrappers from the regular DT_REL/DT_RELA parsers to read them.
 *
 * Also finds any sections that overlap the PLT relocation table
 * and validates them against the data from the dynamic entries and phdrs.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] rel The parsed DT_REL relocation table (`parse_rel`).
 *  Must not be NULL.
 *
 * @param[in] rela The parsed DT_RELA relocation table (`parse_rela`).
 *  Must not be NULL.
 *
 * @param[in,out] max_symidx_p Pointer to a variable storing the highest-seen
 *  dynamic symbol index referenced by a relocation entry. Must not be NULL.
 *
 * @param[out] out Output pointer, populated with actual values on success
 *  and initialized to `empty_reloc_jmprel_st` otherwise. Must not be NULL.
 *
 * @return 0 when the PLT relocation table was successfully parsed,
 *  positive (>0) value if the PLT relocation table is not present,
 *  negative (<0) value if the table is malformed or some other error occurred.
 */
static int parse_jmprel(
        const ElfFileData *data, const struct elf_phdrs *phdrs,
        const struct elf_shdrs *shdrs, const struct elf_dyn_entries *entries,
        const struct elf_reloc_rel *rel, const struct elf_reloc_rela *rela,
        Elf64_Word *max_symidx_p, struct elf_reloc_jmprel *out
);

/**
 * Locates and, if present, parses the metadata of the PLT relocation table,
 * initializing most of the values in the `elf_reloc_jmprel` structure.
 * Part of `parse_jmprel`.
 *
 * Uses the `DT_JMPREL`, `DT_PLTREL` and `DT_PLTRELSZ` entries to determine
 * the virtual address, type of stored relocations and the size of the table,
 * respectively, and then computes the file offset of the table
 * using the virtual address and PT_LOAD segments.
 *
 * Also validates some semantics, notably the possible case of overlap
 * with the DT_REL(A) table. See the description of `relX_overlap_start_idx`
 * in the definition of `struct elf_reloc_jmprel`.
 *
 * On success, the following fields populated with meaningful values:
 *  `vaddr`, `off`, `size`,
 *  `entsize`, `enttype`,
 *  `num`,
 *  `dt_jmprel_idx`, `dt_pltrel_idx`, `dt_pltrelsz_idx`,
 *  `relX_overlap_start_idx`
 * While these fields are initialized with semantically empty values:
 *  `present` (set later, after parsing the actual contents),
 *  `arr`,
 *  `n_shdrs`, `shdrs`.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[in] rel The parsed DT_REL relocation table (`parse_rel`).
 *  Must not be NULL.
 *
 * @param[in] rela The parsed DT_RELA relocation table (`parse_rela`).
 *  Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *  Populated on success as described earlier, otherwise set to
 *  `empty_reloc_jmprel_st`.
 *
 * @return 0 on success (the JMPREL table was found and has valid metadata),
 *  positive (>0) value if the JMPREL table is not present,
 *  negative (<0) value if the JMPREL table metadata is invalid or malformed.
 */
static int find_jmprel(const struct elf_dyn_entries *entries, int clazz,
                       const struct elf_phdrs *phdrs,
                       const struct elf_reloc_rel *rel,
                       const struct elf_reloc_rela *rela,
                       struct elf_reloc_jmprel *out);
/**
 * Finds, and if present, parses the DT_RELR
 * table of packed relative relocations.
 * Part of `parse_reloc`.
 *
 * Parses the metadata and then decodes the RELR table
 * both into the original ElfXX_Relr representation
 * and into a list of relocation target addresses.
 *
 * Also finds any sections that overlap the RELR table
 * and validates them against the data from the dynamic entries and phdrs.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[in] shdrs The parsed section headers array. Must not be NULL.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[out] out Output pointer, populated with actual values on success
 *  and initialized to `empty_reloc_relr_st` otherwise. Must not be NULL.
 *
 * @return 0 when the DT_RELR table was successfully parsed,
 *  positive (>0) value if the DT_RELR table is not present,
 *  negative (<0) value if the table is malformed or some other error occurred.
 */
static int parse_relr(
        const ElfFileData *data, const struct elf_phdrs *phdrs,
        const struct elf_shdrs *shdrs, const struct elf_dyn_entries *entries,
        struct elf_reloc_relr *out
);

/**
 * Locates and parses the DT_RELR table metadata,
 * initializing the relevant fields in the `elf_reloc_relr` struct.
 * Part of `parse_relr`.
 *
 * The following fields are populated with the parsed values:
 *      vaddr, off, size, entsize;
 *      num,
 *      dt_relrsz_idx, dt_relr_idx, dt_relrent_idx;
 * The following fields are initialized to NULL/empty values:
 *      arr;
 *      decoded_arr; num_decoded;
 *      n_shdrs, shdrs;
 *      present; (meant to be set in the top-level `parse_relr`
 *                only after full successful parsing)
 *
 * See the definition of `struct elf_reloc_relr` for the details
 * regarding the values with which the above fields are initialized.
 *
 * In case of failure or if no DT_RELR metadata is found,
 * `out` is initialized to `empty_reloc_relr_st`.
 *
 * @param[in] entries The parsed dynamic entries array. Must not be NULL.
 *
 * @param[in] clazz Class of the ELF file (`ELFCLASS32` or `ELFCLASS64`).
 *
 * @param[in] phdrs The parsed program headers array. Must not be NULL.
 *
 * @param[out] out Output pointer. Must not be NULL.
 *
 * @return 0 if valid DT_RELR metadata was found,
 *         positive (>0) value if the DT_RELR table is absent,
 *         negative (<0) value if the found DT_RELR metadata is invalid.
 */
static int find_relr(const struct elf_dyn_entries *entries, int clazz,
                     const struct elf_phdrs *phdrs, struct elf_reloc_relr *out);

/**
 * Reads and decodes the packed relative relocation (RELR) table entries.
 * In case of failure, any resources allocated by this function are freed
 * and `NULL` is written to `*out_decoded` and `*out_num_decoded`.
 * Part of `parse_relr`.
 *
 * Apart from just reading the raw ElfXX_Relr array, this function
 * actually decodes the RELR entries into a list of target addresses,
 * validating the structure in the process.
 *
 * Each decoded address identifies the location of a machine-word-sized value
 * to which a relative relocation is applied.
 * The implicit addend is the value already stored at that location,
 * so the relocation operation is conceptually:
 *  `addr += load_bias`
 *
 * The following paragraphs describe how the RELR table is decoded.
 *
 * The RELR table has two types of entries:
 *  - Direct address entry; least significant bit `0x1` >clear<
 *  - Region bitmap entry; least significant bit `0x1` >set<
 *
 * Apart from this, there is the concept of a "cursor",
 * used for the bitmap entries.
 *
 * ## Direct entries (least significant bit clear)
 * Reading the direct entries is straight-forward;
 * the entry's value can just be copied into the decoded array.
 * Additionally, when reading a direct entry,
 * the "cursor" is set to point past its target address.
 * Here's what is conceptually done:
 *  ```
 *      target_addrs[n++] = entry_val;
 *      cursor = entry_val + WORD_SIZE
 *  ```
 *
 * Notice that since the least significant bit is always clear for these
 * entries, they cannot describe odd addresses. In fact, the spec itself
 * states that for odd addresses the standard ElfXX_Rel(a) need to be used.
 *
 * ## Bitmap entries (least significant bit set)
 * The bitmap entries (least significant bit set) describe a "batch region"
 * of (WORD_BITS - 1) machine words to which relocations are to be applied.
 * Each set bit in the bitmap corresponds to one target word to be relocated,
 * indexed from the current cursor position:
 * ```
 *  if (entry_val & (1 << bitidx))
 *      target_addrs[n++] = cursor + ((bitidx - 1) * WORD_SIZE);
 * ```
 *
 * Notice that because the least significant bit is reserved to indicate
 * the type of the entry, the bitmap contains one less bit (31 or 63,
 * depending on the class). This is why it only describes
 * a region of (WORD_BITS - 1) words and `(bitidx - 1)` is used
 * as the index into the target word bytes -
 * the first reserved bit needs to be ignored.
 *
 * Also note that bitmap entries use the "cursor" position
 * as the base of the target array, and that the cursor is only set
 * when parsing a direct-address entry.
 * Consequently, a valid RELR table *must* begin with a direct-address entry.
 *
 * @param[in] data The ELF file data. Must not be NULL.
 *
 * @param[in] tbl_off File offset of the base of the RELR table to read.
 *
 * @param[in] num Number of ElfXX_Relr entries to parse;
 *  the value of `DT_RELRSZ / DT_RELRENT`.
 *
 * @param[out] out Output pointer for the new array
 *  of `num` raw ElfXX_Relr entries. Must not be NULL.
 *
 * @param[out] out_decoded Output pointer for the new array
 *  of `*out_num_decoded` decoded relocation target addresses. Must not be NULL.
 *
 * @param[out] out_num_decoded Output pointer for the total number
 *  of addresses relocated by the RELR table; the size of `*out_decoded`.
 *
 * @return 0 on success, non-zero on failure.
 */
static int read_decode_relr(const ElfFileData *data, Elf64_Off tbl_off,
                            size_t num, Elf64_Relr **out,
                            Elf64_Addr **out_decoded, size_t *out_num_decoded);

int parse_reloc(const ElfFileData *data,
                const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
                const struct elf_dyn_entries *entries,
                struct elf_reloc *out, Elf64_Word *out_max_symidx)
{
    struct elf_reloc rel = empty_reloc_st;
    Elf64_Word max_symidx = 0;
    *out = empty_reloc_st;
    *out_max_symidx = 0;

    if (parse_rel(data, phdrs, shdrs, entries, &max_symidx, &rel.rel) < 0) {
        pr_error("Invalid table of "
                 "dynsym relocations (without explicit addends)\n");
        goto err;
    }

    if (parse_rela(data, phdrs, shdrs, entries, &max_symidx, &rel.rela) < 0) {
        pr_error("Invalid table of "
                 "dynsym relocations (with explicit addends)\n");
        goto err;
    }

    if (parse_jmprel(data, phdrs, shdrs, entries, &rel.rel, &rel.rela,
                     &max_symidx, &rel.jmprel) < 0)
    {
        pr_error("Invalid table of PLT relocations\n");
        goto err;
    }

    if (parse_relr(data, phdrs, shdrs, entries, &rel.relr) < 0) {
        pr_error("Invalid table of "
                 "dynsym packed relative relocations\n");
        goto err;
    }

    *out = rel; rel = empty_reloc_st;
    *out_max_symidx = max_symidx;
    return 0;

err:
    destroy_rel(&rel);
    return -1;
}

void destroy_rel(struct elf_reloc *rel)
{
    if (rel == NULL)
        return;

    if (rel->rel.present) {
        if (rel->rel.arr != NULL)
            free(rel->rel.arr);
        if (rel->rel.shdrs != NULL)
            free(rel->rel.shdrs);
    }

    if (rel->rela.present) {
        if (rel->rela.arr != NULL)
            free(rel->rela.arr);
        if (rel->rela.shdrs != NULL)
            free(rel->rela.shdrs);
    }

    if (rel->jmprel.present) {
        if (rel->jmprel.enttype == DT_REL) {
            if (rel->jmprel.arr.rel != NULL)
                free(rel->jmprel.arr.rel);
        } else /* if (rel->jmprel.enttype == DT_RELA) */ {
            if (rel->jmprel.arr.rela != NULL)
                free(rel->jmprel.arr.rela);
        }

        if (rel->jmprel.shdrs != NULL)
            free(rel->jmprel.shdrs);
    }

    if (rel->relr.present) {
        if (rel->relr.arr != NULL)
            free(rel->relr.arr);
        if (rel->relr.decoded_arr != NULL)
            free(rel->relr.decoded_arr);
        if (rel->relr.shdrs != NULL)
            free(rel->relr.shdrs);
    }

    *rel = empty_reloc_st;
}

static int read_relX_table(
        const ElfFileData *data, Elf64_Off tbl_off, size_t num, void **out_arr,
        Elf64_Word *max_symidx_p, size_t struct_size, size_t r_info_offset,
        int (*read_proc)(const ElfFileData *data, Elf64_Off *off_p, void *out)
)
{
    void *arr = NULL;
    Elf64_Off off = 0;

    *out_arr = NULL;

    assert(num > 0);
    assert(num < SIZE_MAX / struct_size);

    arr = calloc(num, struct_size);
    if (arr == NULL) {
        pr_error("Failed to allocate the REL(A) table array\n");
        goto err;
    }

    off = tbl_off;
    for (size_t i = 0; i < num; i++) {
        void *const ptr = (unsigned char *)arr + (struct_size * i);
        if (read_proc(data, &off, ptr)) {
            pr_error("Failed to read REL(A) entry no %zu\n", i);
            goto err;
        }

        /* `r_offset` is a virtual address in ET_DYN ELFs,
         * don't validate here */

        /* This will be used and validated later, in `elf-dyn-sym-parsing` */
        Elf64_Xword r_info;
        memcpy(&r_info, (unsigned char *)ptr + r_info_offset,
                sizeof(Elf64_Xword));
        const Elf64_Word r_sym = (Elf64_Word)ELF64_R_SYM(r_info);
                                /* ^ Always fits in 32 bits */
        if (r_sym > *max_symidx_p)
            *max_symidx_p = (Elf64_Word)r_sym;

        /* `R_TYPE` of `r_info` is machine-specific; don't check it */

        /* (For ElfXX_Rela) `r_addend` can't really be validated here either */
    }

    *out_arr = arr; arr = NULL;
    return 0;

err:
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}

static int find_validate_sht_relX_shdrs(
    const struct elf_shdrs *shdrs, Elf64_Addr tbl_vaddr, Elf64_Off tbl_off,
    Elf64_Xword tbl_size, elf_idx_t sht_dynsym_idx, Elf64_Half entsize,
    elf_idx_t **out_arr, size_t *out_num, Elf64_Word sh_type
)
{
    size_t num = 0;
    elf_idx_t *arr = NULL;
    const bool relr = sh_type == SHT_RELR;

    *out_arr = NULL;
    *out_num = 0;

    assert(tbl_size > 0);

    for (Elf64_Xword i = 0; i < shdrs->num; i++) {
        const Elf64_Shdr *const shdr = &shdrs->arr[i];

        if (shdr->sh_type != sh_type || shdr->sh_size == 0)
            continue;

        if (ranges_overlap(shdr->sh_offset, shdr->sh_size, tbl_off, tbl_size) ||
            ranges_overlap(shdr->sh_addr, shdr->sh_size, tbl_vaddr, tbl_size))
        {
            if (num == SIZE_MAX) {
                pr_error("Too many section headers (integer overflow)\n");
                return -1;
            }
            num++;
        }
    }
    if (num == 0) {
        pr_debug("No SHT_REL* sections overlapping the relocation table\n");
        return 1;
    }

    arr = calloc(num, sizeof(elf_idx_t));
    if (arr == NULL) {
        pr_error("Failed to allocate the SHT_REL* section headers array\n");
        return -1;
    }
    {
        size_t j = 0;
        for (Elf64_Xword i = 0; i < shdrs->num; i++) {
            const Elf64_Shdr *const shdr = &shdrs->arr[i];

            if (shdr->sh_type != sh_type || shdr->sh_size == 0 ||
                (!ranges_overlap(shdr->sh_offset, shdr->sh_size,
                                tbl_off, tbl_size) &&
                 !ranges_overlap(shdr->sh_addr, shdr->sh_size,
                                tbl_vaddr, tbl_size)))
            {
                continue;
            }

            assert(j < num);
            if (validate_sht_relX_shdr(shdrs, i, tbl_vaddr, tbl_off, tbl_size,
                                       arr, j, entsize, sht_dynsym_idx, relr))
            {
                pr_error("Invalid SHT_REL* section header\n");
                free(arr); arr = NULL;
                return -1;
            }
            arr[j++] = i;
        }
        assert(j == num);
    }

    *out_arr = arr; arr = NULL;
    *out_num = num;
    return 0;
}

static int validate_sht_relX_shdr(
        const struct elf_shdrs *shdrs, elf_idx_t shdr_idx,
        Elf64_Addr tbl_addr, Elf64_Off tbl_off, Elf64_Xword tbl_size,
        const elf_idx_t *found_shdrs, size_t curr_num_found_shdrs,
        Elf64_Half entsize, elf_idx_t sht_dynsym_idx, bool is_relr
)
{
    const Elf64_Shdr *const shdr = &shdrs->arr[shdr_idx];
    int ret = 0;

    /* Check that the SHT_REL* section is fully contained
     * in the corresponding DT_REL* table */

    /* The DT_REL* table has already been validated to be fully contained
     * in some PT_LOAD segment, so these additions are safe */
    const Elf64_Addr tbl_end_addr = tbl_addr + tbl_size;
    const Elf64_Off tbl_end_off = tbl_off + tbl_size;

    /* Likewise, all section headers are validated (in `elf-parsing.c`)
     * to not overflow the file or address space bounds */
    const Elf64_Addr section_end_addr = shdr->sh_addr + shdr->sh_size;
    const Elf64_Off section_end_off = shdr->sh_offset + shdr->sh_size;

    if ((shdr->sh_addr < tbl_addr || section_end_addr > tbl_end_addr) ||
        (shdr->sh_offset < tbl_off || section_end_off > tbl_end_off))
    {
        pr_error("SHT_REL* section (%" PRIu64 ") not fully contained "
                 "within the relocation table bounds\n", shdr_idx);
        ret = 1;
    }

    for (size_t i = 0; i < curr_num_found_shdrs; i++) {
        const elf_idx_t curr_idx = found_shdrs[i];
        const Elf64_Shdr *const curr = &shdrs->arr[curr_idx];

        if (ranges_overlap(curr->sh_offset, curr->sh_size,
                           shdr->sh_offset, shdr->sh_size) ||
            ranges_overlap(curr->sh_addr, curr->sh_size,
                           shdr->sh_addr, shdr->sh_size))
        {
            pr_error("SHT_REL* section (%" PRIu64 ") "
                     "overlaps another SHT_REL* section (%" PRIu64 ")\n",
                     shdr_idx, curr_idx);
            ret = 1;
        }
    }

    if (shdr->sh_entsize != entsize) {
        pr_error("Invalid SHT_REL* entsize\n");
        ret = 1;
    }
    if (shdr->sh_size % entsize != 0) {
        pr_error("SHT_REL* sh_size is not divisible "
                 "by the relocation table entry size\n");
        ret = 1;
    }

    if (!is_relr) {
        if (sht_dynsym_idx == ELF_IDX_NULL) {
            pr_error("SHT_REL(A) exists without a SHT_DYNSYM\n");
            ret = 1;
        } else if (shdr->sh_link != sht_dynsym_idx) {
            pr_error("SHT_REL(A) sh_link doesn't reference "
                     "the SHT_DYNSYM section\n");
            ret = 1;
        }

        /* The SHT_REL(A) `sh_info` field should point to
         * "the section to which the relocations apply",
         * or `0` in some cases on some platforms. */
        if (shdr->sh_info >= shdrs->num) {
            pr_error("Invalid SHT_REL(A) sh_info section reference\n");
            ret = 1;
        }
    } else /* if (is_relr) */ {
        if (shdr->sh_link != 0) {
            pr_error("Invalid SHT_RELR sh_link value\n");
            ret = 1;
        }
        if (shdr->sh_info != 0) {
            pr_error("Invalid SHT_RELR sh_info value\n");
            ret = 1;
        }
    }

    return ret;
}

static int parse_rel(
        const ElfFileData *data,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, Elf64_Word *max_symidx_p,
        struct elf_reloc_rel *out
)
{
    *out = empty_reloc_rel_st;
    struct elf_reloc_rel rel = empty_reloc_rel_st;
    elf_idx_t sht_dynsym_idx = ELF_IDX_NULL;

    const int r = find_rel(entries, data->clazz, phdrs, &rel);
    /* Safe to just `return` because neither `rel.arr` nor `rel.shdrs`
     * have been allocated yet */
    if (r < 0) {
        pr_error("Invalid REL table information\n");
        return -1;
    } else if (r > 0) {
        /* No REL table present at all */
        return 1;
    }

    if (read_rel_table(data, rel.off, rel.num, &rel.arr, max_symidx_p)) {
        pr_error("Failed to read the REL table\n");
        goto err;
    }

    sht_dynsym_idx = find_unique_shdr_by_type(shdrs, shdr_unique_SHT_DYNSYM);
    if (find_validate_sht_relX_shdrs(shdrs, rel.vaddr, rel.off, rel.size,
                                     sht_dynsym_idx, rel.entsize,
                                     &rel.shdrs, &rel.n_shdrs, SHT_REL) < 0)
    {
        pr_error("Invalid SHT_REL section header(s)\n");
        goto err;
    }

    pr_debug("DT_REL: %zu entries\n", rel.num);
    if (rel.dt_relcount_idx != ELF_IDX_NULL)
        pr_debug("DT_RELCOUNT: %zu\n", rel.relcount);

    rel.present = true;
    *out = rel; rel = empty_reloc_rel_st;
    return 0;

err:
    if (rel.arr != NULL) {
        free(rel.arr);
        rel.arr = NULL;
    }
    if (rel.shdrs != NULL) {
        free(rel.shdrs);
        rel.shdrs = NULL;
    }
    return -1;
}

static int find_rel(const struct elf_dyn_entries *entries, int clazz,
                    const struct elf_phdrs *phdrs, struct elf_reloc_rel *out)
{
    *out = empty_reloc_rel_st;

    enum { DT_REL_IDX = 0, DT_RELSZ_IDX = 1, DT_RELENT_IDX = 2 };
    elf_idx_t rel_idxs[3] = { ELF_IDX_NULL, ELF_IDX_NULL, ELF_IDX_NULL };
    int r = find_unique_dyn_entries(entries, 3,
                (Elf64_Sxword[]) { DT_REL, DT_RELSZ, DT_RELENT }, rel_idxs);
    if (r < 0) {
        pr_error("Invalid combination of the DT_REL* entries\n");
        return -1;
    } else if (r > 0) {
        pr_debug("No dynsym REL table\n");
        return 1;
    }

    const Elf64_Addr vaddr = entries->arr[rel_idxs[DT_REL_IDX]].d_un.d_ptr;
    const Elf64_Xword size = entries->arr[rel_idxs[DT_RELSZ_IDX]].d_un.d_val;
    const Elf64_Xword entsize =
        entries->arr[rel_idxs[DT_RELENT_IDX]].d_un.d_val;

    if (!(clazz == ELFCLASS32 && entsize == sizeof(Elf32_Rel)) &&
        !(clazz == ELFCLASS64 && entsize == sizeof(Elf64_Rel)))
    {
        pr_error("Invalid ElfXX_Rel entsize\n");
        return -1;
    }

    if (size % entsize != 0) {
        pr_error("REL table size (%" PRIu64 ") is not divisible by "
                 "a REL entry size (%" PRIu64 ")\n", size, entsize);
        return -1;
    } else if (size == 0) {
        pr_error("Zero-size REL table\n");
        return -1;
    }
    const Elf64_Xword n_ents = size / entsize;
    if (n_ents > SIZE_MAX) {
        pr_error("Count of REL entries overflows size_t\n");
        return -1;
    }

    Elf64_Off off = 0;
    if (find_ptload_and_off_from_vaddr(vaddr, size, phdrs, &off, NULL)) {
        pr_error("REL table not contained in any single PT_LOAD segment\n");
        return -1;
    }

    Elf64_Xword relcount = 0;
    elf_idx_t dt_relcount_idx = ELF_IDX_NULL;
    r = find_unique_dyn_entry(entries, DT_RELCOUNT, &dt_relcount_idx);
    if (r < 0) {
        pr_error("Duplicate DT_RELCOUNT tag\n");
        return -1;
    } else if (r == 0) {
        relcount = entries->arr[dt_relcount_idx].d_un.d_val;
        if (relcount > n_ents) {
            pr_error("DT_RELCOUNT value too large\n");
            return -1;
        }
    }

    /* `present` flag set later, only after successful parsing */

    out->vaddr = vaddr;
    out->off = off;
    out->size = size;
    out->entsize = (Elf64_Half)entsize;

    out->arr = NULL;
    out->num = (size_t)n_ents;

    out->dt_rel_idx = rel_idxs[DT_REL_IDX];
    out->dt_relsz_idx = rel_idxs[DT_RELSZ_IDX];
    out->dt_relent_idx = rel_idxs[DT_RELENT_IDX];

    if (r == 0) {
        out->dt_relcount_idx = dt_relcount_idx;
        out->relcount = relcount;
    }

    out->n_shdrs = 0;
    out->shdrs = NULL;

    return 0;
}

static int parse_rela(
        const ElfFileData *data,
        const struct elf_phdrs *phdrs, const struct elf_shdrs *shdrs,
        const struct elf_dyn_entries *entries, Elf64_Word *max_symidx_p,
        struct elf_reloc_rela *out
)
{
    *out = empty_reloc_rela_st;
    struct elf_reloc_rela rela = empty_reloc_rela_st;
    elf_idx_t sht_dynsym_idx = ELF_IDX_NULL;

    const int r = find_rela(entries, data->clazz, phdrs, &rela);
    /* Safe to just `return` because neither `rela.arr` nor `rela.shdrs`
     * have been allocated yet */
    if (r < 0) {
        pr_error("Invalid RELA table information\n");
        return -1;
    } else if (r > 0) {
        /* No RELA table present at all */
        return 1;
    }

    if (read_rela_table(data, rela.off, rela.num, &rela.arr, max_symidx_p)) {
        pr_error("Failed to read the RELA table\n");
        goto err;
    }

    sht_dynsym_idx = find_unique_shdr_by_type(shdrs, shdr_unique_SHT_DYNSYM);
    if (find_validate_sht_relX_shdrs(shdrs, rela.vaddr, rela.off, rela.size,
                                     sht_dynsym_idx, rela.entsize,
                                     &rela.shdrs, &rela.n_shdrs, SHT_RELA) < 0)
    {
        pr_error("Invalid SHT_RELA section header(s)\n");
        goto err;
    }

    pr_debug("DT_RELA: %zu entries\n", rela.num);
    if (rela.dt_relacount_idx != ELF_IDX_NULL)
        pr_debug("DT_RELACOUNT: %zu\n", rela.relacount);

    rela.present = true;
    *out = rela; rela = empty_reloc_rela_st;
    return 0;

err:
    if (rela.arr != NULL) {
        free(rela.arr);
        rela.arr = NULL;
    }
    if (rela.shdrs != NULL) {
        free(rela.shdrs);
        rela.shdrs = NULL;
    }
    return -1;
}

static int find_rela(const struct elf_dyn_entries *entries, int clazz,
                     const struct elf_phdrs *phdrs, struct elf_reloc_rela *out)
{
    *out = empty_reloc_rela_st;

    enum { DT_RELA_IDX = 0, DT_RELASZ_IDX = 1, DT_RELAENT_IDX = 2 };
    elf_idx_t rela_idxs[3] = { ELF_IDX_NULL, ELF_IDX_NULL, ELF_IDX_NULL };
    int r = find_unique_dyn_entries(entries, 3,
                (Elf64_Sxword[]) { DT_RELA, DT_RELASZ, DT_RELAENT }, rela_idxs);
    if (r < 0) {
        pr_error("Invalid combination of the DT_RELA* entries\n");
        return -1;
    } else if (r > 0) {
        pr_debug("No dynsym RELA table\n");
        return 1;
    }

    const Elf64_Addr vaddr = entries->arr[rela_idxs[DT_RELA_IDX]].d_un.d_ptr;
    const Elf64_Xword size = entries->arr[rela_idxs[DT_RELASZ_IDX]].d_un.d_val;
    const Elf64_Xword entsize =
        entries->arr[rela_idxs[DT_RELAENT_IDX]].d_un.d_val;

    if (!(clazz == ELFCLASS32 && entsize == sizeof(Elf32_Rela)) &&
        !(clazz == ELFCLASS64 && entsize == sizeof(Elf64_Rela)))
    {
        pr_error("Invalid ElfXX_Rela entsize\n");
        return -1;
    }

    if (size % entsize != 0) {
        pr_error("RELA table size (%" PRIu64 ") is not divisible by "
                 "a RELA entry size (%" PRIu64 ")\n", size, entsize);
        return -1;
    } else if (size == 0) {
        pr_error("Zero-size RELA table\n");
        return -1;
    }
    const Elf64_Xword n_ents = size / entsize;
    if (n_ents > SIZE_MAX || size > SIZE_MAX) {
        pr_error("RELA entry count too large (integer overflow)\n");
        return -1;
    }

    Elf64_Off off = 0;
    if (find_ptload_and_off_from_vaddr(vaddr, size, phdrs, &off, NULL)) {
        pr_error("RELA table not contained in any single PT_LOAD segment\n");
        return -1;
    }

    Elf64_Xword relacount = 0;
    elf_idx_t dt_relacount_idx = ELF_IDX_NULL;
    r = find_unique_dyn_entry(entries, DT_RELACOUNT, &dt_relacount_idx);
    if (r < 0) {
        pr_error("Duplicate DT_RELACOUNT tag\n");
        return -1;
    } else if (r == 0) {
        relacount = entries->arr[dt_relacount_idx].d_un.d_val;
        if (relacount > n_ents) {
            pr_error("DT_RELACOUNT value too large\n");
            return -1;
        }
    }

    /* `present` flag set later, only after successful parsing */

    out->vaddr = vaddr;
    out->off = off;
    out->size = size;
    out->entsize = (Elf64_Half)entsize;

    out->arr = NULL;
    out->num = (size_t)n_ents;

    out->dt_rela_idx = rela_idxs[DT_RELA_IDX];
    out->dt_relasz_idx = rela_idxs[DT_RELASZ_IDX];
    out->dt_relaent_idx = rela_idxs[DT_RELAENT_IDX];

    if (r == 0) {
        out->dt_relacount_idx = dt_relacount_idx;
        out->relacount = relacount;
    }

    out->n_shdrs = 0;
    out->shdrs = NULL;

    return 0;
}

static int parse_jmprel(
        const ElfFileData *data, const struct elf_phdrs *phdrs,
        const struct elf_shdrs *shdrs, const struct elf_dyn_entries *entries,
        const struct elf_reloc_rel *rel, const struct elf_reloc_rela *rela,
        Elf64_Word *max_symidx_p, struct elf_reloc_jmprel *out
)
{
    *out = empty_reloc_jmprel_st;
    struct elf_reloc_jmprel jmprel = empty_reloc_jmprel_st;

    /* Parse the JMPREL table metadata */
    int r = find_jmprel(entries, data->clazz, phdrs, rel, rela, &jmprel);
    if (r < 0) {
        pr_error("Invalid JMPREL table information\n");
        return -1;
    } else if (r > 0) {
        /* already logged in `find_jmprel` */
        return 1;
    }

    union elf_reloc_jmprel_arr arr = { 0 };
    elf_idx_t *shdrs_arr = NULL;
    size_t n_shdrs = 0;

    const Elf64_Xword enttype = jmprel.enttype;
    const Elf64_Off tbl_off = jmprel.off;
    const size_t num = jmprel.num;

    /* Read the JMPREL entries */
    {
        if (enttype == DT_REL) {
            if (read_rel_table(data, tbl_off, num, &arr.rel, max_symidx_p)) {
                pr_error("Failed to parse the JMPREL REL entries\n");
                goto err;
            }
        } else /* if (enttype == DT_RELA) */ {
            if (read_rela_table(data, tbl_off, num, &arr.rela, max_symidx_p)) {
                pr_error("Failed to parse the JMPREL RELA entries\n");
                goto err;
            }
        }
    }

    /* Find and parse sections overlapping the JMPREL table */
    {
        const Elf64_Word sh_type = (enttype == DT_REL) ? SHT_REL : SHT_RELA;
        const elf_idx_t sht_dynsym_idx =
            find_unique_shdr_by_type(shdrs, shdr_unique_SHT_DYNSYM);

        r = find_validate_sht_relX_shdrs(
                shdrs, jmprel.vaddr, jmprel.off, jmprel.size,
                sht_dynsym_idx, jmprel.entsize,
                &shdrs_arr, &n_shdrs, sh_type
        );
        if (r < 0) {
            pr_error("Invalid PLTREL section headers\n");
            goto err;
        }
    }

    jmprel.arr = arr; arr = (union elf_reloc_jmprel_arr) { 0 };
    jmprel.shdrs = shdrs_arr; shdrs_arr = NULL;
    jmprel.n_shdrs = n_shdrs;

    jmprel.present = true;
    *out = jmprel;
    jmprel = empty_reloc_jmprel_st;
    return 0;

err:
    if (enttype == DT_REL) {
        if (arr.rel != NULL) {
            free(arr.rel);
            arr.rel = NULL;
        }
    } else /* if (enttype == DT_RELA) */ {
        if (arr.rela != NULL) {
            free(arr.rela);
            arr.rela = NULL;
        }
    }
    if (shdrs_arr != NULL) {
        free(shdrs_arr);
        shdrs_arr = NULL;
    }
    return -1;
}

static int find_jmprel(const struct elf_dyn_entries *entries, int clazz,
                       const struct elf_phdrs *phdrs,
                       const struct elf_reloc_rel *rel,
                       const struct elf_reloc_rela *rela,
                       struct elf_reloc_jmprel *out)
{
    *out = empty_reloc_jmprel_st;

    Elf64_Addr jmprel_vaddr = 0;
    Elf64_Xword jmprel_enttype = DT_NULL;
    Elf64_Xword jmprel_size = 0;
    enum { DT_JMPREL_IDX = 0, DT_PLTREL_IDX = 1, DT_PLTRELSZ_IDX = 2 };
    elf_idx_t idxs[3] = { ELF_IDX_NULL, ELF_IDX_NULL, ELF_IDX_NULL };
    {
        int r = find_unique_dyn_entries(entries, 3,
                (Elf64_Sxword[]) { DT_JMPREL, DT_PLTREL, DT_PLTRELSZ }, idxs);
        if (r < 0) {
            pr_error("Invalid combination of DT_JMPREL/DT_PLTREL* entries\n");
            return -1;
        } else if (r > 0) {
            pr_debug("JMPREL/PLTREL table not present\n");
            return 1;
        }

        jmprel_vaddr = entries->arr[idxs[DT_JMPREL_IDX]].d_un.d_ptr;
        jmprel_enttype = entries->arr[idxs[DT_PLTREL_IDX]].d_un.d_val;
        jmprel_size = entries->arr[idxs[DT_PLTRELSZ_IDX]].d_un.d_val;
    }

    if (jmprel_enttype != DT_REL && jmprel_enttype != DT_RELA) {
        pr_error("Invalid relocation type in DT_PLTREL\n");
        return -1;
    }

    Elf64_Half entsize = 0;
    size_t n_ents = 0;
    {
        const bool is32 = clazz == ELFCLASS32;
        if (jmprel_enttype == DT_REL)
            entsize = is32 ? sizeof(Elf32_Rel) : sizeof(Elf64_Rel);
        else /* if (rel_type == DT_RELA) */
            entsize = is32 ? sizeof(Elf32_Rela) : sizeof(Elf64_Rela);

        if (jmprel_size % entsize != 0) {
            pr_error("DT_PLTRELSZ is not divisible by the entry size\n");
            return -1;
        }
        const Elf64_Xword tmp_nents = jmprel_size / entsize;
        if (tmp_nents == 0) {
            pr_error("DT_JMPREL contains zero entries\n");
            return -1;
        } else if (tmp_nents > SIZE_MAX) {
            pr_error("Number of DT_JMPREL entries too large "
                     "(integer overflow)\n");
            return -1;
        }

        n_ents = (size_t)tmp_nents;
    }

    Elf64_Off jmprel_off = 0;
    if (find_ptload_and_off_from_vaddr(jmprel_vaddr, jmprel_size, phdrs,
                                       &jmprel_off, NULL))
    {
        pr_error("DT_JMPREL table not contained in any PT_LOAD segment\n");
        return -1;
    }

    elf_idx_t relX_overlap_start_idx = ELF_IDX_NULL;
    {
        const bool overlaps_rel = rel->present &&
            ranges_overlap(jmprel_vaddr, jmprel_size, rel->vaddr, rel->size);
        const bool overlaps_rela = rela->present &&
            ranges_overlap(jmprel_vaddr, jmprel_size, rela->vaddr, rela->size);
        const bool overlaps_relX = overlaps_rel || overlaps_rela;

        if (jmprel_enttype == DT_REL && overlaps_rela) {
            pr_error("JMPREL contains REL entries but overlaps the RELA table\n");
            return -1;
        } else if (jmprel_enttype == DT_RELA && overlaps_rel) {
            pr_error("JMPREL contains RELA entries but overlaps the REL table\n");
            return -1;
        }

        {
            const char *const relX_name =
                jmprel_enttype == DT_REL ? "REL" : "RELA";
            pr_debug("DT_JMPREL: %zu %s entries; overlaps DT_%s table: %d\n",
                     n_ents, relX_name, relX_name, overlaps_relX);
        }

        if (overlaps_relX) {
            const Elf64_Addr relX_vaddr =
                jmprel_enttype == DT_REL ? rel->vaddr : rela->vaddr;
            const Elf64_Xword relX_size =
                jmprel_enttype == DT_REL ? rel->size : rela->size;


            const Elf64_Addr relX_end = relX_vaddr + relX_size;
            const Elf64_Addr jmprel_end = jmprel_vaddr + jmprel_size;

            /*
             * If the JMPREL table overlaps the REL* table,
             * it must do so at the end of it, encompassing the last REL* entry,
             * like so:
             *  [ REL* ....    { JMPREL ... }]
             *
             * While this is theoretically processor-specific,
             * glibc assumes it and so I feel comfortable doing the same.
             */
            if (jmprel_vaddr < relX_vaddr || jmprel_end != relX_end ||
                (jmprel_vaddr - relX_vaddr) % entsize != 0)
            {
                pr_error("The JMPREL table overlaps the REL(A) table "
                         "in an invalid way\n");
                return -1;
            }

            relX_overlap_start_idx = (jmprel_vaddr - relX_vaddr) / entsize;
        }
    }

    out->vaddr = jmprel_vaddr;
    out->off = jmprel_off;
    out->size = jmprel_size;
    out->entsize = entsize;

    out->enttype = jmprel_enttype;
    out->arr = (union elf_reloc_jmprel_arr) { 0 };
    out->num = n_ents;

    out->dt_jmprel_idx = idxs[DT_JMPREL_IDX];
    out->dt_pltrel_idx = idxs[DT_PLTREL_IDX];
    out->dt_pltrelsz_idx = idxs[DT_PLTRELSZ_IDX];

    out->n_shdrs = 0;
    out->shdrs = NULL;

    out->relX_overlap_start_idx = relX_overlap_start_idx;

    return 0;
}

static int parse_relr(
        const ElfFileData *data, const struct elf_phdrs *phdrs,
        const struct elf_shdrs *shdrs, const struct elf_dyn_entries *entries,
        struct elf_reloc_relr *out
)
{
    struct elf_reloc_relr relr = empty_reloc_relr_st;
    *out = empty_reloc_relr_st;

    int ret = 0;

    const int r = find_relr(entries, data->clazz, phdrs, &relr);
    if (r < 0) {
        pr_error("Invalid RELR table metadata\n");
        ret = -1;
        goto err;
    } else if (r > 0) {
        /* already logged */
        ret = 1;
        goto err;
    }

    if (read_decode_relr(data, relr.off, relr.num,
                         &relr.arr, &relr.decoded_arr, &relr.num_decoded))
    {
        pr_error("Failed to read and decode the RELR table\n");
        ret = -1;
        goto err;
    }

    if (find_validate_sht_relX_shdrs(shdrs, relr.vaddr, relr.off, relr.size,
                                     ELF_IDX_NULL, relr.entsize,
                                     &relr.shdrs, &relr.n_shdrs, SHT_RELR) < 0)
    {
        pr_error("Invalid SHT_RELR section header(s)\n");
        ret = -1;
        goto err;
    }

    pr_debug("DT_RELR: %zu entries; with %zu decoded target addresses\n",
             relr.num, relr.num_decoded);
    relr.present = true;

err:
    if (ret != 0) {
        if (relr.arr != NULL)
            free(relr.arr);
        if (relr.decoded_arr != NULL)
            free(relr.decoded_arr);

        relr = empty_reloc_relr_st;
    } else /* if (ret == 0) */ {
        *out = relr;
        relr = empty_reloc_relr_st;
    }
    return ret;
}

static int find_relr(const struct elf_dyn_entries *entries, int clazz,
                     const struct elf_phdrs *phdrs, struct elf_reloc_relr *out)
{
    *out = empty_reloc_relr_st;

    enum { DT_RELRSZ_IDX = 0, DT_RELR_IDX = 1, DT_RELRENT_IDX = 2 };
    elf_idx_t idxs[3] = { ELF_IDX_NULL, ELF_IDX_NULL, ELF_IDX_NULL };

    const int r = find_unique_dyn_entries(entries, 3,
            (Elf64_Sxword[]) { DT_RELRSZ, DT_RELR, DT_RELRENT }, idxs);
    if (r < 0) {
        pr_error("Invalid combination of the DT_RELR* tags\n");
        return -1;
    } else if (r > 0) {
        pr_debug("No dynsym RELR table\n");
        return 1;
    }

    const Elf64_Xword size = entries->arr[idxs[DT_RELRSZ_IDX]].d_un.d_val;
    const Elf64_Addr vaddr = entries->arr[idxs[DT_RELR_IDX]].d_un.d_ptr;
    const Elf64_Xword entsize = entries->arr[idxs[DT_RELRENT_IDX]].d_un.d_val;

    if (!(clazz == ELFCLASS32 && entsize == sizeof(Elf32_Relr)) &&
        !(clazz == ELFCLASS64 && entsize == sizeof(Elf64_Relr)))
    {
        pr_error("Invalid RELR entry size\n");
        return -1;
    }

    if (size % entsize != 0) {
        pr_error("RELR table size not divisible by the entry size\n");
        return -1;
    } else if (size == 0) {
        pr_error("Zero-size RELR table\n");
        return -1;
    } else if (size / entsize > SIZE_MAX) {
        pr_error("Number of RELR entries too large (integer overflow)\n");
        return -1;
    }
    const size_t n_ents = (size_t)(size / entsize);

    Elf64_Off off = 0;
    if (find_ptload_and_off_from_vaddr(vaddr, size, phdrs, &off, NULL)) {
        pr_error("RELR table not contained in a PT_LOAD segment\n");
        return -1;
    }

    out->vaddr = vaddr;
    out->off = off;
    out->size = size;
    out->entsize = (Elf64_Half)entsize;

    out->arr = NULL;
    out->num = n_ents;

    out->decoded_arr = NULL;
    out->num_decoded = 0;

    out->dt_relrsz_idx = idxs[DT_RELRSZ_IDX];
    out->dt_relr_idx = idxs[DT_RELR_IDX];
    out->dt_relrent_idx = idxs[DT_RELRENT_IDX];

    out->n_shdrs = 0;
    out->shdrs = NULL;

    return 0;
}

static int read_decode_relr(const ElfFileData *data, Elf64_Off tbl_off,
                            size_t num, Elf64_Relr **out,
                            Elf64_Addr **out_decoded, size_t *out_num_decoded)
{
    Elf64_Relr *arr = NULL;
    Elf64_Addr *decoded_arr = NULL;
    size_t num_decoded = 0;
    Elf64_Off off = 0;
    Elf64_Addr cursor = 0;
    const bool is32 = data->clazz == ELFCLASS32;

    const Elf64_Xword WORD_MAX = is32 ? UINT32_MAX : UINT64_MAX;
    const size_t WORD_SIZE = is32 ? sizeof(uint32_t) : sizeof(uint64_t);
    const size_t WORD_BITS = is32 ? 32 : 64;

    *out = NULL;
    *out_decoded = 0;
    *out_num_decoded = 0;

    assert(num > 0);

    arr = calloc(num, sizeof(Elf64_Relr));
    if (arr == NULL) {
        pr_error("Failed to allocate the raw RELR entries array\n");
        goto err;
    }

    off = tbl_off;
    for (size_t i = 0; i < num; i++) {
        if (read_relr(data, &off, &arr[i])) {
            pr_error("Failed to read RELR entry no %zu\n", i);
            goto err;
        }
#if 0
        pr_debug("[offset 0x%" PRIx64 "] RELR entry 0x%016" PRIx64 "\n",
                 off - WORD_SIZE, arr[i]);
#endif /* 0 */

        if (i == 0 && arr[i] & 0x1) {
            /* Without this, the first entry is a bitmap,
             * but the `cursor` used for it is not initialized! */
            pr_error("First RELR entry is not a direct address entry\n");
            goto err;
        }

        if (!(arr[i] & 0x1)) {
            /* Least significant bit clear; direct address entry */

            if (arr[i] % WORD_SIZE != 0) {
                pr_error("Unaligned RELR direct address entry no %zu\n", i);
                goto err;
            }

            if (arr[i] > WORD_MAX - WORD_SIZE) {
                pr_error("Relocation target overflows address space\n");
                goto err;
            }
            cursor = arr[i] + WORD_SIZE;

            if (num_decoded == SIZE_MAX) {
                pr_error("Too many RELR entries (integer overflow)\n");
                goto err;
            }
            num_decoded++;
        } else /* if (arr[i] & 0x1) */ {
            /* Least significant bit set; region bitmap entry */

            /* A bitmap entry always describes an "array" of consecutive words
             * to be relocated, where each set bit corresponds to a word,
             * except of course for the least significant bit.
             * The cursor is always moved by WORD_BITS. */
            if (cursor > WORD_MAX - ((WORD_BITS - 1) * WORD_SIZE)) {
                pr_error("Relocation target region overflows address space\n");
                goto err;
            }
            cursor += (WORD_BITS - 1) * WORD_SIZE;

            for (size_t bit = 1; bit < WORD_BITS; bit++) {
                if (arr[i] & ((Elf64_Relr)1 << bit)) {
                    if (num_decoded == SIZE_MAX) {
                        pr_error("Too many RELR entries (integer overflow)\n");
                        goto err;
                    }
                    num_decoded++;
                }
            }
        }
    }
    assert(num_decoded > 0);

    cursor = 0;
    decoded_arr = calloc(num_decoded, sizeof(Elf64_Addr));
    if (decoded_arr == NULL) {
        pr_error("Failed to allocate the decoded RELR addresses array\n");
        goto err;
    }
    {
        size_t j = 0; /* index into `decoded_arr` */
        for (size_t i = 0; i < num; i++) {
            const Elf64_Relr val = arr[i];
            if (!(val & 0x1)) {
                /* Least significant bit clear; direct entry */
                assert(j < num_decoded);
                decoded_arr[j++] = val;
                cursor = arr[i] + WORD_SIZE;
            } else /* if (arr[i] & 0x1) */ {
                /* Least significant bit set; bitmap entry */
                assert(cursor != 0);
                for (size_t bit = 1; bit < WORD_BITS; bit++) {
                    if (arr[i] & ((Elf64_Relr)1 << bit)) {
                        assert(j < num_decoded);
                        decoded_arr[j++] = cursor + ((bit - 1) * WORD_SIZE);
                    }
                }
                cursor += (WORD_BITS - 1) * WORD_SIZE;
            }
        }
        assert(j == num_decoded);
    }

    *out = arr; arr = NULL;
    *out_decoded = decoded_arr; decoded_arr = NULL;
    *out_num_decoded = num_decoded;
    return 0;

err:
    if (decoded_arr != NULL) {
        free(decoded_arr);
        decoded_arr = NULL;
    }
    if (arr != NULL) {
        free(arr);
        arr = NULL;
    }
    return 1;
}
