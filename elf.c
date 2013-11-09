#include "elf.h"

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <assert.h>
#include <err.h>
#include <elf.h>

enum elfclass { ELF64, ELF32 };

struct elf_size {
    size_t ph;
    size_t sh;
    size_t dyn;
} Sizes[] = {
    [ELF32] = { sizeof(Elf64_Phdr), sizeof(Elf64_Shdr), sizeof(Elf64_Dyn) },
    [ELF64] = { sizeof(Elf64_Phdr), sizeof(Elf64_Shdr), sizeof(Elf64_Dyn) }
};

typedef union {
    Elf64_Ehdr e64;
    Elf32_Ehdr e32;
} Elf_Ehdr;

typedef union {
    Elf64_Phdr e64;
    Elf32_Phdr e32;
} Elf_Phdr;

typedef union {
    Elf64_Shdr e64;
    Elf32_Shdr e32;
} Elf_Shdr;

typedef union {
    Elf64_Dyn e64;
    Elf32_Dyn e32;
} Elf_Dyn;

#define FIELD(elf, hdr, field) ((elf)->class == ELF64 ? (hdr)->e64.field : (hdr)->e32.field)

typedef struct elf_t {
    enum elfclass class;
    const char *memblock;

    const char *ph_ptr;
    const char *sh_ptr;
    size_t sh_num;
    size_t ph_num;

    struct elf_size elem_size;
} elf_t;

bool ids = false;
alpm_list_t *need = NULL;
alpm_list_t *provide = NULL;
alpm_list_t *build_id = NULL;

static char *hex_representation(unsigned char *bytes, size_t size)
{
    static const char *hex_digits = "0123456789abcdef";
    char *str;
    size_t i;

    str = malloc(2 * size + 1);

    for (i = 0; i < size; i++) {
        str[2 * i] = hex_digits[bytes[i] >> 4];
        str[2 * i + 1] = hex_digits[bytes[i] & 0x0f];
    }

    str[2 * size] = '\0';

    return str;
}

static uintptr_t vaddr_to_offset(const elf_t *elf, uintptr_t vma)
{
    size_t i;

    for (i = 0; i < elf->ph_num; ++i) {
        const Elf_Phdr *phdr = (Elf_Phdr *)(elf->ph_ptr + i * elf->elem_size.ph);

        if (phdr->e64.p_type == PT_LOAD) {
            uintptr_t vaddr = FIELD(elf, phdr, p_vaddr);
            if (vma >= vaddr)
                return vma - vaddr - FIELD(elf, phdr, p_offset);
        }
    }

    return vma;
}

static int strcmp_v(const void *p1, const void *p2)
{
    return strcmp(p1, p2);
}

static void list_add(alpm_list_t **list, const char *_data, int size)
{
    // FIXME: hack around the fact that _data can be read-only memory */
    char *data = strdup(_data);

    char *ext = strrchr(data, '.');
    if (!ext || strcmp(ext, ".so") == 0) {
        free(data);
        return;
    }

    *ext = '\0';

    int ver = atoi(ext + 1);
    char *name = NULL;
    asprintf(&name, "%s=%d-%d", data, ver, size);

    if (name && alpm_list_find_str(*list, name) == NULL)
        *list = alpm_list_add_sorted(*list, name, strcmp_v);
    else
        free(name);

    free(data);
}

struct elf_t *load_elf(const char *memblock)
{
    struct elf_t *elf = NULL;

    if (memcmp(memblock, ELFMAG, SELFMAG) != 0) {
        return NULL;
    }

    elf = malloc(sizeof(elf_t));
    *elf = (struct elf_t){ .memblock = memblock };

    switch (memblock[EI_CLASS]) {
    case ELFCLASSNONE:
        errx(1, "invalid elf class");
    case ELFCLASS64:
        elf->class = ELF64;
        break;
    case ELFCLASS32:
        elf->class = ELF32;
        break;
    default:
        return NULL;
    }

    elf->elem_size = Sizes[elf->class];

    const Elf_Ehdr *hdr = (Elf_Ehdr *)memblock;
    elf->ph_ptr = memblock + FIELD(elf, hdr, e_phoff);
    elf->sh_ptr = memblock + FIELD(elf, hdr, e_shoff);
    elf->ph_num = FIELD(elf, hdr, e_phnum);
    elf->sh_num = FIELD(elf, hdr, e_shnum);

    return elf;
}

static const char *find_strtable(const elf_t *elf, uintptr_t dyn_ptr)
{
    uintptr_t strtab = 0;

    for (;;) {
        const Elf_Dyn *dyn = (Elf_Dyn *)(elf->memblock + dyn_ptr);
        uint32_t tag = FIELD(elf, dyn, d_tag);

        if (tag == DT_NULL) {
            break;
        } else if (tag == DT_STRTAB) {
            strtab = FIELD(elf, dyn, d_un.d_val);
            break;
        }

        dyn_ptr += elf->elem_size.dyn;
    }

    if (!strtab)
        errx(1, "failed to find string table");

    return elf->memblock + vaddr_to_offset(elf, strtab);
}

static void read_dynamic(const elf_t *elf, uintptr_t dyn_ptr,
                         alpm_list_t **need, alpm_list_t **provide)
{
    const char *strtable = find_strtable(elf, dyn_ptr);

    for (;;) {
        const Elf_Dyn *dyn = (Elf_Dyn *)(elf->memblock + dyn_ptr);
        const char *name = strtable + FIELD(elf, dyn, d_un.d_val);

        switch (FIELD(elf, dyn, d_tag)) {
        case DT_NULL:
            return;
        case DT_NEEDED:
            list_add(need, name, elf->class);
            break;
        case DT_SONAME:
            list_add(provide, name, elf->class);
            break;
        }

        dyn_ptr += elf->elem_size.dyn;
    }
}

static void read_build_id(const elf_t *elf, uintptr_t offset, alpm_list_t **ids)
{
    assert(sizeof(Elf64_Nhdr) == sizeof(Elf32_Nhdr));

    const Elf64_Nhdr *nhdr = (Elf64_Nhdr *)(elf->memblock + offset);
    const char *data = (char *)(nhdr + 1);

    if (strncmp(data, "GNU", nhdr->n_namesz) == 0 && nhdr->n_type == NT_GNU_BUILD_ID) {
        unsigned char *desc = malloc(nhdr->n_descsz);

        data += nhdr->n_namesz;
        memcpy(desc, data, nhdr->n_descsz);
        *ids = alpm_list_add(*ids, hex_representation(desc, nhdr->n_descsz));

        free(desc);
    }
}

void elf_dynamic(elf_t *elf, alpm_list_t **need, alpm_list_t **provide)
{
    size_t i;

    if (!elf)
        return;

    for (i = 0; i < elf->sh_num; ++i) {
        const Elf_Shdr *shdr = (Elf_Shdr *)(elf->sh_ptr + i * elf->elem_size.sh);

        if (shdr->e64.sh_type == SHT_DYNAMIC) {
            uintptr_t offset = FIELD(elf, shdr, sh_offset);
            read_dynamic(elf, offset, need, provide);
        }
    }
}

void elf_build_id(elf_t *elf, alpm_list_t **ids)
{
    size_t i;

    if (!elf)
        return;

    for (i = 0; i < elf->sh_num; ++i) {
        const Elf_Shdr *shdr = (Elf_Shdr *)(elf->sh_ptr + i * elf->elem_size.sh);

        if (ids && shdr->e64.sh_type == SHT_NOTE) {
            uintptr_t offset = FIELD(elf, shdr, sh_offset);
            read_build_id(elf, offset, ids);
        }
    }
}
