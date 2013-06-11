#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <memory.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <err.h>
#include <ftw.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <alpm.h>
#include <archive.h>
#include <archive_entry.h>

enum elfclass {
    ELF64 = 64,
    ELF32 = 32
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

typedef struct elf {
    enum elfclass class;
    const char *memblock;

    const char *phptr;
    const char *shptr;
    size_t shnum;
    size_t phnum;
    size_t phsize;
    size_t shsize;
    size_t dynsize;
} elf_t;

static alpm_list_t *need = NULL;
static alpm_list_t *provide = NULL;
static alpm_list_t *build_id = NULL;

uintptr_t vaddr_to_offset(const elf_t *elf, uintptr_t vma)
{
    size_t i;

    for (i = 0; i < elf->phnum; ++i) {
        const Elf_Phdr *phdr = (Elf_Phdr *)(elf->phptr + i * elf->phsize);

        if (phdr->e64.p_type == PT_LOAD) {
            uintptr_t vaddr = FIELD(elf, phdr, p_vaddr);
            if (vma >= vaddr)
                return vma - vaddr - FIELD(elf, phdr, p_offset);
        }
    }

    return vma;
}

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

static int strcmp_v(const void *p1, const void *p2)
{
    return strcmp(p1, p2);
}

static void list_add(alpm_list_t **list, const char *_data, int size)
{
    // FIXME: hack around the fact that _data can be read-only memory */
    char *data = strdup(_data);

    char *ext = strrchr(data, '.');
    if (!ext || strcmp(ext, ".so") == 0)
        return;

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

static elf_t *load_elf(const char *memblock)
{
    elf_t *elf = NULL;
    const Elf_Ehdr *hdr = (Elf_Ehdr *)memblock;

    /* check the magic */
    if (memcmp(hdr->e64.e_ident, ELFMAG, SELFMAG) != 0) {
        return NULL;
    }

    elf = calloc(1, sizeof(elf_t));
    elf->memblock = memblock;

    switch (hdr->e64.e_ident[EI_CLASS]) {
    case ELFCLASSNONE:
        errx(1, "invalid elf class");
    case ELFCLASS64:
        elf->class = ELF64;
        elf->phptr = memblock + hdr->e64.e_phoff;
        elf->shptr = memblock + hdr->e64.e_shoff;
        elf->phnum = hdr->e64.e_phnum;
        elf->shnum = hdr->e64.e_shnum;
        elf->phsize = sizeof(Elf64_Phdr);
        elf->shsize = sizeof(Elf64_Shdr);
        elf->dynsize = sizeof(Elf64_Dyn);
        break;
    case ELFCLASS32:
        elf->class = ELF32;
        elf->phptr = memblock + hdr->e32.e_phoff;
        elf->shptr = memblock + hdr->e32.e_shoff;
        elf->phnum = hdr->e32.e_phnum;
        elf->shnum = hdr->e32.e_shnum;
        elf->phsize = sizeof(Elf32_Phdr);
        elf->shsize = sizeof(Elf32_Shdr);
        elf->dynsize = sizeof(Elf32_Dyn);
        break;
    default:
        return NULL;
    }

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

        dyn_ptr += elf->dynsize;
    }

    if (!strtab)
        errx(1, "failed to find string table");

    return elf->memblock + vaddr_to_offset(elf, strtab);
}

static void read_dynamic(const elf_t *elf, uintptr_t dyn_ptr)
{
    const char *strtable = find_strtable(elf, dyn_ptr);

    for (;;) {
        const Elf_Dyn *dyn = (Elf_Dyn *)(elf->memblock + dyn_ptr);
        const char *name = strtable + FIELD(elf, dyn, d_un.d_val);

        switch (FIELD(elf, dyn, d_tag)) {
        case DT_NULL:
            return;
        case DT_NEEDED:
            list_add(&need, name, elf->class);
            break;
        case DT_SONAME:
            list_add(&provide, name, elf->class);
            break;
        }

        dyn_ptr += elf->dynsize;
    }
}

static void read_build_id(const elf_t *elf, uintptr_t offset)
{
    assert(sizeof(Elf64_Nhdr) == sizeof(Elf32_Nhdr));

    const Elf64_Nhdr *nhdr = (Elf64_Nhdr *)(elf->memblock + offset);
    const char *data = (char *)(nhdr + 1);

    if (strncmp(data, "GNU", nhdr->n_namesz) == 0 && nhdr->n_type == NT_GNU_BUILD_ID) {
        unsigned char *desc = malloc(nhdr->n_descsz);

        data += nhdr->n_namesz;
        memcpy(desc, data, nhdr->n_descsz);
        build_id = alpm_list_add(build_id, hex_representation(desc, nhdr->n_descsz));

        free(desc);
    }
}

static void dump_elf(const char *memblock)
{
    const elf_t *elf = load_elf(memblock);
    const Elf_Shdr *shdr;
    size_t i;

    if (!elf)
        return;

    for (i = 0; i < elf->shnum; ++i) {
        shdr = (Elf_Shdr *)(elf->shptr + i * elf->shsize);
        uintptr_t offset;

        switch (shdr->e64.sh_type) {
        case SHT_DYNAMIC:
            offset = FIELD(elf, shdr, sh_offset);
            read_dynamic(elf, offset);
            break;
        case SHT_NOTE:
            offset = FIELD(elf, shdr, sh_offset);
            read_build_id(elf, offset);
            break;
        default:
            break;
        }
    }
}

static int dir_dump(const char *filename, const struct stat *st, int type,
                    struct FTW __attribute__((unused)) *ftw)
{
    char *memblock = MAP_FAILED;
    int fd = 0;

    if (type != FTW_F)
        return 0;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        if(errno != ENOENT)
            err(EXIT_FAILURE, "failed to open %s", filename);
        goto cleanup;
    }

    memblock = mmap(NULL, st->st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (memblock == MAP_FAILED)
        err(EXIT_FAILURE, "failed to mmap package %s", filename);

    madvise(memblock, st->st_size, MADV_WILLNEED | MADV_SEQUENTIAL);
    dump_elf(memblock);

cleanup:
    if (fd)
        close(fd);

    if (memblock != MAP_FAILED)
        munmap(memblock, st->st_size);

    return 0;
}

static int dir_dump_elf(const char *path)
{
    nftw(path, dir_dump, 7, FTW_PHYS);
    return 0;
}

static int pkg_dump_elf(const char *filename)
{
    struct archive *archive = archive_read_new();
    struct stat st;
    char *memblock = MAP_FAILED;
    int fd = 0, rc = 0;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        if(errno != ENOENT)
            err(EXIT_FAILURE, "failed to open %s", filename);
        goto cleanup;
    }

    fstat(fd, &st);
    memblock = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
    if (memblock == MAP_FAILED)
        err(EXIT_FAILURE, "failed to mmap package %s", filename);

    archive_read_support_filter_all(archive);
    archive_read_support_format_all(archive);

    int r = archive_read_open_memory(archive, memblock, st.st_size);
    if (r != ARCHIVE_OK) {
        warnx("%s is not an archive", filename);
        rc = -1;
        goto cleanup;
    }

    for (;;) {
        struct archive_entry *entry;

        r = archive_read_next_header(archive, &entry);
        if (r == ARCHIVE_EOF) {
            break;
        } else if (r != ARCHIVE_OK) {
            errx(EXIT_FAILURE, "failed to read header: %s", archive_error_string(archive));
        }

        const mode_t mode = archive_entry_mode(entry);
        if (!S_ISREG(mode))
            continue;

        size_t block_size = archive_entry_size(entry);
        char *block = malloc(block_size);
        size_t bytes_r = archive_read_data(archive, (void *)block, block_size);
        if (bytes_r < block_size)
            err(1, "didn't read enough bytes");

        dump_elf(block);
        free(block);
    }

cleanup:
    if (fd)
        close(fd);

    if (memblock != MAP_FAILED)
        munmap(memblock, st.st_size);

    archive_read_close(archive);
    archive_read_free(archive);
    return rc;
}

int main(int argc, char *argv[])
{
    static const struct option opts[] = {
        { "help",     no_argument, 0, 'h' },
        { "version",  no_argument, 0, 'v' },
        { "all",      no_argument, 0, 'a' },
        { "pkg",      no_argument, 0, 'p' },
        { "dir",      no_argument, 0, 'd' },
        { 0, 0, 0, 0 }
    };

    int i;
    int (*dumper)(const char *name) = pkg_dump_elf;
    bool all = false;

    while (true) {
        int opt = getopt_long(argc, argv, "hvapd", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            /* usage(stdout); */
            break;
        case 'v':
            printf("%s %s\n", program_invocation_short_name, "devel");
            exit(EXIT_SUCCESS);
        case 'p':
            dumper = pkg_dump_elf;
            break;
        case 'a':
            all = true;
            break;
        case 'd':
            dumper = dir_dump_elf;
            break;
        default:
            break;
        }
    }

    if (argc < 2)
        errx(1, "not enough arguments");

    for (i = 1; i < argc; ++i) {
        const alpm_list_t *it;

        dumper(argv[i]);

        for (it = build_id; it; it = it->next) {
            const char *name = it->data;
            printf("BUILD-ID %s\n", name);
        }

        for (it = need; it; it = it->next) {
            const char *name = it->data;
            if (alpm_list_find_str(provide, name) == NULL)
                printf("REQUIRE %s\n", name);
            else if (all)
                printf("REQUIRE %s [self provided]\n", name);
        }

        for (it = provide; it; it = it->next) {
            const char *name = it->data;
            printf("PROVIDE %s\n", name);
        }

        alpm_list_free(need);
        alpm_list_free(provide);
        alpm_list_free(build_id);
        need = NULL;
        provide = NULL;
        build_id = NULL;
    }
}
