#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <memory.h>
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

static alpm_list_t *need = NULL;
static alpm_list_t *provide = NULL;
static alpm_list_t *build_id = NULL;

static uintptr_t calc_relocbase(const char *memblock, const Elf64_Ehdr *elf)
{
    if (elf->e_type == ET_DYN || elf->e_type == ET_REL)
        return 0;

    const Elf64_Phdr *phdr = (Elf64_Phdr *)&memblock[elf->e_phoff];
    while (phdr->p_type != PT_PHDR)
        ++phdr;

    return elf->e_phoff - phdr->p_vaddr;
}

/* static inline const char *find_strtable(const char *memblock, const Elf64_Ehdr *elf) */
/* { */
/*     const Elf64_Off strtbl_off = elf->e_shoff + elf->e_shstrndx * elf->e_shentsize; */
/*     const Elf64_Shdr* strtbl = (Elf64_Shdr*)&memblock[strtbl_off]; */
/*     return &memblock[strtbl->sh_offset]; */
/* } */

static const char *find_dyn_strtable(const char *memblock, uintptr_t relocbase, const Elf64_Dyn *dyn)
{
    const Elf64_Dyn *i;

    for (i = dyn; i->d_tag != DT_NULL; ++i) {
        if (i->d_tag == DT_STRTAB)
            return &memblock[i->d_un.d_ptr + relocbase];
    }

    errx(1, "failed to find string table");
}

static int strcmp_v(const void *p1, const void *p2)
{
    return strcmp(p1, p2);
}

static void list_add(alpm_list_t **list, const char *_data)
{
    // FIXME: hack around the fact that _data can be read-only memory */
    char *data = strdup(_data);

    char *ext = strrchr(data, '.');
    if (!ext || strcmp(ext, ".so") == 0)
        return;

    *ext = '\0';

    int ver = atoi(ext + 1);
    char *name = NULL;
    asprintf(&name, "%s=%d-%d", data, ver, 64);

    if (name && alpm_list_find_str(*list, name) == NULL)
        *list = alpm_list_add_sorted(*list, name, strcmp_v);
    else
        free(name);

    free(data);
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

static void read_dynamic(const char *memblock, uintptr_t relocbase, const Elf64_Shdr *shdr)
{
    const Elf64_Dyn *j, *dyn = (Elf64_Dyn *)&memblock[shdr->sh_offset];
    const char *strtable = find_dyn_strtable(memblock, relocbase, dyn);

    for (j = dyn; j->d_tag != DT_NULL; ++j) {
        const char *name;
        switch (j->d_tag) {
            case DT_NEEDED:
                name = strtable + j->d_un.d_val;
                list_add(&need, name);
                break;
            case DT_SONAME:
                name = strtable + j->d_un.d_val;
                list_add(&provide, name);
                break;
        }
    }
}

static void read_build_id(const char *memblock, const Elf64_Shdr *shdr)
{
    const Elf64_Nhdr *nhdr = (Elf64_Nhdr *)&memblock[shdr->sh_offset];
    const char *temp = &memblock[shdr->sh_offset + sizeof *nhdr];
    if (strncmp(temp, "GNU", nhdr->n_namesz) == 0 && nhdr->n_type == NT_GNU_BUILD_ID) {
        char *desc = malloc(nhdr->n_descsz);

        temp += nhdr->n_namesz;
        memcpy(desc, temp, nhdr->n_descsz);
        build_id = alpm_list_add(build_id, hex_representation((unsigned char *)desc, nhdr->n_descsz));

        free(desc);
    }
}

static void dump_elf(const char *memblock)
{
    static const char magic[] = { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3 };

    const Elf64_Ehdr *elf = (Elf64_Ehdr *)memblock;
    uintptr_t relocbase = 0;

    if (memcmp(elf->e_ident, magic, sizeof(magic)) != 0) {
        return;
    }

    if (elf->e_machine != EM_X86_64) {
        return;
    }

    if (elf->e_phoff) {
        relocbase = calc_relocbase(memblock, elf);
    }

    if (elf->e_shoff) {
        const Elf64_Shdr *shdr = (Elf64_Shdr *)&memblock[elf->e_shoff];
        int i;

        for (i = 0; i < elf->e_shnum; ++i) {
            switch (shdr[i].sh_type) {
            case SHT_DYNAMIC:
                read_dynamic(memblock, relocbase, &shdr[i]);
                break;
            case SHT_NOTE:
                read_build_id(memblock, &shdr[i]);
                break;
            default:
                break;
            }
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
        { "help",     no_argument,       0, 'h' },
        { "version",  no_argument,       0, 'v' },
        { "pkg",      required_argument, 0, 'p' },
        { "dir",      required_argument, 0, 'd' },
        { 0, 0, 0, 0 }
    };

    int i;
    int (*dumper)(const char *name) = pkg_dump_elf;

    while (true) {
        int opt = getopt_long(argc, argv, "hvpd", opts, NULL);
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
            else
                printf("REQUIRE %s [self provided]\n", name);
        }

        for (it = provide; it; it = it->next) {
            const char *name = it->data;
            printf("PROVIDES %s\n", name);
        }

        alpm_list_free(need);
        alpm_list_free(provide);
        alpm_list_free(build_id);
        need = NULL;
        provide = NULL;
        build_id = NULL;
    }
}
