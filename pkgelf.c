#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <alpm.h>
#include <archive.h>
#include <archive_entry.h>

static uintptr_t find_relocbase(const char *memblock, const Elf64_Ehdr *elf)
{
    if (elf->e_type == ET_DYN || elf->e_type == ET_REL)
        return 0;

    const Elf64_Phdr *phdr = (Elf64_Phdr *)&memblock[elf->e_phoff];
    while (phdr->p_type != PT_PHDR)
        ++phdr;

    return elf->e_phoff - phdr->p_vaddr;
}

static const char *find_strtable(const char *memblock, uintptr_t relocbase, const Elf64_Dyn *dyn)
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

static void list_add(alpm_list_t **list, const char *data)
{
    if (alpm_list_find_str(*list, data) == NULL)
        *list = alpm_list_add_sorted(*list, strdup(data), strcmp_v);
}

static void dump_elf(const char *memblock, alpm_list_t **need, alpm_list_t **provide)
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
        relocbase = find_relocbase(memblock, elf);
    }

    if (elf->e_shoff) {
        const Elf64_Shdr *shdr = (Elf64_Shdr *)&memblock[elf->e_shoff];
        int i;

        for (i = 0; i < elf->e_shnum; ++i) {
            if (shdr[i].sh_type == SHT_DYNAMIC) {
                const Elf64_Dyn *j, *dyn = (Elf64_Dyn *)&memblock[shdr[i].sh_offset];
                const char *strtable = find_strtable(memblock, relocbase, dyn);

                for (j = dyn; j->d_tag != DT_NULL; ++j) {
                    const char *name;
                    switch (j->d_tag) {
                    case DT_NEEDED:
                        name = strtable + j->d_un.d_val;
                        list_add(need, (void *)name);
                        break;
                    case DT_SONAME:
                        name = strtable + j->d_un.d_val;
                        if (strcmp(strrchr(name, '.'), ".so") != 0)
                            list_add(provide, (void *)name);
                        break;
                    }
                }
            }
        }
    }
}

int alpm_dump_elf(const char *filename)
{
    struct archive *archive = archive_read_new();
    struct stat st;
    char *memblock = MAP_FAILED;
    int fd = 0, rc = 0;
    alpm_list_t *need = NULL, *provide = NULL, *it;

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

    printf(":: %s\n", filename);

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

        dump_elf(block, &need, &provide);
        free(block);
    }

    for (it = need; it; it = it->next) {
        const char *name = it->data;
        printf(" NEEDED %s\n", name);
    }

    for (it = provide; it; it = it->next) {
        const char *name = it->data;
        printf(" PROVIDES %s\n", name);
    }

    alpm_list_free(need);
    alpm_list_free(provide);

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
    int i;

    if (argc < 2)
        errx(1, "not enough arguments");

    for (i = 1; i < argc; ++i) {
        alpm_dump_elf(argv[i]);
    }
}
