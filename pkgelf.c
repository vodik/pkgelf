#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <err.h>
#include <ftw.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <alpm.h>
#include <alpm_list.h>
#include <archive.h>
#include <archive_entry.h>

#include "elf.h"

static bool ids;
static alpm_list_t *need;
static alpm_list_t *provide;
static alpm_list_t *build_id;

static void dump_elf(const char *memblock)
{
    struct elf_t *elf = load_elf(memblock);

    elf_dynamic(elf, &need, &provide);
    if (ids)
        elf_build_id(elf, &build_id);
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

static void __attribute__((__noreturn__)) usage(FILE *out)
{
    fprintf(out, "usage: %s [options] [files...]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help            display this help and exit\n"
        " -v, --version         display version\n"
        " -p, --pkg             introspect an archlinux package\n"
        " -d, --dir             introspect a directory\n"
        " -i, --build-ids       introspect binary build-ids\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    static const struct option opts[] = {
        { "help",      no_argument, 0, 'h' },
        { "version",   no_argument, 0, 'v' },
        { "all",       no_argument, 0, 'a' },
        { "pkg",       no_argument, 0, 'p' },
        { "dir",       no_argument, 0, 'd' },
        { "build-ids", no_argument, 0, 'i' },
        { 0, 0, 0, 0 }
    };

    int i;
    int (*dumper)(const char *name) = pkg_dump_elf;

    while (true) {
        int opt = getopt_long(argc, argv, "hvpdi", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
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
        case 'i':
            ids = true;
            break;
        default:
            usage(stderr);
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
        }

        for (it = provide; it; it = it->next) {
            const char *name = it->data;
            printf("PROVIDE %s\n", name);
        }

        alpm_list_free_inner(need, free);
        alpm_list_free(need);
        alpm_list_free_inner(provide, free);
        alpm_list_free(provide);
        alpm_list_free_inner(build_id, free);
        alpm_list_free(build_id);
        need = NULL;
        provide = NULL;
        build_id = NULL;
    }
}
