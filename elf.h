#ifndef ELF_H
#define ELF_H

#include <stdbool.h>
#include <alpm_list.h>

struct elf_t;

/* void dump_elf(const char *memblock); */
struct elf_t *load_elf(const char *memblock);

void elf_dynamic(struct elf_t *elf, alpm_list_t **need, alpm_list_t **provide);
void elf_build_id(struct elf_t *elf, alpm_list_t **ids);

#endif
