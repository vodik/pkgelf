#ifndef ELF_H
#define ELF_H

#include <stdbool.h>
#include <alpm_list.h>

extern bool ids;
extern alpm_list_t *need;
extern alpm_list_t *provide;
extern alpm_list_t *build_id;

void dump_elf(const char *memblock);

#endif
