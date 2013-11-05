VERSION = $(shell git describe --tags)

CFLAGS := -std=c99 \
	-Wall -Wextra -pedantic \
	-D_GNU_SOURCE \
	${CFLAGS}

LDLIBS = -larchive -lalpm

all: pkgelf
pkgelf: pkgelf.o elf.o

install: pkgelf
	install -Dm755 pkgelf ${DESTDIR}/usr/bin/pkgelf
	# install -Dm644 pkgelf.1 $(DESTDIR)/usr/share/man/man1/pkgelf.1

clean:
	${RM} pkgelf *.o alpm/*.o

.PHONY: clean install uninstall
