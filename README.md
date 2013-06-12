## pkgelf

A small tool for ELF-based packages to introspect dynamic linking.

```
usage: pkgelf [options] [files...]
Options:
 -h, --help            display this help and exit
 -v, --version         display version
 -p, --pkg             introspect an archlinux package
 -d, --dir             introspect a directory
 -i, --build-ids       introspect binary build-ids
```

### Example

```
$ ./pkgelf /var/cache/pacman/pkg/libpulse-4.0-2-x86_64.pkg.tar.xz
REQUIRE libasyncns.so=0-64
REQUIRE libc.so=6-64
REQUIRE libdbus-1.so=3-64
REQUIRE libdl.so=2-64
REQUIRE libglib-2.0.so=0-64
REQUIRE libjson-c.so=2-64
REQUIRE libm.so=6-64
REQUIRE libpthread.so=0-64
REQUIRE librt.so=1-64
REQUIRE libsndfile.so=1-64
REQUIRE libxcb.so=1-64
PROVIDE libpulse-mainloop-glib.so=0-64
PROVIDE libpulse-simple.so=0-64
PROVIDE libpulse.so=0-64
```
