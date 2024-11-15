ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include \
          lib \
          test

if BUILD_KERNEL_MODULE
SUBDIRS += kernel
endif

pkgconfig_DATA = cray-xpmem.pc

EXTRA_DIST = \
        $(pkgconfig_DATA) \
	xpmem-lib.spec \
	xpmem-kmod.spec

dist: dist-bzip2
