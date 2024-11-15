ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include \
          lib \
          test

if BUILD_KERNEL_MODULE
SUBDIRS += kernel
endif

pkgconfig_DATA = xpmem.pc

EXTRA_DIST = \
        $(pkgconfig_DATA) \
	xpmem-lib.spec \
	xpmem-kmod.spec

dist: dist-bzip2

install-data-local:
	$(INSTALL_DATA) -D $(srcdir)/module $(DESTDIR)@MODULE_PATH@

