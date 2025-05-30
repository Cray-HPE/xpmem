#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([xpmem], [1.0.1], [https://github.com/Cray-HPE/xpmem/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([include/xpmem.h])
AC_CONFIG_MACRO_DIR([m4])
AM_CONFIG_HEADER([config.h])
AM_SILENT_RULES

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_AR
AM_PROG_LIBTOOL
AC_PROG_LN_S

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdlib.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_C_VOLATILE

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MMAP
AC_CHECK_FUNCS([getpagesize memset])

AC_ARG_WITH([module],
  [AS_HELP_STRING([--with-module=PATH],
     [use $PATH as name of module file to write.])],
     [],
     [withval=$prefix])
AC_SUBST([MODULE_PATH], $withval)
AC_SUBST([MODULE_VERSION], [`basename $withval`])

AC_ARG_WITH([module-prefix],
            [AS_HELP_STRING([--with-module-prefix],
                            [Prefix for kernel module installation])],
            [],
            [with_module_prefix=$prefix])
AC_SUBST([moduleprefix], [${with_module_prefix%%/}])

AC_ARG_WITH([pkgconfig-prefix],
  [AS_HELP_STRING([--with-pkgconfig-prefix=PATH],
     [use $PATH as name of module file to write.])],
     [],
     [with_pkgconfig_prefix=$prefix])
AC_SUBST([pkgconfigdir], [$with_pkgconfig_prefix])

AC_PATH_KERNEL_SOURCE
AC_KERNEL_CHECKS

AC_CONFIG_FILES([Makefile
                 xpmem.pc
                 module
                 include/Makefile
                 kernel/Kbuild
                 kernel/Makefile
                 lib/Makefile
                 test/Makefile])
AC_OUTPUT
