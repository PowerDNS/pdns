AC_INIT([dnsdist], [0.1])
AM_INIT_AUTOMAKE([foreign dist-bzip2 parallel-tests 1.11 subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_CXX
PKG_CHECK_MODULES([libsodium], [libsodium], [AC_DEFINE([HAVE_LIBSODIUM], [1], [Define to 1 if you have libsodium])], [true])
AC_PROG_LIBTOOL
BOOST_REQUIRE([1.35])
BOOST_FOREACH
AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/pdns/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['-L$(top_builddir)/pdns/ext/yahttp/yahttp -lyahttp'])
PDNS_WITH_LUA
AX_CXX_COMPILE_STDCXX_11(ext,mandatory)
AM_CONDITIONAL([CXX2011],[test "$HAVE_CXX11" = "1"])

AC_CONFIG_FILES([Makefile
	pdns/ext/yahttp/Makefile
	pdns/ext/yahttp/yahttp/Makefile])
	
AC_OUTPUT
