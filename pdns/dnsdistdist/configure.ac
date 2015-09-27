AC_INIT([dnsdist], m4_esyscmd_s(build-aux/gen-version))
AM_INIT_AUTOMAKE([foreign dist-bzip2 parallel-tests 1.11 subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_CXX
PDNS_CHECK_LIBSODIUM
AC_PROG_LIBTOOL
PDNS_CHECK_READLINE([mandatory])
PDNS_CHECK_CLOCK_GETTIME
BOOST_REQUIRE([1.35])
BOOST_FOREACH
AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['-L$(top_builddir)/ext/yahttp/yahttp -lyahttp'])
DNSDIST_LUA
AX_CXX_COMPILE_STDCXX_11(ext,mandatory)
AC_DEFINE([HAVE_MBEDTLS2], [1], [Defined if mbed TLS version 2.x.x is used])

AC_CONFIG_FILES([Makefile
	ext/yahttp/Makefile
	ext/yahttp/yahttp/Makefile])
	
AC_OUTPUT
