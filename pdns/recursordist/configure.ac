AC_INIT([pdns-recursor], m4_esyscmd_s(build-aux/gen-version))
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip tar-ustar -Wno-portability subdir-objects parallel-tests 1.11])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([pdns_recursor.cc])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST
: ${CFLAGS="-Wall -g -O2"}
: ${CXXFLAGS="-Wall -g -O2"}

AC_SUBST([pdns_configure_args],["$ac_configure_args"])
AC_DEFINE_UNQUOTED([PDNS_CONFIG_ARGS],
  ["$pdns_configure_args"],
  [pdns-recursor configure arguments]
)

AC_PROG_CC
AC_PROG_CXX
AC_LANG([C++])

AC_DEFINE([_GNU_SOURCE], [1],
  [Define _GNU_SOURCE so that we get all necessary prototypes]
)

# Warn when pkg.m4 is missing
m4_pattern_forbid([^_?PKG_[A-Z_]+$],[*** pkg.m4 missing, please install pkg-config])

AX_CXX_COMPILE_STDCXX_11(ext,mandatory)
AC_PROG_LIBTOOL

PDNS_CHECK_OS

BOOST_REQUIRE([1.35])
PDNS_ENABLE_REPRODUCIBLE

PDNS_WITH_LUAJIT
AS_IF([test "x$with_luajit" = "xno"], [
  PDNS_WITH_LUA
])

PDNS_ENABLE_VERBOSE_LOGGING

# Crypto libraries
PDNS_ENABLE_BOTAN
AX_CHECK_OPENSSL([
	AM_CONDITIONAL([OPENSSL], [true])
	AC_DEFINE(HAVE_OPENSSL, [1], [Define to 1 if you openssl])
	],[
	AM_CONDITIONAL([OPENSSL], [false])
	]
)

# check for tools we might need
PDNS_CHECK_RAGEL
PDNS_CHECK_CURL

AC_CHECK_FUNCS([strcasestr])

AC_SUBST(socketdir)
socketdir="/var/run"
AC_ARG_WITH([socketdir],
  [AS_HELP_STRING([--with-socketdir],[where the controlsocket lives @<:@default=/var/run@:>@])],
  [socketdir="$withval"]
)

AC_MSG_CHECKING([whether we will enable compiler security checks])
AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--disable-hardening],[disable compiler security checks @<:@default=no@:>@])],
  [enable_hardening=$enableval],
  [enable_hardening=yes]
)
AC_MSG_RESULT([$enable_hardening])

AS_IF([test "x$enable_hardening" != "xno"], [
  AC_CC_PIE
  AC_CC_STACK_PROTECTOR
  AC_CC_PARAM_SSP_BUFFER_SIZE([4])
  AC_CC_D_FORTIFY_SOURCE
  AC_LD_RELRO
])

PDNS_ENABLE_SANITIZERS
PDNS_ENABLE_MALLOC_TRACE
PDNS_CHECK_PANDOC

AC_SUBST(LIBS)

AC_SUBST([AM_CPPFLAGS],
  ["AS_ESCAPE([-I$(top_builddir) -I$(top_srcdir)]) $THREADFLAGS $BOOST_CPPFLAGS"]
)

AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['-L$(top_builddir)/ext/yahttp/yahttp -lyahttp'])

CXXFLAGS="$SANITIZER_FLAGS $CXXFLAGS"

LDFLAGS="$RELRO_LDFLAGS $LDFLAGS"

AC_CONFIG_FILES([Makefile
	ext/Makefile
	ext/json11/Makefile
	ext/yahttp/Makefile
	ext/yahttp/yahttp/Makefile])

AC_OUTPUT
