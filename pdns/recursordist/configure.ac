AC_PREREQ([2.61])

AC_INIT([pdns-recursor], m4_esyscmd(build-aux/gen-version))
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

AC_GNU_SOURCE

AC_DEFINE([RECURSOR], [1],
  [This is the PowerDNS Recursor]
)

# Warn when pkg.m4 is missing
m4_pattern_forbid([^_?PKG_[A-Z_]+$], [*** pkg.m4 missing, please install pkg-config])

AX_CXX_COMPILE_STDCXX_11([ext], [mandatory])
AC_PROG_LIBTOOL

PDNS_CHECK_OS
PDNS_CHECK_NETWORK_LIBS

PDNS_CHECK_CLOCK_GETTIME

boost_required_version=1.35

PDNS_WITH_PROTOBUF
AS_IF([test "x$PROTOBUF_LIBS" != "x" -a x"$PROTOC" != "x"],
  # The protobuf code needs boost::uuid, which is available from 1.42 onward
  [AC_MSG_WARN([Bumping minimal Boost requirement to 1.42. To keep the requirement at 1.35, disable protobuf support])
  boost_required_version=1.42]
)

BOOST_REQUIRE([$boost_required_version])
# Boost Context was introduced in 1.51 (Aug 2012), but there was an immediate
# API break in 1.52 (Nov 2012), so we only support that, and later.
pdns_context_library="System V ucontexts"
AS_IF([test $boost_major_version -ge 152], [BOOST_CONTEXT([], [no])])
AC_MSG_CHECKING([what context library to use for MTasker])
AS_IF([test x"$boost_cv_lib_context" = "xyes"], [pdns_context_library="Boost Context"])
AC_MSG_RESULT([$pdns_context_library])

PDNS_ENABLE_UNIT_TESTS
PDNS_ENABLE_REPRODUCIBLE

PDNS_WITH_LUAJIT
AS_IF([test "x$with_luajit" = "xno"], [
  PDNS_WITH_LUA
])
AS_IF([test "x$LUAPC" = "x" -a "x$LUAJITPC" = "x"], [
  AC_MSG_ERROR([Neither Lua nor LuaJIT found, Lua support is not optional])
])
AS_IF([test "x$LUAJITPC" != "x"], [
  # export all symbols to be able to use the Lua FFI interface
  AC_MSG_NOTICE([Adding -rdynamic to export all symbols for the Lua FFI interface])
  LDFLAGS="$LDFLAGS -rdynamic"
])
PDNS_CHECK_LUA_HPP

PDNS_ENABLE_VERBOSE_LOGGING

# Crypto libraries
PDNS_ENABLE_BOTAN
PDNS_CHECK_LIBCRYPTO([
],[
   AC_MSG_ERROR([OpenSSL/libcrypto not found])
  ]
)
PDNS_CHECK_LIBCRYPTO_ECDSA
PDNS_CHECK_LIBSODIUM
PDNS_CHECK_LIBDECAF

PDNS_WITH_NET_SNMP

# check for tools we might need
PDNS_CHECK_RAGEL([pdns/dnslabeltext.cc], [www.powerdns.com])
PDNS_CHECK_CURL

AC_CHECK_FUNCS([strcasestr])

PDNS_CHECK_PTHREAD_NP

AC_SUBST([socketdir])
socketdir="/var/run"
AC_ARG_WITH([socketdir],
  [AS_HELP_STRING([--with-socketdir], [where the controlsocket lives @<:@default=/var/run@:>@])],
  [socketdir="$withval"]
)

AC_MSG_CHECKING([whether we will enable compiler security checks])
AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--disable-hardening], [disable compiler security checks @<:@default=no@:>@])],
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
PDNS_ENABLE_VALGRIND
AX_AVAILABLE_SYSTEMD
AM_CONDITIONAL([HAVE_SYSTEMD], [ test x"$systemd" = "xy" ])
PDNS_CHECK_VIRTUALENV

AC_SUBST(LIBS)

AC_SUBST([AM_CPPFLAGS],
  ["AS_ESCAPE([-I$(top_builddir) -I$(top_srcdir)]) $THREADFLAGS $BOOST_CPPFLAGS"]
)

AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['$(top_builddir)/ext/yahttp/yahttp/libyahttp.la'])

LDFLAGS="$RELRO_LDFLAGS $LDFLAGS"
CFLAGS="$PIE_CFLAGS $CFLAGS"
CXXFLAGS="$SANITIZER_FLAGS $PIE_CFLAGS $CXXFLAGS"
PROGRAM_LDFLAGS="$PIE_LDFLAGS $PROGRAM_LDFLAGS"
AC_SUBST([PROGRAM_LDFLAGS])

AC_CONFIG_FILES([Makefile
	ext/Makefile
	ext/json11/Makefile
	ext/yahttp/Makefile
	ext/yahttp/yahttp/Makefile])

AC_OUTPUT

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AS_IF([test "x$pdns_configure_args" != "x"],
  [summary_conf_opts=$pdns_configure_args],
  [summary_conf_opts="(no options)"]
)
AC_MSG_NOTICE([PowerDNS Recursor configured with: $summary_conf_opts])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([CC: $CC])
AC_MSG_NOTICE([CXX: $CXX])
AC_MSG_NOTICE([LD: $LD])
AC_MSG_NOTICE([CFLAGS: $CFLAGS])
AC_MSG_NOTICE([CPPFLAGS: $CPPFLAGS])
AC_MSG_NOTICE([CXXFLAGS: $CXXFLAGS])
AC_MSG_NOTICE([LDFLAGS: $LDFLAGS])
AC_MSG_NOTICE([LIBS: $LIBS])
AC_MSG_NOTICE([BOOST_CPPFLAGS: $BOOST_CPPFLAGS])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Features enabled])
AC_MSG_NOTICE([----------------])
AS_IF([test "x$LUAPC" != "x"],
  [AC_MSG_NOTICE([Lua: $LUAPC])],
  [AS_IF([test "x$LUAJITPC" != "x"],
    [AC_MSG_NOTICE([LuaJit: $LUAJITPC])],
    [AC_MSG_NOTICE([Lua/LuaJit: no])])
])
AC_MSG_NOTICE([OpenSSL ECDSA: $libcrypto_ecdsa])
AS_IF([test "x$LIBSODIUM_LIBS" != "x"],
  [AC_MSG_NOTICE([libsodium ed25519: yes])],
  [AC_MSG_NOTICE([libsodium ed25519: no])]
)
AS_IF([test "x$LIBDECAF_LIBS" != "x"],
  [AC_MSG_NOTICE([libdecaf ed25519 and ed448: yes])],
  [AC_MSG_NOTICE([libdecaf ed25519 and ed448: no])]
)
AS_IF([test "x$BOTAN_LIBS" != "x"],
  [AC_MSG_NOTICE([Botan gost: yes])],
  [AC_MSG_NOTICE([Botan gost: no])]
)
AS_IF([test "x$PROTOBUF_LIBS" != "x" -a x"$PROTOC" != "x"],
  [AC_MSG_NOTICE([Protobuf: yes])],
  [AC_MSG_NOTICE([Protobuf: no])]
)
AS_IF([test "x$NET_SNMP_LIBS" != "x"],
  [AC_MSG_NOTICE([SNMP: yes])],
  [AC_MSG_NOTICE([SNMP: no])]
)
AS_IF([test "x$systemd" != "xn"],
  [AC_MSG_NOTICE([systemd: yes])],
  [AC_MSG_NOTICE([systemd: no])]
)
AC_MSG_NOTICE([Context library: $pdns_context_library])
AC_MSG_NOTICE([])
