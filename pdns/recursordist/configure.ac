AC_PREREQ([2.69])

AC_INIT([pdns-recursor], m4_esyscmd(build-aux/gen-version))
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip tar-ustar -Wno-portability subdir-objects parallel-tests 1.11])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([pdns_recursor.cc])
AC_CONFIG_MACRO_DIR([m4])

AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST
# Add some default CFLAGS and CXXFLAGS, can be appended to using the environment variables
CFLAGS="-Wall -Wextra -Wshadow -Wmissing-declarations -Wredundant-decls -fvisibility=hidden -g -O2 $CFLAGS"
CXXFLAGS="-Wall -Wextra -Wshadow -Wmissing-declarations -Wredundant-decls -fvisibility=hidden -g -O2 $CXXFLAGS"

AC_SUBST([pdns_configure_args],["$ac_configure_args"])
AC_DEFINE_UNQUOTED([PDNS_CONFIG_ARGS],
  ["$pdns_configure_args"],
  [pdns-recursor configure arguments]
)

AC_PROG_CC
AC_PROG_CXX
AC_LANG([C++])

PDNS_CHECK_TIME_T

CPPFLAGS="-DRECURSOR $CPPFLAGS"

# Warn when pkg.m4 is missing
m4_pattern_forbid([^_?PKG_[A-Z_]+$], [*** pkg.m4 missing, please install pkg-config])

AX_CXX_COMPILE_STDCXX_20([ext], [mandatory])
PDNS_CHECK_CARGO([1.64])

# Rust runtime used dlopen from its static lib
LT_INIT([dlopen])
AC_SUBST([LIBDL], [$lt_cv_dlopen_libs])

PDNS_CHECK_OS
PDNS_CHECK_NETWORK_LIBS
AC_SEARCH_LIBS([res_query], [resolv], [], [AC_SEARCH_LIBS([__res_query], [resolv])])
# macOS uses an alternative name internally
AC_SEARCH_LIBS([res_9_query], [resolv])
PTHREAD_SET_NAME
AC_FUNC_STRERROR_R

PDNS_CHECK_CLOCK_GETTIME

BOOST_REQUIRE([1.54])
BOOST_CONTEXT([], [yes])

PDNS_ENABLE_UNIT_TESTS
PDNS_ENABLE_REPRODUCIBLE
PDNS_ENABLE_COVERAGE

PDNS_WITH_LUA
AS_IF([test "x$LUAPC" = "xluajit"], [
  # export all symbols to be able to use the Lua FFI interface
  AC_MSG_NOTICE([Adding -rdynamic to export all symbols for the Lua FFI interface])
  LDFLAGS="$LDFLAGS -rdynamic"
])

PDNS_CHECK_LUA_HPP

PDNS_ENABLE_VERBOSE_LOGGING

# Crypto libraries
PDNS_CHECK_LIBCRYPTO([
],[
   AC_MSG_ERROR([OpenSSL/libcrypto not found])
  ]
)
PDNS_CHECK_LIBCRYPTO_ECDSA
PDNS_CHECK_LIBCRYPTO_EDDSA
PDNS_WITH_LIBSODIUM
PDNS_WITH_LIBCAP
PDNS_CHECK_LIBCURL

PDNS_WITH_NET_SNMP

# not runtime selectable at the moment
#AM_CONDITIONAL([HAVE_GNUTLS], [false])
AM_CONDITIONAL([HAVE_LIBSSL], [false])

PDNS_ENABLE_DNS_OVER_TLS

AS_IF([test "x$enable_dns_over_tls" != "xno"], [
  PDNS_WITH_LIBSSL
  # not runtime selectable at the moment
  # PDNS_WITH_GNUTLS

  AS_IF([test "x$HAVE_LIBSSL" != "x1"], [
    AC_MSG_ERROR([DNS over TLS support requested but no OpenSSL available])
  ])
])

# check for tools we might need
PDNS_CHECK_RAGEL([pdns/dnslabeltext.cc], [www.powerdns.com])
PDNS_CHECK_CURL

dnl the *_r functions are in posix so we can use them unconditionally, but the ext/yahttp code is
dnl using the defines.
AC_CHECK_FUNCS_ONCE([localtime_r gmtime_r])
AC_CHECK_FUNCS_ONCE([getrandom getentropy arc4random arc4random_uniform arc4random_buf])
PDNS_CHECK_SECURE_MEMSET

AC_CHECK_HEADERS([sys/random.h])

PDNS_CHECK_PTHREAD_NP

AC_SUBST([socketdir])
socketdir="/var/run"
AC_ARG_WITH([socketdir],
  [AS_HELP_STRING([--with-socketdir], [where the controlsocket lives @<:@default=/var/run@:>@])],
  [socketdir="$withval"]
)

PDNS_ENABLE_NOD

AC_SUBST([nodcachedir])
nodcachedir='${localstatedir}/lib/pdns-recursor'
AC_ARG_WITH([nod-cache-dir],
  [AS_HELP_STRING([--with-nodcachedir], [where newly observed domain cache files live @<:@default=LOCALSTATEDIR/lib/pdns-recursor@:>@])],
  [nodcachedir="$withval"]
)

PDNS_CHECK_DNSTAP([auto])

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

PDNS_INIT_AUTO_VARS
PDNS_ENABLE_SANITIZERS
PDNS_ENABLE_LTO
PDNS_ENABLE_MALLOC_TRACE
PDNS_ENABLE_VALGRIND

AX_AVAILABLE_SYSTEMD
AX_CHECK_SYSTEMD_FEATURES
AM_CONDITIONAL([HAVE_SYSTEMD], [ test x"$systemd" = "xy" ])
PDNS_WITH_SERVICE_USER([pdns-recursor])

PDNS_CHECK_PYTHON_VENV

AM_CONDITIONAL([HAVE_MANPAGES], [test -e "$srcdir/pdns_recursor.1"])
AM_COND_IF([HAVE_MANPAGES],[],[
  AM_COND_IF([HAVE_VENV],[],[
    AC_MSG_WARN([Python 3 and/or venv module are not available, documentation will not be built.])
  ])
])

AC_SUBST(LIBS)

AC_SUBST([AM_CPPFLAGS],
  ["AS_ESCAPE([-I$(top_builddir) -I$(top_srcdir)]) $THREADFLAGS $BOOST_CPPFLAGS"]
)

AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['$(top_builddir)/ext/yahttp/yahttp/libyahttp.la'])

LDFLAGS="$RELRO_LDFLAGS $LDFLAGS"
CFLAGS="$SANITIZER_FLAGS $PIE_CFLAGS $CFLAGS"
CXXFLAGS="$SANITIZER_FLAGS $PIE_CFLAGS $CXXFLAGS"
PROGRAM_LDFLAGS="$PIE_LDFLAGS $PROGRAM_LDFLAGS"
AC_SUBST([PROGRAM_LDFLAGS])

CCVERSION=`$CC --version | head -1`
CXXVERSION=`$CXX --version | head -1`

AC_CONFIG_FILES([Makefile
	ext/Makefile
	ext/arc4random/Makefile
	ext/json11/Makefile
	ext/probds/Makefile
	ext/yahttp/Makefile
	ext/yahttp/yahttp/Makefile
	rec-rust-lib/Makefile
	rec-rust-lib/rust/Makefile])

AC_OUTPUT

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AS_IF([test "x$pdns_configure_args" != "x"],
  [summary_conf_opts=$pdns_configure_args],
  [summary_conf_opts="(no options)"]
)
AC_MSG_NOTICE([PowerDNS Recursor $VERSION configured with: $summary_conf_opts])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([CC: $CC ($CCVERSION)])
AC_MSG_NOTICE([CXX: $CXX ($CXXVERSION)])
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
AC_MSG_NOTICE([Lua: $LUAPC])
AC_MSG_NOTICE([OpenSSL ECDSA: $libcrypto_ecdsa])
AS_IF([test "x$LIBSODIUM_LIBS" != "x" || test "x$libcrypto_ed25519" = "xyes"],
  [AC_MSG_NOTICE([ed25519: yes])],
  [AC_MSG_NOTICE([ed25519: no])]
)
AS_IF([test "x$libcrypto_ed448" = "xyes"],
  [AC_MSG_NOTICE([ed448: yes])],
  [AC_MSG_NOTICE([ed448: no])]
)

AC_MSG_NOTICE([Protobuf: yes])

AS_IF([test "x$NET_SNMP_LIBS" != "x"],
  [AC_MSG_NOTICE([SNMP: yes])],
  [AC_MSG_NOTICE([SNMP: no])]
)
AS_IF([test "x$systemd" != "xn"],
  [AC_MSG_NOTICE([systemd: yes])],
  [AC_MSG_NOTICE([systemd: no])]
)
AM_COND_IF([NOD_ENABLED],
  [AC_MSG_NOTICE([nod: yes])],
  [AC_MSG_NOTICE([nod: no])]
)
AM_COND_IF([FSTRM],
  [AC_MSG_NOTICE([dnstap: yes])],
  [AC_MSG_NOTICE([dnstap: no])]
)
AS_IF([test "x$enable_dns_over_tls" != "xno"],
  [AC_MSG_NOTICE([DNS over TLS: yes])],
  [AC_MSG_NOTICE([DNS over TLS: no])]
)
#AS_IF([test "x$enable_dns_over_tls" != "xno"], [
#  AS_IF([test "x$GNUTLS_LIBS" != "x"],
#    [AC_MSG_NOTICE([GnuTLS: yes])],
#    [AC_MSG_NOTICE([GnuTLS: no])]
#  )]
#)
AS_IF([test "x$enable_dns_over_tls" != "xno"], [
  AS_IF([test "x$LIBSSL_LIBS" != "x"],
    [AC_MSG_NOTICE([OpenSSL: yes])],
    [AC_MSG_NOTICE([OpenSSL: no])]
  )]
)
AS_IF([test "x$HAVE_LIBCURL" != "xn"],
  [AC_MSG_NOTICE([libcurl: yes])],
  [AC_MSG_NOTICE([libcurl: no])]
)
AC_MSG_NOTICE([])
