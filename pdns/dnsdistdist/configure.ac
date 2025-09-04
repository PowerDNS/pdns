AC_PREREQ([2.69])

AC_INIT([dnsdist], m4_esyscmd(build-aux/gen-version))
AM_INIT_AUTOMAKE([foreign tar-ustar dist-bzip2 no-dist-gzip parallel-tests 1.11 subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_CXX
AC_LANG([C++])

CPPFLAGS="-DDNSDIST $CPPFLAGS"

# Warn when pkg.m4 is missing
m4_pattern_forbid([^_?PKG_[A-Z_]+$], [*** pkg.m4 missing, please install pkg-config])

LT_PREREQ([2.2.2])
# Rust runtime uses dlopen from its static lib
LT_INIT([disable-static dlopen])
AC_SUBST([LIBDL], [$lt_cv_dlopen_libs])

CFLAGS="-g -O3 -Wall -Wextra -Wshadow -fvisibility=hidden $CFLAGS"
CXXFLAGS="-g -O3 -Wall -Wextra -Wshadow -Wmissing-declarations -Wredundant-decls -fvisibility=hidden $CXXFLAGS"

AC_SUBST([pdns_configure_args], ["$ac_configure_args"])
AC_DEFINE_UNQUOTED([DNSDIST_CONFIG_ARGS],
  ["$pdns_configure_args"],
  [pdns configure arguments]
)

PDNS_WITH_LIBSODIUM
PDNS_WITH_QUICHE
PDNS_CHECK_DNSTAP([auto])
PDNS_CHECK_RAGEL([dnslabeltext.cc], [www.dnsdist.org])
PDNS_WITH_LIBEDIT
PDNS_CHECK_CLOCK_GETTIME

PDNS_CHECK_OS
PTHREAD_SET_NAME
PDNS_CHECK_NETWORK_LIBS
PDNS_CHECK_PTHREAD_NP
PDNS_CHECK_SECURE_MEMSET
AC_FUNC_STRERROR_R

BOOST_REQUIRE([1.54])

PDNS_ENABLE_UNIT_TESTS
PDNS_ENABLE_FUZZ_TARGETS
PDNS_WITH_RE2
DNSDIST_ENABLE_DNSCRYPT
PDNS_WITH_EBPF
PDNS_WITH_XSK
PDNS_WITH_NET_SNMP
PDNS_WITH_LIBCAP

AX_AVAILABLE_SYSTEMD
AX_CHECK_SYSTEMD_FEATURES
AM_CONDITIONAL([HAVE_SYSTEMD], [ test x"$systemd" = "xy" ])
PDNS_WITH_SERVICE_USER([dnsdist])

dnl the *_r functions are in posix so we can use them unconditionally, but the ext/yahttp code is
dnl using the defines.
AC_CHECK_FUNCS_ONCE([localtime_r gmtime_r])
AC_CHECK_FUNCS_ONCE([getrandom getentropy arc4random arc4random_uniform arc4random_buf])
AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['$(top_builddir)/ext/yahttp/yahttp/libyahttp.la'])
AC_SUBST([IPCRYPT_CFLAGS], ['-I$(top_srcdir)/ext/ipcrypt'])
AC_SUBST([IPCRYPT_LIBS], ['$(top_builddir)/ext/ipcrypt/libipcrypt.la'])
AC_SUBST([IPCRYPT2_CFLAGS], ['-I$(top_srcdir)/ext/ipcrypt2/include'])
AC_SUBST([IPCRYPT2_LIBS], ['$(top_builddir)/ext/ipcrypt2/libipcrypt2.la'])
AC_SUBST([ARC4RANDOM_LIBS], ['$(top_builddir)/ext/arc4random/libarc4random.la'])

AC_CHECK_HEADERS([sys/random.h])

PDNS_WITH_LUA
AS_IF([test "x$LUAPC" = "xluajit"], [
  # export all symbols with default visibility, to be able to use the Lua FFI interface
  AC_MSG_NOTICE([Adding -rdynamic to export all symbols for the Lua FFI interface])
  LDFLAGS="$LDFLAGS -rdynamic"
])
PDNS_CHECK_LUA_HPP

AM_CONDITIONAL([HAVE_CDB], [false])
AM_CONDITIONAL([HAVE_GNUTLS], [false])
AM_CONDITIONAL([HAVE_LIBH2OEVLOOP], [false])
AM_CONDITIONAL([HAVE_LIBSSL], [false])
AM_CONDITIONAL([HAVE_LMDB], [false])
AM_CONDITIONAL([HAVE_NGHTTP2], [false])

PDNS_CHECK_LIBCRYPTO

DNSDIST_ENABLE_TLS_PROVIDERS

PDNS_ENABLE_DNS_OVER_TLS
DNSDIST_ENABLE_DNS_OVER_HTTPS
DNSDIST_ENABLE_DNS_OVER_QUIC
DNSDIST_ENABLE_DNS_OVER_HTTP3

AS_IF([test "x$enable_dns_over_tls" != "xno" -o "x$enable_dns_over_https" != "xno" -o "x$enable_dns_over_quic" != "xno" ], [
  PDNS_WITH_LIBSSL
  AS_IF([test "x$enable_dns_over_tls" != "xno" -o "x$enable_dns_over_https" != "xno"], [
    PDNS_WITH_GNUTLS
  ])
])

AS_IF([test "x$enable_dns_over_tls" != "xno"], [
  AS_IF([test "x$HAVE_GNUTLS" != "x1" -a "x$HAVE_LIBSSL" != "x1"], [
    AC_MSG_ERROR([DNS over TLS support requested but neither GnuTLS nor OpenSSL are available])
  ])
])

AS_IF([test "x$enable_dns_over_https" != "xno"], [
  PDNS_WITH_NGHTTP2
  PDNS_WITH_LIBH2OEVLOOP

  AS_IF([test "x$HAVE_LIBH2OEVLOOP" != "x1" -a "x$HAVE_NGHTTP2" != "x1" ], [
    AC_MSG_ERROR([DNS over HTTPS support requested but neither libh2o-evloop nor nghttp2 was not found])
  ])

  AS_IF([test "x$HAVE_GNUTLS" != "x1" -a "x$HAVE_LIBSSL" != "x1"], [
    AC_MSG_ERROR([DNS over HTTPS support requested but neither GnuTLS nor OpenSSL are available])
  ])
])

AS_IF([test "x$enable_dns_over_quic" != "xno"], [
  AS_IF([test "x$HAVE_QUICHE" != "x1"], [
    AC_MSG_ERROR([DNS over QUIC support requested but quiche was not found])
  ])
  AS_IF([test "x$HAVE_LIBSSL" != "x1"], [
    AC_MSG_ERROR([DNS over QUIC support requested but OpenSSL is not available])
  ])
])

AS_IF([test "x$enable_dns_over_http3" != "xno"], [
  AS_IF([test "x$HAVE_QUICHE" != "x1"], [
    AC_MSG_ERROR([DNS over HTTP/3 support requested but quiche was not found])
  ])
])

DNSDIST_ENABLE_YAML

AS_IF([test "x$enable_yaml" != "xno"], [
  PDNS_CHECK_CARGO([1.64])
])

DNSDIST_WITH_CDB
PDNS_CHECK_LMDB
PDNS_ENABLE_IPCIPHER
PDNS_CHECK_AARCH64_UINT64X2_T

AX_CXX_COMPILE_STDCXX_20([noext], [mandatory])

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
PDNS_ENABLE_COVERAGE

PDNS_CHECK_PYTHON_VENV

AM_CONDITIONAL([HAVE_MANPAGES], [test -e "$srcdir/dnsdist.1"])
AM_COND_IF([HAVE_MANPAGES],[],[
  AM_COND_IF([HAVE_VENV],[],[
    AC_MSG_WARN([Python 3 and/or venv module are not available, documentation will not be built.])
  ])
])

LDFLAGS="$RELRO_LDFLAGS $LDFLAGS"

CFLAGS="$SANITIZER_FLAGS $PIE_CFLAGS $CFLAGS"
CXXFLAGS="$SANITIZER_FLAGS $PIE_CFLAGS $CXXFLAGS"

CCVERSION=`$CC --version | head -1`
CXXVERSION=`$CXX --version | head -1`

PROGRAM_LDFLAGS="$PIE_LDFLAGS $PROGRAM_LDFLAGS"
AC_SUBST([PROGRAM_LDFLAGS])

AC_SUBST([AM_CPPFLAGS],
  ["AS_ESCAPE([-I$(top_builddir) -I$(top_srcdir)]) $THREADFLAGS $BOOST_CPPFLAGS"]
)

AC_ARG_VAR(PACKAGEVERSION, [The version used in secpoll queries])
AS_IF([test "x$PACKAGEVERSION" != "x"],
  [AC_DEFINE_UNQUOTED([PACKAGEVERSION], "$PACKAGEVERSION", [Set to the package version used for secpoll])]
)

AC_CONFIG_FILES([Makefile
        dnsdist-rust-lib/Makefile
        dnsdist-rust-lib/rust/Makefile
        ext/arc4random/Makefile
        ext/yahttp/Makefile
        ext/yahttp/yahttp/Makefile
        ext/ipcrypt/Makefile
        ext/ipcrypt2/Makefile])

AC_OUTPUT

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AS_IF([test "x$ac_configure_args" != "x"],
  [summary_conf_opts=$ac_configure_args],
  [summary_conf_opts="(no options)"]
)
AC_MSG_NOTICE([dnsdist configured with: $summary_conf_opts])
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
AC_MSG_NOTICE([Protobuf: yes])
AS_IF([test "x$systemd" != "xn"],
  [AC_MSG_NOTICE([systemd: yes])],
  [AC_MSG_NOTICE([systemd: no])]
)
AS_IF([test x"$BPF_LIBS" != "x" -a x"$XDP_LIBS" != "x"],
  [AC_MSG_NOTICE([AF_XDP/XSK: yes])],
  [AC_MSG_NOTICE([AF_XDP/XSK: no])]
)
AS_IF([test "x$HAVE_IPCIPHER" = "x1"],
  [AC_MSG_NOTICE([ipcipher: yes])],
  [AC_MSG_NOTICE([ipcipher: no])]
)
AS_IF([test "x$LIBEDIT_LIBS" != "x"],
  [AC_MSG_NOTICE([libedit: yes])],
  [AC_MSG_NOTICE([libedit: no])]
)
AS_IF([test "x$LIBSODIUM_LIBS" != "x"],
  [AC_MSG_NOTICE([libsodium: yes])],
  [AC_MSG_NOTICE([libsodium: no])]
)
AS_IF([test "x$enable_dnscrypt" != "xno"],
  [AC_MSG_NOTICE([DNSCrypt: yes])],
  [AC_MSG_NOTICE([DNSCrypt: no])]
)
AS_IF([test "x$FSTRM_LIBS" != "x"],
  [AC_MSG_NOTICE([dnstap: yes])],
  [AC_MSG_NOTICE([dnstap: no])]
)
AS_IF([test "x$QUICHE_LIBS" != "x"],
  [AC_MSG_NOTICE([quiche: yes])],
  [AC_MSG_NOTICE([quiche: no])]
)
AS_IF([test "x$RE2_LIBS" != "x"],
  [AC_MSG_NOTICE([re2: yes])],
  [AC_MSG_NOTICE([re2: no])]
)
AS_IF([test "x$NET_SNMP_LIBS" != "x"],
  [AC_MSG_NOTICE([SNMP: yes])],
  [AC_MSG_NOTICE([SNMP: no])]
)
AS_IF([test "x$enable_dns_over_tls" != "xno"],
  [AC_MSG_NOTICE([DNS over TLS: yes])],
  [AC_MSG_NOTICE([DNS over TLS: no])]
)
AS_IF([test "x$enable_dns_over_https" != "xno"],
  [AC_MSG_NOTICE([DNS over HTTPS (DoH): yes])],
  [AC_MSG_NOTICE([DNS over HTTPS (DoH): no])]
)
AS_IF([test "x$enable_dns_over_quic" != "xno"],
  [AC_MSG_NOTICE([DNS over QUIC (DoQ): yes])],
  [AC_MSG_NOTICE([DNS over QUIC (DoQ): no])]
)
AS_IF([test "x$enable_dns_over_http3" != "xno"],
  [AC_MSG_NOTICE([DNS over HTTP/3 (DoH3): yes])],
  [AC_MSG_NOTICE([DNS over HTTP/3 (DoH3): no])]
)
AS_IF([test "x$enable_dns_over_tls" != "xno"], [
  AS_IF([test "x$GNUTLS_LIBS" != "x"],
    [AC_MSG_NOTICE([GnuTLS: yes])],
    [AC_MSG_NOTICE([GnuTLS: no])]
  )]
)
AS_IF([test "x$enable_dns_over_tls" != "xno" -o "x$enable_dns_over_https" != "xno"], [
  AS_IF([test "x$LIBSSL_LIBS" != "x"],
    [AC_MSG_NOTICE([OpenSSL: yes])],
    [AC_MSG_NOTICE([OpenSSL: no])]
  )]
)
AS_IF([test "x$LIBH2OEVLOOP_LIBS" != "x"],
  [AC_MSG_NOTICE([h2o-evloop: yes])],
  [AC_MSG_NOTICE([h2o-evloop: no])]
)
AS_IF([test "x$NGHTTP2_LIBS" != "x"],
  [AC_MSG_NOTICE([nghttp2: yes])],
  [AC_MSG_NOTICE([nghttp2: no])]
)
AS_IF([test "x$CDB_LIBS" != "x"],
  [AC_MSG_NOTICE([cdb: yes])],
  [AC_MSG_NOTICE([cdb: no])]
)
AS_IF([test "x$LMDB_LIBS" != "x"],
  [AC_MSG_NOTICE([lmdb: yes])],
  [AC_MSG_NOTICE([lmdb: no])]
)
AS_IF([test "x$enable_yaml" != "xno"],
  [AC_MSG_NOTICE([YAML configuration: yes])],
  [AC_MSG_NOTICE([YAML configuration: no])]
)

AC_MSG_NOTICE([])
