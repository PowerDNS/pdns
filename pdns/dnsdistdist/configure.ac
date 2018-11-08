AC_PREREQ([2.61])

AC_INIT([dnsdist], m4_esyscmd(build-aux/gen-version))
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip parallel-tests 1.11 subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_CXX
AC_LANG([C++])
AC_GNU_SOURCE

AC_DEFINE([DNSDIST], [1],
  [This is dnsdist]
)

LT_PREREQ([2.2.2])
LT_INIT([disable-static])

PDNS_CHECK_LIBSODIUM
PDNS_CHECK_FSTRM
PDNS_CHECK_RAGEL([dnslabeltext.cc], [www.dnsdist.org])
PDNS_CHECK_LIBEDIT
PDNS_CHECK_CLOCK_GETTIME

PDNS_CHECK_OS
PTHREAD_SET_NAME
PDNS_CHECK_NETWORK_LIBS
PDNS_CHECK_PTHREAD_NP
PDNS_CHECK_SECURE_MEMSET


PDNS_WITH_PROTOBUF

boost_required_version=1.42
BOOST_REQUIRE([$boost_required_version])

PDNS_ENABLE_UNIT_TESTS
PDNS_CHECK_RE2
DNSDIST_ENABLE_DNSCRYPT
PDNS_WITH_EBPF
PDNS_WITH_NET_SNMP

AX_AVAILABLE_SYSTEMD
AM_CONDITIONAL([HAVE_SYSTEMD], [ test x"$systemd" = "xy" ])

AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['$(top_builddir)/ext/yahttp/yahttp/libyahttp.la'])

PDNS_WITH_LUA([mandatory])
PDNS_CHECK_LUA_HPP

DNSDIST_ENABLE_DNS_OVER_TLS
DNSDIST_CHECK_GNUTLS
DNSDIST_CHECK_LIBSSL
AS_IF([test "x$enable_dns_over_tls" != "xno"], [
  AS_IF([test "$HAVE_LIBSSL" = "1"], [
    # we need libcrypto if libssl is enabled
    PDNS_CHECK_LIBCRYPTO
  ])
  AS_IF([test "$HAVE_GNUTLS" = "0" -a "$HAVE_LIBSSL" = "0"], [
    AC_MSG_ERROR([DNS over TLS support requested but neither GnuTLS nor OpenSSL are available])
  ])
])

AX_CXX_COMPILE_STDCXX_11([ext], [mandatory])

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

PDNS_CHECK_VIRTUALENV

LDFLAGS="$RELRO_LDFLAGS $LDFLAGS"

CFLAGS="$PIE_CFLAGS $CFLAGS"
CXXFLAGS="$PIE_CFLAGS $CXXFLAGS"
PROGRAM_LDFLAGS="$PIE_LDFLAGS $PROGRAM_LDFLAGS"
AC_SUBST([PROGRAM_LDFLAGS])

AC_SUBST([AM_CPPFLAGS],
  ["AS_ESCAPE([-I$(top_builddir) -I$(top_srcdir)]) -Wall -O3 -pthread $BOOST_CPPFLAGS"]
)

AC_ARG_VAR(PACKAGEVERSION, [The version used in secpoll queries])
AS_IF([test "x$PACKAGEVERSION" != "x"],
  [AC_DEFINE_UNQUOTED([PACKAGEVERSION], "$PACKAGEVERSION", [Set to the package version used for secpoll])]
)

AC_CONFIG_FILES([Makefile
	ext/yahttp/Makefile
	ext/yahttp/yahttp/Makefile])

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
AC_MSG_NOTICE([Lua: $LUAPC])
AS_IF([test "x$PROTOBUF_LIBS" != "x" -a x"$PROTOC" != "x"],
  [AC_MSG_NOTICE([Protobuf: yes])],
  [AC_MSG_NOTICE([Protobuf: no])]
)
AS_IF([test "x$systemd" != "xn"],
  [AC_MSG_NOTICE([systemd: yes])],
  [AC_MSG_NOTICE([systemd: no])]
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
  [AC_MSG_NOTICE([fstrm: yes])],
  [AC_MSG_NOTICE([fstrm: no])]
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
AS_IF([test "x$GNUTLS_LIBS" != "x"],
  [AC_MSG_NOTICE([GnuTLS: yes])],
  [AC_MSG_NOTICE([GnuTLS: no])]
)
AS_IF([test "x$LIBSSL_LIBS" != "x"],
  [AC_MSG_NOTICE([OpenSSL: yes])],
  [AC_MSG_NOTICE([OpenSSL: no])]
)
AC_MSG_NOTICE([])
