AC_PREREQ([2.69])

AC_INIT([pdns], m4_esyscmd([builder-support/gen-version]))
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip tar-ustar -Wno-portability subdir-objects parallel-tests 1.11])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([pdns/auth-main.cc])
AC_CONFIG_MACRO_DIR([m4])

AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST
# Add some default CFLAGS and CXXFLAGS, can be appended to using the environment variables
CFLAGS="-g -O2 -Wall -Wextra -Wshadow -Wmissing-declarations -Wredundant-decls $CFLAGS"
CXXFLAGS="-g -O2 -Wall -Wextra -Wshadow -Wmissing-declarations -Wredundant-decls $CXXFLAGS"

AC_SUBST([pdns_configure_args], ["$ac_configure_args"])
AC_DEFINE_UNQUOTED([PDNS_CONFIG_ARGS],
  ["$pdns_configure_args"],
  [pdns configure arguments]
)

AC_PROG_CC
# AM_PROG_CC_C_O
AC_PROG_CXX
AC_LANG([C++])

CPPFLAGS="-DPDNS_AUTH $CPPFLAGS"

PDNS_CHECK_TIME_T
PDNS_CHECK_BISON
PDNS_CHECK_FLEX

# Warn when pkg.m4 is missing
m4_pattern_forbid([^_?PKG_[A-Z_]+$], [*** pkg.m4 missing, please install pkg-config])

AX_CXX_COMPILE_STDCXX_20([noext], [mandatory])
LT_PREREQ([2.2.2])
LT_INIT([disable-static dlopen])

PDNS_CHECK_OS
PTHREAD_SET_NAME
AC_FUNC_STRERROR_R
AX_CXX_CXXFS

PDNS_WITH_LUA
PDNS_CHECK_LUA_HPP

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

PDNS_ENABLE_KISS

PDNS_CHECK_NETWORK_LIBS


MC_TM_GMTOFF

# Define full_libdir to be the fully expanded (${exec_prefix}, etc.)
# "system" library path.
# We use this to search for other libraries.
eval full_libdir="\"$libdir\""

# detect pkg-config explicitly
PKG_PROG_PKG_CONFIG

AC_CHECK_HEADERS(
	[sys/mman.h],
	[AC_CHECK_FUNC(
		[mmap],
		[AC_DEFINE(HAVE_MMAP, [1], [Define to 1 if you have mmap])],
		[have_mmap=no]
	)],
	[have_mmap=no]
)
AC_CHECK_HEADERS([sys/random.h])

PDNS_WITH_LIBSODIUM
PDNS_CHECK_LIBCRYPTO([
],[
   AC_MSG_ERROR([OpenSSL/libcrypto not found])
  ]
)
PDNS_CHECK_LIBCRYPTO_ECDSA
PDNS_CHECK_LIBCRYPTO_EDDSA

AM_CONDITIONAL([HAVE_GNUTLS], [false])
AM_CONDITIONAL([HAVE_LIBSSL], [false])

PDNS_ENABLE_DNS_OVER_TLS
AS_IF([test "x$enable_dns_over_tls" != "xno"], [
  PDNS_WITH_LIBSSL
  PDNS_WITH_GNUTLS
  AS_IF([test "x$HAVE_GNUTLS" != "x1" -a "x$HAVE_LIBSSL" != "x1"], [
    AC_MSG_ERROR([DNS over TLS support requested but neither GnuTLS nor OpenSSL are available])
  ])
])

PDNS_ENABLE_IPCIPHER

PDNS_CHECK_RAGEL([pdns/dnslabeltext.cc], [www.powerdns.com])
PDNS_CHECK_CLOCK_GETTIME

BOOST_REQUIRE([1.54])

BOOST_PROGRAM_OPTIONS([mt])
AS_IF([test "$boost_cv_lib_program_options" = "no"], [
  AC_MSG_ERROR([Boost Program Options library not found])
])
PDNS_ENABLE_UNIT_TESTS
PDNS_ENABLE_BACKEND_UNIT_TESTS
PDNS_ENABLE_REPRODUCIBLE
PDNS_ENABLE_FUZZ_TARGETS
PDNS_ENABLE_COVERAGE

PDNS_WITH_SQLITE3

PDNS_CHECK_PYTHON_VENV

AM_CONDITIONAL([HAVE_API_SWAGGER_JSON], [test -e "$srcdir/pdns/api-swagger.json"])
AM_COND_IF([HAVE_API_SWAGGER_JSON],[],[
  AM_COND_IF([HAVE_VENV],[],[
    AC_MSG_ERROR([Python 3 and/or venv module are not available, Authoritative Server cannot be built.])
  ])
])

AM_CONDITIONAL([HAVE_MANPAGES], [test -e "$srcdir/docs/pdns_server.1"])
AM_COND_IF([HAVE_MANPAGES],[],[
  AM_COND_IF([HAVE_VENV],[],[
    AC_MSG_WARN([Python 3 and/or venv module are not available, documentation will not be built.])
  ])
])

PDNS_FROM_GIT

dnl Checks for library functions.
dnl the *_r functions are in posix so we can use them unconditionally, but the ext/yahttp code is
dnl using the defines.
AC_CHECK_FUNCS_ONCE([localtime_r gmtime_r recvmmsg sched_setscheduler])
AC_CHECK_FUNCS_ONCE([getrandom getentropy arc4random arc4random_uniform arc4random_buf])
PDNS_CHECK_SECURE_MEMSET

AM_CONDITIONAL([HAVE_RECVMMSG], [test "x$ac_cv_func_recvmmsg" = "xyes"])

AS_IF([test "x$lt_cv_dlopen" = "xno"],
  [AC_MSG_ERROR([Your system does not support dlopen])]
)

AC_SUBST([LIBDL], [$lt_cv_dlopen_libs])

PDNS_ENABLE_VERBOSE_LOGGING
PDNS_ENABLE_PKCS11
PDNS_ENABLE_GSS_TSIG

AC_SUBST([socketdir])
socketdir="/var/run"
AC_ARG_WITH([socketdir],
  [AS_HELP_STRING([--with-socketdir], [where the controlsocket lives @<:@default=/var/run@:>@])],
  [socketdir="$withval"]
)

modules="bind gmysql"
AC_ARG_WITH([modules],
  [AS_HELP_STRING([--with-modules], [which backends to compile with @<:@default=bind gmysql@:>@])],
  [modules="$withval"]
)

dynmodules="pipe"
AC_ARG_WITH([dynmodules],
  [AS_HELP_STRING([--with-dynmodules], [which backends to build for dynamic loading @<:@default=pipe@:>@])],
  [dynmodules="$withval"]
)

AC_SUBST([moduledirs])
AC_SUBST([moduleobjects])
AC_SUBST([modulelibs])
AC_DEFINE_UNQUOTED([PDNS_MODULES], "$modules", [Built-in modules])

AS_IF([test x"$modules" = "xno"], [modules=""])
AS_IF([test x"$dynmodules" = "xno"], [dynmodules=""])

for a in $modules $dynmodules; do
  case "$a" in
    godbc)
      PDNS_WITH_UNIXODBC
      ;;
    gmysql)
      PDNS_WITH_MYSQL
      ;;
    gpgsql)
      PDNS_WITH_POSTGRESQL
      ;;
    gsqlite3)
      needsqlite3=yes
      ;;
    ldap)
      PDNS_CHECK_LDAP
      needldap=yes
      ;;
    remote)
      AS_IF([test "x$enable_unit_tests" = "xyes"],
        [PDNS_CHECK_CURL_PROGRAM]
      )
      have_remotebackend=yes
      ;;
    tinydns)
      needcdb=yes
      PDNS_CHECK_CDB
      ;;
    geoip)
      PDNS_CHECK_GEOIP
      ;;
    lua*)
      dnl Lua has been checked above
      ;;
    lmdb)
      needlmdb=yes
      PDNS_CHECK_LMDB
      BOOST_SERIALIZATION
      ;;
  esac
done

PDNS_ENABLE_REMOTEBACKEND_ZEROMQ

PDNS_ENABLE_TOOLS
PDNS_ENABLE_IXFRDIST

PDNS_WITH_LUA_RECORDS

AM_CONDITIONAL([LDAP], [test "x$needldap" = "xyes"])

PDNS_CHECK_SQLITE3
AM_CONDITIONAL([SQLITE3], [test "x$needsqlite3" = "xyes"])

AM_CONDITIONAL([LMDB], [test "x$needlmdb" != "x"])
AM_CONDITIONAL([HAVE_LMDB], [test "x$LMDB_LIBS" != "x"])

AS_IF([test "x$needlmdb" = "xyes"], [
  AS_IF([test "$with_lmdb" = "no"], [
    AC_MSG_ERROR([--with-lmdb is set to 'no', but lmdb support is required])
  ])
  AS_IF([test "x$HAVE_LMDB" != "x1"], [
    AC_MSG_ERROR([lmdb not found via pkg-config, please install lmdb or set --with-lmdb to your lmdb installation directory])
  ])
])

AM_CONDITIONAL([CDB], [test "x$needcdb" != "x"])
AM_CONDITIONAL([HAVE_CDB], [test "x$CDB_LIBS" != "x"])

AS_IF([test "x$needcdb" = "xyes"], [
  AS_IF([test "x$HAVE_CDB" != "x1"], [
    AC_MSG_ERROR([cdb not found via pkg-config, please install cdb])
  ])
])

for a in $modules; do
  AC_MSG_CHECKING([whether we can build module "${a}"])
  if [[ -d "$srcdir/modules/${a}backend" ]]; then
    AC_MSG_RESULT([yes])
    moduledirs="$moduledirs ${a}backend"

    for b in `cat $srcdir/modules/${a}backend/OBJECTFILES`; do
      moduleobjects="$moduleobjects ../modules/${a}backend/$b"
    done
    modulelibs="$modulelibs `cat $srcdir/modules/${a}backend/OBJECTLIBS`"
  else
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([Do not know how to build module "$a", "$srcdir/modules/${a}backend" does not exist! Please review --with-modules parameter for supported values.])
  fi
done

for a in $dynmodules; do
  AC_MSG_CHECKING([whether we can build dynamic module "${a}"])
  if [[ -d "$srcdir/modules/${a}backend" ]]; then
    AC_MSG_RESULT([yes])
    moduledirs="$moduledirs ${a}backend"
  else
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([Do not know how to build module "$a", "$srcdir/modules/${a}backend" does not exist! Please review --with-dynmodules parameter for supported values.])
  fi
done

AX_AVAILABLE_SYSTEMD
AX_CHECK_SYSTEMD_FEATURES
AM_CONDITIONAL([HAVE_SYSTEMD], [ test x"$systemd" = "xy" ])
 PDNS_WITH_SERVICE_USER([pdns])

LDFLAGS="$RELRO_LDFLAGS $LDFLAGS"

CFLAGS="$PIE_CFLAGS $CFLAGS"
CXXFLAGS="$PIE_CFLAGS $CXXFLAGS"
AS_IF([test "$ax_cxx_cv_filesystem_lib" != "none"],
 [CXXFS_LIBS="-l$ax_cxx_cv_filesystem_lib"],
 []
)
AC_SUBST([CXXFS_LIBS])
PROGRAM_LDFLAGS="$PIE_LDFLAGS $PROGRAM_LDFLAGS $CXXFS_LIBS"
AC_SUBST([PROGRAM_LDFLAGS])

PDNS_ENABLE_COVERAGE
PDNS_INIT_AUTO_VARS
PDNS_ENABLE_SANITIZERS
PDNS_ENABLE_MALLOC_TRACE
PDNS_ENABLE_LTO

AC_SUBST(LIBS)

AC_SUBST([AM_CPPFLAGS],
  ["AS_ESCAPE([-I$(top_builddir) -I$(top_srcdir)]) $THREADFLAGS $BOOST_CPPFLAGS"]
)

AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['$(top_builddir)/ext/yahttp/yahttp/libyahttp.la'])
AC_SUBST([IPCRYPT_CFLAGS], ['-I$(top_srcdir)/ext/ipcrypt'])
AC_SUBST([IPCRYPT_LIBS], ['$(top_builddir)/ext/ipcrypt/libipcrypt.la'])

CFLAGS="$SANITIZER_FLAGS $CFLAGS"
CXXFLAGS="$SANITIZER_FLAGS $CXXFLAGS"

CCVERSION=`$CC --version | head -1`
CXXVERSION=`$CXX --version | head -1`

AC_ARG_VAR(PACKAGEVERSION, [The version used in secpoll queries])
AS_IF([test "x$PACKAGEVERSION" != "x"],
  [AC_DEFINE_UNQUOTED([PACKAGEVERSION], "$PACKAGEVERSION", [Set to the package version used for secpoll])]
)

export moduledirs moduleobjects modulelibs

AM_CONDITIONAL([BINDBACKEND_DYNMODULE],     [echo $dynmodules | grep -w bind])
AM_CONDITIONAL([GEOIPBACKEND_DYNMODULE],    [echo $dynmodules | grep -w geoip])
AM_CONDITIONAL([GMYSQLBACKEND_DYNMODULE],   [echo $dynmodules | grep -w gmysql])
AM_CONDITIONAL([GODBCBACKEND_DYNMODULE],    [echo $dynmodules | grep -w godbc])
AM_CONDITIONAL([GPGSQLBACKEND_DYNMODULE],   [echo $dynmodules | grep -w gpgsql])
AM_CONDITIONAL([GSQLITE3BACKEND_DYNMODULE], [echo $dynmodules | grep -w gsqlite3])
AM_CONDITIONAL([LDAPBACKEND_DYNMODULE],     [echo $dynmodules | grep -w ldap])
AM_CONDITIONAL([LMDBBACKEND_DYNMODULE],     [echo $dynmodules | grep -w lmdb])
AM_CONDITIONAL([LUA2BACKEND_DYNMODULE],     [echo $dynmodules | grep -w lua2])
AM_CONDITIONAL([PIPEBACKEND_DYNMODULE],     [echo $dynmodules | grep -w pipe])
AM_CONDITIONAL([REMOTEBACKEND_DYNMODULE],   [echo $dynmodules | grep -w remote])
AM_CONDITIONAL([TINYDNSBACKEND_DYNMODULE],  [echo $dynmodules | grep -w tinydns])

AC_CONFIG_FILES([
  Makefile
  modules/Makefile
  pdns/Makefile
  codedocs/Makefile
  docs/Makefile
  ext/Makefile
  ext/arc4random/Makefile
  ext/ipcrypt/Makefile
  ext/yahttp/Makefile
  ext/yahttp/yahttp/Makefile
  ext/json11/Makefile
  modules/bindbackend/Makefile
  modules/geoipbackend/Makefile
  modules/gmysqlbackend/Makefile
  modules/godbcbackend/Makefile
  modules/gpgsqlbackend/Makefile
  modules/gsqlite3backend/Makefile
  modules/ldapbackend/Makefile
  modules/lmdbbackend/Makefile
  modules/lua2backend/Makefile
  modules/pipebackend/Makefile
  modules/remotebackend/Makefile
  modules/tinydnsbackend/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configured with: $pdns_configure_args])
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
AC_MSG_NOTICE([Extras enabled])
AC_MSG_NOTICE([--------------])
AS_IF([test "x$enable_tools" = "xyes"],
  [AC_MSG_NOTICE([Tools: yes])],
  [AC_MSG_NOTICE([Tools: no])]
)
AS_IF([test "x$enable_ixfrdist" = "xyes"],
  [AC_MSG_NOTICE([ixfrdist: yes])],
  [AC_MSG_NOTICE([ixfrdist: no])]
)
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Server Features enabled])
AC_MSG_NOTICE([-----------------------])
AC_MSG_NOTICE([Built-in modules: $modules])
AC_MSG_NOTICE([Dynamic modules: $dynmodules])
AC_MSG_NOTICE([])
AS_IF([test "x$libcrypto_ecdsa" = "xyes"],
  [AC_MSG_NOTICE([OpenSSL ecdsa: yes])],
  [AC_MSG_NOTICE([OpenSSL ecdsa: no])]
)
AS_IF([test "x$LIBSODIUM_LIBS" != "x" || test "x$libcrypto_ed25519" = "xyes"],
  [AC_MSG_NOTICE([ed25519: yes])],
  [AC_MSG_NOTICE([ed25519: no])]
)
AS_IF([test "x$libcrypto_ed448" = "xyes"],
  [AC_MSG_NOTICE([ed448: yes])],
  [AC_MSG_NOTICE([ed448: no])]
)
AS_IF([test "x$needsqlite3" != "x"],
  [AC_MSG_NOTICE([SQLite3: yes])],
  [AC_MSG_NOTICE([SQLite3: no])]
)
AS_IF([test "x$LUAPC" != "x"],
  [AC_MSG_NOTICE([Lua: $LUAPC])],
  [AS_IF([test "x$LUAJITPC" != "x"],
    [AC_MSG_NOTICE([LuaJit: $LUAJITPC])],
    [AC_MSG_NOTICE([Lua/LuaJit: no])])
])
AS_IF([test "x$enable_experimental_pkcs11" = "xyes"],
  [AC_MSG_NOTICE([PKCS-11: yes])]
)
AS_IF([test "x$enable_experimental_gss_tsig" = "xyes"],
  [AC_MSG_NOTICE([GSS-TSIG: yes])]
)
AS_IF([test "x$enable_lua_records" = "xyes"],
  [AC_MSG_NOTICE([LUA records: yes])]
)
AS_IF([test "x$systemd" != "xn"],
  [AC_MSG_NOTICE([systemd: yes])],
  [AC_MSG_NOTICE([systemd: no])]
)
AS_IF([test "x$enable_remotebackend_zeromq" != "xno"],
  [AC_MSG_NOTICE([ZeroMQ connector for remotebackend: yes])]
)
AS_IF([test -n "$GEOIP_LIBS"],
  [AC_MSG_NOTICE([libgeoip for geoipbackend: yes])]
)
AS_IF([test -n "$MMDB_LIBS"],
  [AC_MSG_NOTICE([libmaxminddb for geoipbackend: yes])]
)
AC_MSG_NOTICE([])
