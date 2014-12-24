AC_PREREQ([2.61])

dnl The following lines may be patched by set-version-auth.
AC_INIT([pdns], [git])
dnl AC_SUBST([DIST_HOST], [TO_BE_PATCHED])
dnl End patch area.

AC_CONFIG_SRCDIR([pdns/receiver.cc])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip tar-ustar -Wno-portability subdir-objects parallel-tests 1.11])
AM_SILENT_RULES([yes])

AC_CANONICAL_HOST
: ${CFLAGS="-Wall -g -O2"}
: ${CXXFLAGS="-Wall -g -O2"}

AC_PROG_CC
AM_PROG_CC_C_O
PDNS_CHECK_BISON
PDNS_CHECK_FLEX
AC_PROG_INSTALL
AC_PROG_MAKE_SET


AC_PROG_CXX
AS_IF([test "x$CXX" = "xno" || test "x$CXX:x$GXX" = "xg++:x"],
  AC_MSG_ERROR([no C++ compiler found])
)

AC_LANG([C++])

AC_DEFINE([_GNU_SOURCE], [1],
  [Define _GNU_SOURCE so that we get all necessary prototypes]
)

PDNS_WITH_LUA
AX_CXX_COMPILE_STDCXX_11(,optional)
AM_CONDITIONAL([CXX2011],[test "$HAVE_CXX11" = "1"])

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

AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([gethostent], [nsl])
AC_SEARCH_LIBS([inet_aton], [resolv])

LT_PREREQ([2.2.2])
LT_INIT([disable-static dlopen])


MC_TM_GMTOFF

AM_CONDITIONAL([RELEASE_BUILD], [test "$PACKAGE_VERSION" != "git"])

# Define full_libdir to be the fully expanded (${exec_prefix}, etc.)
# "system" library path.
# We use this to search for other libraries.
eval full_libdir="\"$libdir\""

# detect pkg-config explicitly
PKG_PROG_PKG_CONFIG

# check if we want a static build
AC_MSG_CHECKING([whether we will be building static binaries])

AC_ARG_ENABLE([static-binaries],
  [AS_HELP_STRING([--enable-static-binaries],[build static binaries @<:@default=no@:>@])],
  [static=$enableval],
  [static=no],
)
AC_MSG_RESULT([$static])

AS_IF([test "x$static" != "xno"], [
  PKG_CONFIG="$PKG_CONFIG --static"
])

AC_CHECK_HEADERS(
	[sys/mman.h],
	[AC_CHECK_FUNC(
		[mmap],
		[AC_DEFINE(HAVE_MMAP, [1], [Define to 1 if you have mmap])],
		[have_mmap=no]
	)],
	[have_mmap=no]
)

PDNS_CHECK_RAGEL

BOOST_REQUIRE([1.35])
BOOST_FOREACH
BOOST_PROGRAM_OPTIONS([mt])
BOOST_SERIALIZATION([mt])

PDNS_ENABLE_UNIT_TESTS

PDNS_WITH_SQLITE3

PDNS_CHECK_PANDOC
PDNS_CHECK_MKDOCS
PDNS_CHECK_LINKCHECKER

dnl Checks for library functions.
AC_CHECK_FUNCS_ONCE([strcasestr localtime_r])

AS_IF([test "x$lt_cv_dlopen" = "xno"],
  [AC_MSG_ERROR([Your system does not support dlopen])]
)

AC_SUBST([LIBDL], [$lt_cv_dlopen_libs])

AC_MSG_CHECKING([for RTLD_NOW]);
ac_save_LIBS="$LIBS"
LIBS="$LIBS $LIBDL"
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([[#include <dlfcn.h>]],
    [[(void) dlopen("",RTLD_NOW);]])],
  [has_RTLD_NOW=yes],
  [has_RTLD_NOW=no])
AC_MSG_RESULT([$has_RTLD_NOW])
if test "$has_RTLD_NOW" = "no"; then
  AC_DEFINE(NEED_RTLD_NOW,,[If host OS misses RTLD_NOW])
fi
LIBS=$ac_save_LIBS

THREADFLAGS=""

case "$host_os" in
solaris2.10)
  LIBS="-lposix4 -lpthread -lrt $LIBS"
  CXXFLAGS="-D_REENTRANT $CXXFLAGS"
  have_solaris="yes"
  ;;
solaris2.8 | solaris2.9 )
  AC_DEFINE(NEED_POSIX_TYPEDEF,,[If POSIX typedefs need to be defined])
  AC_DEFINE(NEED_INET_NTOP_PROTO,,[If your OS is so broken that it needs an additional prototype])
  LIBS="-lposix4 -lpthread $LIBS"
  CXXFLAGS="-D_REENTRANT $CXXFLAGS"
  have_solaris="yes"
  ;;
linux*)
  THREADFLAGS="-pthread"
  have_linux="yes"
  ;;
darwin*)
  CXXFLAGS="-D__APPLE_USE_RFC_3542 -D_XOPEN_SOURCE $CXXFLAGS"
  ;;
freebsd*)
  LDFLAGS="-pthread $LDFLAGS"
  CXXFLAGS="-pthread $CXXFLAGS"
  have_freebsd="yes"
  ;;
*)
  LDFLAGS="-pthread $LDFLAGS"
  CXXFLAGS="-pthread $CXXFLAGS"
  ;;
esac

AM_CONDITIONAL([HAVE_FREEBSD], [test "x$have_freebsd" = "xyes"])
AM_CONDITIONAL([HAVE_LINUX], [test "x$have_linux" = "xyes"])
AM_CONDITIONAL([HAVE_SOLARIS], [test "x$have_solaris" = "xyes"])

AC_SUBST(THREADFLAGS)
AC_SUBST([DYNLINKFLAGS], [-export-dynamic])

PDNS_ENABLE_VERBOSE_LOGGING
PDNS_WITH_SYSTEM_POLARSSL
PDNS_ENABLE_BOTAN
PDNS_ENABLE_PKCS11
PDNS_WITH_CRYPTOPP
PDNS_ENABLE_ED25519

AS_IF([test "x$static" != "xno"], [
  LDFLAGS="-all-static $LDFLAGS"
])

modules="bind gmysql geo random"
AC_ARG_WITH([modules],
  [AS_HELP_STRING([--with-modules],[which backends to compile with @<:@default=bind gmysql geo random@:>@])],
  [modules="$withval"]
)

dynmodules="pipe"
AC_ARG_WITH([dynmodules],
  [AS_HELP_STRING([--with-dynmodules],[which backends to build for dynamic loading @<:@default=pipe@:>@])],
  [dynmodules="$withval"]
)

AC_SUBST(socketdir)
socketdir="/var/run"
AC_ARG_WITH([socketdir],
  [AS_HELP_STRING([--with-socketdir],[where the controlsocket lives @<:@default=/var/run@:>@])],
  [socketdir="$withval"]
)

AC_SUBST(moduledirs)
AC_SUBST(moduleobjects)
AC_SUBST(modulelibs)
AC_DEFINE_UNQUOTED([PDNS_MODULES],"$modules", [Built-in modules])

AC_MSG_CHECKING([whether we will be building the server])
AC_ARG_ENABLE([pdns-server],
  [AS_HELP_STRING([--enable-pdns_server],[if we should build the server @<:@default=yes@:>@])],
  [enable_pdns_server=$enableval],
  [enable_pdns_server=yes]
)
AC_MSG_RESULT([$enable_pdns_server])
AM_CONDITIONAL([WITH_PDNS_SERVER],[test "x$enable_pdns_server" != "xno"])

AC_ARG_ENABLE([gcc-skip-locking],
  [AS_HELP_STRING([--enable-gcc-skip-locking],[if we should forcefully skip gcc locking @<:@default=no@:>@])],
  [AC_DEFINE(GCC_SKIP_LOCKING,[],[Skip gcc locking])],
)

AC_MSG_CHECKING([whether we will be building and installing the extra tools])
AC_ARG_ENABLE([tools],
  [AS_HELP_STRING([--enable-tools],[if we should build and install the tools @<:@default=no@:>@])],
  [enable_tools=$enableval],
  [enable_tools=no]
)

AC_MSG_RESULT([$enable_tools])
AM_CONDITIONAL([TOOLS],[test "x$enable_tools" != "xno"])


for a in $modules $dynmodules; do
  case "$a" in
    oracle|goracle)
      PDNS_WITH_ORACLE
      needoracle=yes
      ;;
    lmdb)
      PDNS_WITH_LMDB
      needlmdb=yes
      ;;
    mydns|gmysql|pdns)
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
    opendbx)
      PDNS_CHECK_OPENDBX
      ;;
    remote)
      AS_IF([test "x$enable_unit_tests" = "xyes"],
        [PDNS_CHECK_CURL_PROGRAM]
      )

      have_remotebackend=yes
      ;;
    tinydns)
      PDNS_CHECK_CDB
      ;;
    geoip)
      PDNS_CHECK_GEOIP
      ;;
    lua)
      AS_IF([test "x$with_lua" = "xno"],
        AC_MSG_ERROR([Lua backend needs lua, run ./configure --with-lua])
      )
      AS_IF([test "x$LUAPC" = "x"],
        AC_MSG_ERROR([Lua backend needs lua but we cannot find it])
      )
      ;;
  esac
done

PDNS_ENABLE_REMOTEBACKEND_ZEROMQ

AM_CONDITIONAL([ORACLE],[test "x$needoracle" = "xyes"])

AM_CONDITIONAL([LDAP],[test "x$needldap" = "xyes"])

AM_CONDITIONAL([LMDB],[test "x$needlmdb" = "xyes"])

PDNS_CHECK_SQLITE3
AM_CONDITIONAL([SQLITE3], [test "x$needsqlite3" = "xyes"])

for a in $modules; do
  moduledirs="$moduledirs ${a}backend"

  for b in `cat $srcdir/modules/${a}backend/OBJECTFILES`; do
    moduleobjects="$moduleobjects ../modules/${a}backend/$b"
  done
  modulelibs="$modulelibs `cat $srcdir/modules/${a}backend/OBJECTLIBS`"
done

for a in $dynmodules; do
  moduledirs="$moduledirs ${a}backend"
done

LDFLAGS="$RELRO_LDFLAGS $LDFLAGS"

AS_IF([test "x$static" != "xyes"], [
  CFLAGS="$PIE_CFLAGS $CFLAGS"
  CXXFLAGS="$PIE_CFLAGS $CXXFLAGS"
  PROGRAM_LDFLAGS="$PIE_LDFLAGS $PROGRAM_LDFLAGS"
])
AC_SUBST([PROGRAM_LDFLAGS])

PDNS_ENABLE_COVERAGE
PDNS_ENABLE_SANITIZERS

AC_SUBST(LIBS)

AC_SUBST([AM_CPPFLAGS],
  ["AS_ESCAPE([-I$(top_builddir) -I$(top_srcdir)]) $THREADFLAGS $BOOST_CPPFLAGS"]
)

AC_SUBST([YAHTTP_CFLAGS], ['-I$(top_srcdir)/pdns/ext/yahttp'])
AC_SUBST([YAHTTP_LIBS], ['-L$(top_builddir)/pdns/ext/yahttp/yahttp -lyahttp'])

CXXFLAGS="$SANITIZER_FLAGS $CXXFLAGS"

export moduledirs moduleobjects modulelibs

AC_CONFIG_FILES([
  Makefile
  modules/Makefile
  pdns/Makefile
  codedocs/Makefile
  docs/Makefile
  pdns/pdns.init
  pdns/ext/Makefile
  pdns/ext/ed25519/Makefile
  pdns/ext/yahttp/Makefile
  pdns/ext/yahttp/yahttp/Makefile
  pdns/ext/polarssl/Makefile
  pdns/ext/polarssl/library/Makefile
  pdns/ext/rapidjson/Makefile
  modules/bindbackend/Makefile
  modules/geobackend/Makefile
  modules/geoipbackend/Makefile
  modules/gmysqlbackend/Makefile
  modules/goraclebackend/Makefile
  modules/gpgsqlbackend/Makefile
  modules/gsqlite3backend/Makefile
  modules/ldapbackend/Makefile
  modules/luabackend/Makefile
  modules/mydnsbackend/Makefile
  modules/opendbxbackend/Makefile
  modules/oraclebackend/Makefile
  modules/pipebackend/Makefile
  modules/randombackend/Makefile
  modules/remotebackend/Makefile
  modules/tinydnsbackend/Makefile
  modules/lmdbbackend/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Modules: $modules])
AC_MSG_NOTICE([Dynamic Modules: $dynmodules])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([With ZeroMQ connector for remotebackend: $enable_remotebackend_zeromq])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([CC: $CC])
AC_MSG_NOTICE([CXX: $CXX])
AC_MSG_NOTICE([LD: $LD])
AC_MSG_NOTICE([CFLAGS: $CFLAGS])
AC_MSG_NOTICE([CPPFLAGS: $CPPFLAGS])
AC_MSG_NOTICE([CXXFLAGS: $CXXFLAGS])
AC_MSG_NOTICE([LDFLAGS: $LDFLAGS])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([BOOST_CPPFLAGS: $BOOST_CPPFLAGS])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([SQLite3 support: $with_sqlite3])
AC_MSG_NOTICE([Lua support: $with_lua])
AS_IF([test "$HAVE_CXX11" = "1"],
  [AC_MSG_NOTICE([C++2011 support: yes])],
  [AC_MSG_NOTICE([C++2011 support: no])]
)
AC_MSG_NOTICE([])
