AC_PREREQ([2.61])

dnl The following lines may be patched by set-version-auth.
AC_INIT([pdns], [git])
dnl AC_SUBST([DIST_HOST], [TO_BE_PATCHED])
dnl End patch area.

AC_CONFIG_SRCDIR([pdns/receiver.cc])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign tar-ustar -Wno-portability subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CANONICAL_HOST
AC_C_BIGENDIAN
: ${CXXFLAGS="-Wall -O2"}

AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_YACC
AM_PROG_LEX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_LANG([C++])

m4_ifndef([LT_INIT],[
AC_PROG_LIBTOOL
],[
LT_INIT
])

AM_CONDITIONAL([RELEASE_BUILD], [test "$PACKAGE_VERSION" != "git"])

# Define full_libdir to be the fully expanded (${exec_prefix}, etc.)
# "system" library path.
# We use this to search for other libraries.
eval full_libdir="\"$libdir\""

# detect pkg-config explicitly
PKG_PROG_PKG_CONFIG

AC_CHECK_PROG([RAGEL], [ragel], [ragel])
AC_CHECK_PROG([ASCIIDOC], [asciidoc], [asciidoc])

PDNS_WITH_LUA

BOOST_REQUIRE([1.35])
BOOST_FOREACH
BOOST_PROGRAM_OPTIONS([mt])
BOOST_SERIALIZATION([mt])

PDNS_ENABLE_UNIT_TESTS

dnl Allow user to require SQLite3
AC_MSG_CHECKING([whether user requires sqlite3])
AC_ARG_WITH([sqlite3],
  [AS_HELP_STRING([--with-sqlite3],[include sqlite3 driver @<:@default=no@:>@])],
  [WITH_SQLITE3=$withval],
  [WITH_SQLITE3=no]
)
AC_MSG_RESULT([$WITH_SQLITE3])
SQLITE3PC=sqlite3
if test "$WITH_SQLITE3" != "no"; then
  needsqlite3=yes
  if test "$WITH_SQLITE3" != "yes"; then
    SQLITE3PC=$WITH_SQLITE3
  fi
fi

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

dnl Checks for library functions.
AC_CHECK_FUNCS([strcasestr])

# Check for libdl
LIBS="$LIBS -lz"

my_save_LIBS="$LIBS"
LIBS=""
AC_CHECK_LIB(dl,dlopen)
LIBDL=$LIBS
LIBS="$my_save_LIBS"
AC_SUBST(LIBDL)

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

# Check for libcrypt

my_save_LIBS="$LIBS"
LIBS=""
AC_CHECK_LIB(crypt, crypt)
LIBCRYPT=$LIBS
LIBS="$my_save_LIBS"
AC_SUBST(LIBCRYPT)

DYNLINKFLAGS=""
THREADFLAGS=""

AM_CONDITIONAL([OS_MACOSX], false)
case "$host_os" in
solaris2.10)
  AC_DEFINE(HAVE_IPV6,1,[If the host operating system understands IPv6])
  LIBS="-lposix4 -lresolv -lnsl -lsocket -lpthread -lrt $LIBS"
  CXXFLAGS="-D_REENTRANT $CXXFLAGS"
  ;;

solaris2.8 | solaris2.9 )
  AC_DEFINE(NEED_POSIX_TYPEDEF,,[If POSIX typedefs need to be defined])
  AC_DEFINE(NEED_INET_NTOP_PROTO,,[If your OS is so broken that it needs an additional prototype])
  AC_DEFINE(HAVE_IPV6,1,[If the host operating system understands IPv6])
  LIBS="-lposix4 -lresolv -lnsl -lsocket -lpthread $LIBS"
  CXXFLAGS="-D_REENTRANT $CXXFLAGS"
  ;;
solaris2.6 | solaris2.7)
  AC_DEFINE(NEED_POSIX_TYPEDEF,,[If POSIX typedefs need to be defined])
  AC_DEFINE(NEED_INET_NTOP_PROTO,,[If your OS is so broken that it needs an additional prototype])
  LIBS="-lposix4 -lresolv -lnsl -lsocket -lpthread $LIBS"
  CXXFLAGS="-D_REENTRANT $CXXFLAGS"
  ;;
linux*)
  AC_DEFINE(HAVE_IPV6,1,[If the host operating system understands IPv6])
  DYNLINKFLAGS="-rdynamic"
  LDFLAGS="$LDFLAGS -lrt"
  THREADFLAGS="-pthread"
  CXXFLAGS="-D_GNU_SOURCE $CXXFLAGS"
  ;;
darwin11* | darwin12* | darwin13*)
  AC_DEFINE(HAVE_IPV6,1,[If the host operating system understands IPv6])
  DYNLINKFLAGS="-rdynamic"
  LDFLAGS="-pthread $LDFLAGS"
  CXXFLAGS="-pthread $CXXFLAGS -D__APPLE_USE_RFC_3542"
  AM_CONDITIONAL([OS_MACOSX], true)
  ;;
*)
  AC_DEFINE(HAVE_IPV6,1,[If the host operating system understands IPv6])
  DYNLINKFLAGS="-rdynamic"
  LDFLAGS="-pthread $LDFLAGS"
  CXXFLAGS="-pthread $CXXFLAGS"
  ;;
esac

AC_SUBST(THREADFLAGS)
AC_SUBST(DYNLINKFLAGS)

PDNS_ENABLE_VERBOSE_LOGGING
PDNS_WITH_SYSTEM_POLARSSL
PDNS_ENABLE_BOTAN
PDNS_ENABLE_PKCS11
PDNS_WITH_CRYPTOPP
PDNS_ENABLE_REMOTEBACKEND_HTTP
PDNS_ENABLE_REMOTEBACKEND_ZEROMQ

AC_MSG_CHECKING([whether we should build static binaries])

AC_ARG_ENABLE([static-binaries],
  [AS_HELP_STRING([--enable-static-binaries],[build static binaries])],
  [case "${enableval}" in
    yes) static=true ;;
    no)  static=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-static-binaries) ;;
   esac],
   [debug=false]
)
AC_MSG_RESULT([$static])

AM_CONDITIONAL([ALLSTATIC], [test "x$static" = "xtrue"])

if test "x$static" = "xtrue"; then
  LDFLAGS="-all-static $LDFLAGS"
fi

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

AS_IF([test "x$enable_pdns_server" = "xyes"],
  [programdescend=pdns]
)

AC_SUBST(programdescend)

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
AM_CONDITIONAL([TOOLS],[test "x$enable_tools" = "xyes"])

for a in $modules $dynmodules; do
  case "$a" in
    oracle|goracle)
      PDNS_WITH_ORACLE
      needoracle=yes
      ;;
    lmdb)
      PDNS_WITH_LMDB
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
      ;;
    opendbx)
      PDNS_CHECK_OPENDBX
      ;;
    tinydns)
      PDNS_CHECK_CDB
      ;;
  esac
done

AM_CONDITIONAL([ORACLE],[test "x$needoracle" = "xyes"])

AM_CONDITIONAL([SQLITE3], [test "x$needsqlite3" = "xyes"])
if test "$needsqlite3"; then
  PKG_CHECK_MODULES([SQLITE3], $SQLITE3PC,
    [HAVE_SQLITE3=yes],
    [AC_MSG_ERROR([Could not find sqlite3])]
  )
  AC_SUBST(SQLITE3_LIBS)
  AC_SUBST(SQLITE3_CFLAGS)
  AC_DEFINE([HAVE_SQLITE3],[1],[If we have sqlite3])
fi

for a in $modules; do
  moduledirs="$moduledirs ${a}backend"

  for b in `cat $srcdir/modules/${a}backend/OBJECTFILES`; do
    moduleobjects="$moduleobjects ../modules/${a}backend/$b"
  done
  modulelibs="$modulelibs `cat $srcdir/modules/${a}backend/OBJECTLIBS`"

  if test ${a} = "gpgsql"; then
    LIBS="$LIBS $LIBCRYPT"

    case "$host_os" in
      freebsd*)
        ;;
      darwin*)
        modulelibs="$modulelibs -lresolv"
        ;;
      *)
        modulelibs="$modulelibs -lresolv -lnsl"
        ;;
    esac
  fi
done

for a in $dynmodules; do
  moduledirs="$moduledirs ${a}backend"
done

AC_SUBST(LIBS)

export moduledirs moduleobjects modulelibs

AC_CONFIG_FILES([
  Makefile
  modules/Makefile
  pdns/Makefile
  codedocs/Makefile
  pdns/pdns
  pdns/ext/yahttp/Makefile
  pdns/ext/yahttp/yahttp/Makefile
  modules/bindbackend/Makefile
  modules/db2backend/Makefile
  modules/geobackend/Makefile
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

