dnl intro
AC_INIT(pdns/receiver.cc)
AM_INIT_AUTOMAKE(pdns, 3.0-rc2)
AC_CANONICAL_HOST
AM_CONFIG_HEADER(config.h)
AC_C_BIGENDIAN 
AC_PREREQ(2.52)
CXXFLAGS="$CXXFLAGS -Wall -O2"

AC_PREFIX_DEFAULT(/usr/local)
AC_PROG_CC
AC_PROG_CXX
AC_PROG_YACC
AM_PROG_LEX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL 
AC_LANG_CPLUSPLUS

BOOST_REQUIRE([1.34])
BOOST_FOREACH
#BOOST_FILESYSTEM([mt])
BOOST_PROGRAM_OPTIONS([mt])
BOOST_SERIALIZATION([mt])
#BOOST_SYSTEM([mt])

dnl Check for lua
AC_MSG_CHECKING(if with lua)
AC_ARG_WITH(lua, AC_HELP_STRING([--with-lua],[lua]), WITH_LUA=$withval],[WITH_LUA=yes])

AC_MSG_RESULT($WITH_LUA)
if test "$WITH_LUA" != "no"; then
 # try pkgconfig
 if test "$WITH_LUA" = "yes"; then
      LUAPC=lua
 else
      LUAPC=$WITH_LUA
 fi
 PKG_CHECK_MODULES(LUA, $LUAPC >= 5.1, [
 	AC_DEFINE([HAVE_LUA], [1], [liblua])
        AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
        ],[
        PKG_CHECK_MODULES(LUA, lua5.1 >= 5.1, [
        	AC_DEFINE([HAVE_LUA], [1], [liblua])
                AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
        ],[
        PKG_CHECK_MODULES(LUA, lua-5.1 >= 5.1, [
        	AC_DEFINE([HAVE_LUA], [1], [liblua])
                AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
                ]) 
                ]) 
        ])
 AC_SUBST(LUA_CFLAGS)
 AC_SUBST(LUA_LIBS)
fi
                                         
dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h  getopt.h limits.h strings.h sys/time.h syslog.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(gethostname gettimeofday mkdir mktime select socket strerror)

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
AC_TRY_LINK(
[#include <dlfcn.h>],
[ (void) dlopen("",RTLD_NOW); ],
has_RTLD_NOW=yes, has_RTLD_NOW=no)
AC_MSG_RESULT([$has_RTLD_NOW])
if test "$has_RTLD_NOW" = "no"
then
	AC_DEFINE(NEED_RTLD_NOW,,[If host OS misses RTLD_NOW])
fi
LIBS=$ac_save_LIBS

DYNLINKFLAGS=""
THREADFLAGS=""

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
	LDFLAGS="$LDFLAGS"
	THREADFLAGS="-pthread"
	CXXFLAGS="-D_GNU_SOURCE $CXXFLAGS"
	;;
openbsd*)
	AC_DEFINE(HAVE_IPV6,1,[If the host operating system understands IPv6])
	DYNLINKFLAGS="-rdynamic"
	LDFLAGS="-lc_r $LDFLAGS"
	CXXFLAGS="-pthread $CXXFLAGS"
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

AC_MSG_CHECKING(whether we will be doing verbose logging)
AC_ARG_ENABLE(verbose-logging, 
 [  --enable-verbose-logging	Do verbose logging],enable_verbose_logging=yes ,enable_verbose_logging=no)

if test $enable_verbose_logging = yes; then AC_DEFINE(VERBOSELOG, 1, [If verbose logging should be enabled]) 
fi
AC_MSG_RESULT($enable_verbose_logging)

AC_MSG_CHECKING(whether we will be linking in Botan 1.9)
AC_ARG_ENABLE(botan1.9, 
 [  --enable-botan1.9	Use Botan 1.9],enable_botan19=yes, enable_botan19=no)
AC_MSG_RESULT($enable_botan19)
AM_CONDITIONAL(BOTAN19,test x"$enable_botan19" = "xyes")

AC_MSG_CHECKING(whether we will be linking in Botan 1.8)
AC_ARG_ENABLE(botan1.8, 
 [  --enable-botan1.8	Use Botan 1.8],enable_botan18=yes, enable_botan18=no)
AC_MSG_RESULT($enable_botan18)
AM_CONDITIONAL(BOTAN18,test x"$enable_botan18" = "xyes")

AC_MSG_CHECKING(whether we will be linking in Crypto++)
AC_ARG_ENABLE(cryptopp, 
 [  --enable-cryptopp	Use Crypto++],enable_cryptopp=yes, enable_cryptopp=no)
AC_MSG_RESULT($enable_cryptopp)
AM_CONDITIONAL(CRYPTOPP,test x"$enable_cryptopp" = "xyes")


AC_MSG_CHECKING(whether we should build static binaries)

AC_ARG_ENABLE(static-binaries, 
	[  --enable-static-binaries	Build static binaries],
     [case "${enableval}" in
       yes) static=true ;;
       no)  static=false ;;
       *) AC_MSG_ERROR(bad value ${enableval} for --enable-static-binaries) ;;
     esac],[debug=false])
AC_MSG_RESULT($static)

AM_CONDITIONAL(ALLSTATIC, test x$static = xtrue)

if test x$static = xtrue; 
then 
	LDFLAGS="-all-static $LDFLAGS"
fi



modules="gmysql geo"
AC_ARG_WITH(modules, [  --with-modules Which backends to compile with ], 
[
        modules="$withval"  
])

dynmodules="pipe"
AC_ARG_WITH(dynmodules, [  --with-dynmodules Which backends to build for dynamic loading ], 
[
        dynmodules="$withval"  
])



AC_SUBST(socketdir)
socketdir="/var/run"
AC_ARG_WITH(socketdir, [  --with-socketdir Where the controlsocket lives ], 
[
        socketdir="$withval"  
])

AC_SUBST(moduledirs)
AC_SUBST(moduleobjects)
AC_SUBST(modulelibs)

AC_MSG_CHECKING(whether we will be building the server)
AC_ARG_ENABLE(pdns-server, 
 [  --enable-pdns_server	If we should build the server],
	enable_pdns_server=$enableval,
	enable_pdns_server=yes)

AC_MSG_RESULT($enable_pdns_server)

if test x"$enable_pdns_server" = "xyes"
then 
	programdescend=pdns
fi

AC_SUBST(programdescend)

AC_ARG_ENABLE(gcc-skip-locking, 
 [ --enable-gcc-skip-locking	If we should forcefully skip gcc locking],
	AC_DEFINE(GCC_SKIP_LOCKING,,[Skip gcc locking]),
 )

AC_MSG_CHECKING(whether we will be building the recursor)
AC_ARG_ENABLE(recursor, 
 [  --enable-recursor	If we should build the recursor],
	enable_recursor=$enableval,
	enable_recursor=no )

AC_MSG_RESULT($enable_recursor)
AM_CONDITIONAL(RECURSOR,test x"$enable_recursor" = "xyes")

for a in $modules $dynmodules
do
	case "$a" in
		mysql )
			needmysql=yes
		;;
		gmysql )
			needmysql=yes
		;;
		mydns )
			needmysql=yes
		;;
		gpgsql )
			needpgsql=yes
		;;
		gsqlite )
			needsqlite=yes
		;;
		gsqlite3 )
			needsqlite3=yes
		;;
		pdns )
			needmysql=yes
		;;
		ldap)
			AC_CHECK_HEADERS([ldap.h], , [AC_MSG_ERROR([ldap header (ldap.h) not found])])
			AC_CHECK_HEADERS([lber.h], , [AC_MSG_ERROR([ldap header (lber.h) not found])])
			AC_SUBST([LIBLDAP])
			AC_CHECK_LIB(
				[ldap_r], [ldap_set_option],
				[AC_DEFINE([HAVE_LIBLDAP_R], 1, [Have -lldap_r]) LIBLDAP="ldap_r"],
				[AC_CHECK_LIB(
					[ldap], [ldap_set_option],
					[AC_DEFINE([HAVE_LIBLDAP], 1, [Have -lldap]) LIBLDAP="ldap"],
					[AC_MSG_ERROR([ldap library (libldap) not found])]
				)]
			)
			AC_CHECK_LIB(
				[$LIBLDAP], [ldap_initialize],
				[AC_DEFINE([HAVE_LDAP_INITIALIZE], 1, [Define to 1 if you have ldap_initialize])]
			)
			AC_CHECK_LIB(
				[$LIBLDAP], [ldap_sasl_bind],
				[AC_DEFINE([HAVE_LDAP_SASL_BIND], 1, [Define to 1 if you have ldap_sasl_bind])]
			)
		;;
		godbc )
			needunixodbc=yes
		;;
		opendbx)
			AC_CHECK_HEADERS([odbx.h], , [AC_MSG_ERROR([opendbx header (odbx.h) not found])])
			AC_SUBST([LIBOPENDBX])
			AC_CHECK_LIB(
				[opendbx], [odbx_init],
				[AC_DEFINE([HAVE_LIBOPENDBX], 1, [Have -lopendbx]) LIBOPENDBX="opendbx"]
			)
		;;
	esac
done


if test "$needmysql"
then
	AC_ARG_WITH(mysql,
	    [  --with-mysql=<path>     root directory path of MySQL installation],
	    [MYSQL_lib_check="$withval/lib/mysql $with_mysql/lib"
	MYSQL_inc_check="$withval/include/mysql"],
	    [MYSQL_lib_check="/usr/local/mysql/lib/mysql /usr/local/lib/mysql /opt/mysql/lib/mysql \
		/usr/lib/mysql /usr/lib64/mysql /usr/local/mysql/lib /usr/local/lib /opt/mysql/lib /usr/lib \
		/usr/sfw/lib/"
	MYSQL_inc_check="/usr/local/mysql/include/mysql /usr/local/include/mysql \
		/opt/mysql/include/mysql /opt/mysql/include /usr/include/mysql /usr/sfw/include/mysql"])
		AC_ARG_WITH(mysql-lib,
	    [  --with-mysql-lib=<path> directory path of MySQL library installation],
	    [MYSQL_lib_check="$withval/lib/mysql $withval/mysql $withval"])
		AC_ARG_WITH(mysql-includes,
	    [  --with-mysql-includes=<path>
                         directory path of MySQL header installation],
	    [MYSQL_inc_check="$withval/include/mysql $withval/mysql $withval"])
		AC_MSG_CHECKING([for MySQL library directory])
	MYSQL_libdir=
	for m in $MYSQL_lib_check; do
	        if test -d "$m" && \
		   (test -f "$m/libmysqlclient.so" || test -f "$m/libmysqlclient.a")
	        then
	                MYSQL_libdir=$m
	                break
	        fi
	done
		if test -z "$MYSQL_libdir"; then
	        AC_MSG_ERROR([Didn't find the mysql library dir in '$MYSQL_lib_check'])
	fi
	case "$MYSQL_libdir" in
                 /usr/lib ) MYSQL_lib="" ;;
	  /* ) MYSQL_lib=-L$MYSQL_libdir; LDFLAGS="$MYSQL_lib $LDFLAGS";;
	  * )  AC_MSG_ERROR([The MySQL library directory ($MYSQL_libdir) must be an absolute path.]) ;;
	esac
	
	AC_SUBST(MYSQL_lib)
	
	AC_MSG_RESULT([$MYSQL_libdir])
		AC_MSG_CHECKING([for MySQL include directory])
	MYSQL_incdir=
	for m in $MYSQL_inc_check; do
	        if test -d "$m" && test -f "$m/mysql.h"
	        then
	                MYSQL_incdir=$m
	                break
	        fi
	done
		if test -z "$MYSQL_incdir"; then
	        AC_MSG_ERROR([Didn't find the mysql include dir in '$MYSQL_inc_check'])
	fi
	
	case "$MYSQL_incdir" in
	  /* ) ;;
	  * )  AC_MSG_ERROR([The MySQL include directory ($MYSQL_incdir) must be an absolute path.]) ;;
	esac
	
	AC_SUBST(MYSQL_incdir)
	AC_MSG_RESULT([$MYSQL_incdir])
#	LIBS="$LIBS -lmysqlclient"
fi



if test "$needpgsql" 
then
	AC_ARG_WITH(pgsql,
	    [  --with-pgsql=<path>     root directory path of PgSQL installation],
	    [PGSQL_lib_check="$withval/lib/pgsql $with_pgsql/lib"
	PGSQL_inc_check="$withval/include/pgsql"],
	    [PGSQL_lib_check="/usr/local/pgsql/lib/pgsql /usr/local/lib/pgsql /opt/pgsql/lib/pgsql /usr/lib/pgsql /usr/local/pgsql/lib /usr/local/lib /opt/pgsql/lib /usr/lib /usr/lib64"
	PGSQL_inc_check="/usr/local/pgsql/include/pgsql /usr/include /usr/local/include/postgresql/ /usr/local/include /opt/pgsql/include/pgsql /opt/pgsql/include /usr/include/pgsql/ /usr/include/postgresql"])
		AC_ARG_WITH(pgsql-lib,
	    [  --with-pgsql-lib=<path> directory path of PgSQL library installation],
	    [PGSQL_lib_check="$withval/lib/pgsql $withval/pgsql $withval"])
		AC_ARG_WITH(pgsql-includes,
	    [  --with-pgsql-includes=<path>
                         directory path of PgSQL header installation],
	    [PGSQL_inc_check="$withval/include/pgsql $withval/pgsql $withval"])
		AC_MSG_CHECKING([for PgSQL library directory])
	PGSQL_libdir=
	for m in $PGSQL_lib_check; do
	        if test -d "$m" && \
		   (test -f "$m/libpq.a" || test -f "$m/libpq.so")
	        then
	                PGSQL_libdir=$m
	                break
	        fi
	done
		if test -z "$PGSQL_libdir"; then
	        AC_MSG_ERROR([Didn't find the pgsql library dir in '$PGSQL_lib_check'])
	fi
	case "$PGSQL_libdir" in
	  /usr/lib ) PGSQL_lib="" ;;
	  /usr/lib64 ) PGSQL_lib="" ;;
	  /* ) PGSQL_lib="-L$PGSQL_libdir -Wl,-rpath,$PGSQL_libdir" 
	       LDFLAGS="$PGSQL_lib $LDFLAGS"
               ;;
	  * )  AC_MSG_ERROR([The PgSQL library directory ($PGSQL_libdir) must be an absolute path.]) ;;
	esac

	AC_SUBST(PGSQL_lib)
	AC_MSG_RESULT([$PGSQL_libdir])
		AC_MSG_CHECKING([for PgSQL include directory])
	PGSQL_incdir=
	for m in $PGSQL_inc_check; do
	        if test -d "$m" && test -f "$m/libpq-fe.h"
	        then
	                PGSQL_incdir=$m
	                break
	        fi
	done
		if test -z "$PGSQL_incdir"; then
	        AC_MSG_ERROR([Didn't find the PgSQL include dir in '$PGSQL_inc_check'])
	fi
	case "$PGSQL_incdir" in
	  /* ) ;;
	  * )  AC_MSG_ERROR([The PgSQL include directory ($PGSQL_incdir) must be an absolute path.]) ;;
	esac
	AC_SUBST(PGSQL_incdir)
	AC_MSG_RESULT([$PGSQL_incdir])

#	LIBS="$LIBS -lpq++ -lpq -lssl -lcrypt -lcrypto"
fi


if test "$needsqlite"
then
        AC_ARG_WITH(sqlite,
            [  --with-sqlite=<path>     root directory path of SQLite installation],
            [SQLITE_lib_check="$withval/lib/sqlite $with_sqlite/lib"
        SQLITE_inc_check="$withval/include/sqlite"],
            [SQLITE_lib_check="/usr/local/sqlite/lib/sqlite /usr/local/lib/sqlite /opt/pgsql/lib/sqlite /usr/lib/sqlite /usr/local/sqlite/lib /usr/local/lib /opt/sqlite/lib /usr/lib /usr/lib64"
        SQLITE_inc_check="/usr/local/sqlite/include/sqlite /usr/local/include/sqlite/ /usr/local/include /opt/sqlite/include/sqlite /opt/sqlite/include /usr/include/ /usr/include/sqlite"])
                AC_ARG_WITH(sqlite-lib,
            [  --with-sqlite-lib=<path> directory path of SQLite library installation],
            [SQLITE_lib_check="$withval/lib/sqlite $withval/sqlite $withval"])
                AC_ARG_WITH(sqlite-includes,
            [  --with-sqlite-includes=<path>
                         directory path of SQLite header installation],
            [SQLITE_inc_check="$withval/include/sqlite $withval/sqlite $withval"])
                AC_MSG_CHECKING([for SQLite library directory])
        SQLITE_libdir=
        for m in $SQLITE_lib_check; do
                if test -d "$m" && \
                   (test -f "$m/libsqlite.so" || test -f "$m/libsqlite.a")
                then
                        SQLITE_libdir=$m
                        break
                fi
        done
                if test -z "$SQLITE_libdir"; then
                AC_MSG_ERROR([Didn't find the sqlite library dir in '$SQLITE_lib_check'])
        fi
        case "$SQLITE_libdir" in
          /usr/lib ) SQLITE_lib="" ;;
          /usr/lib64 ) SQLITE_lib="" ;;
          /* ) SQLITE_lib="-L$SQLITE_libdir -Wl,-rpath,$SQLITE_libdir"
               LDFLAGS="$SQLITE_lib $LDFLAGS"
               ;;
          * )  AC_MSG_ERROR([The SQLite library directory ($SQLITE_libdir) must be an absolute path.]) ;;
        esac

        AC_SUBST(SQLITE_lib)
        AC_MSG_RESULT([$SQLITE_libdir])
                AC_MSG_CHECKING([for SQLite include directory])
        SQLITE_incdir=
        for m in $SQLITE_inc_check; do
                if test -d "$m" && test -f "$m/sqlite.h"
                then
                        SQLITE_incdir=$m
                        break
                fi
        done
                if test -z "$SQLITE_incdir"; then
                AC_MSG_ERROR([Didn't find the SQLite include dir in '$SQLITE_inc_check'])
        fi
        case "$SQLITE_incdir" in
          /* ) ;;
          * )  AC_MSG_ERROR([The SQLite include directory ($SQLITE_incdir) must be an absolute path.]) ;;
        esac
        AC_SUBST(SQLITE_incdir)
        AC_MSG_RESULT([$SQLITE_incdir])

#       LIBS="$LIBS -lsqlite"
fi

if test "$needsqlite3"
then
        AC_ARG_WITH(sqlite3,
            [  --with-sqlite3=<path>     root directory path of SQLite3 installation],
            [SQLITE3_lib_check="$withval/lib/sqlite3 $with_sqlite3/lib"
             SQLITE3_inc_check="$withval/include/sqlite3"],
            [SQLITE3_lib_check="/usr/local/sqlite3/lib/sqlite3 /usr/local/lib/sqlite3 /usr/lib/sqlite3 /usr/local/sqlite3/lib /usr/local/lib /opt/sqlite3/lib /usr/lib"
             SQLITE3_inc_check="/usr/local/sqlite3/include/sqlite3 /usr/local/include/sqlite3/ /usr/local/include /opt/sqlite3/include/sqlite3 /opt/sqlite3/include /usr/include/ /usr/include/sqlite3"])
        AC_ARG_WITH(sqlite3-lib,
            [  --with-sqlite3-lib=<path> directory path of SQLite3 library installation],
            [SQLITE3_lib_check="$withval/lib/sqlite3 $withval/sqlite3 $withval"])
        AC_ARG_WITH(sqlite3-includes,
            [  --with-sqlite3-includes=<path> directory path of SQLite3 header installation],
            [SQLITE3_inc_check="$withval/include/sqlite3 $withval/sqlite3 $withval"])
        AC_MSG_CHECKING([for SQLite3 library directory])
        SQLITE3_libdir=
        for m in $SQLITE3_lib_check; do
                if test -d "$m" && \
                   (test -f "$m/libsqlite3.so" || test -f "$m/libsqlite3.a")
                then
                        SQLITE3_libdir=$m
                        break
                fi
        done
                if test -z "$SQLITE3_libdir"; then
                AC_MSG_ERROR([Didn't find the sqlite3 library dir in '$SQLITE3_lib_check'])
        fi
        case "$SQLITE3_libdir" in
           /usr/lib ) SQLITE3_lib="" ;;
          /* ) SQLITE3_lib="-L$SQLITE3_libdir -Wl,-rpath,$SQLITE3_libdir"
               LDFLAGS="$SQLITE3_lib $LDFLAGS"
               ;;
          * )  AC_MSG_ERROR([The SQLite3 library directory ($SQLITE3_libdir) must be an absolute path.]) ;;
        esac

        AC_SUBST(SQLITE3_lib)
        AC_MSG_RESULT([$SQLITE3_libdir])
        AC_MSG_CHECKING([for SQLite3 include directory])
        SQLITE3_incdir=
        for m in $SQLITE3_inc_check; do
                if test -d "$m" && test -f "$m/sqlite3.h"
                then
                        SQLITE3_incdir=$m
                        break
                fi
        done
                if test -z "$SQLITE3_incdir"; then
                AC_MSG_ERROR([Didn't find the SQLite3 include dir in '$SQLITE3_inc_check'])
        fi
        case "$SQLITE3_incdir" in
          /* ) ;;
          * )  AC_MSG_ERROR([The SQLite3 include directory ($SQLITE3_incdir) must be an absolute path.]) ;;
        esac
        AC_SUBST(SQLITE3_incdir)
        AC_MSG_RESULT([$SQLITE3_incdir])

#       LIBS="$LIBS -lsqlite3"
fi

if test "$needunixodbc"
then
        AC_ARG_WITH(unixodbc,
            [  --with-unixodbc=<path>     root directory path of unixodbc installation],
            [UNIXODBC_lib_check="$withval/lib/unixodbc $with_unixodbc/lib $withval/lib"
             UNIXODBC_inc_check="$withval/include/unixodbc"],
            [UNIXODBC_lib_check="/usr/local/unixodbc/lib/unixodbc /usr/local/lib/unixodbc /usr/lib/unixodbc /usr/local/unixodbc/lib /usr/local/lib /opt/unixodbc/lib /usr/lib"
             UNIXODBC_inc_check="/usr/local/unixodbc/include/unixodbc /usr/local/include/unixodbc/ /usr/local/include /opt/unixodbc/include/unixodbc /opt/unixodbc/include /usr/include/ /usr/include/unixodbc"])
        AC_ARG_WITH(unixodbc-lib,
            [  --with-unixodbc-lib=<path> directory path of unixodbc library installation],
            [UNIXODBC_lib_check="$withval/lib/unixodbc $withval/unixodbc $withval"])
        AC_ARG_WITH(unixodbc-includes,
            [  --with-unixodbc-includes=<path> directory path of unixodbc header installation],
            [UNIXODBC_inc_check="$withval/include $withval/include/unixodbc $withval/unixodbc $withval"])
        AC_MSG_CHECKING([for SQLite3 library directory])
        UNIXODBC_libdir=
        for m in $UNIXODBC_lib_check; do
                if test -d "$m" && \
                   (test -f "$m/libodbc.so" || test -f "$m/libodbc.a")
                then
                        UNIXODBC_libdir=$m
                        break
                fi
        done
                if test -z "$UNIXODBC_libdir"; then
                AC_MSG_ERROR([Didn't find the unixodbc library dir in '$UNIXODBC_lib_check'])
        fi
        case "$UNIXODBC_libdir" in
           /usr/lib ) UNIXODBC_lib="" ;;
          /* ) UNIXODBC_lib="-L$UNIXODBC_libdir -Wl,-rpath,$UNIXODBC_libdir"
               LDFLAGS="$UNIXODBC_lib $LDFLAGS"
               ;;
          * )  AC_MSG_ERROR([The unixodbc library directory ($UNIXODBC_libdir) must be an absolute path.]) ;;
        esac

        AC_SUBST(UNIXODBC_lib)
        AC_MSG_RESULT([$UNIXODBC_libdir])
        AC_MSG_CHECKING([for unixodbc include directory])
        UNIXODBC_incdir=
        for m in $UNIXODBC_inc_check; do
                if test -d "$m" && test -f "$m/sql.h"
                then
                        UNIXODBC_incdir=$m
                        break
                fi
        done
                if test -z "$UNIXODBC_incdir"; then
                AC_MSG_ERROR([Didn't find the unixodbc include dir in '$UNIXODBC_inc_check'])
        fi
        case "$UNIXODBC_incdir" in
          /* ) ;;
          * )  AC_MSG_ERROR([The unixodbc include directory ($UNIXODBC_incdir) must be an absolute path.]) ;;
        esac
        AC_SUBST(UNIXODBC_incdir)
        AC_MSG_RESULT([$UNIXODBC_incdir])

#       LIBS="$LIBS -lunixodbc"
fi

for a in $modules
do
        moduledirs="$moduledirs ${a}backend"

	for b in `cat $srcdir/modules/${a}backend/OBJECTFILES`
	do
	        moduleobjects="$moduleobjects ../modules/${a}backend/$b"
	done
	modulelibs="$modulelibs `cat $srcdir/modules/${a}backend/OBJECTLIBS`"

	if test ${a} == "gpgsql"; then
		case "$host_os" in
		freebsd*)
			;;
		*)
			modulelibs="$modulelibs -lresolv -lnsl"
			;;
		esac
	fi
done

for a in $dynmodules
do
        moduledirs="$moduledirs ${a}backend"
done

AC_SUBST(LIBS)

export moduledirs moduleobjects modulelibs

AC_OUTPUT(Makefile modules/Makefile pdns/Makefile codedocs/Makefile \
pdns/backends/Makefile pdns/backends/bind/Makefile pdns/pdns pdns/precursor \
modules/mysqlbackend/Makefile modules/pdnsbackend/Makefile \
modules/gmysqlbackend/Makefile modules/db2backend/Makefile \
modules/geobackend/Makefile modules/opendbxbackend/Makefile \
modules/pipebackend/Makefile modules/oraclebackend/Makefile \
modules/xdbbackend/Makefile modules/godbcbackend/Makefile \
modules/odbcbackend/Makefile modules/mongodbbackend/Makefile \
modules/gpgsqlbackend/Makefile modules/ldapbackend/Makefile 
modules/gsqlitebackend/Makefile modules/gsqlite3backend/Makefile
modules/goraclebackend/Makefile modules/mydnsbackend/Makefile)
