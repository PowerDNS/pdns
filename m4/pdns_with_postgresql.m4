dnl
dnl Attempt to detect the flags we need for the Postgresql client libraries
dnl First, use pkg-config
dnl If that yields no results, use (optionally find) pg_config and use it to 
dnl determine the CFLAGS and LIBS
dnl
AC_DEFUN([PDNS_WITH_POSTGRESQL], [
  PG_CONFIG=""
  AC_ARG_WITH([pg-config],
    [AS_HELP_STRING([--with-pg-config=<path>], [path to pg_config])
  ], [
    PG_CONFIG="$withval"
    AS_IF([test "x$PG_CONFIG" = "xyes" -o ! -x "$PG_CONFIG"], [
      AC_MSG_ERROR([--with-pg-config must provide a valid path to the pg_config executable])
    ])
  ])

  AS_IF([test "x$PG_CONFIG" = "x"], [
    PKG_CHECK_MODULES([PGSQL], [libpq], [ : ], [ : ])
  ])

  AS_IF([test "x$PG_CONFIG" != "x" -o "x$PGSQL_LIBS" = "x"], [
    dnl Either a path was provided, or pkg-config failed to produce a result
    AS_IF([test "x$PG_CONFIG" == "x"], [
      AC_PATH_PROG([PG_CONFIG], [pg_config])
    ])
    AS_IF([test "x$PG_CONFIG" == "x"], [
      AC_MSG_ERROR([Can not find pg_config, use --with-pg-config to specify the path to pg_config])
    ])
    PGSQL_LIBS="-L$($PG_CONFIG --libdir) -lpq"
    PGSQL_CFLAGS="-I$($PG_CONFIG --includedir)"
  ])
  AC_SUBST([PGSQL_LIBS])
  AC_SUBST([PGSQL_CFLAGS])
])
