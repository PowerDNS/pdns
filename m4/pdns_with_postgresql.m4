AC_DEFUN([PDNS_WITH_POSTGRESQL],[
  AC_ARG_WITH([pgsql],
    AS_HELP_STRING([--with-pgsql=<path>],
      [root directory path of PgSQL installation]
   ),
   [PGSQL_lib_check="$withval/lib/pgsql $with_pgsql/lib"
    PGSQL_inc_check="$withval/include/pgsql"
   ],
   [PGSQL_lib_check="/usr/local/pgsql/lib/pgsql /usr/local/lib/pgsql /opt/pgsql/lib/pgsql /usr/lib/pgsql /usr/local/pgsql/lib /usr/local/lib /opt/pgsql/lib /usr/lib /usr/lib64"
    PGSQL_inc_check="/usr/local/pgsql/include/pgsql /usr/include /usr/local/include/postgresql/ /usr/local/include /opt/pgsql/include/pgsql /opt/pgsql/include /usr/include/pgsql/ /usr/include/postgresql"
   ]
  )

  AC_ARG_WITH([pgsql-lib],
    AS_HELP_STRING([--with-pgsql-lib=<path>],
      [directory path of PgSQL library installation]
    ),
    [PGSQL_lib_check="$withval/lib/pgsql $withval/pgsql $withval"]
  )

  AC_ARG_WITH([pgsql-includes],
    AS_HELP_STRING([--with-pgsql-includes=<path>],
      [directory path of PgSQL header installation]
    ),
    [PGSQL_inc_check="$withval/include/pgsql $withval/pgsql $withval"]i
  )

  AC_MSG_CHECKING([for PgSQL library directory])
  PGSQL_libdir=
  for m in $PGSQL_lib_check; do
    if test -d "$m" && (test -f "$m/libpq.a" || test -f "$m/libpq.so"); then
      PGSQL_libdir=$m
      break
    fi
  done
  if test -z "$PGSQL_libdir"; then
    AC_MSG_ERROR([Did not find the pgsql library dir in '$PGSQL_lib_check'])
  fi
  case "$PGSQL_libdir" in
    /usr/lib)
      PGSQL_lib=""
      ;;
    /usr/lib64)
      PGSQL_lib=""
      ;;
    /*)
      PGSQL_lib="-L$PGSQL_libdir -Wl,-rpath,$PGSQL_libdir"
      LDFLAGS="$PGSQL_lib $LDFLAGS"
      ;;
    *)
      AC_MSG_ERROR([The PgSQL library directory ($PGSQL_libdir) must be an absolute path.])
      ;;
  esac

  AC_SUBST(PGSQL_lib)
  AC_MSG_RESULT([$PGSQL_libdir])
  AC_MSG_CHECKING([for PgSQL include directory])
  PGSQL_incdir=
  for m in $PGSQL_inc_check; do
    if test -d "$m" && test -f "$m/libpq-fe.h"; then
      PGSQL_incdir=$m
      break
    fi
  done
  if test -z "$PGSQL_incdir"; then 
    AC_MSG_ERROR([Did not find the PgSQL include dir in '$PGSQL_inc_check'])
  fi
  case "$PGSQL_incdir" in
    /* )
      ;;
    * )
      AC_MSG_ERROR([The PgSQL include directory ($PGSQL_incdir) must be an absolute path.])
      ;;
  esac
  AC_SUBST(PGSQL_incdir)
  AC_MSG_RESULT([$PGSQL_incdir])
])

