dnl invoking this makes lmdb a requirement
AC_DEFUN([PDNS_CHECK_LMDB], [
  AC_MSG_CHECKING([where to find the lmdb library and headers])
  AC_ARG_WITH([lmdb],
    AC_HELP_STRING([--with-lmdb], [lmdb library to use @<:@default=auto@:>@]),[
    with_lmdb=$withval
    ],[
    with_lmdb=auto
  ])
  AC_MSG_RESULT([$with_lmdb])

  AS_IF([test "$with_lmdb" != "no"], [
    AS_IF([test "x$with_lmdb" = "xyes" -o "x$with_lmdb" = "xauto"], [
      PKG_CHECK_MODULES([LMDB], [lmdb], [
        AC_DEFINE([HAVE_LMDB], [1], [Define to 1 if you have LMDB])
        [HAVE_LMDB=1]
        ], [ : ]
      )
    ], [
      save_CPPFLAGS=$CPPFLAGS
      save_LIBS=$LIBS
      AS_IF([test -d "$with_lmdb/include"], [
        LMDB_CFLAGS="-I$with_lmdb/include"
        LMDB_LIBS="-L$with_lmdb/lib"
      ],[
        LMDB_CFLAGS="-I$with_lmdb"
        LMDB_LIBS="-L$with_lmdb"
      ])
      CPPFLAGS="$LMDB_CFLAGS"
      LIBS="$LMDB_LIBS"

      AC_SEARCH_LIBS([mdb_env_open], [lmdb], [
        AC_CHECK_HEADERS([lmdb.h], [
          dnl ac_cv_search_mdb_env_open contains '-llmdb'
          LMDB_LIBS="$LMDB_LIBS $ac_cv_search_mdb_env_open"
          AC_DEFINE([HAVE_LMDB], [1], [Define to 1 if you have LMDB])
          [HAVE_LMDB=1]
        ], [
          AC_MSG_ERROR([lmdb headers not found in $with_lmdb])
        ])
        CPPFLAGS="$save_CPPFLAGS"
        LIBS="$save_LIBS"
        AC_SUBST([LMDB_CFLAGS])
        AC_SUBST([LMDB_LIBS])
      ])
    ])
  ])
  AM_CONDITIONAL([HAVE_LMDB], [test "x$LMDB_LIBS" != "x"])
])
