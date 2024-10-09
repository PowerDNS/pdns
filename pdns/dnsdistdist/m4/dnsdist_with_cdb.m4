AC_DEFUN([DNSDIST_WITH_CDB], [
  AC_MSG_CHECKING([whether we will we linking with libcdb])
  HAVE_CDB=0
  AC_ARG_WITH([cdb],
    AS_HELP_STRING([--with-cdb], [use CDB @<:@default=auto@:>@]),
    [with_cdb=$withval],
    [with_cdb=auto]
  )
  AC_MSG_RESULT([$with_cdb])

  AS_IF([test "x$with_cdb" != "xno"], [
    AS_IF([test "x$with_cdb" = "xyes" -o "x$with_cdb" = "xauto"], [
      PKG_CHECK_MODULES([CDB], [libcdb], [
        [HAVE_CDB=1]
        AC_DEFINE([HAVE_CDB], [1], [Define to 1 if you have CDB])
        ],
        [AC_CHECK_HEADERS([cdb.h],
          [AC_CHECK_LIB([cdb], [cdb_find],
            [
              CDB_LIBS="-lcdb"
              AC_DEFINE([HAVE_CDB], [1], [Define to 1 if you have CDB])
              [HAVE_CDB=1]
            ],
            [:]
          )],
          [:]
        )]
      )
    ])
  ])
  AC_SUBST(CDB_LIBS)
  AC_SUBST(CDB_CFLAGS)
  AM_CONDITIONAL([HAVE_CDB], [test "x$CDB_LIBS" != "x"])
  AS_IF([test "x$with_cdb" = "xyes"], [
    AS_IF([test x"$CDB_LIBS" = "x"], [
      AC_MSG_ERROR([CDB requested but libraries were not found])
    ])
  ])
])
