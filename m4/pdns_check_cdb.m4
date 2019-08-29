AC_DEFUN([PDNS_CHECK_CDB],[
  PKG_CHECK_MODULES([CDB], [libcdb], [
    AC_DEFINE([HAVE_CDB], [1], [Define to 1 if you have CDB])
    [HAVE_CDB=1]
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
  AC_SUBST(CDB_LIBS)
  AC_SUBST(CDB_CFLAGS)
  AM_CONDITIONAL([HAVE_CDB], [test "x$CDB_LIBS" != "x"])
])
