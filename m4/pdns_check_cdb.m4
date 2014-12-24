AC_DEFUN([PDNS_CHECK_CDB],[
  PKG_CHECK_MODULES([CDB], [libcdb],
    [],
    [AC_CHECK_HEADERS([cdb.h],
      [AC_CHECK_LIB([cdb], [cdb_find],
        [CDB_LIBS="-lcdb"],
        [AC_MSG_ERROR([Could not find libcdb])]
      )],
      [AC_MSG_ERROR([Could not find cdb.h])]
    )]
  )
  AC_SUBST(CDB_LIBS)
  AC_SUBST(CDB_CFLAGS)
])
