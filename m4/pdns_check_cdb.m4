AC_DEFUN([PDNS_CHECK_CDB],[
  PKG_CHECK_MODULES([CDB], [libcdb],
    [HAVE_CDB=yes],
    [AC_MSG_ERROR([Could not find libcdb/tinycdb])]
  )
  AC_SUBST(CDB_LIBS)
  AC_SUBST(CDB_CFLAGS)
])
