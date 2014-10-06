AC_DEFUN([PDNS_WITH_LMDB],[
    AC_CHECK_HEADERS([lmdb.h], , [AC_MSG_ERROR([lmdb header (lmdb.h) not found])])
    AC_SUBST([LMDB_LIBS])
    AC_CHECK_LIB(
        [lmdb], [mdb_env_create],
        [AC_DEFINE([HAVE_LIBLMDB], 1, [Have -llmdb]) LMDB_LIBS="-llmdb"]
    )
])
