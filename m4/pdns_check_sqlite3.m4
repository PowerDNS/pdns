AC_DEFUN([PDNS_CHECK_SQLITE3], [
  AS_IF([test "x$needsqlite3" = "xyes"], [
    PKG_CHECK_MODULES([SQLITE3], [sqlite3],
      [AC_DEFINE([HAVE_SQLITE3], [1], [Define to 1 if you have sqlite3])],
      [AC_MSG_ERROR([Could not find libsqlite3])]
    )
  ])
])
