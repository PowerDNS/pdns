AC_DEFUN([PDNS_WITH_SQLITE3], [
  AC_MSG_CHECKING([whether user requires sqlite3])
  AC_ARG_WITH([sqlite3],
    [AS_HELP_STRING([--with-sqlite3],[include sqlite3 driver @<:@default=no@:>@])],
    [with_sqlite3=$withval],
    [with_sqlite3=no]
  )
  AC_MSG_RESULT([$with_sqlite3])

  AS_IF([test "x$with_sqlite3" != "xno"], [
    needsqlite3=yes
  ])
])
