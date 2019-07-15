AC_DEFUN([PDNS_CHECK_VIRTUALENV], [
  AC_CHECK_PROG([VIRTUALENV], [virtualenv], [virtualenv], [no])

  AS_IF([test "x$VIRTUALENV" = "xno"], [
    AS_IF([test ! -f "$srcdir/pdns_server.8"],
      [AC_MSG_WARN([virtualenv is missing, unable to build manpages.])]
    )
  ])
  AM_CONDITIONAL([HAVE_VIRTUALENV], [test "x$VIRTUALENV" != "xno"])
  AM_CONDITIONAL([HAVE_MANPAGES], [test -e "$srcdir/docs/pdns_server.8"])
])

