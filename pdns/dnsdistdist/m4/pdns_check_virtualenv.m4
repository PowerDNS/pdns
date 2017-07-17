AC_DEFUN([PDNS_CHECK_VIRTUALENV], [
  AC_CHECK_PROG([VIRTUALENV], [virtualenv], [virtualenv], [no])

  AS_IF([test "x$VIRTUALENV" = "xno"], [
    AS_IF([test ! -f "$srcdir/dnsdist.1"],
      [AC_MSG_WARN([virtualenv is missing, unable to build manpages.])]
    )
  ])
  AM_CONDITIONAL([HAVE_VIRTUALENV], [test "x$VIRTUALENV" != "xno"])
  AM_CONDITIONAL([HAVE_MANPAGES], [test -e "$srcdir/dnsdist.1"])
])

