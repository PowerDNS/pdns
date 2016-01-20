AC_DEFUN([PDNS_CHECK_PANDOC], [
  AC_CHECK_PROG([PANDOC], [pandoc], [pandoc], [no])

  AS_IF([test "x$PANDOC" = "xno"], [
    AS_IF([test ! -f "$srcdir/pdns_recursor.1"],
      [AC_MSG_WARN([pandoc is missing, unable to build manpages.])]
    )
  ])
  AM_CONDITIONAL([HAVE_PANDOC], [test "x$PANDOC" != "xno"])
  AM_CONDITIONAL([HAVE_MANPAGES], [test -e "$srcdir/pdns_recursor.1"])
])
