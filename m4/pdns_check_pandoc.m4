AC_DEFUN([PDNS_CHECK_DOC_PREQ], [
  AC_CHECK_PROG([PANDOC], [pandoc], [pandoc], [no])
  AC_CHECK_PROG([MKDOCS], [mkdocs], [mkdocs], [no])

  AS_IF([test "x$PANDOC" = "xno" -o "x$MKDOCS" = "xno"], [
    AC_MSG_ERROR([pandoc or mkdocs not found])
  ])
])
