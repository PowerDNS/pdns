AC_DEFUN([PDNS_CHECK_MKDOCS], [
  AC_REQUIRE([AC_PROG_EGREP])
  AC_CHECK_PROG([MKDOCS], [mkdocs], [yes], [no])

  AS_IF([test "x$MKDOCS" = "xno"], [
    AS_IF([test ! -d "$scrdir/pdns/docs/html" ],
      [AC_MSG_WARN([mkdocs is missing, unable to build documentation.])]
    )
  ])
])
