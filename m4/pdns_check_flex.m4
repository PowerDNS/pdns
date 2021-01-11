AC_DEFUN([PDNS_CHECK_FLEX], [
  AC_PROG_LEX(noyywrap)
  AC_REQUIRE([AC_PROG_EGREP])

  AC_CACHE_CHECK([if the lexer is flex],[pdns_cv_prog_flex],[
    AS_IF([$LEX --version 2>/dev/null | $EGREP -q '^flex '],
      [pdns_cv_prog_flex=yes], [pdns_cv_prog_flex=no])
  ])

  AS_IF([test "x$pdns_cv_prog_flex" = "xno"], [
    AS_IF([test ! -f "${srcdir}/pdns/bindlexer.c"],
      [AC_MSG_ERROR([flex is missing and you don't have ${srcdir}/pdns/bindlexer.c. Please install flex])]
    )]
  )
])
