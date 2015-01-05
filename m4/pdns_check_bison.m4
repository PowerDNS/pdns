AC_DEFUN([PDNS_CHECK_BISON], [
  AC_REQUIRE([AC_PROG_YACC])
  AC_REQUIRE([AC_PROG_EGREP])

  AC_CACHE_CHECK([if bison is the parser generator],[pdns_cv_prog_bison],[
    AS_IF([$YACC --version 2>/dev/null | $EGREP -q '^bison '],
      [pdns_cv_prog_bison=yes], [pdns_cv_prog_bison=no])
  ])

  AS_IF([test "x$pdns_cv_prog_bison" = "xno"], [
    AS_IF([test ! -f "${srcdir}/pdns/bindparser.cc"],
      [AC_MSG_ERROR([bison is missing and you don't have ${srcdir}/pdns/bindparser.cc. Please install bison])]
    )]
  )
])
