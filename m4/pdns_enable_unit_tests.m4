AC_DEFUN([PDNS_ENABLE_UNIT_TESTS], [
  AC_MSG_CHECKING([whether to enable unit test building])
  AC_ARG_ENABLE([unit-tests],
    AS_HELP_STRING([--enable-unit-tests],
      [enable unit test building @<:@default=no@:>@]),
    [enable_unit_tests=$enableval],
    [enable_unit_tests=no]
  )
  AC_MSG_RESULT([$enable_unit_tests])
  AS_IF([test "x$enable_unit_tests" != "xno"], [
     BOOST_TEST([mt])
   ])
])
