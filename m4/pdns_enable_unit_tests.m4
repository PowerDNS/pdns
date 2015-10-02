AC_DEFUN([PDNS_ENABLE_UNIT_TESTS], [
  AC_MSG_CHECKING([whether to enable unit test building])
  AC_ARG_ENABLE([unit-tests],
    AS_HELP_STRING([--enable-unit-tests],
      [enable unit test building @<:@default=no@:>@]),
    [enable_unit_tests=$enableval],
    [enable_unit_tests=no]
  )
  AC_MSG_RESULT([$enable_unit_tests])
  AM_CONDITIONAL([UNIT_TESTS], [test "x$enable_unit_tests" != "xno"])

  AC_MSG_CHECKING([whether to enable backend unit test building])
  AC_ARG_ENABLE([backend-unit-tests],
    AS_HELP_STRING([--enable-backend-unit-tests],
      [enable backend unit test building @<:@default=no@:>@]),
    [enable_backend_unit_tests=$enableval],
    [enable_backend_unit_tests=no]
  )
  AC_MSG_RESULT([$enable_backend_unit_tests])
  AM_CONDITIONAL([BACKEND_UNIT_TESTS], [test "x$enable_backend_unit_tests" != "xno"])

  AS_IF([test "x$enable_unit_tests" != "xno" || test "x$enable_backend_unit_tests" != "xno"], [
     BOOST_TEST([mt])
   ])
])
