AC_DEFUN([PDNS_ENABLE_COVERAGE], [
  AC_MSG_CHECKING([whether to enable code coverage])
  AC_ARG_ENABLE([coverage],
    AS_HELP_STRING([--enable-coverage],
      [enable code coverage @<:@default=no@:>@]),
    [enable_coverage=$enableval],
    [enable_coverage=no]
  )
  AC_MSG_RESULT([$enable_coverage])
  AS_IF([test "x$enable_coverage" != "xno"], [
    gl_COMPILER_OPTION_IF([-fprofile-arcs -ftest-coverage], [
      CXXFLAGS="$CXXFLAGS -U_FORTIFY_SOURCE -g -O0 -fprofile-arcs -ftest-coverage"
    ], [
      AC_MSG_ERROR([$CXX does not support gathering coverage data])
    ])
  ])
])
