AC_DEFUN([PDNS_ENABLE_STATIC_ANALYSIS], [
  AC_MSG_CHECKING([whether to enable static analysis])
  AC_ARG_ENABLE([static-analysis],
    AS_HELP_STRING([--enable-static-analysis],
      [enable code coverage @<:@default=no@:>@]),
    [enable_static_analysis=$enableval],
    [enable_static_analysis=no]
  )
  AC_MSG_RESULT([$enable_static_analysis])
  STATIC_ANALYSIS_LDFLAGS=""
  AS_IF([test "x$enable_static_analysis" != "xno"], [
    AX_CHECK_COMPILE_FLAG([[--analyze]], [
      STATIC_ANALYSIS_LDFLAGS="-export-symbols"
    ], [
      AC_MSG_ERROR([$CXX does not support --analyze])
    ])
  ])
  AM_CONDITIONAL([HAVE_STATIC_ANALYSIS], [ test -n "$STATIC_ANALYSIS_LDFLAGS" ])
])

