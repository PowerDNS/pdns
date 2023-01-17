dnl
dnl Check for support for enabling initialization of automatic variables
dnl

AC_DEFUN([PDNS_INIT_AUTO_VARS],[
  AC_MSG_CHECKING([whether to enable initialization of automatic variables])
  AC_ARG_ENABLE([auto-var-init],
    AS_HELP_STRING([--enable-auto-var-init],[enable initialization of automatic variables (zero, pattern) @<:@default=no@:>@]),
    [enable_initautovars=$enableval],
    [enable_initautovars=no],
  )
  AC_MSG_RESULT([$enable_initautovars])

  AS_IF([test "x$enable_initautovars" = "xyes"], [
    [enable_initautovars=zero]
  ])

  AS_IF([test "x$enable_initautovars" = "xzero" ], [
    gl_COMPILER_OPTION_IF([-ftrivial-auto-var-init=zero], [
      CFLAGS="-ftrivial-auto-var-init=zero $CFLAGS"
      CXXFLAGS="-ftrivial-auto-var-init=zero $CXXFLAGS"
    ])
  ])

  AS_IF([test "x$enable_initautovars" = "xpattern" ], [
    gl_COMPILER_OPTION_IF([-ftrivial-auto-var-init=pattern], [
      CFLAGS="-ftrivial-auto-var-init=pattern $CFLAGS"
      CXXFLAGS="-ftrivial-auto-var-init=pattern $CXXFLAGS"
    ])
  ])
])
