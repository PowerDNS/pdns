AC_DEFUN([PDNS_ENABLE_LTO],[
  AC_ARG_ENABLE([lto],
    AS_HELP_STRING([--enable-lto], [enable Link-Time Optimizations (LTO) support @<:@default=no@:>@]),
    [enable_lto=$enableval],
    [enable_lto=no]
  )

  AS_IF([test "$enable_lto" != "no"], [

    dnl If thin is not supported, we try to fallback to auto
    AS_IF([test "$enable_lto" = "thin"], [
      gl_COMPILER_OPTION_IF([-flto=thin], [
        CFLAGS="-flto=thin $CFLAGS"
        CXXFLAGS="-flto=thin $CXXFLAGS"
        LDFLAGS="-flto=thin $LDFLAGS"
      ], [enable_lto=auto])
    ])

    dnl If auto is not supported, we try to fallback -flto
    AS_IF([test "$enable_lto" = "auto"], [
      gl_COMPILER_OPTION_IF([-flto=auto], [
        CFLAGS="-flto=auto $CFLAGS"
        CXXFLAGS="-flto=auto $CXXFLAGS"
        LDFLAGS="-flto=auto $LDFLAGS"
      ], [enable_lto=yes])
    ])

    AS_IF([test "$enable_lto" = "yes"], [
      gl_COMPILER_OPTION_IF([-flto], [
        CFLAGS="-flto $CFLAGS"
        CXXFLAGS="-flto $CXXFLAGS"
        LDFLAGS="-flto $LDFLAGS"
      ], [enable_lto=no])
    ])
  ])

  AC_MSG_CHECKING([whether link-time optimization is supported])
  AC_MSG_RESULT([$enable_lto])
])
