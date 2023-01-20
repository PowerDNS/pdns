AC_DEFUN([PDNS_ENABLE_LTO],[
  AC_ARG_ENABLE([lto],
    AS_HELP_STRING([--enable-lto], [enable Link-Time Optimizations (LTO) support @<:@default=no@:>@]),
    [enable_lto=$enableval],
    [enable_lto=no]
  )

  AS_IF([test "x$enable_lto" != "xno"], [

    OLD_CXXFLAGS="$CXXFLAGS"
    OLD_LDFLAGS="$LDFLAGS"
    CXXFLAGS="-Wall -W -Werror $CXXFLAGS"

    dnl If thin is not supported, we try to fallback to auto
    AS_IF([test "x$enable_lto" == "xthin"], [
      gl_COMPILER_OPTION_IF([-flto=thin], [
        CFLAGS="-flto=thin $CFLAGS"
        CXXFLAGS="-flto=thin $OLD_CXXFLAGS"
        LDFLAGS="-flto=thin $OLD_LDFLAGS"
      ], [enable_lto=auto],
      [AC_LANG_PROGRAM([[#include <stdio.h>]],[])])
    ])

    dnl If auto is not supported, we try to fallback -flto
    AS_IF([test "x$enable_lto" == "xauto"], [
      gl_COMPILER_OPTION_IF([-flto=auto], [
        CFLAGS="-flto=auto $CFLAGS"
        CXXFLAGS="-flto=auto $OLD_CXXFLAGS"
        LDFLAGS="-flto=auto $OLD_LDFLAGS"
      ], [enable_lto=yes],
      [AC_LANG_PROGRAM([[#include <stdio.h>]],[])])
    ])

    AS_IF([test "x$enable_lto" == "xyes"], [
      gl_COMPILER_OPTION_IF([-flto], [
        CFLAGS="-flto $CFLAGS"
        CXXFLAGS="-flto $OLD_CXXFLAGS"
        LDFLAGS="-flto $OLD_LDFLAGS"
      ], [enable_lto=no],
      [AC_LANG_PROGRAM([[#include <stdio.h>]],[])])
    ])

  ], [])

  AC_MSG_CHECKING([whether link-time optimization is supported])
  AC_MSG_RESULT([$enable_lto])
])
