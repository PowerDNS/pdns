AC_DEFUN([PDNS_ENABLE_IPCRYPT2], [
  AC_MSG_CHECKING([whether to enable ipcrypt2 support])
  AC_ARG_ENABLE([ipcrypt2],
    AS_HELP_STRING([--enable-ipcrypt2], [enable ipcrypt2 support @<:@default=no@:>@]),
    [enable_ipcrypt2=$enableval],
    [enable_ipcrypt2=no]
  )

  AC_MSG_RESULT([$enable_ipcrypt2])

  HAVE_IPCRYPT2=0

  AS_IF([test "x$enable_ipcrypt2" != "xno"], [
    AC_CANONICAL_BUILD()
    AS_IF([test "$build_cpu" = "aarch64"], [
      AC_MSG_CHECKING([whether the compiler supports calculations with uint64x2_t])
      AC_LANG_PUSH([C++])
      AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#    if defined(_MSC_VER) && defined(_M_ARM64)
#        include <arm64_neon.h>
#    else
#        include <arm_neon.h>
#    endif
int main() {
  uint64x2_t foo = {0, 0};
  uint64x2_t bar = vshrq_n_u8(foo, 1);
  return 0;
}
        ])],[
        [HAVE_IPCRYPT2=1]
        AC_MSG_RESULT([ok])
      ], [
        AC_MSG_RESULT([no])
      ])
      AC_LANG_POP()
    ], [
        [HAVE_IPCRYPT2=1]
        AC_MSG_RESULT([ok])
    ])
  ])

  AM_CONDITIONAL([HAVE_IPCRYPT2], [test "x$HAVE_IPCRYPT2" != "x0"])

  AS_IF([test "x$enable_ipcrypt2" != "xno"], [
    AS_IF([test x"$HAVE_IPCRYPT2" = "x0"], [
      AC_MSG_ERROR([ipcrypt2 support requested but is not available])
    ])
  ])

  AM_COND_IF([HAVE_IPCRYPT2], [
    AC_DEFINE([HAVE_IPCRYPT2], [1], [Define to 1 if you enable ipcrypt2 support])
  ])
])
