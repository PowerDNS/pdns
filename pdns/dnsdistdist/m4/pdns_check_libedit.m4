AC_DEFUN([PDNS_WITH_LIBEDIT], [
  AC_MSG_CHECKING([whether to link in libedit])
  AC_ARG_WITH([libedit],
    AS_HELP_STRING([--with-libedit], [enable libedit support @<:@default=yes@:>@]),
    [with_libedit=$enableval],
    [with_libedit=yes]
  )
  AC_MSG_RESULT([$with_libedit])

  AS_IF([test "x$with_libedit" != "xno"], [
    AS_IF([test "x$with_libedit" = "xyes" -o "x$with_libedit" = "xauto"], [
      PKG_CHECK_MODULES([LIBEDIT], [libedit], [
        [HAVE_LIBEDIT=1]
        AC_DEFINE([HAVE_LIBEDIT], [1], [Define to 1 if you have libedit])
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([HAVE_LIBEDIT], [test "x$LIBEDIT_LIBS" != "x"])
  AS_IF([test "x$with_libedit" = "xyes"], [
    AS_IF([test x"$LIBEDIT_LIBS" = "x"], [
      AC_MSG_ERROR([libedit support requested but library not found])
    ])
  ])
])
