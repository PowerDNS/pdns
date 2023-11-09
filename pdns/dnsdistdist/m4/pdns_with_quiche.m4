AC_DEFUN([PDNS_WITH_QUICHE], [
  AC_MSG_CHECKING([whether we will be linking in quiche])
  HAVE_QUICHE=0
  AC_ARG_WITH([quiche],
    AS_HELP_STRING([--with-quiche],[use quiche @<:@default=auto@:>@]),
    [with_quiche=$withval],
    [with_quiche=auto],
  )
  AC_MSG_RESULT([$with_quiche])

  AS_IF([test "x$with_quiche" != "xno"], [
    AS_IF([test "x$with_quiche" = "xyes" -o "x$with_quiche" = "xauto"], [
      PKG_CHECK_MODULES([QUICHE], [quiche >= 0.15.0], [
        [HAVE_QUICHE=1]
        AC_DEFINE([HAVE_QUICHE], [1], [Define to 1 if you have quiche])
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([HAVE_QUICHE], [test "x$QUICHE_LIBS" != "x"])
  AS_IF([test "x$with_quiche" = "xyes"], [
    AS_IF([test x"$QUICHE_LIBS" = "x"], [
      AC_MSG_ERROR([quiche requested but libraries were not found])
    ])
  ])
])
