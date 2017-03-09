AC_DEFUN([PDNS_ENABLE_VALGRIND],[
  AC_MSG_CHECKING([whether to enable Valgrind support])
  AC_ARG_ENABLE([valgrind],
    AS_HELP_STRING([--enable-valgrind],[enable Valgrind support @<:@default=no@:>@]),
    [enable_valgrind=$enableval],
    [enable_valgrind=no],
  )
  AC_MSG_RESULT([$enable_valgrind])

  AS_IF([test "x$enable_valgrind" != "xno"], [
    AS_IF([test "x$enable_valgrind" = "xyes" -o "x$enable_valgrind" = "xauto"], [
      AC_CHECK_HEADERS([valgrind/valgrind.h], valgrind_headers=yes, valgrind_headers=no)
    ])
  ])
  AS_IF([test "x$enable_valgrind" = "xyes"], [
    AS_IF([test x"$valgrind_headers" = "no"], [
      AC_MSG_ERROR([Valgrind support requested but required Valgrind headers were not found])
    ])
  ])
  AM_CONDITIONAL([PDNS_USE_VALGRIND], [test x"$valgrind_headers" = "xyes" ])
  AS_IF([test x"$valgrind_headers" = "xyes" ],
    [ AC_DEFINE([PDNS_USE_VALGRIND], [1], [Define if using Valgrind.]) ],
  )
])
