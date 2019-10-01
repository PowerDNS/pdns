AC_DEFUN([PDNS_ENABLE_NOD],[
  AC_MSG_CHECKING([whether to enable newly observed domain checking])

  AC_ARG_ENABLE([nod],
    AS_HELP_STRING([--enable-nod],
      [enable newly observed domains @<:@default=yes@:>@]
    ),
    [enable_nod=$enableval],
    [enable_nod=yes]
  )

  AS_IF([test "x$enable_nod" != "xno"],
    [AC_DEFINE([NOD_ENABLED], [1], [Define to 1 if nod is enabled])]
  )

  AM_CONDITIONAL([NOD_ENABLED], [test "x$enable_nod" != "xno"])

  AC_MSG_RESULT([$enable_nod])
])
