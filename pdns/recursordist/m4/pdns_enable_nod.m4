AC_DEFUN([PDNS_ENABLE_NOD],[
  AC_MSG_CHECKING([whether to enable newly observed domain checking])

  AC_ARG_ENABLE([nod],
    AS_HELP_STRING([--enable-nod],
      [enable newly observed domains @<:@default=auto@:>@]
    ),
    [enable_nod=$enableval],
    [enable_nod=auto]
  )

  BOOST_FILESYSTEM([], [no])

  AS_IF([test "x$enable_nod" = "xyes"], [
    AS_IF([test "x$BOOST_FILESYSTEM_LIBS" = "x"],
      [AC_MSG_ERROR([Boost filesystem library required by NOD is not installed])])
  ]
  )
  AS_IF([test "x$enable_nod" = "xauto"], [
    AS_IF([test "x$BOOST_FILESYSTEM_LIBS" != "x"],
       [enable_nod="yes"], [enable_nod="no"])
  ])

  AM_CONDITIONAL([NOD_ENABLED], [test "x$enable_nod" = "xyes"])
  AS_IF([test "x$enable_nod" = "xyes"], [AC_DEFINE([NOD_ENABLED],
             [1], [Define to 1 if nod is enabled])])

  AC_MSG_RESULT([$enable_nod])
])
