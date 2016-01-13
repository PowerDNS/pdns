AC_DEFUN([PDNS_CHECK_LIBEDIT], [
  PKG_CHECK_MODULES(LIBEDIT, libedit, [], [
    AS_IF([test "$1" = "mandatory"],[
      AS_IF([test x"$LIBEDIT_LIBS" = "x"],[
        AC_MSG_ERROR([libedit support is mandatory])
      ])
    ])
  ])
])
