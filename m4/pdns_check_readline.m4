AC_DEFUN([PDNS_CHECK_READLINE], [
  OLD_LIBS="$LIBS"
  LIBS=""
  AX_LIB_READLINE
  AC_SUBST([READLINE_LIBS], [$LIBS])
  LIBS="$OLDLIBS"
  AS_IF([test "$1" = "mandatory"],[
    AS_IF([test x"$READLINE_LIBS" = "x"],[
      AC_MSG_ERROR([readline support is mandatory])
    ])
  ])
])
