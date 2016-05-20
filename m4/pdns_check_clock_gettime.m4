AC_DEFUN([PDNS_CHECK_CLOCK_GETTIME],[
  OLD_LIBS="$LIBS"; LIBS=""
  AC_SEARCH_LIBS([clock_gettime], [rt], [AC_DEFINE(HAVE_CLOCK_GETTIME, [1], [Define to 1 if you have clock_gettime])])
  AC_SUBST([RT_LIBS],[$LIBS])
  LIBS="$OLD_LIBS"
])
