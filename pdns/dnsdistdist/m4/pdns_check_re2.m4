AC_DEFUN([PDNS_CHECK_RE2], [
  HAVE_RE2=0
  AC_MSG_CHECKING([if we should compile in libre2 for dnsdist])
  AC_ARG_ENABLE([re2], [AS_HELP_STRING([--enable-re2],[enable libre2 @<:@default=no@:>@])],
    [enable_re2=$enableval],
    [enable_re2=no]
  )
  AC_MSG_RESULT([$enable_re2])
  AS_IF([test "x$enable_re2" = "xyes"], [
    PKG_CHECK_MODULES([RE2], [re2], [
      HAVE_RE2=1 ], [
      AC_CHECK_HEADER([re2/re2.h], [
        AC_CHECK_LIB([re2], [main], [
          HAVE_RE2=1
          RE2_LIBS="-lre2" ], [ : ])
      ])
    ])
    AS_IF([test "$HAVE_RE2" -ne 1], [AC_MSG_ERROR([Could not find libre2])])
  ])
  AM_CONDITIONAL([HAVE_RE2], [test "$HAVE_RE2" -eq 1])
  AS_IF([test "$HAVE_RE2" -eq 1], [AC_DEFINE([HAVE_RE2], [1], [Define if using RE2.])])
])
