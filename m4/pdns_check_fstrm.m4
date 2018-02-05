AC_DEFUN([PDNS_CHECK_FSTRM], [
  AC_MSG_CHECKING([whether we will be linking in fstrm])
  AC_ARG_ENABLE([fstrm],
    AS_HELP_STRING([--enable-fstrm],[use fstrm @<:@default=auto@:>@]),
    [enable_fstrm=$enableval],
    [enable_fstrm=auto],
  )
  AC_MSG_RESULT([$enable_fstrm])

  AS_IF([test "x$enable_fstrm" != "xno"], [
    AS_IF([test "x$enable_fstrm" = "xyes" -o "x$enable_fstrm" = "xauto"], [
      PKG_CHECK_MODULES([FSTRM], [libfstrm], [
        AC_DEFINE([HAVE_FSTRM], [1], [Define to 1 if you have libfstrm])
        save_CFLAGS=$CFLAGS
        save_LIBS=$LIBS
        CFLAGS="$FSTRM_CFLAGS $CFLAGS"
        LIBS="$FSTRM_LIBS $LIBS"
        AC_CHECK_FUNCS([fstrm_tcp_writer_init])
        CFLAGS=$save_CFLAGS
        LIBS=$save_LIBS
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([FSTRM], [test "x$FSTRM_LIBS" != "x"])
  AS_IF([test "x$enable_fstrm" = "xyes"], [
    AS_IF([test x"$FSTRM_LIBS" = "x"], [
      AC_MSG_ERROR([fstrm requested but libfstrm was not found])
    ])
  ])
])
