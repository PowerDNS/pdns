AC_DEFUN([PDNS_CHECK_DNSTAP], [
  AC_MSG_CHECKING([whether we will have dnstap])
  AC_ARG_ENABLE([dnstap],
    AS_HELP_STRING([--enable-dnstap],[enable dnstap support @<:@default=$1@:>@]),
    [enable_dnstap=$enableval],
    [enable_dnstap=$1],
  )
  AC_MSG_RESULT([$enable_dnstap])

  AS_IF([test "x$enable_dnstap" != "xno"], [
    AS_IF([test "x$enable_dnstap" = "xyes" -o "x$enable_dnstap" = "xauto"], [
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
  AS_IF([test "x$enable_dnstap" = "xyes"], [
    AS_IF([test x"$FSTRM_LIBS" = "x"], [
      AC_MSG_ERROR([dnstap requested but libfstrm was not found])
    ])
  ])
])
