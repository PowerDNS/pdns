AC_DEFUN([PDNS_WITH_NGHTTP2], [
  AC_MSG_CHECKING([whether we will be linking in nghttp2])
  HAVE_NGHTTP2=0
  AC_ARG_WITH([nghttp2],
    AS_HELP_STRING([--with-nghttp2],[use nghttp2 @<:@default=auto@:>@]),
    [with_nghttp2=$withval],
    [with_nghttp2=auto],
  )
  AC_MSG_RESULT([$with_nghttp2])

  AS_IF([test "x$with_nghttp2" != "xno"], [
    AS_IF([test "x$with_nghttp2" = "xyes" -o "x$with_nghttp2" = "xauto"], [
      PKG_CHECK_MODULES([NGHTTP2], [libnghttp2], [
        [HAVE_NGHTTP2=1]
        AC_DEFINE([HAVE_NGHTTP2], [1], [Define to 1 if you have nghttp2])
        save_CFLAGS=$CFLAGS
        save_LIBS=$LIBS
        CFLAGS="$NGHTTP2_CFLAGS $CFLAGS"
        LIBS="$NGHTTP2_LIBS $LIBS"
        AC_CHECK_FUNCS([nghttp2_check_header_value_rfc9113 nghttp2_check_method nghttp2_check_path])
        CFLAGS=$save_CFLAGS
        LIBS=$save_LIBS
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([HAVE_NGHTTP2], [test "x$NGHTTP2_LIBS" != "x"])
  AS_IF([test "x$with_nghttp2" = "xyes"], [
    AS_IF([test x"$NGHTTP2_LIBS" = "x"], [
      AC_MSG_ERROR([nghttp2 requested but libraries were not found])
    ])
  ])
])
