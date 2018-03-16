AC_DEFUN([DNSDIST_CHECK_LIBSSL], [
  AC_MSG_CHECKING([whether we will be linking in OpenSSL libssl])
  HAVE_LIBSSL=0
  AC_ARG_ENABLE([libssl],
    AS_HELP_STRING([--enable-libssl],[use OpenSSL libssl @<:@default=auto@:>@]),
    [enable_libssl=$enableval],
    [enable_libssl=auto],
  )
  AC_MSG_RESULT([$enable_libssl])

  AS_IF([test "x$enable_libssl" != "xno"], [
    AS_IF([test "x$enable_libssl" = "xyes" -o "x$enable_libssl" = "xauto"], [
      PKG_CHECK_MODULES([LIBSSL], [libssl], [
        [HAVE_LIBSSL=1]
        AC_DEFINE([HAVE_LIBSSL], [1], [Define to 1 if you have OpenSSL libssl])
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([HAVE_LIBSSL], [test "x$LIBSSL_LIBS" != "x"])
  AS_IF([test "x$enable_libssl" = "xyes"], [
    AS_IF([test x"$LIBSSL_LIBS" = "x"], [
      AC_MSG_ERROR([OpenSSL libssl requested but libraries were not found])
    ])
  ])
])
