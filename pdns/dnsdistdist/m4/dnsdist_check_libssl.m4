AC_DEFUN([DNSDIST_CHECK_LIBSSL], [
  HAVE_LIBSSL=0
  AC_MSG_CHECKING([if OpenSSL libssl is available])
  PKG_CHECK_MODULES([LIBSSL], [libssl], [
    [HAVE_LIBSSL=1],
    AC_DEFINE([HAVE_LIBSSL], [1], [Define to 1 if you have OpenSSL libssl])
  ])
  AM_CONDITIONAL([HAVE_LIBSSL], [test "x$LIBSSL_LIBS" != "x"])
])
