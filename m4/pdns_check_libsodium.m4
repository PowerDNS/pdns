AC_DEFUN([PDNS_CHECK_LIBSODIUM], [
  AC_MSG_CHECKING([whether we will be linking in libsodium])
  AC_ARG_ENABLE([libsodium],
    AS_HELP_STRING([--enable-libsodium],[use libsodium @<:@default=no@:>@]),
    [enable_libsodium=$enableval],
    [enable_libsodium=no],
  )
  AC_MSG_RESULT([$enable_libsodium])

  AM_CONDITIONAL([LIBSODIUM], [test "x$enable_libsodium" != "xno"])

  AM_COND_IF([LIBSODIUM], [
    PKG_CHECK_MODULES([LIBSODIUM], [libsodium], [
      AC_DEFINE([HAVE_LIBSODIUM], [1], [Define to 1 if you have libsodium])
    ],[
      AC_MSG_ERROR([libsodium requested but not available])
    ])
  ])
])
