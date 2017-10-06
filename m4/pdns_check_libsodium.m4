AC_DEFUN([PDNS_CHECK_LIBSODIUM], [
  AC_MSG_CHECKING([whether we will be linking in libsodium])
  AC_ARG_ENABLE([libsodium],
    AS_HELP_STRING([--enable-libsodium],[use libsodium @<:@default=auto@:>@]),
    [enable_libsodium=$enableval],
    [enable_libsodium=auto],
  )
  AC_MSG_RESULT([$enable_libsodium])

  AS_IF([test "x$enable_libsodium" != "xno"], [
    AS_IF([test "x$enable_libsodium" = "xyes" -o "x$enable_libsodium" = "xauto"], [
      PKG_CHECK_MODULES([LIBSODIUM], [libsodium], [
        AC_DEFINE([HAVE_LIBSODIUM], [1], [Define to 1 if you have libsodium])
        save_CFLAGS=$CFLAGS
        save_LIBS=$LIBS
        CFLAGS="$LIBSODIUM_CFLAGS $CFLAGS"
        LIBS="$LIBSODIUM_LIBS $LIBS"
        AC_CHECK_FUNCS([crypto_box_easy_afternm])
        CFLAGS=$save_CFLAGS
        LIBS=$save_LIBS
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([LIBSODIUM], [test "x$LIBSODIUM_LIBS" != "x"])
  AS_IF([test "x$enable_libsodium" = "xyes"], [
    AS_IF([test x"$LIBSODIUM_LIBS" = "x"], [
      AC_MSG_ERROR([libsodium requested but libraries were not found])
    ])
  ])
])
