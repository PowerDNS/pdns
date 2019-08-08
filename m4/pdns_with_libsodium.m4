AC_DEFUN([PDNS_WITH_LIBSODIUM], [
  AC_MSG_CHECKING([whether we will be linking in libsodium])
  AC_ARG_WITH([libsodium],
    AS_HELP_STRING([--with-libsodium],[use libsodium @<:@default=auto@:>@]),
    [with_libsodium=$withval],
    [with_libsodium=auto],
  )
  AC_MSG_RESULT([$with_libsodium])

  AS_IF([test "x$with_libsodium" != "xno"], [
    AS_IF([test "x$with_libsodium" = "xyes" -o "x$with_libsodium" = "xauto"], [
      PKG_CHECK_MODULES([LIBSODIUM], [libsodium], [
        AC_DEFINE([HAVE_LIBSODIUM], [1], [Define to 1 if you have libsodium])
        save_CFLAGS=$CFLAGS
        save_LIBS=$LIBS
        CFLAGS="$LIBSODIUM_CFLAGS $CFLAGS"
        LIBS="$LIBSODIUM_LIBS $LIBS"
        AC_CHECK_FUNCS([crypto_box_easy_afternm crypto_box_curve25519xchacha20poly1305_easy randombytes_stir])
        CFLAGS=$save_CFLAGS
        LIBS=$save_LIBS
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([LIBSODIUM], [test "x$LIBSODIUM_LIBS" != "x"])
  AS_IF([test "x$with_libsodium" = "xyes"], [
    AS_IF([test x"$LIBSODIUM_LIBS" = "x"], [
      AC_MSG_ERROR([libsodium requested but libraries were not found])
    ])
  ])
])
