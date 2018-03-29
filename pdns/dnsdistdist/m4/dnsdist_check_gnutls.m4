AC_DEFUN([DNSDIST_CHECK_GNUTLS], [
  AC_MSG_CHECKING([whether we will be linking in GnuTLS])
  HAVE_GNUTLS=0
  AC_ARG_ENABLE([gnutls],
    AS_HELP_STRING([--enable-gnutls],[use GnuTLS @<:@default=auto@:>@]),
    [enable_gnutls=$enableval],
    [enable_gnutls=auto],
  )
  AC_MSG_RESULT([$enable_gnutls])

  AS_IF([test "x$enable_gnutls" != "xno"], [
    AS_IF([test "x$enable_gnutls" = "xyes" -o "x$enable_gnutls" = "xauto"], [
      # we require gnutls_certificate_set_x509_key_file, added in 3.1.11
      PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.1.11], [
        [HAVE_GNUTLS=1]
        AC_DEFINE([HAVE_GNUTLS], [1], [Define to 1 if you have GnuTLS])
        save_CFLAGS=$CFLAGS
        save_LIBS=$LIBS
        CFLAGS="$GNUTLS_CFLAGS $CFLAGS"
        LIBS="$GNUTLS_LIBS $LIBS"
        AC_CHECK_FUNCS([gnutls_memset])
        CFLAGS=$save_CFLAGS
        LIBS=$save_LIBS

      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([HAVE_GNUTLS], [test "x$GNUTLS_LIBS" != "x"])
  AS_IF([test "x$enable_gnutls" = "xyes"], [
    AS_IF([test x"$GNUTLS_LIBS" = "x"], [
      AC_MSG_ERROR([GnuTLS requested but libraries were not found])
    ])
  ])
])
