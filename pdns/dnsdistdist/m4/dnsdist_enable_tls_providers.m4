AC_DEFUN([DNSDIST_ENABLE_TLS_PROVIDERS], [
  AC_MSG_CHECKING([whether to enable OpenSSL >= 3.0 TLS providers (experimental)])
  AC_ARG_ENABLE([tls-providers],
    AS_HELP_STRING([--enable-tls-providers], [enable TLS providers (experimental and requires OpenSSL >= 3.0) @<:@default=no@:>@]),
    [enable_tls_providers=$enableval],
    [enable_tls_providers=no]
  )
  AC_MSG_RESULT([$enable_tls_providers])
  AM_CONDITIONAL([HAVE_TLS_PROVIDERS], [test "x$enable_tls_providers" != "xno"])

  PKG_CHECK_MODULES([LIBSSL], [libssl >= 3.0], [
    [HAVE_LIBSSL_3_PLUS=1]
    AC_DEFINE([HAVE_LIBSSL_3_PLUS], [1], [Define to 1 if you have OpenSSL >= 3.0])
  ], [ : ])

  AM_COND_IF([HAVE_TLS_PROVIDERS], [
    AC_DEFINE([HAVE_TLS_PROVIDERS], [1], [Define to 1 if you enable OpenSSL >= 3.0 TLS providers])
    AS_IF([test "x$HAVE_LIBSSL_3_PLUS" != "x1"], [
      AC_MSG_ERROR([TLS providers support requires OpenSSL >= 3.0])
    ])
  ])
])
