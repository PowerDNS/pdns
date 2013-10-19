AC_DEFUN([PDNS_WITH_CRYPTOPP],[
  AC_MSG_CHECKING([whether we will be linking in Crypto++])
  AC_ARG_ENABLE([cryptopp],
    AS_HELP_STRING([--enable-cryptopp],
      [use Crypto++]),
    [enable_cryptopp=yes],
    [enable_cryptopp=no]
  )
  AC_MSG_RESULT([$enable_cryptopp])
  AM_CONDITIONAL([CRYPTOPP], [test "x$enable_cryptopp" = "xyes"])

  AS_IF([test "x$enable_cryptopp" = "xyes"],
    [AC_DEFINE([HAVE_CRYPTOPP], [1], [Define to 1 if you have crypto++])]
  )
])

