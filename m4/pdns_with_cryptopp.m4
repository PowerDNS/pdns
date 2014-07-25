AC_DEFUN([PDNS_WITH_CRYPTOPP],[
  AC_MSG_CHECKING([whether we will be linking in Crypto++])
  AC_ARG_ENABLE([cryptopp],
    [AS_HELP_STRING([--enable-cryptopp],[use Crypto++ @<:@default=no@:>@])],
    [enable_cryptopp=$enableval],
    [enable_cryptopp=no],
  )
  AC_MSG_RESULT([$enable_cryptopp])
  AM_CONDITIONAL([CRYPTOPP], [test "x$enable_cryptopp" != "xno"])

  AS_IF([test "x$enable_cryptopp" != "xno"], [
    PKG_CHECK_MODULES([CRYPTOPP], [libcrypto++], [
      AC_DEFINE([HAVE_CRYPTOPP], [1], [Define to 1 if you have crypto++])
    ],[
      PKG_CHECK_MODULES([CRYPTOPP], [cryptopp],
       [AC_DEFINE([HAVE_CRYPTOPP], [1], [Define to 1 if you have cryptopp])
      ],[
        AC_MSG_ERROR([Could not find crypto++])
      ])
    ])
  ])
])
