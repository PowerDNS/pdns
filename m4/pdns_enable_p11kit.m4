AC_DEFUN([PDNS_ENABLE_PKCS11],[
  AC_MSG_CHECKING([whether to enable PKCS11 support])
  AC_ARG_ENABLE([experimental-pkcs11],
    [AS_HELP_STRING([--enable-experimental-pkcs11],[enable experimental PKCS11 support @<:@default=no@:>@])],
    [enable_pkcs11=yes],
    [enable_pkcs11=no]
  )
  AC_MSG_RESULT([$enable_pkcs11])
  AM_CONDITIONAL([PKCS11], [test "x$enable_pkcs11" = "xyes"])

  AS_IF([test "x$enable_pkcs11" = "xyes"], [
    PKG_CHECK_MODULES([P11KIT1], [p11-kit-1],
      [AC_DEFINE([HAVE_P11KIT1],[1],[Define to 1 if you have p11-kit-1])],
      [AC_MSG_ERROR([Could not find p11-kit-1])]
    )]
  )

])
