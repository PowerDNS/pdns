AC_DEFUN([PDNS_ENABLE_BOTAN],[
  AC_MSG_CHECKING([whether we will be linking in Botan 1.10])
  AC_ARG_ENABLE([botan1.10],
    [AS_HELP_STRING([--enable-botan1.10],[use Botan 1.10 @<:@default=no@:>@])],
    [enable_botan110=$enableval],
    [enable_botan110=no]
  )
  AC_MSG_RESULT([$enable_botan110])
  AM_CONDITIONAL(BOTAN110, [test "x$enable_botan110" != "xno"])

  AC_MSG_CHECKING([whether we will be linking in Botan 1.8])
  AC_ARG_ENABLE([botan1.8],
    [AS_HELP_STRING([--enable-botan1.8],[use Botan 1.8 @<:@default=no@:>@])],
    [enable_botan18=$enableval],
    [enable_botan18=no]
  )
  AC_MSG_RESULT([$enable_botan18])
  AM_CONDITIONAL([BOTAN18], [test "x$enable_botan18" != "xno"])

  AS_IF([test "x$enable_botan110" != "xno"], [
    PKG_CHECK_MODULES([BOTAN110], [botan-1.10],
      [AC_DEFINE([HAVE_BOTAN110],[1],[Define to 1 if you have botan 1.10])],
      [AC_MSG_ERROR([Could not find botan 1.10])]
    )]
  )

  AS_IF([test "x$enable_botan18" != "xno"], [
    PKG_CHECK_MODULES([BOTAN18], [botan-1.8],
      [AC_DEFINE([HAVE_BOTAN18], [1], [Define to 1 if you have botan 1.10])],
      [AC_MSG_ERROR([Could not find botan 1.8])]
    )]
  )
])
