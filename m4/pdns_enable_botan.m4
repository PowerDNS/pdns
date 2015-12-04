AC_DEFUN([PDNS_ENABLE_BOTAN],[
  AC_MSG_CHECKING([whether we will be linking in Botan 1.10])
  AC_ARG_ENABLE([botan1.10],
    [AS_HELP_STRING([--enable-botan1.10],[use Botan 1.10 @<:@default=no@:>@])],
    [enable_botan110=$enableval],
    [enable_botan110=no]
  )
  AC_MSG_RESULT([$enable_botan110])
  AM_CONDITIONAL(BOTAN110, [test "x$enable_botan110" != "xno"])


  AS_IF([test "x$enable_botan110" != "xno"], [
    PKG_CHECK_MODULES([BOTAN110], [botan-1.10],
      [AC_DEFINE([HAVE_BOTAN110],[1],[Define to 1 if you have botan 1.10])],
      [AC_MSG_ERROR([Could not find botan 1.10])]
    )]
  )
])
