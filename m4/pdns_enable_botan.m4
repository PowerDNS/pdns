AC_DEFUN([PDNS_ENABLE_BOTAN],[
  AC_MSG_CHECKING([whether we will be linking in Botan 2.x])
  AC_ARG_ENABLE([botan],
    [AS_HELP_STRING([--enable-botan],[use Botan @<:@default=no@:>@])],
    [enable_botan=$enableval],
    [enable_botan=no]
  )
  AC_MSG_RESULT([$enable_botan])
  AM_CONDITIONAL(BOTAN, [test "x$enable_botan" != "xno"])

  AS_IF([test "x$enable_botan" != "xno"], [
    PKG_CHECK_MODULES([BOTAN], [botan-2],
      [AC_DEFINE([HAVE_BOTAN],[1],[Define to 1 if you have botan])],
      [AC_MSG_ERROR([Could not find botan])]
    )]
  )
])
