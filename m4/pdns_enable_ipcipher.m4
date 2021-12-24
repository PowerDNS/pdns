AC_DEFUN([PDNS_ENABLE_IPCIPHER], [
  AC_MSG_CHECKING([whether to enable ipcipher support])
  HAVE_IPCIPHER=0
  AC_ARG_ENABLE([ipcipher],
    AS_HELP_STRING([--enable-ipcipher], [enable ipcipher support (requires libcrypto) @<:@default=auto@:>@]),
    [enable_ipcipher=$enableval],
    [enable_ipcipher=auto]
  )
  AC_MSG_RESULT([$enable_ipcipher])

  AS_IF([test "x$enable_ipcipher" != "xno"], [
    AS_IF([test "x$enable_ipcipher" = "xyes" -o "x$enable_ipcipher" = "xauto"], [
      AM_COND_IF([HAVE_LIBCRYPTO], [
        AC_DEFINE([HAVE_IPCIPHER], [1], [Define to 1 if you enable ipcipher support])
        [HAVE_IPCIPHER=1]
      ])
    ])
  ])
  AM_CONDITIONAL([IPCIPHER], [test "x$HAVE_IPCIPHER" != "x0"])

  AS_IF([test "x$enable_ipcipher" = "xyes"], [
    AS_IF([test x"$HAVE_IPCIPHER" = "x0"], [
      AC_MSG_ERROR([ipcipher support requested but libcrypto is not available])
    ])
  ])
])
