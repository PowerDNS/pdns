AC_DEFUN([PDNS_ENABLE_IPCIPHER], [
  AC_MSG_CHECKING([whether to enable ipcipher support])
  AC_ARG_ENABLE([ipcipher],
    AS_HELP_STRING([--enable-ipcipher], [enable ipcipher support (requires libcrypto) @<:@default=yes@:>@]),
    [enable_ipcipher=$enableval],
    [enable_ipcipher=yes]
  )
  AC_MSG_RESULT([$enable_ipcipher])
  AM_CONDITIONAL([IPCIPHER], [test "x$enable_ipcipher" != "xno"])

  AM_COND_IF([IPCIPHER], [
    AM_COND_IF([HAVE_LIBCRYPTO], [
      AC_DEFINE([HAVE_IPCIPHER], [1], [Define to 1 if you enable ipcipher support])
    ],[
      AC_MSG_ERROR([ipcipher support requested but libcrypto is not available])
    ])
  ])
])
