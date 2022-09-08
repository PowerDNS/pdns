AC_DEFUN([PDNS_ENABLE_GSS_TSIG],[
  AC_MSG_CHECKING([whether to enable experimental GSS-TSIG support])
  AC_ARG_ENABLE([experimental_gss_tsig],
    AS_HELP_STRING([--enable-experimental-gss-tsig],
      [enable experimental GSS-TSIG support @<:@default=no@:>@]
    ),
    [enable_experimental_gss_tsig=$enableval],
    [enable_experimental_gss_tsig=no]
  )

  AC_MSG_RESULT([$enable_experimental_gss_tsig])

  AM_CONDITIONAL([GSS_TSIG],[test "x$enable_experimental_gss_tsig" != "xno"])
  AC_SUBST(GSS_TSIG)
  AS_IF([test "x$enable_experimental_gss_tsig" != "xno"],
   [PKG_CHECK_MODULES([GSS], [krb5 krb5-gssapi],
      [
        AC_DEFINE([ENABLE_GSS_TSIG], [1], [Define to 1 if you want to enable GSS-TSIG support])
        GSS_TSIG=yes
      ],
      [AC_MSG_ERROR([Required libraries for GSS-TSIG not found])]
   )],
    [GSS_TSIG=no])
])
