AC_DEFUN([PDNS_ENABLE_DNSTAP],[
  AC_MSG_CHECKING([whether to enable logging of outgoing queries using dnstap])

  AC_ARG_ENABLE([dnstap],
    AS_HELP_STRING([--enable-dnstap],
      [enable logging of outgoing queries using dnstap @<:@default=no@:>@]
    ),
    [enable_dnstap=$enableval],
    [enable_dnstap=no]
  )

  AS_IF([test "x$enable_dnstap" != "xno"],
    [AC_DEFINE([DNSTAP_ENABLED], [1], [Define to 1 if dnstap is enabled])]
  )

  AM_CONDITIONAL([DNSTAP_ENABLED], [test "x$enable_dnstap" != "xno"])

  AC_MSG_RESULT([$enable_dnstap])
])
