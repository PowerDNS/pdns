AC_DEFUN([DNSDIST_ENABLE_DNS_OVER_HTTPS], [
  AC_MSG_CHECKING([whether to enable DNS over HTTPS (DoH) support])
  AC_ARG_ENABLE([dns-over-https],
    AS_HELP_STRING([--enable-dns-over-https], [enable DNS over HTTPS (DoH) support (requires libh2o) @<:@default=no@:>@]),
    [enable_dns_over_https=$enableval],
    [enable_dns_over_https=no]
  )
  AC_MSG_RESULT([$enable_dns_over_https])
  AM_CONDITIONAL([HAVE_DNS_OVER_HTTPS], [test "x$enable_dns_over_https" != "xno"])

  AM_COND_IF([HAVE_DNS_OVER_HTTPS], [
    AC_DEFINE([HAVE_DNS_OVER_HTTPS], [1], [Define to 1 if you enable DNS over HTTPS support])
  ])
])

