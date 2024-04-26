AC_DEFUN([DNSDIST_ENABLE_DNS_OVER_HTTP3], [
  AC_MSG_CHECKING([whether to enable incoming DNS over HTTP3 (DoH3) support])
  AC_ARG_ENABLE([dns-over-http3],
    AS_HELP_STRING([--enable-dns-over-http3], [enable incoming DNS over HTTP3 (DoH3) support (requires quiche) @<:@default=no@:>@]),
    [enable_dns_over_http3=$enableval],
    [enable_dns_over_http3=no]
  )
  AC_MSG_RESULT([$enable_dns_over_http3])
  AM_CONDITIONAL([HAVE_DNS_OVER_HTTP3], [test "x$enable_dns_over_http3" != "xno"])

  AM_COND_IF([HAVE_DNS_OVER_HTTP3], [
    AC_DEFINE([HAVE_DNS_OVER_HTTP3], [1], [Define to 1 if you enable DNS over HTTP/3 support])
  ])
])
