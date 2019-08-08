AC_DEFUN([PDNS_ENABLE_DNS_OVER_TLS], [
  AC_MSG_CHECKING([whether to enable DNS over TLS support])
  AC_ARG_ENABLE([dns-over-tls],
    AS_HELP_STRING([--enable-dns-over-tls], [enable DNS over TLS support (requires GnuTLS or OpenSSL) @<:@default=no@:>@]),
    [enable_dns_over_tls=$enableval],
    [enable_dns_over_tls=no]
  )
  AC_MSG_RESULT([$enable_dns_over_tls])
  AM_CONDITIONAL([HAVE_DNS_OVER_TLS], [test "x$enable_dns_over_tls" != "xno"])

  AM_COND_IF([HAVE_DNS_OVER_TLS], [
    AC_DEFINE([HAVE_DNS_OVER_TLS], [1], [Define to 1 if you enable DNS over TLS support])
  ])
])
