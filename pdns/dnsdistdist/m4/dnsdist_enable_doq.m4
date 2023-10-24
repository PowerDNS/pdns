AC_DEFUN([DNSDIST_ENABLE_DNS_OVER_QUIC], [
  AC_MSG_CHECKING([whether to enable incoming DNS over QUIC (DoQ) support])
  AC_ARG_ENABLE([dns-over-quic],
    AS_HELP_STRING([--enable-dns-over-quic], [enable incoming DNS over QUIC (DoQ) support (requires quiche) @<:@default=no@:>@]),
    [enable_dns_over_quic=$enableval],
    [enable_dns_over_quic=no]
  )
  AC_MSG_RESULT([$enable_dns_over_quic])
  AM_CONDITIONAL([HAVE_DNS_OVER_QUIC], [test "x$enable_dns_over_quic" != "xno"])

  AM_COND_IF([HAVE_DNS_OVER_QUIC], [
    AC_DEFINE([HAVE_DNS_OVER_QUIC], [1], [Define to 1 if you enable DNS over QUIC support])
  ])
])
