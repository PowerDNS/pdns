AC_DEFUN([DNSDIST_ENABLE_DNSCRYPT], [
  AC_MSG_CHECKING([whether to enable DNSCrypt support])
  AC_ARG_ENABLE([dnscrypt],
    AS_HELP_STRING([--enable-dnscrypt], [enable DNSCrypt support (requires libsodium) @<:@default=no@:>@]),
    [enable_dnscrypt=$enableval],
    [enable_dnscrypt=no]
  )
  AC_MSG_RESULT([$enable_dnscrypt])
  AM_CONDITIONAL([DNSCRYPT], [test "x$enable_dnscrypt" != "xno"])

  AM_COND_IF([DNSCRYPT], [
    AM_COND_IF([LIBSODIUM], [
      AC_DEFINE([HAVE_DNSCRYPT], [1], [Define to 1 if you enable dnscrypt support])
    ],[
      AC_MSG_ERROR([dnscrypt support requested but libsodium is not available])
    ])
  ])
])
