AC_DEFUN([PDNS_ENABLE_REPRODUCIBLE], [
  AC_MSG_CHECKING([whether to enable reproducible builds.])
  AC_ARG_ENABLE([reproducible],
    AS_HELP_STRING([--enable-reproducible],
      [Create reproducible builds. Use this only if you are a distribution maintainer and need reproducible builds. If you compile PowerDNS yourself, leave this disabled, as it might make debugging harder. @<:@default=no@:>@]),
    [enable_reproducible=$enableval],
    [enable_reproducible=no])

  AC_MSG_RESULT($enable_reproducible)

  AS_IF([test x"$enable_reproducible" = "xyes"],[
    AC_DEFINE([REPRODUCIBLE], [1], [Define to 1 for reproducible builds])
  ],[
    build_user=m4_esyscmd_s(id -u -n)
    AS_IF([test x"$host_os" = "xSunOS"],[
      build_host_host=m4_esyscmd_s(hostname)
      build_host_domain=m4_esyscmd_s(domainname)
      build_host="$build_host_host.$build_host_domain"
    ],[
      build_host=m4_esyscmd_s(hostname -f || hostname || echo 'localhost')
    ])
    AC_DEFINE_UNQUOTED([BUILD_HOST], ["$build_user@$build_host"], [Set to the user and host that builds PowerDNS])
  ])
])
