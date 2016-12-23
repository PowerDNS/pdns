AC_DEFUN([PDNS_ENABLE_REPRODUCIBLE], [
  AC_REQUIRE([PDNS_CHECK_OS])
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
    build_user=$(id -u -n)

    case "$host_os" in
    solaris2.1* | SunOS | openbsd*)
      build_host_host=$(hostname)
      build_host_domain=$(domainname)
      build_host="$build_host_host.$build_host_domain"
      ;;
    *)
      build_host=$(hostname -f || hostname || echo 'localhost')
      ;;
    esac
    AC_DEFINE_UNQUOTED([BUILD_HOST], ["$build_user@$build_host"], [Set to the user and host that builds PowerDNS])
  ])
])
