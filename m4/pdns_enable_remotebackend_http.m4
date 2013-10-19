AC_DEFUN([PDNS_ENABLE_REMOTEBACKEND_HTTP],[
  AC_MSG_CHECKING([whether to enable http connector in remotebackend])
  AC_ARG_ENABLE([remotebackend_http],
    AS_HELP_STRING([--enable-remotebackend-http],
      [enable HTTP connector for remotebackend @<:@default=no@:>@]
    ),
    [enable_remotebackend_http=yes],
    [enable_remotebackend_http=no]
  )

  AC_MSG_RESULT([$enable_remotebackend_http])

  AM_CONDITIONAL([REMOTEBACKEND_HTTP],[test "x$enable_remotebackend_http" = "xyes"])
  AS_IF([test "x$enable_remotebackend_http" = "xyes"],
    [PKG_CHECK_MODULES([LIBCURL], [libcurl],
        [AC_DEFINE([HAVE_LIBCURL], [1], [Define to 1 if you have libcurl])]
        [AC_DEFINE([REMOTEBACKEND_HTTP], [1], [Define to 1 if you have http connector])],
        [AC_MSG_ERROR([Could not find libcurl])]
     )]
  )
])

