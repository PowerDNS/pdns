AC_DEFUN([PDNS_ENABLE_VERBOSE_LOGGING],[
  AC_MSG_CHECKING([whether to enable verbose logging])

  AC_ARG_ENABLE([verbose-logging],
    AS_HELP_STRING([--enable-verbose-logging],
      [enable verbose logging @<:@default=no@:>@]
    ),
    [enable_verbose_logging=yes],
    [enable_verbose_logging=no]
  )

  AS_IF([test "x$enable_verbose_logging" = "xyes"],
    [AC_DEFINE([VERBOSELOG], [1], [Define to 1 if verbose logging is enabled])]
  )

  AC_MSG_RESULT([$enable_verbose_logging])
])
