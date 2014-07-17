AC_DEFUN([PDNS_ENABLE_STATIC_BINARIES],[
  AC_MSG_CHECKING([whether we should build static binaries])

  AC_ARG_ENABLE([static-binaries],
    [AS_HELP_STRING([--enable-static-binaries],
      [build static binaries @<:@default=no@:>@]
    )],
    [enable_static_binaries=$enableval],
    [enable_static_binaries=no],
  )
  AC_MSG_RESULT([$enable_static_binaries])
  AM_CONDITIONAL([ALLSTATIC], [test "x$enable_static_binaries" != "xno"])

  if test "x$enable_static_binaries" != "xno"; then
    LDFLAGS="-all-static $LDFLAGS"
  fi
])
